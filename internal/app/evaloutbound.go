package app

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// runEvalOutbound 是 eval --outbound：用 outbound 标注语料评估判断层，报告仅本地与本地 + 模型的漏报率、误报率；
// --sweep 只在 tune 切分上扫描门槛，按扫出的门槛再报告一次（holdout 的数字才是没有拟合过的估计），打印带 outbound 题集
// 指纹的建议（不写配置）。会把语料文本发给后端，所以先说明，在终端里确认或带 --yes。
//
// threshold 不为 -1 时按它报告（--threshold：采纳的门槛不一定是扫描的建议），否则按档案的门槛。
func runEvalOutbound(s setup, o Options, name string, st judgeState, casesPath string, sweep, yes bool, threshold float64) int {
	if !st.backend.Caps().Supports(judge.KindProbability) {
		fmt.Fprintf(o.Stderr, "h-guard: backend %s cannot answer probability questions, which h-guard eval --outbound asks\n", shown(name))
		return 1
	}
	cases, err := eval.OutboundCorpus()
	source := "the built-in outbound corpus"
	if casesPath != "" {
		cases, err = eval.LoadOutboundCases(casesPath)
		source = shown(casesPath)
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	ob := s.cfg.Outbound
	fmt.Fprintf(o.Stderr, "h-guard eval --outbound sends %d texts from %s to backend %s (%s) %s: each prompt or tool output in up to %d chunks,\n"+
		"with credentials, private keys and personal information that h-guard recognizes masked. Texts that local rules already block,\n"+
		"or shorter than %d characters, are not sent.\n", len(cases), source, shown(name), st.typ, targetOf(st), ob.JudgeMaxChunks, ob.JudgeMinChars)
	if !yes {
		if !o.IsTerminal() {
			fmt.Fprintln(o.Stderr, "h-guard: not a terminal; pass --yes to send without asking")
			return 1
		}
		fmt.Fprint(o.Stderr, "Continue? [y/N] ")
		answer, _ := bufio.NewReader(o.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(o.Stderr, "cancelled")
			return 1
		}
	}
	env := eval.OutboundEnv{Rules: s.rules, Config: s.cfg, Backend: st.backend, Progress: func(i, n int, out eval.OutboundOutcome) {
		state := "not sent"
		switch {
		case out.Err != "":
			state = out.Err
		case out.Sent:
			state = "sent"
		}
		fmt.Fprintf(o.Stderr, "[%d/%d] %s (%s) local %v\n", i, n, out.Case.Source, state, out.Local)
	}}
	outs := eval.RunOutbound(context.Background(), env, cases)
	current := st.outboundThreshold
	fmt.Fprintf(o.Stdout, "backend %s (%s) %s\noutbound threshold: %s\n", shown(name), st.typ, targetOf(st), outboundCalibrationText(st))
	if threshold != -1 {
		current = threshold
		fmt.Fprintf(o.Stdout, "reported at threshold %g (--threshold)\n", threshold)
	}
	// 评估的设置与默认配置不同，写明，读数字时才不会当成默认配置下的效果
	piiState := "off"
	if s.cfg.Category("pii").Enabled {
		piiState = "on"
	}
	fmt.Fprintf(o.Stdout, "evaluation settings: tier 3 (all tool output), PII on, each category with its configured action (pii %s); judge_min_chars %d, "+
		"up to %d chunks of %d characters.\nyour config: outbound tier %d, PII %s; the default config scans prompts only with PII off.\n\n",
		s.cfg.Category("pii").Action, ob.JudgeMinChars, ob.JudgeMaxChunks, ob.JudgeChunkChars, ob.Tier, piiState)
	eval.WriteOutboundReport(o.Stdout, outs, current)
	all := eval.ScoreOutbound(outs, current, "")
	if all.Failed > 0 {
		// 写明失败的类别与说明（如 auth (ANTHROPIC_API_KEY is not set)）与后端的提示：stdout 常被重定向到文件
		fmt.Fprintf(o.Stderr, "h-guard: %d of %d texts sent to the backend failed: %s. Nothing was swept or suggested; fix the backend and run again.\n",
			all.Failed, all.Cases-all.NotSent, eval.OutboundFailureSummary(outs))
		var fails []eval.Outcome
		for _, out := range outs {
			if out.ErrKind != "" {
				fails = append(fails, eval.Outcome{Err: out.ErrKind, ErrDetail: out.ErrDetail})
			}
		}
		for _, hint := range failureHints(st.backend, fails) {
			fmt.Fprintln(o.Stderr, "h-guard: hint:", hint)
		}
		return 1
	}
	if all.Bad > 0 {
		fmt.Fprintf(o.Stderr, "h-guard: %d texts had questions without a valid answer; no threshold is suggested. Fix the backend and run again.\n", all.Bad)
		return 1
	}
	if !sweep {
		return 0
	}
	// 建议要有证据：tune 切分里至少一条得到了模型的有效答案。都没送模型（短于门槛、本地已拦）或只有 fresh、holdout 时，
	// 扫描的结果只是保留当前值，不能写成校准过的档案
	if !slices.ContainsFunc(outs, func(o eval.OutboundOutcome) bool { return o.Case.Split == eval.SplitTune && o.Answered() }) {
		fmt.Fprintln(o.Stderr, "h-guard: no tune case got an answer from the judge (texts shorter than judge_min_chars or blocked by local rules are not sent), so no threshold is suggested.")
		return 1
	}
	rows, best := eval.SweepOutbound(outs, current)
	eval.WriteOutboundSweep(o.Stdout, rows)
	if best != current {
		eval.WriteOutboundReport(o.Stdout, outs, best)
	}
	tune := eval.ScoreOutbound(outs, best, eval.SplitTune)
	profile := st.outboundCal.Profile
	if profile == "" {
		profile = name
	}
	info := describeOf(st.backend)
	fmt.Fprintf(o.Stdout, "# Suggested outbound threshold, fitted on %d tune cases (%d errors there); the holdout and fresh figures at this\n"+
		"# threshold are the estimates that were not fitted (fresh was added after the question wording was frozen).\n"+
		"# The profile below keeps its action thresholds and fingerprint and adds the outbound ones; it replaces the whole profile.\n",
		tune.Cases, tune.Missed+tune.FP)
	fmt.Fprint(o.Stdout, outboundProfileYAML(profile, s.cfg.Profiles[profile], best, info))
	if own := ownCategoryQuestions(s); len(own) > 0 {
		fmt.Fprintf(o.Stdout, "# Your categories %s ask their own questions; the fingerprint covers only the built-in ones.\n", strings.Join(own, ", "))
	}
	if st.outboundCal.Profile == "" {
		fmt.Fprintf(o.Stdout, "# and reference it from the backend: backends.%s.profile: %s\n", name, profile)
	}
	return 0
}

// outboundProfileYAML 是建议档案：加上 outbound 门槛与 outbound 题集指纹，打印整份档案，照抄进配置是合法的。
// 已有档案的 action 阈值与指纹只在它的模型、概率获取方式与当前后端一致时保留：指纹里的模型与概率获取方式
// 两部分共用，换了模型时照抄会让旧模型上的 action 阈值变成「已校准」，而 outbound 的扫描并没有验证它们。
// 不一致时只写 outbound 的部分，action 按未校准。
func outboundProfileYAML(name string, p config.Profile, threshold float64, info judge.Info) string {
	var th, fp []string
	t := p.Thresholds
	sameBackend := p.Fingerprint != nil && p.Fingerprint.Model == info.Model && p.Fingerprint.Probability == info.Probability
	if t.Hit != nil && t.Veto != nil && t.Requested != nil && sameBackend {
		th = append(th, fmt.Sprintf("hit: %g", *t.Hit), fmt.Sprintf("veto: %g", *t.Veto), fmt.Sprintf("requested: %g", *t.Requested))
		if len(t.RadiusFloor) > 0 {
			var rf []string
			for _, k := range slices.Sorted(maps.Keys(t.RadiusFloor)) {
				rf = append(rf, fmt.Sprintf("%s: %g", k, t.RadiusFloor[k]))
			}
			th = append(th, "radius_floor: {"+strings.Join(rf, ", ")+"}")
		}
	}
	th = append(th, fmt.Sprintf("outbound: %g", threshold))
	fp = append(fp, fmt.Sprintf("model: %q", info.Model), fmt.Sprintf("probability: %q", info.Probability))
	if p.Fingerprint != nil && p.Fingerprint.Questions != "" && len(th) > 1 {
		fp = append(fp, fmt.Sprintf("questions: %q", p.Fingerprint.Questions))
	}
	fp = append(fp, fmt.Sprintf("outbound_questions: %q", outbound.BuiltinQuestionsDigest))
	return fmt.Sprintf("profiles:\n  %q:\n    thresholds: {%s}\n    fingerprint: {%s}\n", name, strings.Join(th, ", "), strings.Join(fp, ", "))
}

// describeOf 返回后端的模型与概率获取方式（没有实现 Describer 时为空）。
func describeOf(b judge.Backend) judge.Info {
	if d, ok := b.(judge.Describer); ok {
		return d.Describe()
	}
	return judge.Info{}
}

// ownCategoryQuestions 返回配置里写了自己题目的类别（含覆盖内置类别题的）：它们不在 outbound 题集指纹内。
func ownCategoryQuestions(s setup) []string {
	var names []string
	for name, c := range s.cfg.Outbound.Categories {
		if c.Question != nil {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

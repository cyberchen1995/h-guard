package app

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runEval 用标注语料评估判断后端（spec §12）：报告结论与类别识别的准确率；--sweep 复用答案扫描阈值并打印
// 带指纹的建议档案（不写配置）。会把语料中的命令与指令发给后端，所以先说明目标与条数，在终端里确认或带 --yes。
// 内置语料是标注数据、不含用户的内容，因此不要求同意记录（同意约束的是 hook 发出的用户数据）。
func runEval(args []string, o Options) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	backend := fs.String("backend", "", "backend to evaluate (default: judge.backend)")
	sweep := fs.Bool("sweep", false, "scan thresholds with the recorded answers and suggest a profile")
	casesPath := fs.String("cases", "", "JSONL corpus to use instead of the built-in one")
	yes := fs.Bool("yes", false, "send the corpus without asking")
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, *extra)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	name := *backend
	if name == "" {
		name = s.cfg.Judge.Backend
	}
	if _, ok := s.cfg.Backends[name]; !ok {
		fmt.Fprintf(o.Stderr, "h-guard: no backend named %q in the config\n", shown(name))
		return 1
	}
	st := s.inspectJudge(o, name)
	if st.err != nil {
		fmt.Fprintln(o.Stderr, "h-guard: backend", shown(name)+":", shown(st.err.Error()))
		return 1
	}
	cases, err := eval.Corpus()
	if *casesPath != "" {
		cases, err = eval.LoadCases(*casesPath)
	}
	if err != nil {
		// 解析错误里有文件路径与写错的字段名，都可能带凭据（评审 R2-03）
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	source := "the built-in corpus"
	if *casesPath != "" {
		source = shown(*casesPath)
	}
	// 这是一次数据发送授权：写明目标、来源与发送的内容（评审：--cases 的语料可能含用户数据）
	fmt.Fprintf(o.Stderr, "h-guard eval sends %d cases from %s to backend %s (%s) %s: each command and its user instructions,\n"+
		"with credentials that h-guard recognizes masked; the cwd, harness and tool are fixed placeholders.\n",
		len(cases), source, shown(name), st.typ, targetOf(st))
	if !*yes {
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
	env := eval.Env{Rules: s.rules, Config: s.cfg, Backend: st.backend, Thresholds: st.thresholds,
		Progress: func(i, n int, out eval.Outcome) {
			fmt.Fprintf(o.Stderr, "[%d/%d] %s -> %s\n", i, n, shown(out.Case.Command), out.Decision)
		}}
	ctx := context.Background()
	outs, err := eval.Run(ctx, env, cases)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	fmt.Fprintf(o.Stdout, "backend %s (%s) %s\nthresholds: %s\n\n", shown(name), st.typ, targetOf(st), calibrationText(st))
	var ids []string
	for _, r := range s.rules.All() {
		ids = append(ids, r.ID)
	}
	eval.Report(o.Stdout, outs, ids, nil)
	// 调用失败时结论来自保守处理，不扫描、不建议；退出码为 1，并在 stderr 写明——stdout 常被重定向到文件，
	// 否则用户只看到退出码 0（如 API key 没传进来，全部调用都以 auth 失败）
	if failed := eval.Failed(outs); failed > 0 {
		next := "Fix the backend and run again."
		if *sweep {
			next = "Nothing was swept or suggested; fix the backend and run again."
		}
		fmt.Fprintf(o.Stderr, "h-guard: %d of %d calls failed: %s. %s\n", failed, calledCount(outs), eval.FailureSummary(outs), next)
		return 1
	}
	// 答案不完整同样不能作为证据（评审 M2-05）：照常扫描给出参考，但不建议档案，退出码为 1 并在 stderr 写明
	incomplete := eval.Incomplete(outs)
	if incomplete > 0 {
		fmt.Fprintf(o.Stderr, "h-guard: %d cases had questions without a valid answer (see === Incomplete answers in the report). "+
			"Fix the backend and run again.\n", incomplete)
	}
	if !*sweep {
		if incomplete > 0 {
			return 1
		}
		return 0
	}
	tables, th, score, err := eval.Sweep(ctx, env, outs, st.thresholds, 1)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	eval.WriteSweep(o.Stdout, tables)
	// 答案不完整时，结论靠缺题时的保守处理得出，不是模型的判断：不给建议档案（评审 M2-05）
	if incomplete > 0 {
		fmt.Fprintf(o.Stdout, "\nNo profile suggested: %d cases had questions without a valid answer. Fix the backend and run again.\n", incomplete)
		return 1
	}
	profile := st.cal.Profile
	if profile == "" {
		profile = name
	}
	fmt.Fprintln(o.Stdout)
	builtin, err := rules.Builtin()
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprint(o.Stdout, eval.ProfileYAML(profile, th, eval.Fingerprint(st.backend, action.QuestionSet(builtin)), score, len(cases)))
	if own := s.ownQuestions(); len(own) > 0 {
		fmt.Fprintf(o.Stdout, "# Your rules %s ask their own questions; the fingerprint covers only the built-in ones.\n", strings.Join(own, ", "))
	}
	if st.cal.Profile == "" {
		fmt.Fprintf(o.Stdout, "# and reference it from the backend: backends.%s.profile: %s\n", name, profile)
	}
	return 0
}

// calledCount 返回调用了后端的条数（deny 级的不调用）。
func calledCount(outs []eval.Outcome) int {
	n := 0
	for _, o := range outs {
		if o.Called {
			n++
		}
	}
	return n
}

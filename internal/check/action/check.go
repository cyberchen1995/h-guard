// Package action 是 action 检查（spec §5）：命令检测（pkg/detect/command）+ 规则包（internal/rules）+
// 判断后端（pkg/judge）+ 纯函数策略（Decide）。M1 处理 exec 动作；文件动作（第 2 档）在 M3 加入。
package action

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Name 是 Check 的名字。
const Name = "action"

// ProbeCommand 是安装探针：agent 执行它时请求一次确认，用来验证 hook 已生效（spec §5.6）。
const ProbeCommand = "h-guard-probe"

// Judge 描述判断层在这次调用中能否使用。
type Judge struct {
	Backend     judge.Backend // 可调用的后端
	Unavailable string        // 模型已开启但不能调用的原因码（如 judge_consent_missing）；非空时不调用
}

// Check 是 action 检查。字段在构造后只读，可并发使用。
type Check struct {
	Rules   *rules.Set
	Config  *config.Config
	Catalog *i18n.Catalog
	Locale  string
	Judge   Judge
}

func (c *Check) Name() string { return Name }

// Applies 报告事件是否含 exec 动作。
func (c *Check) Applies(ev guard.Event) bool {
	if ev.Kind != guard.EventAction {
		return false
	}
	return slices.ContainsFunc(ev.Actions, func(a guard.Action) bool { return a.Kind == guard.ActionExec && a.Exec != nil })
}

// Evaluate 逐个评估 exec 动作，取最严（spec §5.1 多动作）。每个动作完成全部判断后立即提交；
// 灾难性 deny 一经命中就提交，之后的预算耗尽、出错或 panic 都不能让它变宽（spec §3.3）。
func (c *Check) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	out := guard.Verdict{Decision: guard.DecisionPass}
	first := true
	for _, a := range ev.Actions {
		if a.Kind != guard.ActionExec || a.Exec == nil {
			continue
		}
		v := c.evalExec(ctx, ev, a.Exec, commit)
		commit(v)
		if first {
			out, first = v, false
		} else {
			out = merge(out, v)
		}
		if out.Decision == guard.DecisionDeny {
			break
		}
	}
	return out, nil
}

// merge 以更严的结论为主（同样严时取先出现的），合并全部命中与降级原因。
func merge(acc, v guard.Verdict) guard.Verdict {
	base, other := acc, v
	if guard.Stricter(acc.Decision, v.Decision) != acc.Decision {
		base, other = v, acc
	}
	out := base
	out.Findings = append(slices.Clone(base.Findings), other.Findings...)
	for _, f := range other.Fallbacks {
		out.Fallbacks = appendOnce(out.Fallbacks, f)
	}
	return out
}

func (c *Check) evalExec(ctx context.Context, ev guard.Event, ex *guard.ExecAction, commit func(guard.Verdict)) guard.Verdict {
	if strings.TrimSpace(ex.Command) == ProbeCommand {
		return guard.Verdict{
			Decision: guard.DecisionAsk,
			Reasons:  []guard.Reason{{Code: i18n.KeyActionProbe}},
			Signals:  map[string]any{"probe": true},
		}
	}
	exp, err := command.Expand(ctx, ex.Command, ex.Shell)
	if err != nil {
		return budgetExceeded()
	}
	policyRules := map[string]Rule{}
	var hits []RegexHit
	judgeOn := c.Config.Judge.Enabled
	th := c.Config.Thresholds()
	committed := false
	// deny 级规则先匹配：预算可能在任何一条规则处耗尽，确定的 deny 要尽早得出、尽早提交
	ordered := slices.Clone(c.Rules.All())
	slices.SortStableFunc(ordered, func(a, b *rules.Rule) int {
		return boolRank(b.Action == guard.DecisionDeny) - boolRank(a.Action == guard.DecisionDeny)
	})
	for _, r := range ordered {
		if !r.Enabled() || !r.AppliesTo(guard.ActionExec) {
			continue
		}
		_, hasQ := r.JudgeQuestion()
		policyRules[r.ID] = Rule{
			ID: r.ID, Action: r.Action, Bypassable: r.Bypassable(), RadiusFloor: r.RadiusFloor,
			RequiresJudge: r.RequiresJudge, Asked: judgeOn && hasQ,
		}
		res, err := r.MatchExec(ctx, exp)
		if res.Hit {
			hits = append(hits, RegexHit{Rule: r.ID, TimedOut: res.TimedOut})
		}
		if err != nil {
			return c.budgetVerdict(policyRules, hits)
		}
		if !committed && r.Action == guard.DecisionDeny && res.Hit && !res.TimedOut {
			in := Input{Rules: policyRules, Regex: hits, Judge: JudgeOff}
			commit(c.render(Decide(in), in))
			committed = true
		}
	}
	in := Input{
		Rules: policyRules, Regex: hits, Thresholds: th,
		OnUnavailable: guard.Decision(c.Config.Policy.OnUnavailable),
	}
	requests := userRequests(ev.Requests, c.Config.Policy.RequestWindow)
	in.HaveRequests = len(requests) > 0

	denyNow := slices.ContainsFunc(hits, func(h RegexHit) bool { return policyRules[h.Rule].Action == guard.DecisionDeny && !h.TimedOut })
	switch {
	case denyNow:
		in.Judge = JudgeOff // 灾难性形态不调模型
	case !judgeOn:
		in.Judge = JudgeOff
	case c.Judge.Unavailable != "":
		in.Judge, in.JudgeFallback = JudgeFailed, c.Judge.Unavailable
	case c.Judge.Backend == nil:
		in.Judge, in.JudgeFallback = JudgeFailed, FallbackJudgeUnavailable
	default:
		state, truncated := BuildState(StateInput{
			Harness: ev.Harness, Tool: ev.Tool, Command: ex.Command, Cwd: ev.Cwd, Requests: requests,
			MaxCommandChars: c.Config.Policy.MaxCommandChars, MaxRequestChars: c.Config.Policy.MaxRequestChars,
		})
		qs := questions(c.Rules, policyRules)
		resp, err := judge.AskAll(ctx, c.Judge.Backend, state, qs)
		if err != nil {
			in.Judge, in.JudgeFallback = JudgeFailed, FallbackJudgeUnavailable
			if judge.KindOf(err) == judge.Timeout {
				in.JudgeFallback = FallbackJudgeTimeout
			}
		} else {
			in.Judge, in.Answers, in.Truncated = JudgeAnswered, judge.Validate(qs, resp), truncated
		}
	}
	return c.render(Decide(in), in)
}

// Questions 返回在当前配置下 exec 动作调用模型时问的全部题，与 evalExec 一致：启用且适用于 exec、
// 带题的规则（模型开启时）按 id 排序，再加两个信号题。供离线核对录制的答案（golden 正式验收，评审 R3-05）。
func (c *Check) Questions() []judge.Question {
	policyRules := map[string]Rule{}
	for _, r := range c.Rules.All() {
		if r.Enabled() && r.AppliesTo(guard.ActionExec) {
			_, hasQ := r.JudgeQuestion()
			policyRules[r.ID] = Rule{ID: r.ID, Asked: c.Config.Judge.Enabled && hasQ}
		}
	}
	return questions(c.Rules, policyRules)
}

// questions 返回这次要问的题：被问规则的题（按 id 排序）+ 两个信号题。
func questions(set *rules.Set, policyRules map[string]Rule) []judge.Question {
	var qs []judge.Question
	for _, id := range sortedRuleIDs(policyRules) {
		if !policyRules[id].Asked {
			continue
		}
		if q, ok := set.Get(id).JudgeQuestion(); ok {
			qs = append(qs, q)
		}
	}
	return append(qs, requestedQuestion, radiusQuestion)
}

// userRequests 取最近 window 条用户本人的指令，最新的在前（spec §5.4；automated 指令不参与）。
func userRequests(reqs []guard.Request, window int) []string {
	var out []string
	for i := len(reqs) - 1; i >= 0 && len(out) < window; i-- {
		if reqs[i].Source == guard.SourceUser && strings.TrimSpace(reqs[i].Text) != "" {
			out = append(out, reqs[i].Text)
		}
	}
	return out
}

func budgetExceeded() guard.Verdict {
	return guard.Verdict{
		Decision:  guard.DecisionAsk,
		Reasons:   []guard.Reason{{Code: i18n.KeyActionBudgetExceeded}, {Code: i18n.KeyHintNarrow}},
		Fallbacks: []string{FallbackBudget},
	}
}

// budgetVerdict 是本地阶段耗尽预算时的结论（spec §3.4）：已经得出的 deny 保持 deny；否则请求确认。
// 两种情况都保留已得出的命中，并带 local_budget_exceeded。
func (c *Check) budgetVerdict(policyRules map[string]Rule, hits []RegexHit) guard.Verdict {
	in := Input{Rules: policyRules, Regex: hits, Judge: JudgeOff}
	res := Decide(in)
	if res.Decision == guard.DecisionDeny {
		v := c.render(res, in)
		v.Fallbacks = appendOnce(v.Fallbacks, FallbackBudget)
		return v
	}
	v := budgetExceeded()
	for _, h := range res.Hits {
		v.Findings = append(v.Findings, guard.Finding{Rule: h.Rule, Source: h.Source})
	}
	return v
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// render 把策略结论变成 Verdict：命中、信号、结构化原因与前进路径（spec §7.3）。
// 原因参数里的规则说明按 c.Locale 生成，Verdict 中只有键与参数。
func (c *Check) render(res Result, in Input) guard.Verdict {
	v := guard.Verdict{Decision: res.Decision, Fallbacks: res.Fallbacks, Signals: map[string]any{}}
	for _, h := range res.Hits {
		v.Findings = append(v.Findings, guard.Finding{Rule: h.Rule, Source: h.Source, Probability: h.P})
	}
	v.Signals["judge"] = [...]string{"off", "failed", "answered"}[in.Judge]
	if res.Requested != nil {
		v.Signals[SignalRequested] = round(*res.Requested, 3)
	}
	if res.Radius != nil {
		v.Signals[SignalRadius] = round(*res.Radius, 2)
	}
	for k, list := range map[string][]string{"regex_vetoed": res.Vetoed, "below_radius_floor": res.Below, "judge_disabled_hits": res.Silenced} {
		if len(list) > 0 {
			v.Signals[k] = list
		}
	}
	if in.Truncated {
		v.Signals["truncated"] = true
	}
	if res.Decision == guard.DecisionPass {
		return v
	}

	rulesText := c.describe(res.Dangerous)
	// 超时的命中与不可豁免的规则一样不能被豁免（决定前进路径）；只有确定命中了不可豁免的规则才说「修改护栏本身」，
	// 超时的命中不能确定（原因里另有正则超时的说明，评审 M1 终审）
	guardSelf := slices.ContainsFunc(res.Dangerous, func(h Hit) bool { return !in.Rules[h.Rule].Bypassable && !h.TimedOut })
	unbypassable := guardSelf || slices.ContainsFunc(res.Dangerous, func(h Hit) bool { return h.TimedOut })
	add := func(code string, params map[string]string) {
		v.Reasons = append(v.Reasons, guard.Reason{Code: code, Params: params})
	}
	switch res.Branch {
	case BranchBlocked:
		add(i18n.KeyActionBlocked, map[string]string{"rules": rulesText})
		add(i18n.KeyHintManual, nil)
		return v
	case BranchUnavailable:
		add(i18n.KeyActionJudgeUnavailable, map[string]string{"code": in.JudgeFallback, "rules": rulesText})
	case BranchJudgeOff:
		if guardSelf {
			add(i18n.KeyActionGuardSelf, map[string]string{"rules": rulesText})
		} else {
			add(i18n.KeyActionDangerous, map[string]string{"rules": rulesText})
		}
	default:
		add(i18n.KeyActionDangerous, map[string]string{"rules": rulesText})
		if in.Truncated {
			add(i18n.KeyActionEvidenceTruncated, nil)
		} else {
			if res.Radius != nil {
				add(i18n.KeyActionRadius, map[string]string{"radius": strconv.FormatFloat(*res.Radius, 'f', 1, 64)})
			}
			if res.Requested != nil {
				add(i18n.KeyActionNotRequested, map[string]string{"p": strconv.FormatFloat(*res.Requested, 'f', 2, 64)})
			}
		}
	}
	if slices.Contains(res.Fallbacks, FallbackRegexTimeout) {
		add(i18n.KeyActionRegexTimeout, nil)
	}
	// 前进路径：按 spec §7.3 的表从上到下取第一条
	switch {
	case unbypassable:
		add(i18n.KeyHintManual, nil)
	case in.JudgeFallback == FallbackConsentMissing:
		add(i18n.KeyHintConsent, map[string]string{"backend": c.Config.Judge.Backend})
	case in.Judge == JudgeFailed:
		add(i18n.KeyHintJudgeUnavailable, nil)
	case in.Truncated:
		add(i18n.KeyHintSplit, nil)
	case in.Judge == JudgeAnswered && res.Requested != nil:
		add(i18n.KeyHintRequest, nil)
	default:
		add(i18n.KeyHintManual, nil)
	}
	return v
}

// describe 生成「原因 [来源 概率]」列表（Python 版 _describe），按 c.Locale。
func (c *Check) describe(hits []Hit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		reason := h.Rule
		if r := c.Rules.Get(h.Rule); r != nil {
			reason = r.ReasonText(c.Locale)
		}
		label := c.Catalog.Text(c.Locale, "source."+string(h.Source), nil)
		if h.P != nil {
			parts = append(parts, fmt.Sprintf("%s [%s %.2f]", reason, label, *h.P))
		} else {
			parts = append(parts, fmt.Sprintf("%s [%s]", reason, label))
		}
	}
	return strings.Join(parts, c.Catalog.Text(c.Locale, i18n.KeyListSeparator, nil))
}

func round(v float64, digits int) float64 {
	f, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', digits, 64), 64)
	return f
}

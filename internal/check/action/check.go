// Package action 是 action 检查：命令检测（pkg/detect/command）+ 规则包（internal/rules）+
// 判断后端（pkg/judge）+ 纯函数策略（Decide）。exec 动作走完整流程；文件动作只按路径匹配（pkg/detect/paths）：
// 硬规则（护栏自我保护）不受档位限制，其余文件规则（内置的 sensitive_read、用户的文件规则）须档位覆盖（第 2 档）。
package action

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/grant"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Name 是 Check 的名字。
const Name = "action"

// ProbeCommand 是安装探针：agent 执行它时请求一次确认，用来验证 hook 已生效。
const ProbeCommand = "h-guard-probe"

// Judge 描述判断层在这次调用中能否使用。
type Judge struct {
	Backend     judge.Backend // 可调用的后端
	Unavailable string        // 模型已开启但不能调用的原因码（如 judge_consent_missing）；非空时不调用
	// Thresholds 是这次使用的阈值，由入口按校准档案与指纹选出；nil 时用保守默认值。
	Thresholds *config.Thresholds
}

// Check 是 action 检查。字段在构造后只读，可并发使用。
type Check struct {
	Rules   *rules.Set
	Config  *config.Config
	Catalog *i18n.Catalog
	Locale  string
	Judge   Judge
	// Paths 是解析文件动作目标所需的环境：主目录、{config}、{cache} 的值与大小写规则；Cwd 取自事件。
	Paths paths.Env
	// Grants 是单次授权，入口只在 harness 不能请求确认时接入（能确认时用户直接在确认框里决定）；nil 时不提供。
	Grants Grants
	// GrantInput 是 harness 原始工具输入的规范写法，GrantCwd 是工作目录的真实路径，GrantDir 是它的文件身份，
	// 都绑进授权（grant.Op.Input、RealCwd、DirID）；入口取不到时不接入 Grants。
	GrantInput, GrantCwd, GrantDir string
}

// Grants 是单次授权的存取（grant.Store 实现它）。
type Grants interface {
	Has(op grant.Op) bool
	Consume(op grant.Op) bool
	Offer(op grant.Op, rules []string) (string, error)
}

// OpOf 返回事件的授权对象：harness、工具、工作目录与每个动作的规范写法（命令原文；文件动作的类型与路径）。
func OpOf(ev guard.Event) grant.Op {
	op := grant.Op{Harness: ev.Harness, Tool: ev.Tool, Cwd: ev.Cwd, Session: ev.SessionID}
	for _, a := range ev.Actions {
		switch {
		case isExec(a):
			op.Actions = append(op.Actions, fmt.Sprintf("exec[%s] %s", a.Exec.Shell, a.Exec.Command))
		case isFile(a):
			s := string(a.Kind) + " " + a.File.Path
			if a.File.To != "" {
				s += " -> " + a.File.To
			}
			op.Actions = append(op.Actions, s)
		}
	}
	return op
}

func (c *Check) Name() string { return Name }

// Applies 报告事件是否含 exec 动作或文件动作。
func (c *Check) Applies(ev guard.Event) bool {
	if ev.Kind != guard.EventAction {
		return false
	}
	return slices.ContainsFunc(ev.Actions, func(a guard.Action) bool { return isExec(a) || isFile(a) })
}

func isExec(a guard.Action) bool { return a.Kind == guard.ActionExec && a.Exec != nil }

func isFile(a guard.Action) bool {
	switch a.Kind {
	case guard.ActionFileRead, guard.ActionFileWrite, guard.ActionFileDelete, guard.ActionFileRename:
		return a.File != nil
	}
	return false
}

// Evaluate 逐个评估动作，取最严。每个动作完成全部判断后立即提交；
// 灾难性 deny 一经命中就提交，之后的预算耗尽、出错或 panic 都不能让它变宽。
//
// 接入了单次授权时：这次操作有用户批准过的授权、结论是可以授权的请求确认时，用掉授权并放行（命中照常记录，
// 信号带 grant）；结论本来就是放行时同样用掉授权（只批准一次重试）；没有授权时记下待批准的操作，前进路径换成 h-guard allow。有授权时请求确认的局部结论不提交
// （提交过的结论不能再放宽），deny 照常提交。
func (c *Check) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	var op grant.Op
	granted := false
	if c.Grants != nil {
		op = OpOf(ev)
		op.Input, op.RealCwd, op.DirID = c.GrantInput, c.GrantCwd, c.GrantDir
		granted = c.Grants.Has(op)
	}
	if granted {
		outer := commit
		commit = func(v guard.Verdict) {
			if v.Decision == guard.DecisionDeny {
				outer(v)
			}
		}
	}
	out := guard.Verdict{Decision: guard.DecisionPass}
	first := true
	for _, a := range ev.Actions {
		var v guard.Verdict
		switch {
		case isExec(a):
			v = c.evalExec(ctx, ev, a.Exec, commit)
		case isFile(a):
			v = c.evalFile(ctx, ev, a)
		default:
			continue
		}
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
	if c.Grants == nil {
		return out, nil
	}
	if granted && out.Decision == guard.DecisionPass {
		// 这次没用上授权也照样用掉它：批准的是「下一次重试」，不能留到之后再放行一次同样的操作
		c.Grants.Consume(op)
		return out, nil
	}
	if out.Decision != guard.DecisionAsk || !c.grantable(ev, out) {
		return out, nil
	}
	if granted && c.Grants.Consume(op) {
		// 保留判断层的信号（是否要求过、影响范围等），决策日志里查得到批准放行的是怎样的操作
		signals := maps.Clone(out.Signals)
		if signals == nil {
			signals = map[string]any{}
		}
		signals[SignalGrant] = op.ID()
		return guard.Verdict{Decision: guard.DecisionPass, Findings: out.Findings, Fallbacks: out.Fallbacks, Signals: signals}, nil
	}
	var ids []string
	for _, f := range out.Findings {
		ids = appendOnce(ids, f.Rule)
	}
	if id, err := c.Grants.Offer(op, ids); err == nil {
		minutes := strconv.Itoa(int(grant.DefaultTTL.Minutes()))
		out.Reasons = append([]guard.Reason{{Code: i18n.KeyHintGrant, Params: map[string]string{"id": id, "minutes": minutes}}}, out.Reasons...)
	}
	return out, nil
}

// SignalGrant 是用掉的单次授权的编号（决策日志据此可查是哪次批准放行的）。
const SignalGrant = "grant"

// grantable 报告请求确认的结论能否由单次授权放行：命中的规则都不是硬规则（护栏自我保护只能由用户自己改），
// 本地检查也没有因为超时而没做完（没做完的检查可能漏掉 deny），动作都是命令。
func (c *Check) grantable(ev guard.Event, v guard.Verdict) bool {
	// 本地检查没做完（时限用完、某个规则的正则超时）：不知道确定命中会是什么，不提供授权
	if slices.Contains(v.Fallbacks, FallbackBudget) || slices.Contains(v.Fallbacks, FallbackRegexTimeout) {
		return false
	}
	// 只授权命令：文件动作的事件只带路径，写进去的内容、读的时候路径指向哪里（符号链接可以在批准之后换掉）都绑不住
	if slices.ContainsFunc(ev.Actions, func(a guard.Action) bool { return !isExec(a) }) {
		return false
	}
	for _, f := range v.Findings {
		if r := c.Rules.Get(f.Rule); r == nil || r.Locked {
			return false
		}
	}
	return true
}

// explain 在打断时补上拦截说明的其余部分：要执行的操作与目标（命令与工作目录，遮蔽凭据形状），
// 决定结论的规则写明的后果与更稳妥的做法。规则没有写时只有操作。
func (c *Check) explain(v *guard.Verdict, hits []Hit, cmd, cwd string) {
	if v.Decision == guard.DecisionPass {
		return
	}
	if strings.TrimSpace(cmd) != "" {
		// 先遮蔽完整命令再截断：截断可能切掉凭据检测需要的上下文（如 URL 密码后面的 @）
		// 控制字符转义：harness 显示原因时，命令里的终端控制序列或双向文本控制符会改写用户看到的内容
		shown := Visible(clip(secrets.Redact(strings.ReplaceAll(strings.TrimSpace(cmd), "\n", " ↵ ")), maxShownCommand))
		if cwd != "" {
			v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyActionOperation, Params: map[string]string{"command": shown, "cwd": Visible(clip(secrets.Redact(cwd), maxShownCommand))}})
		} else {
			v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyActionOperationHere, Params: map[string]string{"command": shown}})
		}
	}
	var impacts, advices []string
	for _, h := range hits {
		r := c.Rules.Get(h.Rule)
		if r == nil {
			continue
		}
		if t := r.ImpactText(c.Locale); t != "" {
			impacts = appendOnce(impacts, t)
		}
		if t := r.AdviceText(c.Locale); t != "" {
			advices = appendOnce(advices, t)
		}
	}
	if len(impacts) > 0 {
		v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyActionImpact, Params: map[string]string{"impact": strings.Join(impacts, " ")}})
	}
	if len(advices) > 0 {
		v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyActionAdvice, Params: map[string]string{"advice": strings.Join(advices, " ")}})
	}
}

// Visible 把控制字符与双向文本控制符写成 \u 转义。操作的原文来自 agent：原样显示在终端或确认框里可以清屏、
// 移动光标或颠倒显示顺序，让用户看到的不是将要发生（或将要批准）的操作。
func Visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// maxShownCommand 是拦截说明里命令的最大长度（字符），更长的截断。
const maxShownCommand = 200

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// merge 以更严的结论为主（同样严时以先出现的为主、原因合在一起），合并全部命中与降级原因。
// maxMergedReasons 是一次调用的全部动作合起来最多保留的说明条数（每个动作的操作、后果、建议各算一条）。
const maxMergedReasons = 24

func merge(acc, v guard.Verdict) guard.Verdict {
	base, other := acc, v
	if guard.Stricter(acc.Decision, v.Decision) != acc.Decision {
		base, other = v, acc
	}
	out := base
	if acc.Decision == v.Decision {
		// 同样严：两个动作的说明都保留（一次补丁改了几个受保护的文件时，每个文件都写明），前进路径取先出现的
		out.Reasons = append(slices.Clone(acc.Reasons), v.Reasons...)
		// 说明总数有上限：一次调用里成百上千个同样结论的动作不能把回复撑到几 MB
		if len(out.Reasons) > maxMergedReasons {
			out.Reasons = out.Reasons[:maxMergedReasons]
		}
	}
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
		v := budgetExceeded()
		c.explain(&v, nil, ex.Command, ev.Cwd)
		return v
	}
	policyRules := map[string]Rule{}
	var hits []RegexHit
	judgeOn := c.Config.Judge.Enabled
	th := c.thresholds()
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
			ID: r.ID, Action: r.Action, Bypassable: r.Bypassable(), Vetoable: r.Vetoable(), RadiusFloor: r.RadiusFloor,
			RequiresJudge: r.RequiresJudge, Asked: judgeOn && hasQ,
		}
		res, err := r.MatchExec(ctx, exp, c.Paths)
		if res.Hit {
			hits = append(hits, RegexHit{Rule: r.ID, TimedOut: res.TimedOut})
		}
		if err != nil {
			// 预算耗尽同样写明操作，已经命中的规则写明后果与建议
			v := c.budgetVerdict(policyRules, hits)
			done := make([]Hit, 0, len(hits))
			for _, h := range hits {
				done = append(done, Hit{Rule: h.Rule})
			}
			c.explain(&v, done, ex.Command, ev.Cwd)
			return v
		}
		if !committed && r.Action == guard.DecisionDeny && res.Hit && !res.TimedOut {
			in := Input{Rules: policyRules, Regex: hits, Judge: JudgeOff}
			// 提前提交的结论同样写明操作、后果与建议：之后的匹配卡住、由看门狗兜底时用的就是它
			v := c.render(Decide(in), in)
			done := make([]Hit, 0, len(hits))
			for _, h := range hits {
				done = append(done, Hit{Rule: h.Rule})
			}
			c.explain(&v, done, ex.Command, ev.Cwd)
			commit(v)
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
			Harness: ev.Harness, Tool: ev.Tool, Command: ex.Command, Cwd: ev.Cwd, Shell: ex.Shell, Requests: requests,
			MaxCommandChars: c.Config.Policy.MaxCommandChars, MaxRequestChars: c.Config.Policy.MaxRequestChars,
		})
		qs := questions(c.Rules, policyRules)
		// AskAll 不把后端不支持的题型发给它，这些题保持未答：先记下是哪些，策略据此给出准确的原因码
		in.Unsupported = unsupportedQuestions(c.Judge.Backend.Caps(), qs)
		if len(qs) > 0 && len(in.Unsupported) == len(qs) {
			// 一道题都发不出去：AskAll 不会调用后端，这等于模型不可用，不是「已答」。按 JudgeFailed 处理，
			// policy.on_unavailable 与不可用时的其余处理照常适用
			in.Judge, in.JudgeFallback = JudgeFailed, FallbackKindUnsupported
			break
		}
		resp, err := judge.AskAll(ctx, c.Judge.Backend, state, qs)
		if err != nil {
			in.Judge, in.JudgeFallback = JudgeFailed, FallbackJudgeUnavailable
			if judge.KindOf(err) == judge.Timeout {
				in.JudgeFallback = FallbackJudgeTimeout
			}
		} else {
			in.Judge, in.Answers, in.Truncated = JudgeAnswered, judge.Validate(qs, resp), truncated
			// 没有返回错误但截止时间已到：后端保留了已答的题（如逐题请求），缺的题是超时造成的
			in.JudgeTimedOut = ctx.Err() != nil
		}
	}
	res := Decide(in)
	v := c.render(res, in)
	c.explain(&v, res.Dangerous, ex.Command, ev.Cwd)
	return v
}

// unsupportedQuestions 返回 qs 中后端不支持其题型的题的 ID。
func unsupportedQuestions(caps judge.BackendCaps, qs []judge.Question) []string {
	var ids []string
	for _, q := range qs {
		if !caps.Supports(q.Kind) {
			ids = append(ids, q.ID)
		}
	}
	return ids
}

// Questions 返回在当前配置下 exec 动作调用模型时问的全部题，与 evalExec 一致：启用且适用于 exec、
// 带题的规则（模型开启时）按 id 排序，再加两个信号题。供离线核对录制的答案（golden 正式验收）。
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

// QuestionSet 返回 set 的校准题集：作用于 exec、带题的全部规则（不论是否启用）+ 两个信号题。
// 校准档案的指纹取内置规则包的题集：规则开关不改变它，改写内置题目或信号题的措辞会；
// 用户自定义规则的题目不在指纹内，由 status 单独提示。
func QuestionSet(set *rules.Set) []judge.Question {
	var qs []judge.Question
	for _, r := range set.All() {
		if q, ok := r.JudgeQuestion(); ok && r.AppliesTo(guard.ActionExec) {
			qs = append(qs, q)
		}
	}
	return append(qs, requestedQuestion, radiusQuestion)
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

// thresholds 返回这次使用的阈值：入口注入的，没有时用保守默认值。
func (c *Check) thresholds() config.Thresholds {
	if c.Judge.Thresholds != nil {
		return *c.Judge.Thresholds
	}
	return config.ConservativeThresholds
}

// userRequests 取最近 window 条用户本人的指令，按时间先后排列、旧的在前（automated 指令不参与）。
// reqs 本身按时间先后排列。
func userRequests(reqs []guard.Request, window int) []string {
	var out []string
	for i := len(reqs) - 1; i >= 0 && len(out) < window; i-- {
		if reqs[i].Source == guard.SourceUser && strings.TrimSpace(reqs[i].Text) != "" {
			out = append(out, reqs[i].Text)
		}
	}
	slices.Reverse(out)
	return out
}

// evalFile 按路径匹配作用于该文件动作的规则：不调模型，不看用户授权与影响范围。
// 原因写明命中的文件：护栏自我保护用 guard_self_file，其余路径规则（sensitive_read、用户的文件规则）用 file_rule。
// 硬规则不受档位限制，其余规则须当前档位覆盖该动作类型。file_rename 的源与目标都检查。
// 目标解析失败、或受保护目录读不全时按已知的写法匹配，带 path_unresolved。
func (c *Check) evalFile(ctx context.Context, ev guard.Event, a guard.Action) guard.Verdict {
	env := c.Paths
	env.Cwd = ev.Cwd
	raw := []string{a.File.Path}
	if a.Kind == guard.ActionFileRename && a.File.To != "" {
		raw = append(raw, a.File.To)
	}
	var targets []paths.Resolved
	unresolved := false
	for _, p := range raw {
		r := paths.Resolve(p, env)
		unresolved = unresolved || r.Err != nil
		targets = append(targets, r)
	}
	policyRules := map[string]Rule{}
	var hits []RegexHit
	var hitPaths []string
	for _, r := range c.Rules.All() {
		if !r.Enabled() || !r.AppliesTo(a.Kind) || (!r.Locked && !rules.TierCovers(c.Config.Action.Tier, a.Kind)) {
			continue
		}
		if ctx.Err() != nil {
			// 预算耗尽同样写明是哪个文件操作，已经命中的规则写明后果与建议
			v := c.budgetVerdict(policyRules, hits)
			done := make([]Hit, 0, len(hits))
			for _, h := range hits {
				done = append(done, Hit{Rule: h.Rule})
			}
			c.explain(&v, done, strings.Join(raw, " -> ")+" ("+string(a.Kind)+")", ev.Cwd)
			return v
		}
		// 路径命中本身就是结论：RequiresJudge 只对命令规则有意义
		policyRules[r.ID] = Rule{ID: r.ID, Action: r.Action, Bypassable: r.Bypassable(), Vetoable: r.Vetoable(), RadiusFloor: r.RadiusFloor}
		hit := false
		for i, t := range targets {
			matched, complete := r.MatchFile(t, env)
			// 受保护目录里的符号链接没有收集完整：照常按已知的模式判断，带 path_unresolved
			unresolved = unresolved || !complete
			if matched {
				hit = true
				hitPaths = appendOnce(hitPaths, raw[i])
			}
		}
		if hit {
			hits = append(hits, RegexHit{Rule: r.ID})
		}
	}
	in := Input{Rules: policyRules, Regex: hits, Judge: JudgeOff}
	res := Decide(in)
	v := c.render(res, in)
	// 原因里写明是哪个文件（遮蔽凭据形状）
	shown := make([]string, len(hitPaths))
	for j, p := range hitPaths {
		shown[j] = secrets.Redact(p)
	}
	fileKey := map[string]string{i18n.KeyActionGuardSelf: i18n.KeyActionGuardSelfFile, i18n.KeyActionDangerous: i18n.KeyActionFileRule}
	for i, rs := range v.Reasons {
		if key, ok := fileKey[rs.Code]; ok {
			v.Reasons[i] = guard.Reason{Code: key, Params: map[string]string{
				"rules": rs.Params["rules"],
				"paths": strings.Join(shown, c.Catalog.Text(c.Locale, i18n.KeyListSeparator, nil)),
			}}
		}
	}
	if unresolved {
		v.Fallbacks = appendOnce(v.Fallbacks, FallbackPathUnresolved)
	}
	c.explain(&v, res.Dangerous, "", "")
	return v
}

func budgetExceeded() guard.Verdict {
	return guard.Verdict{
		Decision:  guard.DecisionAsk,
		Reasons:   []guard.Reason{{Code: i18n.KeyActionBudgetExceeded}, {Code: i18n.KeyHintNarrow}},
		Fallbacks: []string{FallbackBudget},
	}
}

// budgetVerdict 是本地阶段耗尽预算时的结论：已经得出的 deny 保持 deny；否则请求确认。
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

// render 把策略结论变成 Verdict：命中、信号、结构化原因与前进路径。
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
	// 超时的命中不能确定（原因里另有正则超时的说明）
	// 「修改护栏本身」只说护栏自我保护；别的不可豁免规则（obfuscated_exec）用通用的原因，前进路径同样是手动执行
	guardSelf := slices.ContainsFunc(res.Dangerous, func(h Hit) bool { return h.Rule == guardTamperingID && !h.TimedOut })
	unbypassable := slices.ContainsFunc(res.Dangerous, func(h Hit) bool { return !in.Rules[h.Rule].Bypassable || h.TimedOut })
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
	// 前进路径：按前进路径表从上到下取第一条
	switch {
	case unbypassable:
		add(i18n.KeyHintManual, nil)
	case in.JudgeFallback == FallbackConsentMissing:
		// 后端名由用户起，可能像凭据；hook 的原因是遮蔽边界，不经过 CLI 的遮蔽
		add(i18n.KeyHintConsent, map[string]string{"backend": secrets.Redact(c.Config.Judge.Backend)})
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

// guardTamperingID 是护栏自我保护的规则 id：它的原因写明改动的是护栏本身。
const guardTamperingID = "guard_tampering"

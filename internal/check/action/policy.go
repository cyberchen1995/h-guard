package action

import (
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// 降级原因码（spec §10.2）。
const (
	FallbackJudgeUnavailable = "judge_unavailable"
	FallbackJudgeTimeout     = "judge_timeout"
	FallbackConsentMissing   = "judge_consent_missing"
	FallbackAnswerInvalid    = "judge_answer_invalid"
	FallbackTruncated        = "evidence_truncated"
	FallbackRegexTimeout     = "regex_timeout"
	FallbackBudget           = "local_budget_exceeded"
)

// MaxRadius 是影响范围的最大值（blast_radius 共 4 级，0..3）。
const MaxRadius = 3.0

// Rule 是策略需要的规则属性。纯数据，便于表驱动测试。
type Rule struct {
	ID            string
	Action        guard.Decision // ask 或 deny
	Bypassable    bool           // 用户明确要求能否放行
	RadiusFloor   float64        // 已合并校准档案的覆盖值
	RequiresJudge bool           // 模型关闭时命中不打断
	Asked         bool           // 它的问题在这次判断请求里
}

// RegexHit 是一条规则的本地命中。
type RegexHit struct {
	Rule     string
	TimedOut bool // 正则匹配超时，按命中处理
}

// JudgeStatus 是这次判断层的状态。
type JudgeStatus int

const (
	JudgeOff      JudgeStatus = iota // judge.enabled: false
	JudgeFailed                      // 已开启但不可用：同意缺失、超时、出错
	JudgeAnswered                    // 拿到了答案（逐题仍可能无效）
)

// Input 是策略的全部输入。
type Input struct {
	Rules         map[string]Rule
	Regex         []RegexHit
	Judge         JudgeStatus
	JudgeFallback string                  // JudgeFailed 时的原因码
	Answers       map[string]judge.Answer // 已经 judge.Validate 校验并归一化；不在其中的题即无效
	HaveRequests  bool                    // 发给模型的用户指令非空
	Truncated     bool                    // 命令或任一条指令被截断
	Thresholds    config.Thresholds
	OnUnavailable guard.Decision // 模型不可用且无正则命中时的结论
}

// Hit 是合并后的一条命中。
type Hit struct {
	Rule     string
	Action   guard.Decision
	Source   guard.FindingSource
	P        *float64 // 模型给出的概率；纯本地命中为 nil
	TimedOut bool
}

// Branch 是策略走到的分支，决定原因文本。
type Branch string

const (
	BranchNone        Branch = "none"         // 无命中
	BranchBlocked     Branch = "blocked"      // deny 级形态
	BranchJudgeOff    Branch = "judge_off"    // 模型关闭：只有不依赖模型的规则打断
	BranchUnavailable Branch = "unavailable"  // 模型不可用：正则命中即请求确认
	BranchRequested   Branch = "requested"    // 用户明确要求过
	BranchBelowRadius Branch = "below_radius" // 影响范围低于下限
	BranchDangerous   Branch = "dangerous"    // 危险信号成立
)

// Result 是策略的结论与依据。
type Result struct {
	Decision  guard.Decision
	Branch    Branch
	Hits      []Hit    // 合并后的全部命中，按规则 id 排序
	Dangerous []Hit    // 决定结论的命中
	Silenced  []string // 模型关闭时不打断的命中（只写入决策日志）
	Vetoed    []string // 被模型否决的正则命中
	Below     []string // 影响范围低于下限的命中
	Requested *float64 // explicitly_requested 的有效答案
	Radius    *float64 // blast_radius 分布的期望；无效或缺失时为 nil
	Fallbacks []string
}

// Decide 是纯函数策略（spec §5.1）：危险信号 = 规则命中 ∧ 用户未明确要求 ∧ 影响范围 ≥ 该规则下限。
// 与 Python 版 decide() 的比较方向一致：命中 p ≥ hit，否决 p ≤ veto，授权 p ≥ requested，危险 radius ≥ floor。
func Decide(in Input) Result {
	res := Result{Decision: guard.DecisionPass, Branch: BranchNone}
	var regex []Hit
	for _, rh := range in.Regex {
		rule := in.Rules[rh.Rule]
		action := rule.Action
		if rh.TimedOut {
			res.Fallbacks = appendOnce(res.Fallbacks, FallbackRegexTimeout)
			action = guard.DecisionAsk // deny 级规则超时降为请求确认（spec §3.4）
		}
		regex = append(regex, Hit{Rule: rh.Rule, Action: action, Source: guard.FindingLocal, TimedOut: rh.TimedOut})
	}
	sortHits(regex)

	// 1. deny 级形态：不看任何信号，不接受授权，不调模型。
	var deny []Hit
	for _, h := range regex {
		if h.Action == guard.DecisionDeny {
			deny = append(deny, h)
		}
	}
	if len(deny) > 0 {
		res.Decision, res.Branch, res.Hits, res.Dangerous = guard.DecisionDeny, BranchBlocked, regex, deny
		return res
	}

	switch in.Judge {
	case JudgeOff:
		// 2. 模型关闭：缺少「是否要求过」「影响范围」两个信号，requires_judge 规则的命中不打断（spec §4）。
		res.Hits = regex
		for _, h := range regex {
			if in.Rules[h.Rule].RequiresJudge {
				res.Silenced = append(res.Silenced, h.Rule)
			} else {
				res.Dangerous = append(res.Dangerous, h)
			}
		}
		if len(res.Dangerous) > 0 {
			res.Decision, res.Branch = strictest(res.Dangerous), BranchJudgeOff
		}
		return res
	case JudgeFailed:
		// 3. 模型开启但不可用：有正则命中即按正则请求确认，否则按 on_unavailable（spec §5.1）。
		res.Fallbacks = appendOnce(res.Fallbacks, in.JudgeFallback)
		res.Hits, res.Branch = regex, BranchUnavailable
		if len(regex) == 0 {
			res.Decision = in.OnUnavailable
			return res
		}
		res.Dangerous = regex
		res.Decision = strictest(regex)
		return res
	}

	// 4. 模型给出了答案：合并正则命中与模型命中。
	if in.Truncated {
		res.Fallbacks = appendOnce(res.Fallbacks, FallbackTruncated)
	}
	byRule := make(map[string]Hit, len(regex))
	for _, h := range regex {
		byRule[h.Rule] = h
	}
	invalid := false
	for _, id := range sortedRuleIDs(in.Rules) {
		rule := in.Rules[id]
		if !rule.Asked {
			continue
		}
		a, ok := in.Answers[id]
		if !ok {
			invalid = true // 无效答案：不能否决，也不新增命中（spec §8.1）
			continue
		}
		p := *a.P
		existing, hit := byRule[id]
		if p < in.Thresholds.Hit {
			// 模型有把握的否定可以否决正则命中；证据被截断或正则超时时不否决
			if hit && p <= in.Thresholds.Veto && !in.Truncated && !existing.TimedOut {
				delete(byRule, id)
				res.Vetoed = append(res.Vetoed, id)
			}
			continue
		}
		src := guard.FindingJudge
		if hit {
			src = guard.FindingBoth
		}
		byRule[id] = Hit{Rule: id, Action: rule.Action, Source: src, P: judge.Prob(p), TimedOut: existing.TimedOut}
	}
	if a, ok := in.Answers[SignalRequested]; ok {
		res.Requested = judge.Prob(*a.P)
	} else {
		invalid = true
	}
	if a, ok := in.Answers[SignalRadius]; ok {
		r := 0.0
		for i, p := range a.Dist {
			r += float64(i) * p
		}
		res.Radius = &r
	} else {
		invalid = true
	}
	if invalid {
		res.Fallbacks = appendOnce(res.Fallbacks, FallbackAnswerInvalid)
	}
	for _, h := range byRule {
		res.Hits = append(res.Hits, h)
	}
	sortHits(res.Hits)
	if len(res.Hits) == 0 {
		return res
	}

	exempt := func(h Hit) bool { return in.Rules[h.Rule].Bypassable && !h.TimedOut }

	// 5. 用户在窗口内明确要求过且命中规则都可被授权：pass。证据被截断或没有指令时跳过。
	if !in.Truncated && in.HaveRequests && res.Requested != nil && *res.Requested >= in.Thresholds.Requested &&
		!slices.ContainsFunc(res.Hits, func(h Hit) bool { return !exempt(h) }) {
		res.Branch = BranchRequested
		return res
	}

	// 6. 影响范围：低于下限的不算危险；不可授权的规则不看影响范围；缺失或证据截断时按最大处理。
	radius := MaxRadius
	if res.Radius != nil && !in.Truncated {
		radius = *res.Radius
	}
	for _, h := range res.Hits {
		if !exempt(h) || radius >= floorOf(in, h.Rule) {
			res.Dangerous = append(res.Dangerous, h)
		} else {
			res.Below = append(res.Below, h.Rule)
		}
	}
	if len(res.Dangerous) == 0 {
		res.Branch = BranchBelowRadius
		return res
	}
	res.Decision, res.Branch = strictest(res.Dangerous), BranchDangerous
	return res
}

func floorOf(in Input, id string) float64 {
	if f, ok := in.Thresholds.RadiusFloor[id]; ok {
		return f
	}
	return in.Rules[id].RadiusFloor
}

func strictest(hits []Hit) guard.Decision {
	d := guard.DecisionPass
	for _, h := range hits {
		d = guard.Stricter(d, h.Action)
	}
	return d
}

func sortHits(hits []Hit) {
	slices.SortFunc(hits, func(a, b Hit) int { return strings.Compare(a.Rule, b.Rule) })
}

func sortedRuleIDs(m map[string]Rule) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func appendOnce(list []string, s string) []string {
	if s == "" || slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

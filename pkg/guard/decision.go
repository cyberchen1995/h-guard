// Package guard 定义 h-guard 的核心类型：事件、动作、结论与检查接口。
package guard

// Decision 是一次检查的结论。严格程度：deny > ask > warn > pass。
// h-guard 只收紧、不放宽，因此没有 allow。
type Decision string

const (
	DecisionPass Decision = "pass"
	DecisionWarn Decision = "warn"
	DecisionAsk  Decision = "ask"
	DecisionDeny Decision = "deny"
)

var decisionRank = map[Decision]int{
	DecisionPass: 0,
	DecisionWarn: 1,
	DecisionAsk:  2,
	DecisionDeny: 3,
}

// Valid 报告 d 是否为已知结论。
func (d Decision) Valid() bool {
	_, ok := decisionRank[d]
	return ok
}

// Stricter 返回 a、b 中更严的结论。任一方是未知结论时返回 deny：
// 第三方 Check 返回了读不懂的结论，宁可拦也不放。
func Stricter(a, b Decision) Decision {
	if !a.Valid() || !b.Valid() {
		return DecisionDeny
	}
	if decisionRank[a] >= decisionRank[b] {
		return a
	}
	return b
}

package guard

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Check 是一类检查。新增一类检查 = 新增一个 Check。
type Check interface {
	Name() string
	// Applies 报告该 Check 是否处理 ev。对任意事件都不得 panic。
	Applies(Event) bool
	// Evaluate 返回结论。commit 只提交已经成立、后续任何判断都不会撤销的结论（灾难性 deny、
	// outbound 本地 deny、某个已完成全部判断的动作的最终结论），提交后再进入可能失败的后续阶段；
	// 尚待模型否决、用户授权或影响范围判断的普通正则候选不得提交，否则会吞掉正常的豁免路径。
	// 出错或 panic 时，已提交的结论仍然有效；正常返回的结论应包含已提交的内容。
	// 出错时返回的 Verdict 仍须带合法的 Decision；ctx 结束后应尽快返回。
	Evaluate(ctx context.Context, ev Event, commit func(Verdict)) (Verdict, error)
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// ValidName 报告 name 能否用作 Check、adapter、后端类型、规则或题目的名字：
// 小写字母、数字、点、下划线和连字符，以字母或数字开头。
func ValidName(name string) bool { return namePattern.MatchString(name) }

var (
	checksMu sync.RWMutex
	checks   []Check
)

// RegisterCheck 注册一个 Check。c 为 nil、名字非法或重复时返回错误。
func RegisterCheck(c Check) error {
	if c == nil {
		return errors.New("guard: nil check")
	}
	name := c.Name()
	if !ValidName(name) {
		return fmt.Errorf("guard: invalid check name %q", name)
	}
	checksMu.Lock()
	defer checksMu.Unlock()
	for _, existing := range checks {
		if existing.Name() == name {
			return fmt.Errorf("guard: check %q already registered", name)
		}
	}
	checks = append(checks, c)
	return nil
}

// Checks 返回已注册的 Check，按名字排序。
func Checks() []Check {
	checksMu.RLock()
	defer checksMu.RUnlock()
	out := slices.Clone(checks)
	slices.SortFunc(out, func(a, b Check) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// PanicError 表示 Check 在 Evaluate 中 panic。Value 只供进程内调试，可能含输入内容，不得写入日志；
// Error() 不包含它。
type PanicError struct {
	Check string
	Value any
}

func (e *PanicError) Error() string { return fmt.Sprintf("guard: check %q panicked", e.Check) }

// Run 执行单个 Check，保证已提交的结论不会因后续故障丢失（spec §3.3）：
//   - 正常返回或出错时：返回值至少与已提交的最严结论一样严；若返回值更宽，改用该提交结论。
//     返回的 Decision 不合法时按 deny 处理。
//   - Evaluate panic 时：返回已提交的最严结论（没有提交过则为 pass，不含命中）与 *PanicError；
//     调用方再与该 Check 的故障兜底取更严。
//   - 降级原因与最严结论分开累计：所有已提交结论与返回值中的降级原因按首次出现的顺序去重合并，
//     panic 时也不丢（spec §3.3，评审 H04）。
func Run(ctx context.Context, c Check, ev Event) (v Verdict, err error) {
	var (
		mu        sync.Mutex
		strongest *Verdict
		fallbacks []string
	)
	commit := func(cv Verdict) {
		if !cv.Decision.Valid() {
			cv.Decision = DecisionDeny
		}
		mu.Lock()
		defer mu.Unlock()
		fallbacks = appendUnique(fallbacks, cv.Fallbacks...)
		// 同样严时取后提交的：后一次通常是更完整的局部结论
		if strongest == nil || Stricter(cv.Decision, strongest.Decision) == cv.Decision {
			strongest = &cv
		}
	}
	defer func() {
		if p := recover(); p != nil {
			mu.Lock()
			defer mu.Unlock()
			v = Verdict{Decision: DecisionPass}
			if strongest != nil {
				v = *strongest
			}
			v.Fallbacks = slices.Clone(fallbacks)
			err = &PanicError{Check: c.Name(), Value: p}
		}
	}()
	r, err := c.Evaluate(ctx, ev, commit)
	if !r.Decision.Valid() {
		r.Decision = DecisionDeny
	}
	mu.Lock()
	defer mu.Unlock()
	out := r
	if strongest != nil && Stricter(r.Decision, strongest.Decision) != r.Decision {
		out = *strongest
	}
	out.Fallbacks = appendUnique(slices.Clone(fallbacks), r.Fallbacks...)
	return out, err
}

// appendUnique 把 add 中 dst 尚未包含的元素依次追加到 dst。
func appendUnique(dst []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(dst, a) {
			dst = append(dst, a)
		}
	}
	return dst
}

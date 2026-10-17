// Package engine 运行全部适用的 Check 并聚合结论：结论只会变严；Check 出错或 panic 时
// 保留已提交的结论，再与故障兜底（按事件类型）取更严；然后按本次事件的实际能力（CapsFor）统一降级，
// 最后把结构化原因本地化成 Outcome。所有降级在渲染之前确定，adapter 只渲染。
//
// 组装 API 放在 internal，不作为公开接口。
package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// 降级原因码。
const (
	FallbackInternal          = "internal_error"
	FallbackAskUnsupported    = "ask_unsupported"
	FallbackOutputNotReplaced = "output_not_replaced"
	FallbackWarnUndelivered   = "warn_undelivered"
	FallbackInputTooLarge     = "input_too_large"
	FallbackConfigInvalid     = "config_invalid"
	FallbackTargetUnparsed    = "target_unparsed" // 文件工具的目标无法解析
)

// Engine 运行 Check 并产生 Outcome。字段在构造后只读。
type Engine struct {
	Checks             []guard.Check
	Catalog            *i18n.Catalog
	Locale             string
	WhenAskUnsupported guard.Decision // ask 无法渲染时的结论：deny（默认）或 pass
	// OnCommit 非空时，Check 每次经 commit 提交结论都会在同一调用中同步转告（先交给 guard.Run，再调它），
	// 不经队列，中间不调用 Check 的任何方法。入口用 Committed 累计这些提交，看门狗与顶层兜底据此知道已经
	// 成立的结论，与兜底结论一起聚合。
	OnCommit func(check string, v guard.Verdict)
}

// observed 包装一个 Check：Name 返回事先取得的名字，guard.Run 的恢复路径与提交路径都不再调用可能失败的
// Check 方法；OnCommit 非空时把每次提交同步转告它。
type observed struct {
	guard.Check
	name string
	on   func(string, guard.Verdict)
}

func (o observed) Name() string { return o.name }

func (o observed) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	if o.on == nil {
		return o.Check.Evaluate(ctx, ev, commit)
	}
	return o.Check.Evaluate(ctx, ev, func(v guard.Verdict) {
		commit(v)
		o.on(o.name, v)
	})
}

// Committed 累计各 Check 经 commit 提交的结论，供入口的看门狗与顶层兜底使用。
// 每个 Check 内的合并与 guard.Run 相同：取最严的一次，同样严时取后提交的（通常是更完整的局部结论），
// 降级原因按首次出现的顺序全部累计；各 Check 之间与兜底结论按 Evaluate 的规则聚合（fold）。
// 提交的 Verdict 在记下时复制（切片与 map），之后 Check 再改动也不影响已记下的内容。
// 零值可用；不并发安全，由调用方加锁。
type Committed struct {
	names []string // 按首次提交的顺序
	per   map[string]guard.Verdict
}

// Add 记下 check 的一次提交。
func (c *Committed) Add(check string, v guard.Verdict) {
	if !v.Decision.Valid() {
		v.Decision = guard.DecisionDeny // 与 guard.Run 一致：不合法的结论按 deny 处理
	}
	v = clone(v)
	if c.per == nil {
		c.per = map[string]guard.Verdict{}
	}
	cur, ok := c.per[check]
	if !ok {
		c.names = append(c.names, check)
		c.per[check] = v
		return
	}
	fallbacks := cur.Fallbacks
	for _, f := range v.Fallbacks {
		fallbacks = appendOnce(fallbacks, f)
	}
	if guard.Stricter(v.Decision, cur.Decision) == v.Decision {
		cur = v
	}
	cur.Fallbacks = fallbacks
	c.per[check] = cur
}

// With 返回已提交的结论与 extra（入口的兜底结论）按 Evaluate 的规则聚合的结果：取最严，
// 命中与降级原因全部保留。
func (c *Committed) With(extra guard.Verdict) guard.Verdict {
	var f fold
	for _, name := range c.names {
		f.add(name, c.per[name])
	}
	f.add("", extra)
	return f.result()
}

func clone(v guard.Verdict) guard.Verdict {
	v.Findings = slices.Clone(v.Findings)
	v.Reasons = slices.Clone(v.Reasons)
	for i := range v.Reasons {
		v.Reasons[i].Params = maps.Clone(v.Reasons[i].Params)
	}
	v.Signals = maps.Clone(v.Signals)
	v.Fallbacks = slices.Clone(v.Fallbacks)
	return v
}

// fold 聚合各 Check 的结论：结论取最严，原因取自最严结论所在的 Check（同样严的合并），
// 命中全部保留，降级原因去重累计，信号按 Check 名字分开。Evaluate 与 Committed 共用它。
type fold struct {
	agg       guard.Verdict
	strictest []guard.Reason
	signals   map[string]any
}

func (f *fold) add(name string, v guard.Verdict) {
	if f.agg.Decision == "" {
		f.agg.Decision = guard.DecisionPass
	}
	switch {
	case guard.Stricter(f.agg.Decision, v.Decision) != f.agg.Decision:
		f.agg.Decision, f.strictest = v.Decision, slices.Clone(v.Reasons)
	case v.Decision == f.agg.Decision:
		f.strictest = append(f.strictest, v.Reasons...)
	}
	f.agg.Findings = append(f.agg.Findings, v.Findings...)
	for _, fb := range v.Fallbacks {
		f.agg.Fallbacks = appendOnce(f.agg.Fallbacks, fb)
	}
	if len(v.Signals) > 0 && name != "" {
		if f.signals == nil {
			f.signals = map[string]any{}
		}
		f.signals[name] = v.Signals
	}
}

func (f *fold) result() guard.Verdict {
	v := f.agg
	if v.Decision == "" {
		v.Decision = guard.DecisionPass
	}
	if v.Decision != guard.DecisionPass {
		v.Reasons = f.strictest
	}
	if len(f.signals) > 0 {
		v.Signals = f.signals
	}
	return v
}

// CheckRun 是一个 Check 的运行记录，供健康记录与决策日志使用。
type CheckRun struct {
	Name     string
	Verdict  guard.Verdict
	Panicked bool
	Err      error // 只用于进程内调试，可能含输入内容，不得写入日志
}

// Result 是一次评估的结果。
type Result struct {
	Outcome guard.Outcome
	Runs    []CheckRun
}

// Evaluate 运行全部适用的 Check，聚合、降级并本地化。
func (e *Engine) Evaluate(ctx context.Context, ev guard.Event, caps harness.EventCaps) Result {
	var res Result
	var f fold
	for i, c := range e.Checks {
		var (
			v   guard.Verdict
			err error
		)
		// 名字只取一次：Name 自己 panic 时按该 Check 故障处理（结论只会更严），Check 照常运行
		name, nameErr := checkName(c, i)
		ok, perr := applies(c, name, ev)
		switch {
		case perr != nil:
			// Applies 自己 panic：该 Check 故障，不再调用 Evaluate（它不会知道这次 panic）
			err = perr
		case !ok:
			continue
		default:
			v, err = guard.Run(ctx, observed{Check: c, name: name, on: e.OnCommit}, ev)
		}
		if err == nil {
			err = nameErr
		}
		run := CheckRun{Name: name, Err: err}
		var pe *guard.PanicError
		run.Panicked = errors.As(err, &pe)
		if !v.Decision.Valid() {
			v.Decision = guard.DecisionPass
		}
		if err != nil {
			fail := failureDecision(ev.Kind)
			if guard.Stricter(v.Decision, fail) != v.Decision {
				v.Decision = fail
				v.Reasons = []guard.Reason{{Code: i18n.KeyErrorInternal}}
			}
			v.Fallbacks = appendOnce(v.Fallbacks, FallbackInternal)
		}
		run.Verdict = v
		res.Runs = append(res.Runs, run)
		f.add(name, v)
	}
	res.Outcome = e.Finish(ev, caps, f.result())
	return res
}

// Finish 对已聚合的结论做能力降级与本地化。也用于不经过 Check 的结论
// （输入超限、配置非法等由入口直接给出的兜底结论）。
func (e *Engine) Finish(ev guard.Event, caps harness.EventCaps, v guard.Verdict) guard.Outcome {
	raw := v.Decision
	switch {
	case v.Decision == guard.DecisionAsk && !caps.Ask:
		v.Decision = e.whenAskUnsupported()
		v.Fallbacks = appendOnce(v.Fallbacks, FallbackAskUnsupported)
		if v.Decision == guard.DecisionDeny {
			v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyDegradeAskUnsupported})
		}
	case v.Decision == guard.DecisionDeny && ev.Kind == guard.EventToolOutput && !caps.Replace:
		v.Decision = guard.DecisionWarn
		v.Fallbacks = appendOnce(v.Fallbacks, FallbackOutputNotReplaced)
	}
	if v.Decision == guard.DecisionWarn && !caps.Warn {
		v.Fallbacks = appendOnce(v.Fallbacks, FallbackWarnUndelivered)
	}
	out := guard.Outcome{Verdict: v, Raw: raw}
	if v.Decision == guard.DecisionPass {
		return out
	}
	var msg []string
	for _, r := range v.Reasons {
		text := e.Catalog.Text(e.Locale, r.Code, r.Params)
		if strings.HasPrefix(r.Code, "hint.") {
			if out.Hint == "" {
				out.Hint = text
			}
			continue
		}
		msg = append(msg, text)
	}
	out.Message = strings.Join(msg, " ")
	if out.Hint == "" {
		out.Hint = e.defaultHint(v.Fallbacks)
	}
	return out
}

// defaultHint 在 Check 没有给出前进路径时按降级原因选择。
func (e *Engine) defaultHint(fallbacks []string) string {
	key := i18n.KeyHintManual
	if slices.Contains(fallbacks, FallbackInputTooLarge) || slices.Contains(fallbacks, "local_budget_exceeded") {
		key = i18n.KeyHintNarrow
	}
	return e.Catalog.Text(e.Locale, key, nil)
}

func (e *Engine) whenAskUnsupported() guard.Decision {
	if e.WhenAskUnsupported == guard.DecisionPass {
		return guard.DecisionPass
	}
	return guard.DecisionDeny
}

// failureDecision 是 Check 出错或 panic 时的兜底结论：动作事件请求确认；提示词与工具输出放行
// （不能因护栏 bug 吞掉用户输入）。按事件类型决定、与 Check 的名字无关：名字取不到（Name panic）时也一样。
// 与入口的兜底（输入超限、预算耗尽、配置非法）一致。
func failureDecision(kind guard.EventKind) guard.Decision {
	if kind == guard.EventAction {
		return guard.DecisionAsk
	}
	return guard.DecisionPass
}

// checkName 返回 c.Name()；它 panic 时返回按序号生成的名字与 *guard.PanicError。
func checkName(c guard.Check, i int) (name string, err error) {
	defer func() {
		if p := recover(); p != nil {
			name = fmt.Sprintf("check-%d", i)
			err = &guard.PanicError{Check: name, Value: p}
		}
	}()
	return c.Name(), nil
}

// applies 调用 c.Applies；它 panic 时返回 *guard.PanicError，由调用方按该 Check 的故障兜底处理。
func applies(c guard.Check, name string, ev guard.Event) (ok bool, err error) {
	defer func() {
		if p := recover(); p != nil {
			ok, err = false, &guard.PanicError{Check: name, Value: p}
		}
	}()
	return c.Applies(ev), nil
}

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

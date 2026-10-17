package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/internal/cache"
	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	hglog "github.com/cyberchen1995/h-guard/internal/log"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// MaxInput 是 hook 的 stdin 上限（spec §3.4）。
const MaxInput = 16 << 20

// requestScan 是从缓存或 transcript 取回的指令条数上限；action 检查再从中取窗口内的用户指令。
const requestScan = 20

// eventKinds 把 --event 映射为事件类型，用于输入超限、超时等读不了或来不及处理 stdin 的情况（spec §3.4）。
var eventKinds = map[string]guard.EventKind{
	"PreToolUse": guard.EventAction, "tool.check": guard.EventAction,
	"UserPromptSubmit": guard.EventPrompt, "prompt.submit": guard.EventPrompt,
	"PostToolUse": guard.EventToolOutput, "tool.result": guard.EventToolOutput,
	"action": guard.EventAction, "prompt": guard.EventPrompt, "tool_output": guard.EventToolOutput, // generic 契约
}

// budgets 由 --timeout 推出两个时间点：内部截止时间（经 context 传给各阶段）为 timeout 减 1 秒；
// 看门狗在内部截止时间与 timeout 的中点触发。timeout 太短时内部截止时间取一半。
func budgets(timeout time.Duration) (deadline, watchdog time.Duration) {
	deadline = timeout - time.Second
	if deadline < timeout/2 {
		deadline = timeout / 2
	}
	return deadline, deadline + (timeout-deadline)/2
}

func runHook(args []string, o Options) (code int) {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	eventName := fs.String("event", "", "hook event name")
	timeout := fs.Int("timeout", 20, "hook timeout in seconds")
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 || *timeout < 1 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	ad, ok := harness.Lookup(pos[0])
	if !ok {
		fmt.Fprintf(o.Stderr, "h-guard: unknown harness %q (known: %s)\n", pos[0], strings.Join(harness.Names(), ", "))
		return 2
	}
	h := &hookRun{o: o, adapter: ad, event: *eventName, start: o.Now()}
	h.logs = &hglog.Writer{Dir: o.CacheDir, Now: o.Now}
	deadline, watchdog := budgets(time.Duration(*timeout) * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	// 整个流程（含同步读 stdin）在 worker 中运行；看门狗保证在 harness 的超时之前一定输出兜底结论。
	// 看门狗触发后 worker 不再产生任何输出或写入；仍阻塞在读 stdin 或日志上的 worker 随进程退出而结束。
	// 退出不等待任何日志写入：看门狗路径的健康记录在后台尽力写，进程退出时可能丢失。
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer h.recover()
		h.run(ctx, *extra)
	}()
	timer := time.NewTimer(watchdog)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		h.expire()
	}
	return h.finish()
}

// finish 返回退出码。要求始终有输出的 adapter（generic 契约，spec §7.4）在没有输出任何结论时——读不懂的输入、
// 读 stdin 出错、没有 --event 时的输入超限或看门狗——输出它的失败说明与非零退出码，调用方不会把空输出当作放行。
func (h *hookRun) finish() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if fr, ok := h.adapter.(harness.ParseFailureRenderer); ok && !h.written {
		stdout, code := fr.RenderParseFailure()
		_, _ = h.o.Stdout.Write(stdout)
		h.written, h.exit = true, code
	}
	return h.exit
}

// hookRun 是一次 hook 调用的状态。输出与兜底由 mu 串行：先写的为准，看门狗触发后不再写任何东西。
// 持有 mu 时只做内存操作与 stdout 输出，不做日志等磁盘 I/O。
type hookRun struct {
	o       Options
	adapter harness.Adapter
	event   string
	start   time.Time
	logs    *hglog.Writer

	mu        sync.Mutex
	ev        *guard.Event     // 已解析的事件
	committed engine.Committed // Check 已提交的结论（Engine.OnCommit 同步记录）
	best      *guard.Outcome   // 已输出的结论
	written   bool
	abandoned bool // 看门狗已经接手
	exit      int  // 退出码：Render 给出的（generic 契约读不懂输入时为非零），看门狗接手后不再改变
	// scan 是 outbound 检查这一次扫出的用户正则区间（决策日志遮蔽摘录用，M4b）；outbound 没有运行时为 nil
	scan *outbound.Scan
}

// commit 同步记录 Check 的一次提交，按 guard.Run 的规则累计（spec §3.3，评审 R3-04）。由 Engine.OnCommit
// 在提交的同一调用中调用。
func (h *hookRun) commit(check string, v guard.Verdict) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.committed.Add(check, v)
}

// newEngine 是 hook 使用的 Engine：判断层按配置与同意接入（spec §8.5），再接上提交记录，供看门狗读取。
func (h *hookRun) newEngine(s setup) (*engine.Engine, judgeState) {
	j, st := s.actionJudge(h.o)
	oj := s.outboundJudge(st)
	if h.ev != nil && h.ev.Kind != guard.EventAction && !h.adapter.CapsFor(*h.ev).Warn {
		oj.Skip = true // harness 显示不了提示：outbound 判断层的命中只提示，不调用（M4b 终审 I-1）
	}
	eng := s.newEngine(h.o, j, oj)
	eng.OnCommit = h.commit
	for _, c := range eng.Checks {
		if oc, ok := c.(*outbound.Check); ok {
			oc.Scanned = func(sc outbound.Scan) {
				h.mu.Lock()
				defer h.mu.Unlock()
				h.scan = &sc
			}
		}
	}
	return eng, st
}

// setEvent 记下解析出的事件与解析它的 adapter（按配置设了 shell 的副本），之后的渲染与兜底都用它们。
func (h *hookRun) setEvent(ev guard.Event, ad harness.Adapter) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ev, h.adapter = &ev, ad
	return !h.abandoned
}

// parseEvent 解析 hook 输入。*harness.TargetUnparsedError 不是读不懂：返回它带的事件（按动作处理）与 unparsed。
func parseEvent(ad harness.Adapter, raw []byte) (ev guard.Event, unparsed bool, err error) {
	ev, err = ad.Parse(raw)
	var tu *harness.TargetUnparsedError
	if errors.As(err, &tu) {
		ev = tu.Event
		ev.Kind = guard.EventAction
		if ev.Harness == "" {
			ev.Harness = ad.Name()
		}
		return ev, true, nil
	}
	return ev, false, err
}

func (h *hookRun) live() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.abandoned
}

func (h *hookRun) run(ctx context.Context, extra string) {
	raw, err := io.ReadAll(io.LimitReader(h.o.Stdin, MaxInput+1))
	if err != nil || !h.live() {
		return
	}
	if len(raw) > MaxInput {
		h.oversize()
		return
	}
	// 先按默认 shell 解析并记下事件（读配置卡住时看门狗与兜底要用它）；标不出 shell 的 harness 读完配置后
	// 再按 harnesses.<name>.shell 重新解析（spec §5.3 第 3 步）。配置非法时保留默认 shell 的解析结果。
	ev, unparsed, err := parseEvent(h.adapter, raw)
	if err != nil {
		// 读不懂的输入什么都不输出（spec §3.3）；要求始终有输出的 adapter（generic 契约）由 finish 输出失败说明
		return
	}
	if !h.setEvent(ev, h.adapter) {
		return
	}
	s, err := load(h.o, extra)
	if err != nil {
		h.configInvalid(s, err)
		return
	}
	if sd, ok := h.adapter.(harness.ShellDefaulter); ok {
		ad := sd.WithShell(s.cfg.ShellFor(h.adapter.Name()))
		rev, runparsed, rerr := parseEvent(ad, raw)
		if rerr != nil {
			// 按配置的 shell 读不懂：沿用默认 shell 的解析结果照常检查，另外请求确认，不能什么都不输出（M3c 终审 M-2）
			rev, runparsed = ev, true
		}
		if ev, unparsed = rev, runparsed; !h.setEvent(ev, ad) {
			return
		}
	}
	h.logs.Decisions, h.logs.RetentionDays = s.cfg.Log.Decisions, s.cfg.Log.RetentionDays

	prompts := &cache.Prompts{Dir: under(h.o.CacheDir, "prompts"), Now: h.o.Now}
	if ev.Kind == guard.EventAction && len(ev.Requests) == 0 {
		ev.Requests = h.requests(prompts, ev)
	}
	eng, st := h.newEngine(s)
	if unparsed {
		eng.Checks = append(eng.Checks, unparsedCheck{tool: ev.Tool})
	}
	res := eng.Evaluate(ctx, ev, h.adapter.CapsFor(ev))
	if !h.write(ev, res.Outcome) {
		return
	}
	if ev.Kind == guard.EventPrompt {
		h.remember(prompts, ev, res.Outcome.Verdict.Decision)
	}
	h.health(healthOf(ev, res))
	h.decision(s, st, ev, res.Outcome)
}

// remember 在提示词的结论输出之后写指令缓存（spec §5.4）：被拦下的提示词（deny）不写入，只记指纹，transcript
// 回退时据此跳过它；其余（含 warn）照常写入。看门狗接手之后什么都不写。
func (h *hookRun) remember(p *cache.Prompts, ev guard.Event, d guard.Decision) {
	if !h.live() {
		return
	}
	if d == guard.DecisionDeny {
		_ = p.Block(ev.Harness, ev.SessionID, ev.Text)
		return
	}
	// 用户自己的凭据正则认出的值在写入前遮蔽（缓存只认 secrets 的内置形状，M4a 终审 M-3）；这些区间找不全时不写入：
	// 少一条授权依据只会多问，写进去的值之后会作为用户指令发给判断后端。残余路径（M4b 计划评审 M-9）：缓存为空时
	// transcript 回退读到的是原文，用户正则认出的值仍会作为指令发给 action 判断；不写缓存会让这次会话更早走回退
	h.mu.Lock()
	scan := h.scan
	h.mu.Unlock()
	if scan != nil && !scan.Complete {
		return
	}
	for _, r := range ev.Requests {
		if scan != nil && r.Text == ev.Text {
			r.Text = redactSpans(r.Text, scan.Secret)
		}
		if h.live() {
			_ = p.Add(ev.Harness, ev.SessionID, r)
		}
	}
}

// redactSpans 把 text 中的区间（字节偏移，可以重叠）换成 [redacted]。
func redactSpans(text string, spans [][2]int) string {
	if len(spans) == 0 {
		return text
	}
	sorted := slices.Clone(spans)
	slices.SortFunc(sorted, func(a, b [2]int) int { return a[0] - b[0] })
	var b strings.Builder
	last := 0
	for _, sp := range sorted {
		if sp[1] <= last {
			continue
		}
		b.WriteString(text[last:max(last, sp[0])])
		b.WriteString("[redacted]")
		last = sp[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// blockFingerprint 在兜底路径（看门狗、panic）输出了提示词的 deny 时记下指纹：正常路径由 remember 记，兜底路径之前
// 漏了，transcript 回退会把被拦的提示词读成授权（M4a 终审 M-1）。
func (h *hookRun) blockFingerprint(ev guard.Event, out guard.Outcome) {
	if ev.Kind != guard.EventPrompt || out.Verdict.Decision != guard.DecisionDeny || ev.Text == "" {
		return
	}
	p := &cache.Prompts{Dir: under(h.o.CacheDir, "prompts"), Now: h.o.Now}
	_ = p.Block(ev.Harness, ev.SessionID, ev.Text)
}

// requests 补全用户指令：指令缓存优先，没有时读 transcript（spec §3.3 第 3 步）。
func (h *hookRun) requests(p *cache.Prompts, ev guard.Event) []guard.Request {
	if got := p.Recent(ev.Harness, ev.SessionID, requestScan); len(got) > 0 {
		return got
	}
	if tr, ok := h.adapter.(harness.TranscriptReader); ok && ev.TranscriptPath != "" {
		got, err := tr.ReadRequests(ev.TranscriptPath, requestScan)
		if err == nil {
			// 跳过被 outbound 拦下的提示词（指纹）与 h-guard 自己的拦截说明：它们不能重新成为授权依据（spec §5.4）
			return slices.DeleteFunc(got, func(r guard.Request) bool {
				return p.Blocked(ev.Harness, ev.SessionID, r.Text) || strings.HasPrefix(strings.TrimSpace(r.Text), "h-guard: ")
			})
		}
	}
	return nil
}

// write 输出结论；已经输出过或看门狗已接手时什么都不做，返回 false。
func (h *hookRun) write(ev guard.Event, out guard.Outcome) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.writeLocked(ev, out)
}

func (h *hookRun) writeLocked(ev guard.Event, out guard.Outcome) bool {
	if h.written || h.abandoned {
		return false
	}
	h.best = &out
	stdout, code := h.adapter.Render(ev, out)
	if len(stdout) > 0 {
		_, _ = h.o.Stdout.Write(stdout)
	}
	h.written, h.exit = true, code
	return true
}

// fallbackOutcome 生成不经过 Check 的兜底结论：action 请求确认，其余放行（spec §10.1）。
func fallbackOutcome(kind guard.EventKind, code, reasonKey string, params map[string]string) guard.Verdict {
	v := guard.Verdict{Decision: guard.DecisionPass, Fallbacks: []string{code}}
	if kind == guard.EventAction {
		v.Decision = guard.DecisionAsk
		v.Reasons = []guard.Reason{{Code: reasonKey, Params: params}}
	}
	return v
}

// oversize 处理超过上限的输入：不解析，按 --event 决定（spec §3.4）。
func (h *hookRun) oversize() {
	kind, ok := eventKinds[h.event]
	if !ok {
		h.health([]hglog.Health{{Event: h.event, Check: "app", Code: engine.FallbackInputTooLarge}})
		return
	}
	ev := guard.Event{Kind: kind, Harness: h.adapter.Name()}
	out := h.bareEngine().Finish(ev, h.adapter.CapsFor(ev), fallbackOutcome(kind, engine.FallbackInputTooLarge, i18n.KeyErrorInputTooLarge, nil))
	if h.write(ev, out) {
		h.health([]hglog.Health{{Event: string(kind), Check: "app", Code: engine.FallbackInputTooLarge}})
	}
}

// expire 是看门狗：到点仍没有输出时，按事件类型输出兜底结论（action 请求确认，其余放行），
// 与 Check 已提交的结论一起聚合（已提交的 deny 保持 deny，命中与降级原因都保留），带 local_budget_exceeded；
// 之后 worker 不再开始新的输出或写入（spec §3.3、§3.4、§10.1）。健康记录在后台尽力写入，不等待。
func (h *hookRun) expire() {
	h.mu.Lock()
	if h.written {
		h.abandoned = true
		h.mu.Unlock()
		return
	}
	kind, ok := eventKinds[h.event]
	ev := guard.Event{Kind: kind, Harness: h.adapter.Name()}
	if h.ev != nil {
		ev, kind, ok = *h.ev, h.ev.Kind, true
	}
	var fin guard.Outcome
	if ok {
		v := h.committed.With(fallbackOutcome(kind, action.FallbackBudget, i18n.KeyActionBudgetExceeded, nil))
		fin = h.bareEngine().Finish(ev, h.adapter.CapsFor(ev), v)
		h.writeLocked(ev, fin)
	}
	h.abandoned = true
	recs := h.stamp([]hglog.Health{{Event: string(kind), Check: "app", Code: action.FallbackBudget}})
	h.mu.Unlock()
	go h.logs.Health(recs)         // 不等待：日志存储卡住时也要按时退出，这条记录可能丢失
	go h.blockFingerprint(ev, fin) // 同上：尽力而为
}

// configInvalid：配置或规则非法时，action 请求确认，其余放行并计入健康记录（spec §10.1）。
// 原因只给出文件名与出错的字段路径，不带错误说明（说明可能含写错的值，如带密码的 URL）。
func (h *hookRun) configInvalid(s setup, err error) {
	ev := *h.ev
	eng := &engine.Engine{Catalog: s.catalog, Locale: s.locale, WhenAskUnsupported: guard.DecisionDeny}
	if eng.Catalog == nil {
		eng = h.bareEngine()
	}
	out := eng.Finish(ev, h.adapter.CapsFor(ev),
		fallbackOutcome(ev.Kind, engine.FallbackConfigInvalid, i18n.KeyErrorConfigInvalid, map[string]string{"detail": brief(err)}))
	if h.write(ev, out) {
		h.health([]hglog.Health{{Event: string(ev.Kind), Check: "app", Code: engine.FallbackConfigInvalid}})
	}
}

// unparsedCheck 给目标无法解析的动作事件加上「请求确认」（spec §5.5）。它作为一个 Check 与其他检查一起聚合：
// 读得出的动作照常检查，灾难性形态的 deny 与原因保留，when_ask_unsupported: pass 也不能让它们放行；健康记录与
// 决策日志照常写（终审 I-1）。
type unparsedCheck struct{ tool string }

func (unparsedCheck) Name() string { return "app" }

func (unparsedCheck) Applies(ev guard.Event) bool { return ev.Kind == guard.EventAction }

func (c unparsedCheck) Evaluate(context.Context, guard.Event, func(guard.Verdict)) (guard.Verdict, error) {
	return fallbackOutcome(guard.EventAction, engine.FallbackTargetUnparsed, i18n.KeyErrorTargetUnparsed,
		map[string]string{"tool": secrets.MaskForLog(c.tool)}), nil
}

// brief 返回配置或规则错误的位置（文件名与字段路径），不含说明。动态片段（后端名、规则 id、文件名）是用户写下的，
// 输出前再遮蔽一次凭据形状（最终输出边界，评审 N04）。
func brief(err error) string {
	var ce *config.Error
	if errors.As(err, &ce) {
		return secrets.MaskForLog(ce.Brief())
	}
	var re *rules.Error
	if errors.As(err, &re) {
		return secrets.MaskForLog(re.Brief())
	}
	return "config"
}

func (h *hookRun) bareEngine() *engine.Engine {
	cat, _ := i18n.Load()
	return &engine.Engine{Catalog: cat, Locale: i18n.SelectLocale("", h.o.Getenv), WhenAskUnsupported: guard.DecisionDeny}
}

// recover 是顶层兜底（spec §10.1）：内部异常时 action 请求确认，与 Check 已提交的结论一起聚合；
// 已经输出过则不再输出。健康记录只记 panic 所在的函数与行号。
func (h *hookRun) recover() {
	p := recover()
	if p == nil {
		return
	}
	where := panicSite()
	h.mu.Lock()
	if h.abandoned {
		h.mu.Unlock()
		return
	}
	// 事件还没解析时与看门狗一样按 --event 推出事件类型（解析前的 panic 也不能让 PreToolUse 放行，评审 M1 终审）
	kind, ok := eventKinds[h.event]
	ev := guard.Event{Kind: kind, Harness: h.adapter.Name()}
	if h.ev != nil {
		ev, kind, ok = *h.ev, h.ev.Kind, true
	}
	recs := h.stamp([]hglog.Health{{Event: string(kind), Check: "app", Code: engine.FallbackInternal, Where: where}})
	var fin guard.Outcome
	if !h.written && ok {
		v := h.committed.With(fallbackOutcome(kind, engine.FallbackInternal, i18n.KeyErrorInternal, nil))
		fin = h.bareEngine().Finish(ev, h.adapter.CapsFor(ev), v)
		h.writeLocked(ev, fin)
	}
	h.mu.Unlock()
	h.logs.Health(recs)
	h.blockFingerprint(ev, fin)
}

// panicSite 返回 panic 发生处的函数与行号（跳过 runtime 帧），不含 panic 值。
func panicSite() string {
	pcs := make([]uintptr, 32)
	n := runtime.Callers(3, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if f.Function != "" && !strings.HasPrefix(f.Function, "runtime.") {
			return fmt.Sprintf("%s:%d", f.Function, f.Line)
		}
		if !more {
			return ""
		}
	}
}

// healthOf 把各 Check 的降级原因与 Engine 的能力降级整理成健康记录（每个原因码一条）。
func healthOf(ev guard.Event, res engine.Result) []hglog.Health {
	var out []hglog.Health
	seen := map[string]bool{}
	for _, r := range res.Runs {
		for _, code := range r.Verdict.Fallbacks {
			out = append(out, hglog.Health{Event: string(ev.Kind), Check: r.Name, Code: code})
			seen[code] = true
		}
	}
	for _, code := range res.Outcome.Verdict.Fallbacks {
		if !seen[code] {
			out = append(out, hglog.Health{Event: string(ev.Kind), Check: "engine", Code: code})
		}
	}
	return out
}

// health 写健康记录（worker 中同步调用）；看门狗已接手时不写。磁盘 I/O 在锁外进行。
func (h *hookRun) health(recs []hglog.Health) {
	if !h.live() {
		return
	}
	h.logs.Health(h.stamp(recs))
}

func (h *hookRun) stamp(recs []hglog.Health) []hglog.Health {
	for i := range recs {
		recs[i].Version, recs[i].Harness = Version, h.adapter.Name()
	}
	return recs
}

// excerptContext 是摘录里命中行前后各带的行数（spec §10.3）。
const excerptContext = 2

// excerpts 返回 outbound 命中行前后各 n 行的摘录，相邻或重叠的合并成一段；没有带位置的命中时为空。
func excerpts(text string, findings []guard.Finding, n int) []hglog.Excerpt {
	var hitLines []int
	for _, f := range findings {
		for _, l := range f.Locations {
			if l.Line > 0 {
				hitLines = append(hitLines, l.Line)
			}
		}
	}
	if len(hitLines) == 0 {
		return nil
	}
	slices.Sort(hitLines)
	lines := strings.Split(text, "\n")
	var out []hglog.Excerpt
	from, to := -1, -1 // 当前一段的首尾行号（从 1 开始，含）
	flush := func() {
		if from > 0 {
			out = append(out, hglog.Excerpt{Line: from, Text: strings.Join(lines[from-1:to], "\n")})
		}
	}
	for _, l := range hitLines {
		lo, hi := max(1, l-n), min(len(lines), l+n)
		if from > 0 && lo <= to+1 {
			to = max(to, hi)
			continue
		}
		flush()
		from, to = lo, hi
	}
	flush()
	return out
}

// decision 写决策日志。动作事件记动作与参与判断的用户指令；提示词与工具输出只记长度、命中与命中行前后各 2 行的
// 摘录，不记整段正文（spec §10.3）。
func (h *hookRun) decision(s setup, st judgeState, ev guard.Event, out guard.Outcome) {
	d := hglog.Decision{
		Version: Version, Harness: ev.Harness, SessionID: ev.SessionID, CallID: ev.CallID, Cwd: ev.Cwd,
		Event: ev.Kind, Tool: ev.Tool, Decision: out.Verdict.Decision, RawDecision: out.Raw,
		Findings: out.Verdict.Findings, Signals: out.Verdict.Signals, Fallbacks: out.Verdict.Fallbacks,
		LatencyMS: hglog.Latency{Total: h.o.Now().Sub(h.start).Milliseconds()},
		TextBytes: len(ev.Text),
	}
	if ev.Kind == guard.EventAction {
		d.Actions, d.Requests = ev.Actions, ev.Requests
	} else {
		// 先遮蔽再按行截取（保持行数）：摘录只切到私钥的一部分时日志层认不出它（M4a 计划评审 C1）；用户正则认出的
		// 凭据与私钥一起遮蔽（Codex 评审 M4A-02），区间取自 outbound 这一次的扫描（M4b，不再重扫）。扫描不完整
		// （正则超时、截止时间已过，Codex 第二轮 R2-01）或没有扫描时不记摘录。决策日志关闭或没有命中时摘录本来就
		// 用不上，不做全文遮蔽（M4a 终审 I-2：大段工具输出每次多出数秒）
		h.mu.Lock()
		scan := h.scan
		h.mu.Unlock()
		if scan != nil && scan.Complete && s.cfg.Log.Decisions && len(out.Verdict.Findings) > 0 {
			d.Excerpts = excerpts(secrets.MaskKeepLines(ev.Text, scan.Secret...), out.Verdict.Findings, excerptContext)
		}
	}
	if s.cfg.Judge.Enabled {
		d.Backend = s.cfg.Judge.Backend
		if st.cal.Calibrated() && st.backend != nil {
			d.Profile = st.cal.Profile // 未校准时用的是保守默认值，不记档案名
		}
	}
	if h.live() {
		h.logs.Decision(d)
	}
}

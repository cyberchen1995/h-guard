package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/internal/cache"
	"github.com/cyberchen1995/h-guard/internal/check/action"
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
	return 0
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
	eng := s.newEngine(h.o, j)
	eng.OnCommit = h.commit
	return eng, st
}

func (h *hookRun) setEvent(ev guard.Event) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ev = &ev
	return !h.abandoned
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
	ev, err := h.adapter.Parse(raw)
	if err != nil {
		return // 读不懂的输入什么都不输出（spec §3.3）
	}
	if !h.setEvent(ev) {
		return
	}
	s, err := load(h.o, extra)
	if err != nil {
		h.configInvalid(s, err)
		return
	}
	h.logs.Decisions, h.logs.RetentionDays = s.cfg.Log.Decisions, s.cfg.Log.RetentionDays

	prompts := &cache.Prompts{Dir: under(h.o.CacheDir, "prompts"), Now: h.o.Now}
	switch ev.Kind {
	case guard.EventPrompt:
		// M1 没有 outbound 检查，提示词不会被拦截，全部写入指令缓存（spec §5.4）
		for _, r := range ev.Requests {
			if h.live() {
				_ = prompts.Add(ev.Harness, ev.SessionID, r)
			}
		}
	case guard.EventAction:
		if len(ev.Requests) == 0 {
			ev.Requests = h.requests(prompts, ev)
		}
	}
	eng, st := h.newEngine(s)
	res := eng.Evaluate(ctx, ev, h.adapter.CapsFor(ev))
	if !h.write(ev, res.Outcome) {
		return
	}
	h.health(healthOf(ev, res))
	h.decision(s, st, ev, res.Outcome)
}

// requests 补全用户指令：指令缓存优先，没有时读 transcript（spec §3.3 第 3 步）。
func (h *hookRun) requests(p *cache.Prompts, ev guard.Event) []guard.Request {
	if got := p.Recent(ev.Harness, ev.SessionID, requestScan); len(got) > 0 {
		return got
	}
	if tr, ok := h.adapter.(harness.TranscriptReader); ok && ev.TranscriptPath != "" {
		got, err := tr.ReadRequests(ev.TranscriptPath, requestScan)
		if err == nil {
			return got
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
	stdout, _ := h.adapter.Render(ev, out)
	if len(stdout) > 0 {
		_, _ = h.o.Stdout.Write(stdout)
	}
	h.written = true
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
	if ok {
		v := h.committed.With(fallbackOutcome(kind, action.FallbackBudget, i18n.KeyActionBudgetExceeded, nil))
		h.writeLocked(ev, h.bareEngine().Finish(ev, h.adapter.CapsFor(ev), v))
	}
	h.abandoned = true
	recs := h.stamp([]hglog.Health{{Event: string(kind), Check: "app", Code: action.FallbackBudget}})
	h.mu.Unlock()
	go h.logs.Health(recs) // 不等待：日志存储卡住时也要按时退出，这条记录可能丢失
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
	if !h.written && ok {
		v := h.committed.With(fallbackOutcome(kind, engine.FallbackInternal, i18n.KeyErrorInternal, nil))
		h.writeLocked(ev, h.bareEngine().Finish(ev, h.adapter.CapsFor(ev), v))
	}
	h.mu.Unlock()
	h.logs.Health(recs)
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

// decision 写决策日志。动作事件记动作与参与判断的用户指令；提示词与工具输出只记长度，
// 不记正文（spec §10.3：outbound 只记长度、命中与摘录，M1 没有 outbound 命中）。
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

package action_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// fakeBackend 按题返回固定答案；panicOn 非空时对含该命令的 state panic。
type fakeBackend struct {
	calls   atomic.Int32
	answers map[string]judge.Answer
	err     error
	panicOn string
	states  []map[string]any
}

func (f *fakeBackend) Name() string            { return "fake" }
func (f *fakeBackend) Caps() judge.BackendCaps { return judge.BackendCaps{Batch: true} }
func (f *fakeBackend) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	f.calls.Add(1)
	f.states = append(f.states, state)
	if f.panicOn != "" && strings.Contains(state["call"].(map[string]any)["command"].(string), f.panicOn) {
		panic("boom")
	}
	if f.err != nil {
		return judge.Response{}, f.err
	}
	return judge.Response{Answers: f.answers}, nil
}

// low 是「模型认为都不是」的答案：各规则 0，未要求，影响范围 0。
func low() map[string]judge.Answer {
	a := map[string]judge.Answer{action.SignalRequested: {P: judge.Prob(0)}, action.SignalRadius: {Dist: []float64{1, 0, 0, 0}}}
	for _, id := range []string{"guard_tampering", "recursive_delete", "destructive_git", "branch_ops", "publish", "verify_bypass"} {
		a[id] = judge.Answer{P: judge.Prob(0)}
	}
	return a
}

func with(a map[string]judge.Answer, kv ...any) map[string]judge.Answer {
	for i := 0; i+1 < len(kv); i += 2 {
		switch v := kv[i+1].(type) {
		case float64:
			a[kv[i].(string)] = judge.Answer{P: judge.Prob(v)}
		case []float64:
			a[kv[i].(string)] = judge.Answer{Dist: v}
		}
	}
	return a
}

// jevThresholds 是 Python 版在 Jev 上校准的阈值（与内置 jev 档案不同：内置档案按当前措辞重新校准）。
// 测试与 golden 回放钉住它们：golden 的答案是在这套阈值下录制的（维护者决定，2026-10-13）。
var jevThresholds = config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.7, RadiusFloor: map[string]float64{"recursive_delete": 1.25}}

// newCheck 返回用内置规则与默认配置的检查；j 没有注入阈值时用 jevThresholds。
func newCheck(t *testing.T, judgeOn bool, j action.Judge) *action.Check {
	t.Helper()
	if j.Thresholds == nil {
		j.Thresholds = &jevThresholds
	}
	cfg := config.Defaults()
	cfg.Judge.Enabled = judgeOn
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	return &action.Check{Rules: set, Config: cfg, Catalog: cat, Locale: "en", Judge: j}
}

func event(requests []guard.Request, cmds ...string) guard.Event {
	ev := guard.Event{Kind: guard.EventAction, Harness: "claudecode", Tool: "Bash", Cwd: "/w", Requests: requests}
	for _, c := range cmds {
		ev.Actions = append(ev.Actions, guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: c, Shell: guard.ShellPOSIX}})
	}
	return ev
}

func user(text string) guard.Request { return guard.Request{Text: text, Source: guard.SourceUser} }

func run(t *testing.T, c *action.Check, ev guard.Event) guard.Verdict {
	t.Helper()
	v, err := guard.Run(context.Background(), c, ev)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func codes(v guard.Verdict) []string {
	var out []string
	for _, r := range v.Reasons {
		out = append(out, r.Code)
	}
	return out
}

func TestJudgeOff(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, "git push origin main")); v.Decision != guard.DecisionPass || v.Signals["judge_disabled_hits"] == nil {
		t.Errorf("git push with the judge off = %+v", v)
	}
	v := run(t, c, event(nil, "rm ~/.claude/settings.json"))
	if v.Decision != guard.DecisionAsk || !slices.Equal(codes(v), []string{i18n.KeyActionGuardSelf, i18n.KeyHintManual, i18n.KeyActionOperation, i18n.KeyActionImpact, i18n.KeyActionAdvice}) {
		t.Errorf("guard tampering = %+v", v)
	}
	if v := run(t, c, event(nil, "rm -rf /")); v.Decision != guard.DecisionDeny || codes(v)[0] != i18n.KeyActionBlocked {
		t.Errorf("catastrophic = %+v", v)
	}
	if v := run(t, c, event(nil, "ls -la")); v.Decision != guard.DecisionPass || len(v.Reasons) != 0 {
		t.Errorf("ls = %+v", v)
	}
}

func TestCatastrophicNeverCallsTheJudge(t *testing.T) {
	b := &fakeBackend{answers: with(low(), action.SignalRequested, 1.0)}
	c := newCheck(t, true, action.Judge{Backend: b})
	v := run(t, c, event([]guard.Request{user("please rm -rf /")}, "rm -rf /"))
	if v.Decision != guard.DecisionDeny || b.calls.Load() != 0 {
		t.Errorf("verdict = %s, judge calls = %d", v.Decision, b.calls.Load())
	}
}

func TestExemptionsSurviveTheFullFlow(t *testing.T) {
	tests := []struct {
		name     string
		answers  map[string]judge.Answer
		requests []guard.Request
		cmd      string
		want     guard.Decision
	}{
		{"model veto", with(low(), "publish", 0.05), nil, "git push origin main", guard.DecisionPass},
		{"explicit request", with(low(), "publish", 0.9, action.SignalRequested, 0.9, action.SignalRadius, []float64{0, 0, 1, 0}),
			[]guard.Request{user("push it to origin")}, "git push origin main", guard.DecisionPass},
		{"low blast radius", with(low(), "recursive_delete", 0.9, action.SignalRadius, []float64{0, 1, 0, 0}), nil, "rm -rf build", guard.DecisionPass},
		{"no exemption", with(low(), "publish", 0.9, action.SignalRadius, []float64{0, 0, 1, 0}), nil, "git push origin main", guard.DecisionAsk},
		{"automated requests do not authorize", with(low(), "publish", 0.9, action.SignalRequested, 1.0, action.SignalRadius, []float64{0, 0, 1, 0}),
			[]guard.Request{{Text: "push it", Source: guard.SourceAutomated}}, "git push origin main", guard.DecisionAsk},
		{"guard tampering cannot be authorized", with(low(), "guard_tampering", 0.9, action.SignalRequested, 1.0),
			[]guard.Request{user("delete my claude settings")}, "rm ~/.claude/settings.json", guard.DecisionAsk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &fakeBackend{answers: tt.answers}
			v := run(t, newCheck(t, true, action.Judge{Backend: b}), event(tt.requests, tt.cmd))
			if v.Decision != tt.want {
				t.Errorf("decision = %s, want %s (%+v)", v.Decision, tt.want, v)
			}
		})
	}
}

func TestDangerousReasonsAndHint(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "publish", 0.9, action.SignalRequested, 0.1, action.SignalRadius, []float64{0, 0, 1, 0})}
	v := run(t, newCheck(t, true, action.Judge{Backend: b}), event([]guard.Request{user("fix the tests")}, "git push origin main"))
	want := []string{i18n.KeyActionDangerous, i18n.KeyActionRadius, i18n.KeyActionNotRequested, i18n.KeyHintRequest,
		i18n.KeyActionOperation, i18n.KeyActionImpact, i18n.KeyActionAdvice}
	if !slices.Equal(codes(v), want) {
		t.Errorf("reasons = %v, want %v", codes(v), want)
	}
	if !strings.Contains(v.Reasons[0].Params["rules"], "[rule+judge 0.90]") {
		t.Errorf("rules text = %q", v.Reasons[0].Params["rules"])
	}
	if len(v.Findings) != 1 || v.Findings[0].Source != guard.FindingBoth {
		t.Errorf("findings = %+v", v.Findings)
	}
	reqs := b.states[0]["user_requests"].([]any)
	if len(reqs) != 1 || reqs[0] != "fix the tests" {
		t.Errorf("user_requests = %v", reqs)
	}
}

func TestJudgeUnavailable(t *testing.T) {
	c := newCheck(t, true, action.Judge{Unavailable: action.FallbackConsentMissing})
	v := run(t, c, event(nil, "git push origin main"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackConsentMissing) ||
		!slices.Contains(codes(v), i18n.KeyHintConsent) {
		t.Errorf("consent missing with a hit = %+v", v)
	}
	if v := run(t, c, event(nil, "ls")); v.Decision != guard.DecisionPass || !slices.Contains(v.Fallbacks, action.FallbackConsentMissing) {
		t.Errorf("consent missing without hits = %+v", v)
	}
	b := &fakeBackend{err: &judge.Error{Kind: judge.Timeout}}
	v = run(t, newCheck(t, true, action.Judge{Backend: b}), event(nil, "git push"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackJudgeTimeout) ||
		!slices.Contains(codes(v), i18n.KeyHintJudgeUnavailable) {
		t.Errorf("timeout = %+v", v)
	}
	for _, r := range v.Reasons {
		if r.Code == i18n.KeyHintRequest {
			t.Error("an unavailable judge must not suggest restating the request")
		}
	}
}

// recordingBackend 是可配置能力与行为的后端：记下每次收到的题目，answer 决定怎么回答。
type recordingBackend struct {
	caps   judge.BackendCaps
	answer func(ctx context.Context, qs []judge.Question) (judge.Response, error)
	mu     sync.Mutex // 不能批量的后端会被并发调用
	asked  []string
}

func (b *recordingBackend) Name() string            { return "recording" }
func (b *recordingBackend) Caps() judge.BackendCaps { return b.caps }
func (b *recordingBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	b.mu.Lock()
	for _, q := range qs {
		b.asked = append(b.asked, q.ID)
	}
	b.mu.Unlock()
	return b.answer(ctx, qs)
}

// answersFor 把 all 里属于 qs 的答案作为回答（不多给）。
func answersFor(all map[string]judge.Answer, qs []judge.Question) judge.Response {
	out := map[string]judge.Answer{}
	for _, q := range qs {
		if a, ok := all[q.ID]; ok {
			out[q.ID] = a
		}
	}
	return judge.Response{Answers: out}
}

// dangerous 是「模型认为 git push 命中 publish，没有被要求，影响范围 2」的答案。
func dangerous() map[string]judge.Answer {
	return with(low(), "publish", 0.9, action.SignalRadius, []float64{0, 0, 1, 0})
}

// TestKindUnsupportedIsReported：后端不能回答某种题型时，这些题不发给它、保持未答，结论带 judge_kind_unsupported，
// 不记成 judge_answer_invalid；结论与缺答的处理一致，不产生任何豁免。
func TestKindUnsupportedIsReported(t *testing.T) {
	tests := []struct {
		name     string
		kinds    []judge.Kind
		requests []guard.Request
		cmd      string
		answers  map[string]judge.Answer
		want     guard.Decision
		missing  []string // 不应发给后端的题
	}{
		{"probability only: the scale question is not asked, the radius is the maximum",
			[]judge.Kind{judge.KindProbability}, nil, "git push origin main", dangerous(), guard.DecisionAsk, []string{action.SignalRadius}},
		{"scale only: no probability question is asked, the hit stays",
			[]judge.Kind{judge.KindScale}, nil, "git push origin main", dangerous(), guard.DecisionAsk,
			[]string{"publish", action.SignalRequested}},
		{"nothing supported: the backend is never asked",
			[]judge.Kind{}, nil, "git push origin main", dangerous(), guard.DecisionAsk,
			[]string{"publish", action.SignalRequested, action.SignalRadius}},
		{"a confident veto still applies without the scale question",
			[]judge.Kind{judge.KindProbability}, nil, "git push origin main", with(low(), "publish", 0.05), guard.DecisionPass,
			[]string{action.SignalRadius}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &recordingBackend{
				caps: judge.BackendCaps{Batch: true, Kinds: tt.kinds},
				answer: func(_ context.Context, qs []judge.Question) (judge.Response, error) {
					return answersFor(tt.answers, qs), nil
				},
			}
			v := run(t, newCheck(t, true, action.Judge{Backend: b}), event(tt.requests, tt.cmd))
			if v.Decision != tt.want {
				t.Errorf("decision = %s, want %s (%+v)", v.Decision, tt.want, v)
			}
			if !slices.Equal(v.Fallbacks, []string{action.FallbackKindUnsupported}) {
				t.Errorf("fallbacks = %v, want only %s", v.Fallbacks, action.FallbackKindUnsupported)
			}
			for _, id := range tt.missing {
				if slices.Contains(b.asked, id) {
					t.Errorf("the backend was asked %q, which it does not support (asked %v)", id, b.asked)
				}
			}
		})
	}
}

// TestNoSendableQuestionIsUnavailable：这次要问的题一道都发不出去（后端不支持其中任何一种题型）时，模型等于不可用：
// 结论按 JudgeFailed 处理，原因码只有 judge_kind_unsupported，policy.on_unavailable 照常适用；后端不会被调用。
func TestNoSendableQuestionIsUnavailable(t *testing.T) {
	for _, tt := range []struct {
		name, cmd, onUnavailable string
		want                     guard.Decision
	}{
		{"no hit, on_unavailable ask", "ls", "ask", guard.DecisionAsk},
		{"no hit, on_unavailable pass", "ls", "pass", guard.DecisionPass},
		{"a regex hit asks", "git push origin main", "pass", guard.DecisionAsk},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			b := &recordingBackend{
				caps: judge.BackendCaps{Batch: true, Kinds: []judge.Kind{}},
				answer: func(_ context.Context, qs []judge.Question) (judge.Response, error) {
					called = true
					return answersFor(dangerous(), qs), nil
				},
			}
			c := newCheck(t, true, action.Judge{Backend: b})
			c.Config.Policy.OnUnavailable = tt.onUnavailable
			v := run(t, c, event(nil, tt.cmd))
			if v.Decision != tt.want || !slices.Equal(v.Fallbacks, []string{action.FallbackKindUnsupported}) {
				t.Errorf("decision = %s, fallbacks = %v, want %s [%s] (%+v)", v.Decision, v.Fallbacks, tt.want,
					action.FallbackKindUnsupported, v)
			}
			if v.Signals["judge"] != "failed" {
				t.Errorf("judge signal = %v, want failed", v.Signals["judge"])
			}
			if called {
				t.Error("the backend was called although it supports none of the questions")
			}
		})
	}
}

// TestMissingAnswersWithoutADeadlineStayInvalid：没有截止时间时缺答仍是 judge_answer_invalid；答案齐全时两个新原因码都不出现。
func TestMissingAnswersWithoutADeadlineStayInvalid(t *testing.T) {
	partial := dangerous()
	delete(partial, action.SignalRadius)
	for name, tt := range map[string]struct {
		answers map[string]judge.Answer
		want    []string
	}{
		"a missing answer":    {partial, []string{action.FallbackAnswerInvalid}},
		"complete answers":    {dangerous(), nil},
		"an invalid scale":    {with(dangerous(), action.SignalRadius, []float64{0.5, 0.5, 0.5, 0.5}), []string{action.FallbackAnswerInvalid}},
		"an out-of-range p":   {with(dangerous(), "publish", 1.5), []string{action.FallbackAnswerInvalid}},
		"missing requested p": {without(dangerous(), action.SignalRequested), []string{action.FallbackAnswerInvalid}},
		"a nil probability": {func() map[string]judge.Answer {
			a := dangerous()
			a["publish"] = judge.Answer{}
			return a
		}(), []string{action.FallbackAnswerInvalid}},
	} {
		t.Run(name, func(t *testing.T) {
			b := &recordingBackend{
				caps: judge.BackendCaps{Batch: true},
				answer: func(_ context.Context, qs []judge.Question) (judge.Response, error) {
					return answersFor(tt.answers, qs), nil
				},
			}
			v := run(t, newCheck(t, true, action.Judge{Backend: b}), event(nil, "git push origin main"))
			if v.Decision != guard.DecisionAsk || !slices.Equal(v.Fallbacks, tt.want) {
				t.Errorf("decision = %s, fallbacks = %v, want ask %v", v.Decision, v.Fallbacks, tt.want)
			}
		})
	}
}

// without 返回去掉 ids 的答案副本。
func without(m map[string]judge.Answer, ids ...string) map[string]judge.Answer {
	out := map[string]judge.Answer{}
	for id, a := range m {
		if !slices.Contains(ids, id) {
			out[id] = a
		}
	}
	return out
}

// TestDeadlineDuringAskIsReportedAsTimeout：截止时间落在取答中途，后端保留已答的、没有返回错误（如 openai logprobs
// 逐题请求）：缺的题记 judge_timeout，不记 judge_answer_invalid。已答的保留，缺答不产生豁免，所以结论仍是请求确认。
//
// 截止时间不靠墙钟：假后端在被调用时自己结束 ctx（expire），所以截止一定落在取答中途，与机器快慢无关。
// 用墙钟的话，慢机器上构建检查与本地阶段（展开与正则）可能先用完时间，结论变成 local_budget_exceeded，测不到这里。
// 取消与超时对产品是一回事：judge.KindOf 把 context.Canceled 与 DeadlineExceeded 都归为超时，
// evalExec 用 ctx.Err() != nil 判断取答时截止时间是否已到。
func TestDeadlineDuringAskIsReportedAsTimeout(t *testing.T) {
	partial := without(dangerous(), action.SignalRequested, action.SignalRadius)
	type answerFunc = func(ctx context.Context, qs []judge.Question) (judge.Response, error)
	tests := []struct {
		name string
		caps judge.BackendCaps
		// backend 返回这次子测试的回答函数；expire 让截止时间立刻到达，nonSignal 是信号题以外的题数
		backend func(expire func(), nonSignal int) answerFunc
		want    guard.Decision
		fb      []string
	}{
		{"a batch backend returns the partial answers after the deadline", judge.BackendCaps{Batch: true},
			func(expire func(), _ int) answerFunc {
				return func(ctx context.Context, qs []judge.Question) (judge.Response, error) {
					expire()
					<-ctx.Done()
					return answersFor(partial, qs), nil
				}
			}, guard.DecisionAsk, []string{action.FallbackJudgeTimeout}},
		{"a per-question backend: the later questions fail at the deadline, the earlier answers are kept", judge.BackendCaps{},
			// 信号题以外的题立刻作答；两道信号题等到截止时间后报错。所有题都已发出、其余题都已答完时截止时间才到，
			// 所以「已答的保留」是确定的（MaxConcurrent = 4：两道阻塞的信号题之外还有空位给其余题）
			func(expire func(), nonSignal int) answerFunc {
				var answered, waiting atomic.Int32
				expireWhenAllArrived := func() {
					if answered.Load() == int32(nonSignal) && waiting.Load() == 2 {
						expire()
					}
				}
				return func(ctx context.Context, qs []judge.Question) (judge.Response, error) {
					if qs[0].ID == action.SignalRequested || qs[0].ID == action.SignalRadius {
						waiting.Add(1)
						expireWhenAllArrived()
						<-ctx.Done()
						return judge.Response{}, ctx.Err()
					}
					r := answersFor(partial, qs)
					answered.Add(1)
					expireWhenAllArrived()
					return r, nil
				}
			}, guard.DecisionAsk, []string{action.FallbackJudgeTimeout}},
		{"the deadline passes after every answer arrived: no reason", judge.BackendCaps{Batch: true},
			func(expire func(), _ int) answerFunc {
				return func(ctx context.Context, qs []judge.Question) (judge.Response, error) {
					expire()
					<-ctx.Done()
					return answersFor(dangerous(), qs), nil
				}
			}, guard.DecisionAsk, nil},
		{"only the radius is missing at the deadline", judge.BackendCaps{Batch: true},
			func(expire func(), _ int) answerFunc {
				return func(ctx context.Context, qs []judge.Question) (judge.Response, error) {
					expire()
					<-ctx.Done()
					return answersFor(without(with(low(), "publish", 0.9), action.SignalRadius), qs), nil
				}
			}, guard.DecisionAsk, []string{action.FallbackJudgeTimeout}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// 先构建检查，再开始计时：构建（加载内置规则与文案）不占用这次检查的时间
			c := newCheck(t, true, action.Judge{})
			qs := c.Questions()
			parent, expire := context.WithCancel(context.Background())
			defer expire()
			// 兜底：测试或产品有 bug 时不让整个测试挂住。正确的运行里永远走不到
			ctx, stop := context.WithTimeout(parent, 30*time.Second)
			defer stop()
			b := &recordingBackend{caps: tt.caps, answer: tt.backend(expire, len(qs)-2)}
			c.Judge.Backend = b
			v, err := guard.Run(ctx, c, event(nil, "git push origin main"))
			if err != nil {
				t.Fatal(err)
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("the safety timeout fired: the backend never ended the context (%+v)", v)
			}
			if slices.Contains(v.Fallbacks, action.FallbackBudget) {
				t.Fatalf("the local stage ran out of budget before the judge was asked (%+v)", v)
			}
			if len(b.asked) != len(qs) {
				t.Errorf("asked %d questions %v, want all %d", len(b.asked), b.asked, len(qs))
			}
			if v.Decision != tt.want || !slices.Equal(v.Fallbacks, tt.fb) {
				t.Errorf("decision = %s, fallbacks = %v, want %s %v (%+v)", v.Decision, v.Fallbacks, tt.want, tt.fb, v)
			}
		})
	}
}

func TestTruncatedEvidence(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "recursive_delete", 0.01, action.SignalRequested, 1.0)}
	c := newCheck(t, true, action.Judge{Backend: b})
	c.Config.Policy.MaxCommandChars = 40
	cmd := "git status && " + strings.Repeat("echo ok && ", 10) + "rm -rf src && git status"
	v := run(t, c, event([]guard.Request{user("run git status")}, cmd))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackTruncated) || !slices.Contains(codes(v), i18n.KeyHintSplit) {
		t.Errorf("truncated = %+v", v)
	}
}

func TestMultipleActionsTakeTheStrictest(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, "ls", "rm -rf /", "git status")); v.Decision != guard.DecisionDeny {
		t.Errorf("decision = %s", v.Decision)
	}
}

func TestCommittedActionSurvivesALaterPanic(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "publish", 0.9, action.SignalRadius, []float64{0, 0, 1, 0}), panicOn: "second"}
	c := newCheck(t, true, action.Judge{Backend: b})
	v, err := guard.Run(context.Background(), c, event(nil, "git push origin main", "echo second"))
	var pe *guard.PanicError
	if !errors.As(err, &pe) || v.Decision != guard.DecisionAsk {
		t.Errorf("verdict = %s, err = %v", v.Decision, err)
	}
}

// TestDenySurvivesBudgetExhaustion：灾难性形态命中之后预算耗尽，结论仍为 deny 且保留命中，
// 并且 deny 在后续匹配之前就已提交。
func TestDenySurvivesBudgetExhaustion(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	dir := t.TempDir()
	for name, pattern := range map[string]string{"zzslow": "(a+)+$", "zzz": "nevermatch"} {
		body := "schema: 1\nid: " + name + "\naction: ask\non: [exec]\nreason: {en: slow}\nmatch:\n  exec:\n    any: ['" + pattern + "']\n"
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if c.Rules, err = rules.Load(dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var commits []guard.Verdict
	v, err := c.Evaluate(ctx, event(nil, "rm -rf ~; echo "+strings.Repeat("a", 40)+"!"), func(cv guard.Verdict) { commits = append(commits, cv) })
	if err != nil || v.Decision != guard.DecisionDeny || !slices.Contains(v.Fallbacks, action.FallbackBudget) {
		t.Fatalf("verdict = %+v, err = %v", v, err)
	}
	if !slices.ContainsFunc(v.Findings, func(f guard.Finding) bool { return f.Rule == "catastrophic" }) {
		t.Errorf("findings = %+v, want catastrophic", v.Findings)
	}
	if len(commits) == 0 || commits[0].Decision != guard.DecisionDeny {
		t.Errorf("the deny must be committed before the slow rules run: %+v", commits)
	}
}

func TestBudgetExhaustionWithoutDenyAsks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, _ := guard.Run(ctx, newCheck(t, false, action.Judge{}), event(nil, "ls"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackBudget) {
		t.Errorf("verdict = %+v", v)
	}
}

// TestRegexTimeoutDoesNotWeakenADefiniteDeny：某个模式超时不能让另一处的确定命中降为请求确认；只有超时命中时
// 请求确认并说明正则超时，不能说成「修改护栏本身」。
func TestRegexTimeoutDoesNotWeakenADefiniteDeny(t *testing.T) {
	slow := "rmdir" + strings.Repeat(" -r", 20000) // 让灾难性规则的一个模式超时
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, slow+"; echo $(rm -rf /)")); v.Decision != guard.DecisionDeny {
		t.Errorf("a definite catastrophic match after a timeout: %s, want deny", v.Decision)
	}
	v := run(t, c, event(nil, slow))
	codes := map[string]bool{}
	for _, r := range v.Reasons {
		codes[r.Code] = true
	}
	if v.Decision != guard.DecisionAsk || codes[i18n.KeyActionGuardSelf] || !codes[i18n.KeyActionRegexTimeout] {
		t.Errorf("a timed-out match alone: %s, reasons %v", v.Decision, v.Reasons)
	}
}

// TestShellContextDecides：同一个危险命令在不同的 shell 上下文里结论不同——真正执行时阻止，作为数据时放行
// （命令只交给检测器，不执行）。
func TestShellContextDecides(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	tests := []struct {
		name, cmd string
		want      guard.Decision
	}{
		{"heredoc paren inside substitution", "echo \"$(cat <<'EOF'\n)\nEOF\nrm -rf ~\n)\"", guard.DecisionDeny},
		{"comment paren inside substitution", "echo \"$(echo x # )\nrm -rf ~\n)\"", guard.DecisionDeny},
		{"nested quotes control", "echo \"$(echo \"$(printf ')')\"; rm -rf ~)\"", guard.DecisionDeny},
		{"space in quoted delimiter", "cat <<' EOF'\nsafe\n EOF\nrm -rf ~", guard.DecisionDeny},
		{"indented delimiter line is data", "cat <<'EOF'\n EOF\nrm -rf ~\nEOF", guard.DecisionPass},
		{"split prefix word", "su\\\ndo rm -rf ~", guard.DecisionDeny},
		{"split command word", "rm -r\\\nf ~", guard.DecisionDeny},
		{"split heredoc delimiter", "cat <<E\\\nOF\nsafe\nEOF\nrm -rf ~", guard.DecisionDeny},
		{"quoted heredoc keeps the backslash", "cat <<'EOF'\nx\\\nEOF\nrm -rf ~", guard.DecisionDeny},
		{"unquoted heredoc joins lines", "cat <<EOF\nx\\\nEOF\nrm -rf ~\nEOF", guard.DecisionPass},
		{"continuation inside single quotes is text", "echo 'su\\\ndo rm -rf ~'", guard.DecisionPass},
		{"continuation inside quoted heredoc is text", "cat > f <<'EOF'\nsu\\\ndo rm -rf ~\nEOF", guard.DecisionPass},
		{"comment backslash does not continue", "echo hi # note \\\nrm -rf ~", guard.DecisionDeny},
		// 续行先于词法单元的识别
		{"split substitution in double quotes", "echo \"$\\\n(rm -rf ~)\"", guard.DecisionDeny},
		{"split substitution in expandable heredoc", "cat <<EOF\n$\\\n(rm -rf ~)\nEOF", guard.DecisionDeny},
		{"split assignment prefix", "F\\\nOO=1 rm -rf ~", guard.DecisionDeny},
		{"split interpreter name", "bas\\\nh <<'EOF'\nrm -rf ~\nEOF", guard.DecisionDeny},
		// 被续行拆开的 heredoc 运算符：正文照常按执行或数据处理
		{"split heredoc operator, expandable body", "cat <\\\n<EOF\n$(rm -rf ~)\nEOF", guard.DecisionDeny},
		{"split heredoc operator, interpreter body", "bash <\\\n<'EOF'\nrm -rf ~\nEOF", guard.DecisionDeny},
		// 参数默认值里的进程替换会执行；引号里的是字面内容
		{"process substitution in parameter default", "echo ${x:-<(rm -rf ~)}", guard.DecisionDeny},
		{"output process substitution in parameter default", "echo ${x:->(rm -rf ~)}", guard.DecisionDeny},
		{"process substitution mid-word in parameter default", "echo ${x:-a<(rm -rf ~)}", guard.DecisionDeny},
		{"split process substitution in parameter default", "echo ${x:-<\\\n(rm -rf ~)}", guard.DecisionDeny},
		{"single-quoted process substitution in parameter default", "echo ${x:-'<(rm -rf ~)'}", guard.DecisionPass},
		{"double-quoted process substitution in parameter default", "echo ${x:-\">(rm -rf ~)\"}", guard.DecisionPass},
		{"parameter default in double quotes", "echo \"${x:-<(rm -rf ~)}\"", guard.DecisionPass},
		// 命令替换再多，后面的内容也要检查
		{"after many substitutions", "echo" + strings.Repeat(" $(true)", 70) + " $(rm -rf /)", guard.DecisionDeny},
		// 灾难性形态的常见写法：加引号、带路径、转义的命令词、timeout 前缀
		{"quoted home", `rm -rf "$HOME"`, guard.DecisionDeny},
		{"braced home with slash", `rm -rf ${HOME}/`, guard.DecisionDeny},
		{"quoted root", `rm -rf '/'`, guard.DecisionDeny},
		{"absolute rm", `/bin/rm -rf /`, guard.DecisionDeny},
		{"escaped rm", `\rm -rf /`, guard.DecisionDeny},
		{"timeout prefix", `timeout 5 rm -rf /`, guard.DecisionDeny},
		{"quoted relative target", `rm -rf "./build"`, guard.DecisionPass},
		{"quoted project path", `rm -rf "/home/dev/proj/dist"`, guard.DecisionPass},
		{"quoted text after echo", `echo "rm -rf $HOME"`, guard.DecisionPass},
	}
	for _, tt := range tests {
		if v := run(t, c, event(nil, tt.cmd)); v.Decision != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, v.Decision, tt.want)
		}
	}
	// 引号里的进程替换是字面内容：模型开启时可以因普通全文规则请求确认，但不能当作灾难性执行
	for _, cmd := range []string{"echo ${x:-'<(rm -rf ~)'}", "echo ${x:-\">(rm -rf ~)\"}", "echo \"${x:-<(rm -rf ~)}\""} {
		if v := run(t, newCheck(t, true, action.Judge{}), event(nil, cmd)); v.Decision == guard.DecisionDeny {
			t.Errorf("%q: literal text treated as catastrophic execution", cmd)
		}
	}
	// 模型开启但不可用时普通正则命中请求确认：嵌套上下文里的字面反斜杠换行不能拼出命令
	unavailable := newCheck(t, true, action.Judge{})
	for _, cmd := range []string{
		"echo \"$(printf '%s' 'r\\\nm -rf build')\"",
		"echo hi # r\\\nm -rf build",
		"echo \"$(cat <<'EOF'\nr\\\nm -rf build\nEOF\n)\"",
		"cat <\\\n<'EOF'\nrm -rf build\nEOF",               // 拆开的运算符，正文是字面数据
		"echo ${x:-\"$(printf '%s' 'r\\\nm -rf build')\"}", // 参数展开里的嵌套引号
	} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionPass {
			t.Errorf("%q: %s, want pass", cmd, v.Decision)
		}
	}
	for _, cmd := range []string{"r\\\nm -rf build", "echo ${x:-$(r\\\nm -rf build)}"} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionAsk {
			t.Errorf("%q: a real continuation must still match: %s", cmd, v.Decision)
		}
	}
	for _, cmd := range []string{"cat <\\\n<EOF\n$(rm -rf ~)\nEOF", "bash <\\\n<'EOF'\nrm -rf ~\nEOF",
		"echo ${x:-<(rm -rf ~)}", "echo ${x:->(rm -rf ~)}"} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionDeny {
			t.Errorf("%q with the judge enabled: %s, want deny", cmd, v.Decision)
		}
	}
}

func TestProbe(t *testing.T) {
	v := run(t, newCheck(t, false, action.Judge{}), event(nil, "  h-guard-probe "))
	if v.Decision != guard.DecisionAsk || codes(v)[0] != i18n.KeyActionProbe {
		t.Errorf("probe = %+v", v)
	}
}

func TestAppliesToExecAndFileActions(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	file := guard.Event{Kind: guard.EventAction, Harness: "h", Actions: []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "x"}}}}
	tool := guard.Event{Kind: guard.EventAction, Harness: "h", Actions: []guard.Action{{Kind: guard.ActionToolCall, Raw: map[string]any{}}}}
	if !c.Applies(file) || c.Applies(tool) || c.Applies(guard.Event{Kind: guard.EventPrompt}) || !c.Applies(event(nil, "ls")) {
		t.Error("Applies must be true only for events with exec or file actions")
	}
}

func TestDisabledRuleNoLongerMatches(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if _, err := c.Rules.Apply(rules.Overrides{"catastrophic": false}); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, event(nil, "rm -rf /")); v.Decision == guard.DecisionDeny {
		t.Error("a disabled hard rule must not match")
	}
}

// TestUserRequestsAreChronological：发给模型的是最近 request_window 条用户本人的指令，旧的在前。
func TestUserRequestsAreChronological(t *testing.T) {
	b := &fakeBackend{answers: low()}
	reqs := []guard.Request{user("first"), user("second"), {Text: "scheduled", Source: guard.SourceAutomated}, user("third"), user("  "), user("fourth")}
	run(t, newCheck(t, true, action.Judge{Backend: b}), event(reqs, "git push"))
	got := b.states[0]["user_requests"].([]any)
	if len(got) != 3 || got[0] != "second" || got[1] != "third" || got[2] != "fourth" {
		t.Errorf("user_requests = %v, want [second third fourth]", got)
	}
}

// TestRevocationWording：题目写明指令按时间先后排列、以后来的为准。
func TestRevocationWording(t *testing.T) {
	var q judge.Question
	for _, x := range newCheck(t, true, action.Judge{}).Questions() {
		if x.ID == action.SignalRequested {
			q = x
		}
	}
	if !strings.Contains(q.Instructions.Question, "oldest first") || !strings.Contains(q.Instructions.CountsAsNo, "withdraws") ||
		strings.Contains(q.Instructions.Question, "newest first") {
		t.Errorf("explicitly_requested wording = %+v", q.Instructions)
	}
}

// TestThresholdsComeFromTheEntry：阈值由入口注入；没有注入时用保守默认值，不读档案。
func TestThresholdsComeFromTheEntry(t *testing.T) {
	answers := with(low(), "publish", 0.9, action.SignalRequested, 0.8, action.SignalRadius, []float64{0, 0, 1, 0})
	ev := event([]guard.Request{user("push it to origin")}, "git push origin main")
	if v := run(t, newCheck(t, true, action.Judge{Backend: &fakeBackend{answers: answers}}), ev); v.Decision != guard.DecisionPass {
		t.Errorf("requested 0.8 with jev thresholds (0.7) = %s, want pass", v.Decision)
	}
	c := newCheck(t, true, action.Judge{Backend: &fakeBackend{answers: answers}})
	c.Judge.Thresholds = nil
	if v := run(t, c, ev); v.Decision != guard.DecisionAsk {
		t.Errorf("requested 0.8 with conservative thresholds (0.9) = %s, want ask", v.Decision)
	}
}

func fileEvent(kind guard.ActionKind, path, to string) guard.Event {
	return guard.Event{Kind: guard.EventAction, Harness: "claudecode", Tool: "Write", Cwd: "/home/user/project",
		Actions: []guard.Action{{Kind: kind, File: &guard.FileAction{Path: path, To: to}}}}
}

func fileCheck(t *testing.T, judgeOn bool, b judge.Backend) *action.Check {
	t.Helper()
	c := newCheck(t, judgeOn, action.Judge{Backend: b})
	c.Paths = paths.Env{Home: "/home/user", Lexical: true,
		Vars: map[string]string{rules.VarConfig: "/xdg/h-guard", rules.VarCache: "/home/user/.cache/h-guard"}}
	return c
}

// TestFileActionsOnProtectedPaths：写、删、重命名护栏配置、指令缓存与 harness hook 配置时请求确认，
// 只按路径匹配、不调模型、不能由用户授权；普通文件不打断（维护者决定，2026-10-13）。
func TestFileActionsOnProtectedPaths(t *testing.T) {
	b := &fakeBackend{answers: with(low(), action.SignalRequested, 1.0)}
	for _, judgeOn := range []bool{false, true} {
		c := fileCheck(t, judgeOn, b)
		for _, ev := range []guard.Event{
			fileEvent(guard.ActionFileWrite, "~/.claude/settings.json", ""),
			fileEvent(guard.ActionFileWrite, "/xdg/h-guard/config.yaml", ""),
			fileEvent(guard.ActionFileWrite, "/home/user/.cache/h-guard/requests/s/1.json", ""),
			fileEvent(guard.ActionFileWrite, ".codex/hooks.json", ""),
			fileEvent(guard.ActionFileDelete, "/home/user/.codex/config.toml", ""),
			fileEvent(guard.ActionFileRename, "notes.md", "/home/user/.claude/settings.local.json"),
		} {
			ev.Requests = []guard.Request{user("update my claude settings")}
			v := run(t, c, ev)
			if v.Decision != guard.DecisionAsk || !slices.Equal(codes(v), []string{i18n.KeyActionGuardSelfFile, i18n.KeyHintManual, i18n.KeyActionImpact, i18n.KeyActionAdvice}) ||
				len(v.Findings) != 1 || v.Findings[0].Rule != "guard_tampering" {
				t.Errorf("judge %v, %s %+v = %+v", judgeOn, ev.Actions[0].Kind, *ev.Actions[0].File, v)
			}
		}
		for _, ev := range []guard.Event{
			fileEvent(guard.ActionFileWrite, "src/main.go", ""),
			fileEvent(guard.ActionFileRead, "~/.claude/settings.json", ""),
			fileEvent(guard.ActionFileWrite, "/home/user/.config/h-guard-notes/x.md", ""),
		} {
			if v := run(t, c, ev); v.Decision != guard.DecisionPass || len(v.Reasons) != 0 {
				t.Errorf("judge %v, %+v = %+v", judgeOn, *ev.Actions[0].File, v)
			}
		}
	}
	if b.calls.Load() != 0 {
		t.Errorf("file actions called the judge %d times", b.calls.Load())
	}
}

func TestProtectedFileReasonNamesThePath(t *testing.T) {
	c := fileCheck(t, false, nil)
	v := run(t, c, fileEvent(guard.ActionFileWrite, "~/.claude/settings.json", ""))
	if p := v.Reasons[0].Params["paths"]; p != "~/.claude/settings.json" || !strings.Contains(v.Reasons[0].Params["rules"], "[rule]") {
		t.Errorf("params = %v", v.Reasons[0].Params)
	}
	text := c.Catalog.Text("zh-CN", v.Reasons[0].Code, v.Reasons[0].Params)
	if !strings.Contains(text, "~/.claude/settings.json") || !strings.Contains(text, "受保护的文件") {
		t.Errorf("zh-CN text = %q", text)
	}
}

func TestDisabledSelfProtectionIgnoresFiles(t *testing.T) {
	c := fileCheck(t, false, nil)
	if _, err := c.Rules.Apply(rules.Overrides{"guard_tampering": false}); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, fileEvent(guard.ActionFileWrite, "~/.claude/settings.json", "")); v.Decision != guard.DecisionPass {
		t.Errorf("disabled guard_tampering = %+v", v)
	}
}

// TestSensitiveRead：第 2 档（默认）读取 .env、私钥等之前请求确认，原因写明是哪个文件；只按路径匹配，不调模型，
// 用户要求过也一样。示例文件不打断；第 1 档不检查文件读取，但硬规则（护栏自我保护）
// 不受档位限制。
func TestSensitiveRead(t *testing.T) {
	b := &fakeBackend{answers: with(low(), action.SignalRequested, 1.0)}
	c := fileCheck(t, true, b)
	for _, p := range []string{".env", "~/.ssh/id_ed25519", "/home/user/.aws/credentials"} {
		ev := fileEvent(guard.ActionFileRead, p, "")
		ev.Requests = []guard.Request{user("read " + p)}
		v := run(t, c, ev)
		if v.Decision != guard.DecisionAsk || !slices.Equal(codes(v), []string{i18n.KeyActionFileRule, i18n.KeyHintManual, i18n.KeyActionImpact, i18n.KeyActionAdvice}) ||
			v.Reasons[0].Params["paths"] != p || len(v.Findings) != 1 || v.Findings[0].Rule != "sensitive_read" {
			t.Errorf("read %s = %+v", p, v)
		}
	}
	text := c.Catalog.Text("zh-CN", i18n.KeyActionFileRule, map[string]string{"paths": ".env", "rules": "x"})
	if !strings.Contains(text, ".env") || strings.Contains(text, "{") {
		t.Errorf("zh-CN text = %q", text)
	}
	for _, ev := range []guard.Event{
		fileEvent(guard.ActionFileRead, ".env.example", ""),
		fileEvent(guard.ActionFileWrite, ".env", ""), // sensitive_read 只管读取
		fileEvent(guard.ActionFileRead, "src/main.go", ""),
	} {
		if v := run(t, c, ev); v.Decision != guard.DecisionPass {
			t.Errorf("%s %s = %+v", ev.Actions[0].Kind, ev.Actions[0].File.Path, v)
		}
	}
	if b.calls.Load() != 0 {
		t.Errorf("file actions called the judge %d times", b.calls.Load())
	}
	c.Config.Action.Tier = 1
	if v := run(t, c, fileEvent(guard.ActionFileRead, ".env", "")); v.Decision != guard.DecisionPass {
		t.Errorf("tier 1 read .env = %+v", v)
	}
	if v := run(t, c, fileEvent(guard.ActionFileWrite, "~/.claude/settings.json", "")); v.Decision != guard.DecisionAsk {
		t.Errorf("tier 1 write ~/.claude/settings.json = %+v, want ask (hard rules ignore the tier)", v)
	}
	c.Config.Action.Tier = 2
	if _, err := c.Rules.Apply(rules.Overrides{"sensitive_read": false}); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, fileEvent(guard.ActionFileRead, ".env", "")); v.Decision != guard.DecisionPass {
		t.Errorf("disabled sensitive_read = %+v", v)
	}
}

// TestPowerShellStateNamesTheShell：PowerShell 的 exec 动作发给模型的 state 带 call.shell。
func TestPowerShellStateNamesTheShell(t *testing.T) {
	b := &fakeBackend{answers: with(low(), action.SignalRequested, 0.0)}
	ev := event(nil, "Remove-Item -Recurse -Force .\\build")
	ev.Actions[0].Exec.Shell = guard.ShellPowerShell
	run(t, newCheck(t, true, action.Judge{Backend: b}), ev)
	if len(b.states) != 1 || b.states[0]["call"].(map[string]any)["shell"] != "powershell" {
		t.Errorf("states = %v", b.states)
	}
}

// TestPowerShellPublishAsksWhenTheJudgeIsUnsure：远端写请求的本地命中在模型不确定时（概率在否决与命中阈值之间）
// 照常请求确认；请求正文里的本机 URL 不能消掉这个命中。
func TestPowerShellPublishAsksWhenTheJudgeIsUnsure(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "publish", 0.35, action.SignalRequested, 0.0, action.SignalRadius, []float64{0, 0, 1, 0})}
	for _, cmd := range []string{
		"Invoke-RestMethod -Uri https://api.example.com/deploy -Method Post -Body 'http://localhost/payload'",
		"Invoke-RestMethod -Uri $url -Method Post -Body 'http://localhost/payload'",                                           // URI 是变量，请求正文里有本机 URL
		"Invoke-RestMethod -Method Post -Body 'http://localhost/;x' -Uri https://api.example.com/deploy",                      // 同上
		"Invoke-RestMethod -Uri https://api.example.com/deploy -Method Post -Body \"hello`\" -Uri http://localhost/payload\"", // 正文里转义的引号不结束字符串，其中的伪 -Uri 不算
	} {
		ev := event(nil, cmd)
		ev.Actions[0].Exec.Shell = guard.ShellPowerShell
		if v := run(t, newCheck(t, true, action.Judge{Backend: b}), ev); v.Decision != guard.DecisionAsk ||
			!slices.ContainsFunc(v.Findings, func(f guard.Finding) bool { return f.Rule == "publish" }) {
			t.Errorf("%s: verdict = %+v", cmd, v)
		}
	}
}

// TestSignalIDsAreReserved：规则 id 不能与信号题同名，否则两道题的答案会混在一起。
func TestSignalIDsAreReserved(t *testing.T) {
	if !slices.Equal(rules.ReservedIDs, []string{action.SignalRequested, action.SignalRadius}) {
		t.Errorf("rules.ReservedIDs = %v, want the two signal question ids", rules.ReservedIDs)
	}
}

// TestUnresolvedPathFallsBackToTheCleanPath：相对路径没有 cwd 时按规范化后的原始路径匹配，带 path_unresolved。
func TestUnresolvedPathFallsBackToTheCleanPath(t *testing.T) {
	c := fileCheck(t, false, nil)
	ev := fileEvent(guard.ActionFileWrite, "sub/../.claude/settings.json", "")
	ev.Cwd = ""
	v := run(t, c, ev)
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackPathUnresolved) {
		t.Errorf("unresolved protected path = %+v", v)
	}
	ev = fileEvent(guard.ActionFileWrite, "README.md", "")
	ev.Cwd = ""
	if v := run(t, c, ev); v.Decision != guard.DecisionPass || !slices.Contains(v.Fallbacks, action.FallbackPathUnresolved) {
		t.Errorf("unresolved ordinary path = %+v", v)
	}
}

// TestMixedActionsTakeTheStrictest：同一次调用里的命令与文件动作逐个评估，取最严。
func TestMixedActionsTakeTheStrictest(t *testing.T) {
	c := fileCheck(t, false, nil)
	ev := fileEvent(guard.ActionFileWrite, "README.md", "")
	ev.Actions = append(ev.Actions, guard.Action{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "~/.codex/hooks.json"}},
		guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "ls", Shell: guard.ShellPOSIX}})
	if v := run(t, c, ev); v.Decision != guard.DecisionAsk {
		t.Errorf("mixed actions = %+v", v)
	}
}

// TestQuestionSetIgnoresSwitches：校准题集包含全部带题的 exec 规则，停用规则不改变题集，改写措辞会。
func TestQuestionSetIgnoresSwitches(t *testing.T) {
	set, _ := rules.Builtin()
	before := action.QuestionSet(set)
	if _, err := set.Apply(rules.Overrides{"publish": false}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(action.QuestionSet(set), before) {
		t.Error("disabling a rule changed the question set")
	}
	var ids []string
	for _, q := range before {
		ids = append(ids, q.ID)
	}
	want := []string{"branch_ops", "destructive_git", "guard_tampering", "publish", "recursive_delete", "verify_bypass",
		action.SignalRequested, action.SignalRadius}
	if !slices.Equal(ids, want) {
		t.Errorf("question set = %v, want %v", ids, want)
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "publish.yaml"), []byte(`schema: 1
id: publish
action: ask
on: [exec]
requires_judge: true
reason: {en: publish}
match: {exec: {any: ['\bgit\s+push\b']}}
question: {kind: probability, instructions: {question: 'Reworded: would it publish?'}}
`), 0o600)
	custom, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(action.QuestionSet(custom), before) {
		t.Error("rewording a question kept the question set")
	}
}

// TestBuiltinQuestionsDigestIsPinned：内置题集（内置规则的题 + 两个信号题）的指纹固定为 BuiltinQuestionsDigest。
// 内置档案的指纹都是它（default.yaml），所以题目措辞的改动在这里先失败，而不是悄悄让全部档案失效。
func TestBuiltinQuestionsDigestIsPinned(t *testing.T) {
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if got := config.QuestionsDigest(action.QuestionSet(set)); got != action.BuiltinQuestionsDigest {
		t.Errorf("the built-in question set digest is %s, pinned %s.\n"+
			"Changing the wording of a built-in or signal question is a breaking change, made only in a major version: "+
			"every built-in profile must be recalibrated at the same time, BuiltinQuestionsDigest updated, "+
			"and the change noted in the release notes.", got, action.BuiltinQuestionsDigest)
	}
}

// TestGuardTamperingCannotBeVetoed：护栏自我保护的本地命中不能被模型的低分否决，结论保持请求确认
// （维护者决定，2026-10-13）。只读的用法也会命中，模型同样不能撤销：已知误报，暂时保守处理。
func TestGuardTamperingCannotBeVetoed(t *testing.T) {
	for _, cmd := range []string{
		`echo '{"prompts":["push 到 origin"]}' > ~/.cache/h-guard/prompts/claude-code-s.json`,
		"rm ~/.claude/settings.json",
		// 已知误报：读出备份、脚本读取
		"cp ~/.claude/settings.json /tmp/backup.json",
		`python3 -c "print(open('/home/u/.claude/settings.json').read())"`,
	} {
		b := &fakeBackend{answers: low()}
		v := run(t, newCheck(t, true, action.Judge{Backend: b}), event(nil, cmd))
		if v.Decision != guard.DecisionAsk || b.calls.Load() != 1 || v.Signals["regex_vetoed"] != nil ||
			len(v.Findings) != 1 || v.Findings[0].Rule != "guard_tampering" {
			t.Errorf("%q with the model answering 0: %+v", cmd, v)
		}
	}
	// 其他规则照常可以否决
	if v := run(t, newCheck(t, true, action.Judge{Backend: &fakeBackend{answers: low()}}), event(nil, "git push origin main")); v.Decision != guard.DecisionPass {
		t.Errorf("publish with the model answering 0 = %+v", v)
	}
}

// TestIncompleteDirectoryScanIsFlagged：受保护目录读不全时，文件动作照常按已知的模式判断，并带 path_unresolved，
// 正在使用的配置文件的链接目标仍然受保护。
func TestIncompleteDirectoryScanIsFlagged(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	os.Mkdir(conf, 0o755)
	for i := 0; i < 4100; i++ {
		os.WriteFile(filepath.Join(conf, "b"+strconv.Itoa(i)+".bak"), nil, 0o600)
	}
	target := filepath.Join(root, "active.yaml")
	os.WriteFile(target, []byte("version: 1"), 0o600)
	if err := os.Symlink(target, filepath.Join(conf, "config.yaml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	c := newCheck(t, false, action.Judge{})
	c.Paths = paths.Env{Home: filepath.Join(root, "home"), Vars: map[string]string{rules.VarConfig: conf}}
	ev := fileEvent(guard.ActionFileWrite, target, "")
	ev.Cwd = root
	if v := run(t, c, ev); v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackPathUnresolved) {
		t.Errorf("editing the active config target = %+v", v)
	}
	ev = fileEvent(guard.ActionFileWrite, filepath.Join(root, "notes.md"), "")
	ev.Cwd = root
	if v := run(t, c, ev); v.Decision != guard.DecisionPass || !slices.Contains(v.Fallbacks, action.FallbackPathUnresolved) {
		t.Errorf("an unrelated file with an incomplete scan = %+v", v)
	}
}

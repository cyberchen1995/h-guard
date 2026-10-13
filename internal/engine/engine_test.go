package engine_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// stub 是可编排的 Check：先提交 commit（若有），再按 panics / err 失败，否则返回 ret。
type stub struct {
	name          string
	commit, ret   *guard.Verdict
	err           error
	panics        bool
	appliesPanics bool
}

func (s *stub) Name() string { return s.name }
func (s *stub) Applies(guard.Event) bool {
	if s.appliesPanics {
		panic("applies")
	}
	return true
}
func (s *stub) Evaluate(_ context.Context, _ guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	if s.commit != nil {
		commit(*s.commit)
	}
	if s.panics {
		panic("boom")
	}
	if s.ret != nil {
		return *s.ret, s.err
	}
	return guard.Verdict{Decision: guard.DecisionPass}, s.err
}

func verdict(d guard.Decision, codes ...string) *guard.Verdict {
	v := &guard.Verdict{Decision: d}
	for _, c := range codes {
		v.Reasons = append(v.Reasons, guard.Reason{Code: c})
	}
	return v
}

var (
	actionEv = guard.Event{Kind: guard.EventAction, Harness: "h"}
	allCaps  = harness.EventCaps{Block: true, Ask: true, Warn: true, Replace: true}
)

func newEngine(t *testing.T, checks ...guard.Check) *engine.Engine {
	t.Helper()
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	return &engine.Engine{Checks: checks, Catalog: cat, Locale: "en", WhenAskUnsupported: guard.DecisionDeny}
}

func TestAggregationNeverLoosens(t *testing.T) {
	tests := []struct {
		name   string
		checks []guard.Check
		want   guard.Decision
	}{
		{"deny then a failing check", []guard.Check{
			&stub{name: "a", ret: verdict(guard.DecisionDeny, i18n.KeyActionBlocked)},
			&stub{name: "b", err: errors.New("x")},
		}, guard.DecisionDeny},
		{"commit deny then panic", []guard.Check{&stub{name: "a", commit: verdict(guard.DecisionDeny), panics: true}}, guard.DecisionDeny},
		{"panic without commit falls back to ask", []guard.Check{&stub{name: "action", panics: true}}, guard.DecisionAsk},
		// 故障兜底按事件类型，与 Check 的名字无关（评审 R4-03；提示词事件见 TestFailureOnPromptPasses）
		{"failure on an action asks whatever the name", []guard.Check{&stub{name: "outbound", err: errors.New("x")}}, guard.DecisionAsk},
		{"applies panic alone is a failure", []guard.Check{&stub{name: "action", appliesPanics: true, ret: verdict(guard.DecisionPass)}}, guard.DecisionAsk},
		{"applies panic keeps another check's deny", []guard.Check{
			&stub{name: "a", ret: verdict(guard.DecisionDeny, i18n.KeyActionBlocked)},
			&stub{name: "action", appliesPanics: true, ret: verdict(guard.DecisionPass)},
		}, guard.DecisionDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := newEngine(t, tt.checks...).Evaluate(context.Background(), actionEv, allCaps)
			if res.Outcome.Verdict.Decision != tt.want {
				t.Errorf("decision = %s, want %s", res.Outcome.Verdict.Decision, tt.want)
			}
			failed := slices.ContainsFunc(res.Runs, func(r engine.CheckRun) bool { return r.Err != nil })
			if tt.name == "applies panic alone is a failure" && (len(res.Runs) != 1 || !res.Runs[0].Panicked) {
				t.Errorf("runs = %+v, want one panicked run", res.Runs)
			}
			if failed != slices.Contains(res.Outcome.Verdict.Fallbacks, engine.FallbackInternal) {
				t.Errorf("internal_error fallback = %v, failed = %v", res.Outcome.Verdict.Fallbacks, failed)
			}
		})
	}
}

// TestFailureOnPromptPasses：提示词与工具输出上的 Check 故障放行并带 internal_error，不能因护栏 bug 吞掉
// 用户输入；已提交的 deny 仍保持（spec §10.1）。
func TestFailureOnPromptPasses(t *testing.T) {
	for _, kind := range []guard.EventKind{guard.EventPrompt, guard.EventToolOutput} {
		ev := guard.Event{Kind: kind, Harness: "h"}
		res := newEngine(t, &stub{name: "action", err: errors.New("x")}).Evaluate(context.Background(), ev, allCaps)
		if v := res.Outcome.Verdict; v.Decision != guard.DecisionPass || !slices.Contains(v.Fallbacks, engine.FallbackInternal) {
			t.Errorf("%s: %+v", kind, v)
		}
		res = newEngine(t, &stub{name: "outbound", commit: verdict(guard.DecisionDeny), panics: true}).Evaluate(context.Background(), ev, allCaps)
		if res.Outcome.Verdict.Decision != guard.DecisionDeny {
			t.Errorf("%s: a committed deny must stay, got %s", kind, res.Outcome.Verdict.Decision)
		}
	}
}

// TestOnCommitIsSynchronous：提交在 Evaluate 返回之前、在提交的同一调用中转告（评审 N02）。
func TestOnCommitIsSynchronous(t *testing.T) {
	var seen []guard.Decision
	inCommit := false
	e := newEngine(t, &stub{name: "action", commit: verdict(guard.DecisionDeny, i18n.KeyActionBlocked), panics: true})
	e.OnCommit = func(check string, v guard.Verdict) {
		inCommit = true
		if check != "action" {
			t.Errorf("check = %q", check)
		}
		seen = append(seen, v.Decision)
	}
	res := e.Evaluate(context.Background(), actionEv, allCaps)
	if !inCommit || !slices.Equal(seen, []guard.Decision{guard.DecisionDeny}) || res.Outcome.Verdict.Decision != guard.DecisionDeny {
		t.Errorf("seen = %v, outcome = %s", seen, res.Outcome.Verdict.Decision)
	}
	if res.Runs[0].Name != "action" {
		t.Errorf("runs = %+v", res.Runs)
	}
}

// scripted 依次提交 commits，然后 panic：guard.Run 返回的就是它对这些提交的合并结果。
type scripted struct{ commits []guard.Verdict }

func (s *scripted) Name() string             { return "action" }
func (s *scripted) Applies(guard.Event) bool { return true }
func (s *scripted) Evaluate(_ context.Context, _ guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	for _, v := range s.commits {
		commit(v)
	}
	panic("after commits")
}

// TestCommittedMatchesGuardRun：Committed 对同一个 Check 的提交合并与 guard.Run 一致——最严的一次、
// 同样严时取后一次、降级原因全部累计（评审 R3-04）。随机提交序列逐个对照。
func TestCommittedMatchesGuardRun(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	decisions := []guard.Decision{guard.DecisionWarn, guard.DecisionAsk, guard.DecisionDeny}
	for n := 0; n < 500; n++ {
		var commits []guard.Verdict
		for k := r.Intn(5) + 1; k > 0; k-- {
			v := guard.Verdict{Decision: decisions[r.Intn(len(decisions))], Reasons: []guard.Reason{{Code: fmt.Sprint("r", r.Intn(4))}}}
			for f := r.Intn(3); f > 0; f-- {
				v.Findings = append(v.Findings, guard.Finding{Rule: fmt.Sprint("f", r.Intn(4))})
				v.Fallbacks = append(v.Fallbacks, fmt.Sprint("fb", r.Intn(4)))
			}
			commits = append(commits, v)
		}
		want, err := guard.Run(context.Background(), &scripted{commits: commits}, actionEv)
		if err == nil {
			t.Fatal("scripted check must panic")
		}
		var c engine.Committed
		for _, v := range commits {
			c.Add("action", v)
		}
		got := c.With(guard.Verdict{Decision: guard.DecisionPass})
		if got.Decision != want.Decision || !reflect.DeepEqual(got.Findings, want.Findings) ||
			!reflect.DeepEqual(got.Reasons, want.Reasons) || !reflect.DeepEqual(got.Fallbacks, want.Fallbacks) {
			t.Fatalf("commits %+v:\nCommitted %+v\nguard.Run %+v", commits, got, want)
		}
	}
}

// nameOnce 的 Name 第一次调用时 panic；之后正常。
type nameOnce struct {
	*stub
	once sync.Once
}

func (n *nameOnce) Name() string {
	n.once.Do(func() { panic("name") })
	return n.stub.Name()
}

// TestNamePanicIsACheckFailure：Name 自己 panic 按该 Check 故障处理，Check 照常运行，已提交的 deny 照常转告；
// 提交与恢复路径上不再调用 Name（评审 R3-04）。
func TestNamePanicIsACheckFailure(t *testing.T) {
	var seen []guard.Decision
	e := newEngine(t, &nameOnce{stub: &stub{name: "action", commit: verdict(guard.DecisionDeny, i18n.KeyActionBlocked), panics: true}})
	e.OnCommit = func(_ string, v guard.Verdict) { seen = append(seen, v.Decision) }
	res := e.Evaluate(context.Background(), actionEv, allCaps)
	if res.Outcome.Verdict.Decision != guard.DecisionDeny || !slices.Equal(seen, []guard.Decision{guard.DecisionDeny}) {
		t.Errorf("outcome = %s, commits seen = %v", res.Outcome.Verdict.Decision, seen)
	}
	if len(res.Runs) != 1 || !res.Runs[0].Panicked || !slices.Contains(res.Outcome.Verdict.Fallbacks, engine.FallbackInternal) {
		t.Errorf("runs = %+v, fallbacks = %v", res.Runs, res.Outcome.Verdict.Fallbacks)
	}
	// 没有提交时，Name 的 panic 按故障兜底请求确认
	res = newEngine(t, &nameOnce{stub: &stub{name: "action", ret: verdict(guard.DecisionPass)}}).Evaluate(context.Background(), actionEv, allCaps)
	if res.Outcome.Verdict.Decision != guard.DecisionAsk || !res.Runs[0].Panicked {
		t.Errorf("name panic without a commit: %s %+v", res.Outcome.Verdict.Decision, res.Runs)
	}
}

func TestReasonsComeFromTheStrictestChecks(t *testing.T) {
	res := newEngine(t,
		&stub{name: "a", ret: verdict(guard.DecisionWarn, i18n.KeyActionRegexTimeout)},
		&stub{name: "b", ret: verdict(guard.DecisionAsk, i18n.KeyActionProbe)},
	).Evaluate(context.Background(), actionEv, allCaps)
	o := res.Outcome
	if o.Verdict.Decision != guard.DecisionAsk || !strings.Contains(o.Message, "install probe") || strings.Contains(o.Message, "too long") {
		t.Errorf("outcome = %+v", o)
	}
}

func TestAskUnsupportedDegrades(t *testing.T) {
	e := newEngine(t, &stub{name: "action", ret: verdict(guard.DecisionAsk, i18n.KeyActionDangerous, i18n.KeyHintRequest)})
	o := e.Evaluate(context.Background(), actionEv, harness.EventCaps{Block: true, Warn: true}).Outcome
	if o.Verdict.Decision != guard.DecisionDeny || o.Raw != guard.DecisionAsk ||
		!slices.Contains(o.Verdict.Fallbacks, engine.FallbackAskUnsupported) || !strings.Contains(o.Message, "cannot ask") {
		t.Errorf("outcome = %+v", o)
	}
	if !strings.Contains(o.Hint, "next message") {
		t.Errorf("an ask degraded to deny keeps the request hint, got %q", o.Hint)
	}
	e.WhenAskUnsupported = guard.DecisionPass
	if o := e.Evaluate(context.Background(), actionEv, harness.EventCaps{}).Outcome; o.Verdict.Decision != guard.DecisionPass {
		t.Errorf("when_ask_unsupported: pass = %s", o.Verdict.Decision)
	}
}

func TestToolOutputDenyWithoutReplaceBecomesWarn(t *testing.T) {
	ev := guard.Event{Kind: guard.EventToolOutput, Harness: "h"}
	e := newEngine(t, &stub{name: "outbound", ret: verdict(guard.DecisionDeny)})
	o := e.Evaluate(context.Background(), ev, harness.EventCaps{Block: true, Warn: true}).Outcome
	if o.Verdict.Decision != guard.DecisionWarn || !slices.Contains(o.Verdict.Fallbacks, engine.FallbackOutputNotReplaced) {
		t.Errorf("outcome = %+v", o.Verdict)
	}
	o = e.Evaluate(context.Background(), ev, harness.EventCaps{Block: true}).Outcome
	if !slices.Contains(o.Verdict.Fallbacks, engine.FallbackWarnUndelivered) {
		t.Errorf("warn without Warn capability: %+v", o.Verdict)
	}
	if o := e.Evaluate(context.Background(), ev, allCaps).Outcome; o.Verdict.Decision != guard.DecisionDeny {
		t.Errorf("with Replace the deny stays: %s", o.Verdict.Decision)
	}
}

func TestLocalization(t *testing.T) {
	e := newEngine(t, &stub{name: "action", ret: verdict(guard.DecisionAsk, i18n.KeyActionGuardSelf, i18n.KeyHintManual)})
	e.Locale = "zh-CN"
	o := e.Evaluate(context.Background(), actionEv, allCaps).Outcome
	if !strings.Contains(o.Message, "安全护栏") || o.Hint != "请用户自己手动执行。" {
		t.Errorf("zh-CN outcome = %+v", o)
	}
	if o := newEngine(t).Evaluate(context.Background(), actionEv, allCaps).Outcome; o.Message != "" || o.Hint != "" {
		t.Errorf("pass must have no message: %+v", o)
	}
}

func TestFinishPicksAHintFromFallbacks(t *testing.T) {
	e := newEngine(t)
	o := e.Finish(actionEv, allCaps, guard.Verdict{Decision: guard.DecisionAsk,
		Reasons: []guard.Reason{{Code: i18n.KeyErrorInputTooLarge}}, Fallbacks: []string{engine.FallbackInputTooLarge}})
	if !strings.Contains(o.Hint, "Narrow") || strings.Contains(o.Hint, "next message") {
		t.Errorf("hint = %q", o.Hint)
	}
}

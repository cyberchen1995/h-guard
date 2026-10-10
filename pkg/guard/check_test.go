package guard_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

type stubCheck struct{ name string }

func (s stubCheck) Name() string           { return s.name }
func (stubCheck) Applies(guard.Event) bool { return true }
func (stubCheck) Evaluate(context.Context, guard.Event, func(guard.Verdict)) (guard.Verdict, error) {
	return guard.Verdict{Decision: guard.DecisionPass}, nil
}

// uniq 给注册表测试的名字加后缀，避免 -count=2 时重复注册。
func uniq(name string) string {
	return name + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func TestRegisterCheck(t *testing.T) {
	a, b := uniq("test.check-a"), uniq("test.check-b")
	if err := guard.RegisterCheck(stubCheck{b}); err != nil {
		t.Fatalf("register b: %v", err)
	}
	if err := guard.RegisterCheck(stubCheck{a}); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := guard.RegisterCheck(stubCheck{a}); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := guard.RegisterCheck(stubCheck{"Bad Name"}); err == nil {
		t.Error("invalid name accepted")
	}
	if err := guard.RegisterCheck(nil); err == nil {
		t.Error("nil check accepted")
	}
	var names []string
	for _, c := range guard.Checks() {
		names = append(names, c.Name())
	}
	ia, ib := slices.Index(names, a), slices.Index(names, b)
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("Checks() = %v, want both registered and sorted by name", names)
	}
}

func TestValidName(t *testing.T) {
	for _, n := range []string{"claudecode", "pii.email", "pii.phone_cn", "blast_radius", "acme.deploy-check", "jev2"} {
		if !guard.ValidName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range []string{"", "Bad", "has space", ".lead", "-lead", "_lead", "a/b"} {
		if guard.ValidName(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
}

// scriptedCheck 依次提交 commits，然后 panic（panicV 非 nil 时）或返回 ret、err。
type scriptedCheck struct {
	commits []guard.Verdict
	panicV  any
	ret     guard.Verdict
	err     error
}

func (scriptedCheck) Name() string             { return "test.scripted" }
func (scriptedCheck) Applies(guard.Event) bool { return true }
func (s scriptedCheck) Evaluate(_ context.Context, _ guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	for _, v := range s.commits {
		commit(v)
	}
	if s.panicV != nil {
		panic(s.panicV)
	}
	return s.ret, s.err
}

func TestRun(t *testing.T) {
	deny := guard.Verdict{Decision: guard.DecisionDeny, Findings: []guard.Finding{{Rule: "credentials.aws_access_key", Source: guard.FindingLocal}}}
	ask := guard.Verdict{Decision: guard.DecisionAsk}
	passWithFallback := guard.Verdict{Decision: guard.DecisionPass, Fallbacks: []string{"judge_timeout"}}
	boom := errors.New("boom")
	tests := []struct {
		name         string
		check        scriptedCheck
		want         guard.Decision
		wantRule     string // 期望保留的命中；空表示不检查
		wantFallback string // 期望保留的降级原因；空表示不检查
		wantPanic    bool
		wantErr      error
	}{
		{"commit deny then panic", scriptedCheck{commits: []guard.Verdict{deny}, panicV: "SECRET-PANIC"},
			guard.DecisionDeny, "credentials.aws_access_key", "", true, nil},
		{"panic without commit", scriptedCheck{panicV: "x"}, guard.DecisionPass, "", "", true, nil},
		{"returns weaker than committed", scriptedCheck{commits: []guard.Verdict{deny}, ret: passWithFallback},
			guard.DecisionDeny, "credentials.aws_access_key", "judge_timeout", false, nil},
		{"returns stricter than committed", scriptedCheck{commits: []guard.Verdict{ask}, ret: deny},
			guard.DecisionDeny, "credentials.aws_access_key", "", false, nil},
		{"error keeps partial result", scriptedCheck{ret: ask, err: boom}, guard.DecisionAsk, "", "", false, boom},
		{"invalid returned decision fails closed", scriptedCheck{ret: guard.Verdict{}}, guard.DecisionDeny, "", "", false, nil},
		{"panic keeps fallbacks of every commit", scriptedCheck{commits: []guard.Verdict{
			{Decision: guard.DecisionAsk, Fallbacks: []string{"judge_timeout"}},
			{Decision: guard.DecisionDeny, Fallbacks: []string{"regex_timeout"}},
		}, panicV: "x"}, guard.DecisionDeny, "", "judge_timeout", true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := guard.Run(context.Background(), tt.check, guard.Event{Kind: guard.EventPrompt, Harness: "test"})
			if v.Decision != tt.want {
				t.Errorf("Decision = %q, want %q", v.Decision, tt.want)
			}
			if tt.wantRule != "" && (len(v.Findings) == 0 || v.Findings[0].Rule != tt.wantRule) {
				t.Errorf("Findings = %+v, want rule %q kept", v.Findings, tt.wantRule)
			}
			if tt.wantFallback != "" && !slices.Contains(v.Fallbacks, tt.wantFallback) {
				t.Errorf("Fallbacks = %v, want %q kept", v.Fallbacks, tt.wantFallback)
			}
			var pe *guard.PanicError
			if got := errors.As(err, &pe); got != tt.wantPanic {
				t.Fatalf("PanicError = %v, want %v (err = %v)", got, tt.wantPanic, err)
			}
			if tt.wantPanic && strings.Contains(err.Error(), "SECRET-PANIC") {
				t.Errorf("PanicError message must not include the panic value: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

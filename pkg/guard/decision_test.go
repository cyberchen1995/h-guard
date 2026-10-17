package guard_test

import (
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func TestStricter(t *testing.T) {
	tests := []struct {
		a, b, want guard.Decision
	}{
		{guard.DecisionPass, guard.DecisionPass, guard.DecisionPass},
		{guard.DecisionPass, guard.DecisionWarn, guard.DecisionWarn},
		{guard.DecisionAsk, guard.DecisionWarn, guard.DecisionAsk},
		{guard.DecisionDeny, guard.DecisionAsk, guard.DecisionDeny},
		{guard.DecisionPass, guard.DecisionDeny, guard.DecisionDeny},
		// 未知结论按 deny：空值、h-guard 从不使用的 allow、大小写不同的写法
		{"", guard.DecisionPass, guard.DecisionDeny},
		{guard.DecisionPass, "allow", guard.DecisionDeny},
		{"PASS", guard.DecisionPass, guard.DecisionDeny},
	}
	for _, tt := range tests {
		if got := guard.Stricter(tt.a, tt.b); got != tt.want {
			t.Errorf("Stricter(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDecisionValid(t *testing.T) {
	for _, d := range []guard.Decision{guard.DecisionPass, guard.DecisionWarn, guard.DecisionAsk, guard.DecisionDeny} {
		if !d.Valid() {
			t.Errorf("%q should be valid", d)
		}
	}
	for _, d := range []guard.Decision{"", "allow", "PASS"} {
		if d.Valid() {
			t.Errorf("%q should be invalid", d)
		}
	}
}

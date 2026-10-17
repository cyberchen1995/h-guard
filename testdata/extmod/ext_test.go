package hguardext

import (
	"encoding/json"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/guard/guardtest"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

func TestRegister(t *testing.T) {
	if err := Register(); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok := harness.Lookup("echo"); !ok {
		t.Error("adapter echo not registered")
	}
	found := false
	for _, c := range guard.Checks() {
		found = found || c.Name() == "ext.keyword"
	}
	if !found {
		t.Error("check ext.keyword not registered")
	}
	f, ok := judge.LookupType("const")
	if !ok {
		t.Fatal("backend type const not registered")
	}
	b, err := f("mine", func(v any) error { return json.Unmarshal([]byte(`{"p":0.3}`), v) })
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if got := b.(ConstBackend).P; got != 0.3 {
		t.Errorf("decoded P = %v, want 0.3", got)
	}
}

func TestAdapterContract(t *testing.T) {
	harnesstest.Run(t, EchoAdapter{}, []harnesstest.Case{
		{Name: "exec", Input: []byte(`{"command":"ls"}`), WantKind: guard.EventAction},
	})
}

func TestCheckContract(t *testing.T) {
	guardtest.RunCheck(t, KeywordCheck{Keyword: "rm -rf /"}, []guard.Event{
		{Kind: guard.EventAction, Harness: "echo", Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf /", Shell: guard.ShellPOSIX}},
		}},
	})
}

func TestBackendContract(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return ConstBackend{P: 0.1} }, []judge.Question{
		{ID: "q1", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
	})
}

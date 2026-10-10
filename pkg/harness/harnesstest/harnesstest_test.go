package harnesstest_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
)

// jsonAdapter 是测试用的最小 adapter：输入 {"cmd": "..."} 或 {"prompt": "..."}。
type jsonAdapter struct{}

func (jsonAdapter) Name() string { return "test-json" }

func (jsonAdapter) Capabilities() harness.Caps {
	return harness.Caps{MinVersion: "0.0.1", Events: map[guard.EventKind]harness.EventCaps{
		guard.EventAction: {Block: true, Ask: true},
		guard.EventPrompt: {Block: true},
	}}
}

func (jsonAdapter) Parse(raw []byte) (guard.Event, error) {
	var in struct {
		Cmd    *string `json:"cmd"`
		Prompt *string `json:"prompt"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return guard.Event{}, err
	}
	switch {
	case in.Cmd != nil:
		return guard.Event{Kind: guard.EventAction, Harness: "test-json", Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: *in.Cmd, Shell: guard.ShellPOSIX}},
		}}, nil
	case in.Prompt != nil:
		return guard.Event{Kind: guard.EventPrompt, Harness: "test-json", Text: *in.Prompt}, nil
	}
	return guard.Event{}, errors.New("unknown input")
}

func (a jsonAdapter) CapsFor(ev guard.Event) harness.EventCaps {
	return a.Capabilities().Events[ev.Kind]
}

func (jsonAdapter) Render(_ guard.Event, out guard.Outcome) ([]byte, int) {
	if out.Verdict.Decision == guard.DecisionPass {
		return nil, 0
	}
	b, _ := json.Marshal(map[string]string{"decision": string(out.Verdict.Decision), "reason": out.Message})
	return b, 0
}

// checkDecision 是 jsonAdapter 的协议检查：pass 无输出，其余输出对应的 decision。
func checkDecision(t *testing.T, d guard.Decision, stdout []byte, exitCode int) {
	t.Helper()
	if exitCode != 0 {
		t.Errorf("exit code = %d, want 0", exitCode)
	}
	if d == guard.DecisionPass {
		if len(stdout) != 0 {
			t.Errorf("pass rendered %s, want no output", stdout)
		}
		return
	}
	var out struct{ Decision string }
	if err := json.Unmarshal(stdout, &out); err != nil || out.Decision != string(d) {
		t.Errorf("Render(%s) = %s", d, stdout)
	}
}

func TestRun(t *testing.T) {
	harnesstest.Run(t, jsonAdapter{}, []harnesstest.Case{
		{Name: "exec", Input: []byte(`{"cmd":"ls -la"}`), WantKind: guard.EventAction, Check: checkDecision},
		{Name: "prompt", Input: []byte(`{"prompt":"hi"}`), WantKind: guard.EventPrompt, Check: checkDecision},
	})
}

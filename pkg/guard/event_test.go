package guard_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func execAction(cmd string) guard.Action {
	return guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: cmd, Shell: guard.ShellPOSIX}}
}

func fileAction(kind guard.ActionKind, path, to string) guard.Action {
	return guard.Action{Kind: kind, File: &guard.FileAction{Path: path, To: to}}
}

func TestEventValidate(t *testing.T) {
	tests := []struct {
		name    string
		ev      guard.Event
		wantErr bool
	}{
		{"exec ok", guard.Event{Kind: guard.EventAction, Harness: "claudecode", Actions: []guard.Action{execAction("ls")}}, false},
		{"multi file ok", guard.Event{Kind: guard.EventAction, Harness: "codex", Actions: []guard.Action{
			fileAction(guard.ActionFileWrite, "a.txt", ""),
			fileAction(guard.ActionFileRename, "a.txt", "b.txt"),
			fileAction(guard.ActionFileDelete, "b.txt", ""),
		}}, false},
		{"prompt ok", guard.Event{Kind: guard.EventPrompt, Harness: "codex", Text: "hi",
			Requests: []guard.Request{{Text: "hi", Source: guard.SourceUser}}}, false},
		{"tool output ok", guard.Event{Kind: guard.EventToolOutput, Harness: "claudecode", Tool: "Read", Text: "x"}, false},
		{"unknown kind", guard.Event{Kind: "other", Harness: "x"}, true},
		{"no harness", guard.Event{Kind: guard.EventPrompt}, true},
		{"action without actions", guard.Event{Kind: guard.EventAction, Harness: "x"}, true},
		{"prompt with actions", guard.Event{Kind: guard.EventPrompt, Harness: "x", Actions: []guard.Action{execAction("ls")}}, true},
		{"exec without command", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{execAction("")}}, true},
		{"exec unknown shell", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "dir", Shell: "cmd"}},
		}}, true},
		{"exec with file payload", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "ls", Shell: guard.ShellPOSIX}, File: &guard.FileAction{Path: "a"}},
		}}, true},
		{"rename without target", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			fileAction(guard.ActionFileRename, "a", ""),
		}}, true},
		{"write with target", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			fileAction(guard.ActionFileWrite, "a", "b"),
		}}, true},
		{"file without path", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			fileAction(guard.ActionFileRead, "", ""),
		}}, true},
		{"tool call with exec payload", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{
			{Kind: guard.ActionToolCall, Exec: &guard.ExecAction{Command: "ls", Shell: guard.ShellPOSIX}},
		}}, true},
		{"unknown action kind", guard.Event{Kind: guard.EventAction, Harness: "x", Actions: []guard.Action{{Kind: "spawn"}}}, true},
		{"unknown request source", guard.Event{Kind: guard.EventPrompt, Harness: "x", Requests: []guard.Request{{Text: "hi"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ev.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerdictJSONRoundTrip(t *testing.T) {
	p := 0.25
	v := guard.Verdict{
		Decision: guard.DecisionAsk,
		Findings: []guard.Finding{{
			Rule: "publish", Source: guard.FindingBoth, Probability: &p,
			Locations: []guard.Location{{Line: 1, Start: 0, End: 8}},
		}},
		Reasons:   []guard.Reason{{Code: "rule.publish", Params: map[string]string{"count": "1"}}},
		Fallbacks: []string{"judge_timeout", "regex_timeout"},
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var got guard.Verdict
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(v, got) {
		t.Fatalf("round trip mismatch:\n got  %+v\n want %+v", got, v)
	}
}

func TestLocalFindingHasNoProbability(t *testing.T) {
	b, err := json.Marshal(guard.Finding{Rule: "pii.email", Category: "pii", Source: guard.FindingLocal})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "probability") {
		t.Errorf("local-only finding should omit probability: %s", b)
	}
}

func TestEventNativeNotSerialized(t *testing.T) {
	ev := guard.Event{Kind: guard.EventToolOutput, Harness: "x", Text: "t", Native: json.RawMessage(`{"secret":"NATIVE-ONLY"}`)}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "NATIVE-ONLY") {
		t.Errorf("Native must not be serialized: %s", b)
	}
}

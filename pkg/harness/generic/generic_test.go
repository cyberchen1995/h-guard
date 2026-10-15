package generic_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/generic"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
)

var a = generic.Adapter{}

func input(m map[string]any) []byte {
	base := map[string]any{"version": 1, "session_id": "s1", "call_id": "c1", "cwd": "/w", "tool": "shell"}
	for k, v := range m {
		base[k] = v
	}
	b, _ := json.Marshal(base)
	return b
}

type output struct {
	Version     int             `json:"version"`
	Decision    string          `json:"decision"`
	RawDecision string          `json:"raw_decision"`
	Reason      string          `json:"reason"`
	Hint        string          `json:"hint"`
	Reasons     []guard.Reason  `json:"reasons"`
	Findings    []guard.Finding `json:"findings"`
	Signals     map[string]any  `json:"signals"`
	Fallbacks   []string        `json:"fallbacks"`
	Error       string          `json:"error"`
}

func parseOutput(t *testing.T, b []byte) output {
	t.Helper()
	var o output
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatalf("stdout %q: %v", b, err)
	}
	return o
}

// TestConformance：公共一致性套件；generic 的输出始终是 JSON，pass 也输出，decision 与结论一致（spec §7.4）。
func TestConformance(t *testing.T) {
	check := func(t *testing.T, d guard.Decision, out []byte, code int) {
		if o := parseOutput(t, out); code != 0 || o.Version != 1 || o.Decision != string(d) {
			t.Errorf("%s: %s, exit %d", d, out, code)
		}
	}
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "action", Input: input(map[string]any{"kind": "action", "actions": []map[string]any{{"kind": "exec", "command": "ls", "shell": "posix"}}}),
			WantKind: guard.EventAction, Check: check},
		{Name: "prompt", Input: input(map[string]any{"kind": "prompt", "text": "hi"}), WantKind: guard.EventPrompt, Check: check},
		{Name: "tool_output", Input: input(map[string]any{"kind": "tool_output", "text": "out"}), WantKind: guard.EventToolOutput, Check: check},
	})
}

// TestCapabilities：调用方按 decision 自行处理，所以三类事件都能阻止、确认与提示，工具输出能替换
// （decision 为 deny 时由调用方用 reason 代替原输出）。
func TestCapabilities(t *testing.T) {
	all := harness.EventCaps{Block: true, Ask: true, Warn: true}
	want := map[guard.EventKind]harness.EventCaps{guard.EventAction: all, guard.EventPrompt: all,
		guard.EventToolOutput: {Block: true, Ask: true, Warn: true, Replace: true}}
	if got := a.Capabilities(); got.MinVersion != "1" || !reflect.DeepEqual(got.Events, want) {
		t.Errorf("capabilities = %+v", got)
	}
}

func TestParse(t *testing.T) {
	ev, err := a.Parse(input(map[string]any{"kind": "action", "actions": []map[string]any{
		{"kind": "exec", "command": "Remove-Item x", "shell": "powershell"},
		{"kind": "exec", "command": "ls"},
		{"kind": "file_rename", "path": "a", "to": "b"},
		{"kind": "file_read", "path": ".env"},
	}, "requests": []map[string]any{{"text": "clean up"}, {"text": "<x>", "source": "automated"}}}))
	want := guard.Event{Kind: guard.EventAction, Harness: "generic", SessionID: "s1", CallID: "c1", Cwd: "/w", Tool: "shell",
		Actions: []guard.Action{
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "Remove-Item x", Shell: guard.ShellPowerShell}},
			{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "ls", Shell: guard.ShellPOSIX}},
			{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a", To: "b"}},
			{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: ".env"}},
		},
		Requests: []guard.Request{{Text: "clean up", Source: guard.SourceUser}, {Text: "<x>", Source: guard.SourceAutomated}}}
	if err != nil || !reflect.DeepEqual(ev, want) {
		t.Errorf("action:\n got %+v, %v\nwant %+v", ev, err, want)
	}
	// 提示词没有给 requests 时，提示词本身是一条用户指令；给了就以 requests 为准（调用方知道来源）
	ev, err = a.Parse(input(map[string]any{"kind": "prompt", "text": "push it"}))
	if err != nil || ev.Text != "push it" || !reflect.DeepEqual(ev.Requests, []guard.Request{{Text: "push it", Source: guard.SourceUser}}) {
		t.Errorf("prompt: %+v, %v", ev, err)
	}
	ev, err = a.Parse(input(map[string]any{"kind": "prompt", "text": "<cron>", "requests": []map[string]any{{"text": "<cron>", "source": "automated"}}}))
	if err != nil || ev.Requests[0].Source != guard.SourceAutomated {
		t.Errorf("automated prompt: %+v, %v", ev, err)
	}
	// 没有 cwd 时绝对路径照常
	if _, err := a.Parse(input(map[string]any{"kind": "action", "cwd": "", "actions": []map[string]any{{"kind": "file_read", "path": "/w/.env"}}})); err != nil {
		t.Errorf("absolute path without cwd: %v", err)
	}
	// 新增的可选字段不升版本：不认识的字段忽略
	if _, err := a.Parse(input(map[string]any{"kind": "tool_output", "text": "x", "extra": 1})); err != nil {
		t.Errorf("unknown field: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	exec := []map[string]any{{"kind": "exec", "command": "ls"}}
	for name, m := range map[string]map[string]any{
		"version 2":                 {"version": 2, "kind": "action", "actions": exec},
		"no version":                {"version": nil, "kind": "action", "actions": exec},
		"unknown kind":              {"kind": "stop"},
		"action without any":        {"kind": "action"},
		"unknown action":            {"kind": "action", "actions": []map[string]any{{"kind": "tool_call"}}},
		"bad shell":                 {"kind": "action", "actions": []map[string]any{{"kind": "exec", "command": "dir", "shell": "cmd"}}},
		"empty command":             {"kind": "action", "actions": []map[string]any{{"kind": "exec", "command": ""}}},
		"file without path":         {"kind": "action", "actions": []map[string]any{{"kind": "file_write"}}},
		"prompt with action":        {"kind": "prompt", "text": "x", "actions": exec},
		"bad source":                {"kind": "prompt", "text": "x", "requests": []map[string]any{{"text": "x", "source": "bot"}}},
		"relative path without cwd": {"kind": "action", "cwd": "", "actions": []map[string]any{{"kind": "file_write", "path": "rel/x"}}},
	} {
		if _, err := a.Parse(input(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestRender：输出带全部结构化字段；pass 也输出（spec §7.4）。
func TestRender(t *testing.T) {
	p := 0.9
	out := guard.Outcome{
		Verdict: guard.Verdict{Decision: guard.DecisionDeny, Reasons: []guard.Reason{{Code: "action.dangerous", Params: map[string]string{"rules": "publish"}}},
			Findings: []guard.Finding{{Rule: "publish", Source: guard.FindingJudge, Probability: &p}}, Signals: map[string]any{"judge": "answered"},
			Fallbacks: []string{"ask_unsupported"}},
		Raw: guard.DecisionAsk, Message: "Publishes without being asked", Hint: "Ask the user.",
	}
	b, code := a.Render(guard.Event{Kind: guard.EventAction}, out)
	o := parseOutput(t, b)
	if code != 0 || o.Decision != "deny" || o.RawDecision != "ask" || o.Reason != out.Message || o.Hint != out.Hint ||
		!reflect.DeepEqual(o.Reasons, out.Verdict.Reasons) || len(o.Findings) != 1 || o.Signals["judge"] != "answered" ||
		!reflect.DeepEqual(o.Fallbacks, []string{"ask_unsupported"}) {
		t.Errorf("render = %s", b)
	}
	b, _ = a.Render(guard.Event{Kind: guard.EventPrompt}, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionPass}, Raw: guard.DecisionPass})
	if o := parseOutput(t, b); o.Decision != "pass" || o.RawDecision != "pass" || o.Version != 1 {
		t.Errorf("pass = %s", b)
	}
}

// TestParseFailure：generic 的输出始终是 JSON；读不懂的输入输出 error 与非零退出码，调用方据此知道 h-guard
// 自身失败（spec §7.4）。错误说明是固定文本，不含输入内容。
func TestParseFailure(t *testing.T) {
	var r harness.ParseFailureRenderer = a
	b, code := r.RenderParseFailure()
	if o := parseOutput(t, b); code == 0 || o.Version != 1 || o.Error != "input not understood" || o.Decision != "" {
		t.Errorf("parse failure = %s, exit %d", b, code)
	}
}

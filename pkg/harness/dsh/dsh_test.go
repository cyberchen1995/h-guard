package dsh_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/dsh"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
)

func req(hook string, data, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": "dsh", "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	b, _ := json.Marshal(r)
	return b
}

func pre(tool string, args any) []byte {
	return req("tools/pre-execute", map[string]any{"name": tool, "callId": "c1", "arguments": args, "nested": false}, nil)
}

func post(tool string, args any, text string) []byte {
	return req("tools/post-execute", map[string]any{"name": tool, "callId": "c1", "arguments": args},
		map[string]any{"isError": false, "content": []map[string]string{{"type": "text", "text": text}}})
}

type msg struct {
	kind, text string
}

func step(origin string, depth int, msgs ...msg) []byte {
	var ms []any
	for _, m := range msgs {
		ms = append(ms, map[string]any{"source": map[string]string{"kind": m.kind}, "content": []map[string]string{{"type": "text", "text": m.text}}})
	}
	return req("agent/pre-step", map[string]any{"messages": ms, "session": map[string]any{"origin": origin, "delegationDepth": depth}}, nil)
}

var a = dsh.Adapter{}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestConformance(t *testing.T) {
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "bash", Input: pre("bash", map[string]string{"command": "git push"}), WantKind: guard.EventAction, Check: checkReply},
		{Name: "result", Input: post("read", map[string]string{"file_path": "a"}, "x"), WantKind: guard.EventToolOutput, Check: checkReply},
		{Name: "step", Input: step("", 0, msg{"user", "hi"}), WantKind: guard.EventPrompt, Check: checkReply},
	})
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestActions(t *testing.T) {
	tests := []struct {
		tool string
		args any
		want []guard.Action
		cwd  string
	}{
		{"bash", map[string]any{"command": "rm -rf dist", "workdir": "/tmp/x", "timeoutMs": 1000}, []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf dist", Shell: guard.ShellPOSIX}}}, "/tmp/x"},
		{"pwsh", map[string]any{"command": "Remove-Item -Recurse x", "workdir": "sub"}, []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "Remove-Item -Recurse x", Shell: guard.ShellPowerShell}}}, "/w/sub"},
		{"read", map[string]any{"file_path": "/w/.env"}, []guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/w/.env"}}}, "/w"},
		{"grep", map[string]any{"pattern": "k", "path": "/w/secrets"}, []guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/w/secrets"}}}, "/w"},
		{"write", map[string]any{"file_path": "a", "content": "x"}, []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "a"}}}, "/w"},
		{"edit", map[string]any{"file_path": "b", "old_string": "x", "new_string": "y"}, []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "b"}}}, "/w"},
		{"str_replace_editor", map[string]any{"command": "view", "path": "/w/.env"}, []guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/w/.env"}}}, "/w"},
		{"str_replace_editor", map[string]any{"command": "create", "path": "/w/n", "file_text": "x"}, []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "/w/n"}}}, "/w"},
	}
	for _, tt := range tests {
		ev, err := a.Parse(pre(tt.tool, tt.args))
		if err != nil {
			t.Errorf("%s: %v", tt.tool, err)
			continue
		}
		if asJSON(ev.Actions) != asJSON(tt.want) || ev.Cwd != tt.cwd {
			t.Errorf("%s: %s cwd %q, want %s cwd %q", tt.tool, asJSON(ev.Actions), ev.Cwd, asJSON(tt.want), tt.cwd)
		}
	}
	for _, tool := range []string{"glob", "web_fetch", "run_code", "subagent", "mcp__srv__q"} {
		if _, err := a.Parse(pre(tool, map[string]any{"path": "x"})); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", tool, err)
		}
	}
	var tu *harness.TargetUnparsedError
	for name, in := range map[string][]byte{
		"editor without a known command": pre("str_replace_editor", map[string]any{"command": "frob", "path": "x"}),
		"bash with a wrong type":         pre("bash", map[string]any{"command": []int{1}}),
	} {
		if _, err := a.Parse(in); !errors.As(err, &tu) {
			t.Errorf("%s: %v, want TargetUnparsedError", name, err)
		}
	}
}

// TestStep：新消息的文本都扫描；source.kind 为 user 的是用户指令，其余是自动消息；子 agent 会话里都是自动消息。
func TestStep(t *testing.T) {
	ev, err := a.Parse(step("", 0, msg{"user", "deploy"}, msg{"schedule", "nightly run"}))
	if err != nil || ev.Text != "deploy\nnightly run" || len(ev.Requests) != 2 ||
		ev.Requests[0].Source != guard.SourceUser || ev.Requests[1].Source != guard.SourceAutomated {
		t.Fatalf("%+v %v", ev, err)
	}
	for _, in := range [][]byte{step("subagent", 1, msg{"user", "push it"}), step("", 2, msg{"user", "push it"})} {
		ev, err := a.Parse(in)
		if err != nil || ev.Requests[0].Source != guard.SourceAutomated {
			t.Errorf("subagent: %+v %v", ev, err)
		}
	}
}

func TestToolOutput(t *testing.T) {
	ev, err := a.Parse(post("str_replace_editor", map[string]any{"command": "view", "path": "a"}, "K=V"))
	if err != nil || ev.Text != "K=V" || !ev.FileContent {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = a.Parse(post("web_fetch", map[string]any{"url": "https://example.com"}, "page"))
	if err != nil || ev.FileContent || ev.Text != "page" {
		t.Fatalf("%+v %v", ev, err)
	}
}

// TestTerminalSend：写进持久终端的内容按 POSIX 命令检查，另外请求确认（看不出终端是哪种 shell）。
func TestTerminalSend(t *testing.T) {
	var tu *harness.TargetUnparsedError
	_, err := a.Parse(pre("terminal_send", map[string]any{"session_id": "t1", "text": "rm ~/.dsh/cordis.patch.yml"}))
	if !errors.As(err, &tu) || len(tu.Event.Actions) != 1 || tu.Event.Actions[0].Exec.Command != "rm ~/.dsh/cordis.patch.yml" {
		t.Fatalf("%v %+v", err, tu)
	}
	if _, err := a.Parse(pre("terminal_send", map[string]any{"session_id": "t1", "text": ""})); !errors.Is(err, harness.ErrNoAction) {
		t.Errorf("empty text: %v", err)
	}
	ev, err := a.Parse(post("terminal_send", map[string]any{"session_id": "t1", "text": "cat ~/.ssh/id_rsa\n"}, "KEY"))
	if err != nil || !ev.FileContent {
		t.Errorf("terminal_send output: %+v %v", ev, err)
	}
	for _, tool := range []string{"terminal_read", "job_output", "run_code", "skill", "session_event_read", "session_event_search", "session_search"} {
		if ev, err := a.Parse(post(tool, map[string]any{"session_id": "t1"}, "KEY")); err != nil || !ev.FileContent {
			t.Errorf("%s output: %+v %v", tool, ev, err)
		}
	}
}

// TestDriveRootedWorkdir：Windows 上 \repo 从当前盘的根开始，不拼到会话目录后面。
func TestDriveRootedWorkdir(t *testing.T) {
	ev, err := a.Parse(req("tools/pre-execute", map[string]any{"name": "pwsh", "callId": "c", "arguments": map[string]string{"command": "dir", "workdir": `\repo`}}, nil))
	if err != nil || ev.Cwd != `\repo` {
		t.Fatalf("%q %v", ev.Cwd, err)
	}
}

// TestToolLists：dsh 自带的只读工具与 MCP 工具不产生动作；其余 h-guard 不认识的工具返回 UnknownToolError。
func TestToolLists(t *testing.T) {
	for _, tool := range []string{"todo_write", "terminal_read", "schedule_list", "mcp__srv__q"} {
		if _, err := a.Parse(pre(tool, map[string]any{})); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", tool, err)
		}
	}
	if _, err := a.Parse(pre("stagehand_tabs", map[string]any{"action": "list"})); !errors.Is(err, harness.ErrNoAction) {
		t.Errorf("stagehand_tabs list: %v, want ErrNoAction", err)
	}
	var ut *harness.UnknownToolError
	if _, err := a.Parse(pre("stagehand_tabs", map[string]any{"action": "close", "tabId": "t1"})); !errors.As(err, &ut) {
		t.Errorf("stagehand_tabs close: %v, want UnknownToolError", err)
	}
	for _, tool := range []string{"plugin_manager", "schedule_create", "create_worktree", "lsp", "terminal_open", "terminal_signal", "terminal_close", "job_kill", "some_plugin_tool"} {
		if _, err := a.Parse(pre(tool, map[string]any{"x": 1})); !errors.As(err, &ut) || ut.Event.Tool != tool {
			t.Errorf("%s: %v, want UnknownToolError", tool, err)
		}
	}
}

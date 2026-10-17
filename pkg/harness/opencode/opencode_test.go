package opencode_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
	"github.com/cyberchen1995/h-guard/pkg/harness/opencode"
)

func req(hook string, data, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": "opencode", "hook": hook,
		"session": map[string]string{"id": "ses_1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	b, _ := json.Marshal(r)
	return b
}

func before(tool string, args any) []byte {
	return req("tool.execute.before", map[string]any{"tool": tool, "sessionID": "ses_1", "callID": "call_1", "args": args}, nil)
}

func after(tool string, args, result any) []byte {
	return req("tool.execute.after", map[string]any{"tool": tool, "sessionID": "ses_1", "callID": "call_1", "args": args}, result)
}

func prompt(parentID string, parts ...map[string]any) []byte {
	return req("chat.message", map[string]any{"sessionID": "ses_1", "agent": "build", "parts": parts, "parentID": parentID}, nil)
}

var a = opencode.Adapter{}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestConformance(t *testing.T) {
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "bash", Input: before("bash", map[string]string{"command": "git push"}), WantKind: guard.EventAction, Check: checkReply},
		{Name: "result", Input: after("bash", map[string]string{"command": "ls"}, map[string]any{"output": "a\nb"}), WantKind: guard.EventToolOutput, Check: checkReply},
		{Name: "prompt", Input: prompt("", map[string]any{"type": "text", "text": "hi"}), WantKind: guard.EventPrompt, Check: checkReply},
	})
}

// TestActions：内置工具映射为动作；bash 的 workdir 是命令的工作目录（相对的按会话目录解析）。
func TestActions(t *testing.T) {
	tests := []struct {
		name, tool string
		args       any
		want       []guard.Action
		cwd        string
	}{
		{"bash", "bash", map[string]string{"command": "rm -rf build", "workdir": "sub"},
			[]guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf build", Shell: guard.ShellPOSIX}}}, "/w/sub"},
		{"read", "read", map[string]string{"filePath": "/w/.env"},
			[]guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/w/.env"}}}, "/w"},
		{"grep", "grep", map[string]string{"pattern": "x", "path": "/etc"},
			[]guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/etc"}}}, "/w"},
		{"write", "write", map[string]string{"filePath": "a.txt", "content": "x"},
			[]guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "a.txt"}}}, "/w"},
		{"edit", "edit", map[string]string{"filePath": "/w/b.go", "oldString": "a", "newString": "b"},
			[]guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "/w/b.go"}}}, "/w"},
		{"apply_patch", "apply_patch", map[string]string{"patchText": "*** Begin Patch\n*** Delete File: old.txt\n*** Update File: a.go\n*** Move to: b.go\n@@\n-x\n+y\n*** End Patch"},
			[]guard.Action{{Kind: guard.ActionFileDelete, File: &guard.FileAction{Path: "old.txt"}}, {Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a.go", To: "b.go"}}}, "/w"},
	}
	for _, tt := range tests {
		ev, err := a.Parse(before(tt.tool, tt.args))
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		got, _ := json.Marshal(ev.Actions)
		want, _ := json.Marshal(tt.want)
		if string(got) != string(want) || ev.Cwd != tt.cwd || ev.Tool != tt.tool || ev.CallID != "call_1" || ev.SessionID != "ses_1" {
			t.Errorf("%s: actions %s cwd %q, want %s cwd %q", tt.name, got, ev.Cwd, want, tt.cwd)
		}
	}
}

// TestShell：bash 的命令按 harnesses.opencode.shell 给出的 shell 检查（Windows 上多半是 PowerShell）。
func TestShell(t *testing.T) {
	ad := a.WithShell(guard.ShellPowerShell)
	ev, err := ad.Parse(before("bash", map[string]string{"command": "Remove-Item -Recurse x"}))
	if err != nil || ev.Actions[0].Exec.Shell != guard.ShellPowerShell {
		t.Fatalf("%+v %v", ev.Actions, err)
	}
}

// TestNoAction：不产生动作的工具返回 harness.ErrNoAction，且有放行回复（扩展协议要求每个请求都有回复）。
func TestNoAction(t *testing.T) {
	for _, in := range [][]byte{
		before("glob", map[string]string{"pattern": "**/*.go"}),
		before("webfetch", map[string]string{"url": "https://example.com"}),
		before("github_create_issue", map[string]string{"title": "x"}),
		before("bash", map[string]string{"command": "  "}),
	} {
		if _, err := a.Parse(in); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", in, err)
		}
	}
	out, code := a.RenderNoAction()
	if r, err := extproto.ParseReply(out); err != nil || r.Action != extproto.ActionPass || code != 0 {
		t.Errorf("RenderNoAction = %s %d", out, code)
	}
}

// TestUnparsedPatch：读不懂的补丁不能当作没有动作，返回 TargetUnparsedError（调用方请求确认，opencode 上阻止）。
func TestUnparsedPatch(t *testing.T) {
	_, err := a.Parse(before("apply_patch", map[string]string{"patchText": "*** Begin Patch\n*** Frobnicate: x\n*** End Patch"}))
	var tu *harness.TargetUnparsedError
	if !errors.As(err, &tu) || tu.Event.Tool != "apply_patch" || tu.Event.SessionID != "ses_1" {
		t.Fatalf("%v", err)
	}
}

// TestToolOutput：内置工具取 output，MCP 工具取 content 里的文本；读文件的工具与命令是文件内容。
func TestToolOutput(t *testing.T) {
	ev, err := a.Parse(after("read", map[string]string{"filePath": "/w/a"}, map[string]any{"output": "SECRET"}))
	if err != nil || ev.Text != "SECRET" || !ev.FileContent || ev.Kind != guard.EventToolOutput {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = a.Parse(after("srv_query", map[string]string{}, map[string]any{"content": []map[string]string{{"type": "text", "text": "row1"}, {"type": "text", "text": "row2"}}}))
	if err != nil || ev.Text != "row1\nrow2" || ev.FileContent {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = a.Parse(after("bash", map[string]string{"command": "cat id_rsa"}, map[string]any{"output": "k"}))
	if err != nil || !ev.FileContent {
		t.Fatalf("%+v %v", ev, err)
	}
}

// TestPrompt：消息的全部文本都扫描；用户指令只取用户写的部分；子 agent 会话（parentID 不为空）的消息是自动消息。
func TestPrompt(t *testing.T) {
	ev, err := a.Parse(prompt("",
		map[string]any{"type": "text", "text": "deploy it"},
		map[string]any{"type": "text", "text": "<file contents>", "synthetic": true},
		map[string]any{"type": "file", "mime": "image/png"}))
	if err != nil || ev.Text != "deploy it\n<file contents>" || len(ev.Requests) != 1 ||
		ev.Requests[0] != (guard.Request{Text: "deploy it", Source: guard.SourceUser}) {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = a.Parse(prompt("ses_parent", map[string]any{"type": "text", "text": "push the branch"}))
	if err != nil || ev.Requests[0].Source != guard.SourceAutomated {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = a.Parse(prompt("?", map[string]any{"type": "text", "text": "push the branch"})) // 插件查不到父会话
	if err != nil || ev.Requests[0].Source != guard.SourceAutomated {
		t.Fatalf("unknown parent: %+v %v", ev, err)
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"other harness": []byte(`{"protocol":"h-guard.ext/v1","harness":"pi","hook":"tool.execute.before","session":{"id":"s"},"data":{}}`),
		"unknown hook":  req("event", map[string]any{"x": 1}, nil),
		"bad args":      before("bash", []string{"x"}),
	} {
		if _, err := a.Parse(in); err == nil || errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

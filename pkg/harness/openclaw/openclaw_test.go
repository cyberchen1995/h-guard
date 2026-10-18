package openclaw_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
	"github.com/cyberchen1995/h-guard/pkg/harness/openclaw"
)

func req(hook string, data, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": "openclaw", "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	b, _ := json.Marshal(r)
	return b
}

func call(tool string, params any) []byte { return callOn("linux", tool, params) }

func callOn(platform, tool string, params any) []byte {
	return req("before_tool_call", map[string]any{"toolName": tool, "toolCallId": "c1", "params": params, "platform": platform}, nil)
}

func result(tool string, args any, text string) []byte {
	return req("tool_result", map[string]any{"toolName": tool, "toolCallId": "c1", "args": args, "isError": false, "platform": "linux"},
		map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
}

func run(prompt, trigger, provenance, sessionKey string) []byte {
	return req("before_agent_run", map[string]any{"prompt": prompt, "trigger": trigger, "provenance": provenance, "sessionKey": sessionKey}, nil)
}

var a = openclaw.Adapter{}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestConformance(t *testing.T) {
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "exec", Input: call("exec", map[string]string{"command": "git push"}), WantKind: guard.EventAction, Check: checkReply},
		{Name: "result", Input: result("read", map[string]string{"path": "a"}, "x"), WantKind: guard.EventToolOutput, Check: checkReply},
		{Name: "run", Input: run("hi", "user", "external_user", "agent:main:main"), WantKind: guard.EventPrompt, Check: checkReply},
	})
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func exec(cmd string, sh guard.Shell) guard.Action {
	return guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: cmd, Shell: sh}}
}

func file(kind guard.ActionKind, p string) guard.Action {
	return guard.Action{Kind: kind, File: &guard.FileAction{Path: p}}
}

func TestActions(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: n.txt\n+x\n*** Update File: a.go\n*** Move to: b.go\n@@\n-x\n+y\n*** Delete File: old\n*** End Patch"
	tests := []struct {
		name, platform, tool string
		params               any
		want                 []guard.Action
		cwd                  string
	}{
		{"exec", "linux", "exec", map[string]any{"command": "rm -rf dist", "workdir": "/tmp/x", "env": map[string]string{"A": "b"}}, []guard.Action{exec("rm -rf dist", guard.ShellPOSIX)}, "/tmp/x"},
		{"exec relative workdir", "darwin", "exec", map[string]any{"command": "ls", "workdir": "sub"}, []guard.Action{exec("ls", guard.ShellPOSIX)}, "/w/sub"},
		{"exec on Windows", "win32", "exec", map[string]any{"command": "Remove-Item -Recurse x"}, []guard.Action{exec("Remove-Item -Recurse x", guard.ShellPowerShell)}, "/w"},
		{"exec in the sandbox on Windows", "win32", "exec", map[string]any{"command": "rm x", "host": "sandbox"}, []guard.Action{exec("rm x", guard.ShellPOSIX)}, "/w"},
		{"read", "linux", "read", map[string]any{"path": "/w/.env", "offset": 1}, []guard.Action{file(guard.ActionFileRead, "/w/.env")}, "/w"},
		{"read with file_path", "linux", "read", map[string]any{"file_path": ".env"}, []guard.Action{file(guard.ActionFileRead, ".env")}, "/w"},
		{"grep", "linux", "grep", map[string]any{"pattern": "k", "path": "secrets"}, []guard.Action{file(guard.ActionFileRead, "secrets")}, "/w"},
		{"view_image", "linux", "view_image", map[string]any{"paths": []string{"a.png", "https://x/y.png"}}, []guard.Action{file(guard.ActionFileRead, "a.png")}, "/w"},
		{"write", "linux", "write", map[string]any{"path": "a", "content": "x"}, []guard.Action{file(guard.ActionFileWrite, "a")}, "/w"},
		{"edit", "linux", "edit", map[string]any{"path": "b", "edits": []map[string]string{{"oldText": "x", "newText": "y"}}}, []guard.Action{file(guard.ActionFileWrite, "b")}, "/w"},
		{"edit with filePath", "linux", "edit", map[string]any{"filePath": "c"}, []guard.Action{file(guard.ActionFileWrite, "c")}, "/w"},
		{"apply_patch", "linux", "apply_patch", map[string]any{"input": patch}, []guard.Action{file(guard.ActionFileWrite, "n.txt"),
			{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a.go", To: "b.go"}}, file(guard.ActionFileDelete, "old")}, "/w"},
	}
	for _, tt := range tests {
		ev, err := a.Parse(callOn(tt.platform, tt.tool, tt.params))
		if err != nil {
			t.Errorf("%s: %v", tt.name, err)
			continue
		}
		if asJSON(ev.Actions) != asJSON(tt.want) || ev.Cwd != tt.cwd {
			t.Errorf("%s: %s cwd %q, want %s cwd %q", tt.name, asJSON(ev.Actions), ev.Cwd, asJSON(tt.want), tt.cwd)
		}
	}
}

func TestNoAction(t *testing.T) {
	for _, in := range [][]byte{
		call("ls", map[string]any{"path": "x"}),
		call("web_fetch", map[string]any{"url": "https://example.com"}),
		call("sessions_spawn", map[string]any{"task": "x"}),
		call("message", map[string]any{"action": "send", "message": "done"}),
		call("github__create_issue", map[string]any{"title": "x"}),
		call("process", map[string]any{"action": "poll", "sessionId": "p1"}),
		call("exec", map[string]any{"command": ""}),
		// Code Mode 的单元：参数是 JavaScript，里面的工具调用各自检查
		req("before_tool_call", map[string]any{"toolName": "exec", "toolKind": "code_mode_exec", "params": map[string]string{"code": "await tools.exec({command: 'ls'})", "command": "await tools.exec({command: 'ls'})"}}, nil),
	} {
		if _, err := a.Parse(in); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", in, err)
		}
	}
}

func TestAsks(t *testing.T) {
	var tu *harness.TargetUnparsedError
	for name, in := range map[string][]byte{
		"exec on a node":         call("exec", map[string]any{"command": "ls", "host": "node"}),
		"exec on a named node":   call("exec", map[string]any{"command": "ls", "node": "phone"}),
		"process write":          call("process", map[string]any{"action": "write", "sessionId": "p1", "data": "rm -rf ~\n"}),
		"process paste":          call("process", map[string]any{"action": "paste", "sessionId": "p1", "text": "make deploy"}),
		"broken patch":           call("apply_patch", map[string]any{"input": "*** Begin Patch\n*** Frob File: x\n*** End Patch"}),
		"write without a path":   call("write", map[string]any{"content": "x"}),
		"exec with a wrong type": call("exec", map[string]any{"command": []int{1}}),
	} {
		ev, err := a.Parse(in)
		if !errors.As(err, &tu) {
			t.Errorf("%s: %+v %v, want TargetUnparsedError", name, ev, err)
		}
	}
	if !errors.As(must(a.Parse(call("process", map[string]any{"action": "write", "data": "rm -rf ~"}))), &tu) || len(tu.Event.Actions) != 1 {
		t.Errorf("process write: the command is checked as well")
	}
	var ut *harness.UnknownToolError
	for _, tool := range []string{"nodes", "gateway", "plugins", "automations", "computer", "terminal", "secrets", "github_publish", "my_plugin_tool"} {
		if _, err := a.Parse(call(tool, map[string]any{})); !errors.As(err, &ut) || ut.Event.Tool != tool {
			t.Errorf("%s: %v, want UnknownToolError", tool, err)
		}
	}
	for _, action := range []string{"kill", "send-keys", "remove", "frob"} {
		if _, err := a.Parse(call("process", map[string]any{"action": action, "sessionId": "p1"})); !errors.As(err, &ut) {
			t.Errorf("process %s: %v, want UnknownToolError", action, err)
		}
	}
}

func must(_ guard.Event, err error) error { return err }

// TestResult：读文件的工具与读文件的命令的结果按文件内容扫描；Code Mode 单元同样如此。
func TestResult(t *testing.T) {
	for _, tt := range []struct {
		tool string
		args any
		want bool
	}{
		{"read", map[string]string{"path": "a"}, true},
		{"exec", map[string]string{"command": "cat .env"}, true},
		{"exec", map[string]string{"command": "go test ./..."}, false},
		{"exec", map[string]string{"code": "return (await tools.read({path: 'a'})).content"}, true},
		{"process", map[string]string{"action": "log"}, true},
		{"web_fetch", map[string]string{"url": "https://example.com"}, false},
	} {
		ev, err := a.Parse(result(tt.tool, tt.args, "SECRET"))
		if err != nil || ev.Kind != guard.EventToolOutput || ev.Text != "SECRET" || ev.FileContent != tt.want {
			t.Errorf("%s %v: %+v %v", tt.tool, tt.args, ev, err)
		}
	}
}

// TestRun：起因为 user 的外部用户消息是用户指令；定时、心跳、webhook、会话间转交与子 agent 会话里的输入都是自动消息。
func TestRun(t *testing.T) {
	for _, tt := range []struct {
		trigger, provenance, key string
		want                     guard.Source
	}{
		{"user", "external_user", "agent:main:telegram:dm:1", guard.SourceUser},
		{"user", "", "agent:main:main", guard.SourceUser},
		{"manual", "", "agent:main:main", guard.SourceUser},
		{"cron", "", "agent:main:cron:nightly:run:1", guard.SourceAutomated},
		{"heartbeat", "", "agent:main:main", guard.SourceAutomated},
		{"event", "", "agent:main:hook:x", guard.SourceAutomated},
		{"", "", "agent:main:main", guard.SourceAutomated},
		{"user", "inter_session", "agent:main:main", guard.SourceAutomated},
		{"user", "internal_system", "agent:main:main", guard.SourceAutomated},
		{"user", "external_user", "agent:main:subagent:abc", guard.SourceAutomated},
	} {
		ev, err := a.Parse(run("deploy", tt.trigger, tt.provenance, tt.key))
		if err != nil || ev.Text != "deploy" || len(ev.Requests) != 1 || ev.Requests[0].Source != tt.want {
			t.Errorf("%+v: %+v %v", tt, ev, err)
		}
	}
	if ev, err := a.Parse(run("", "user", "", "k")); err != nil || len(ev.Requests) != 0 {
		t.Errorf("empty prompt: %+v %v", ev, err)
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"other harness": []byte(`{"protocol":"h-guard.ext/v1","harness":"dsh","hook":"before_tool_call","session":{"id":"s"},"data":{}}`),
		"unknown hook":  req("after_tool_call", map[string]any{"toolName": "exec"}, nil),
		"bad data":      req("before_agent_run", "x", nil),
	} {
		if _, err := a.Parse(in); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestRender(t *testing.T) {
	out, code := a.Render(guard.Event{}, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionDeny}, Message: "no", Hint: "do it by hand"})
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || r.Action != extproto.ActionDeny || r.Message != "no" || r.Hint != "do it by hand" {
		t.Errorf("%s %d %v", out, code, err)
	}
	out, _ = a.RenderNoAction()
	if r, err := extproto.ParseReply(out); err != nil || r.Action != extproto.ActionPass {
		t.Errorf("%s %v", out, err)
	}
}

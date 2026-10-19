package hermes_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
	"github.com/cyberchen1995/h-guard/pkg/harness/hermes"
)

func req(hook string, data, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": "hermes", "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	b, _ := json.Marshal(r)
	return b
}

func pre(tool string, args any) []byte { return preWith(tool, args, "prompt") }

func preWith(tool string, args any, approval string) []byte {
	return req(hermes.HookPreToolCall, map[string]any{"tool_name": tool, "args": args, "tool_call_id": "c1", "approval": approval, "backend": "local"}, nil)
}

func post(tool string, args any, result string) []byte {
	return req(hermes.HookToolResult, map[string]any{"tool_name": tool, "args": args, "tool_call_id": "c1"}, map[string]any{"content": result})
}

func prompt(hook, text, platform, parent string) []byte {
	return req(hook, map[string]any{"text": text, "platform": platform, "parent_session_id": parent}, nil)
}

var a = hermes.Adapter{}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestConformance(t *testing.T) {
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "terminal", Input: pre("terminal", map[string]string{"command": "git push"}), WantKind: guard.EventAction, Check: checkReply},
		{Name: "result", Input: post("read_file", map[string]string{"path": "a"}, `{"content":"x"}`), WantKind: guard.EventToolOutput, Check: checkReply},
		{Name: "admission", Input: prompt(hermes.HookAdmission, "hi", "telegram", ""), WantKind: guard.EventPrompt, Check: checkReply},
		{Name: "pre_llm_call", Input: prompt(hermes.HookPreLLMCall, "hi", "cli", ""), WantKind: guard.EventPrompt, Check: checkReply},
	})
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestActions(t *testing.T) {
	exec := func(c string) []guard.Action {
		return []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: c, Shell: guard.ShellPOSIX}}}
	}
	file := func(k guard.ActionKind, p string) guard.Action {
		return guard.Action{Kind: k, File: &guard.FileAction{Path: p}}
	}
	tests := []struct {
		tool string
		args any
		want []guard.Action
		cwd  string
	}{
		{"terminal", map[string]any{"command": "rm -rf dist", "workdir": "/tmp/x", "background": true}, exec("rm -rf dist"), "/tmp/x"},
		{"terminal", map[string]any{"command": "ls"}, exec("ls"), "/w"},
		{"read_file", map[string]any{"path": "/w/.env", "offset": 1}, []guard.Action{file(guard.ActionFileRead, "/w/.env")}, "/w"},
		{"search_files", map[string]any{"pattern": "k", "path": "secrets"}, []guard.Action{file(guard.ActionFileRead, "secrets")}, "/w"},
		{"search_files", map[string]any{"pattern": "k"}, []guard.Action{file(guard.ActionFileRead, ".")}, "/w"},
		{"write_file", map[string]any{"path": "a", "content": "x"}, []guard.Action{file(guard.ActionFileWrite, "a")}, "/w"},
		{"patch", map[string]any{"path": "b", "old_string": "x", "new_string": "y"}, []guard.Action{file(guard.ActionFileWrite, "b")}, "/w"},
		{"text_to_speech", map[string]any{"text": "hi", "output_path": "/w/a.mp3"}, []guard.Action{file(guard.ActionFileWrite, "/w/a.mp3")}, "/w"},
		{"patch", map[string]any{"mode": "patch", "patch": "*** Begin Patch\n*** Update File: a.go\n@@\n-x\n+y\n*** Add File: n.txt\n+hi\n*** Delete File: old.txt\n*** Move File: src.go -> dst.go\n*** End Patch\n"},
			[]guard.Action{file(guard.ActionFileWrite, "a.go"), file(guard.ActionFileWrite, "n.txt"), file(guard.ActionFileDelete, "old.txt"),
				{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "src.go", To: "dst.go"}}}, "/w"},
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
}

// TestV4A：与 Hermes 的解析器一样，从第一个 End Patch 之前最后一个 Begin Patch 之后开始读；没有 Begin 时从头读；
// 行首不是标记的行（「+*** Delete File: x」这样的正文）不算操作；一个操作都没有、路径为空时请求确认。
func TestV4A(t *testing.T) {
	paths := func(in string) (string, error) {
		ev, err := a.Parse(pre("patch", map[string]any{"mode": "patch", "patch": in}))
		var tu *harness.TargetUnparsedError
		if errors.As(err, &tu) {
			return asJSON(tu.Event.Actions), err
		}
		return asJSON(ev.Actions), err
	}
	got, err := paths("*** Update File: early.go\n*** Begin Patch\n*** Update File: a.go\n+*** Delete File: body.txt\n*** End Patch\n*** Delete File: after.txt\n")
	if err != nil || got != `[{"kind":"file_write","file":{"path":"a.go"}}]` {
		t.Errorf("begin/end window: %s %v", got, err)
	}
	if got, err := paths("***Update File:  x.go \r\n@@\n-a\n+b\n"); err != nil || got != `[{"kind":"file_write","file":{"path":"x.go"}}]` {
		t.Errorf("no begin, CRLF, no space after ***: %s %v", got, err)
	}
	var tu *harness.TargetUnparsedError
	for name, in := range map[string]string{
		"empty":            "*** Begin Patch\n*** End Patch\n",
		"move without dst": "*** Begin Patch\n*** Move File: a ->   \n*** End Patch\n",
	} {
		if _, err := paths(in); !errors.As(err, &tu) {
			t.Errorf("%s: %v, want TargetUnparsedError", name, err)
		}
	}
	if _, err := a.Parse(pre("patch", map[string]any{"mode": "frob", "path": "x"})); !errors.As(err, &tu) {
		t.Errorf("unknown mode: %v", err)
	}
}

// TestCodeAndProcesses：execute_code 请求确认；process_manage 写进 stdin 的内容按命令检查并请求确认，kill 按不认识的
// 工具请求确认，poll 等只读。
func TestCodeAndProcesses(t *testing.T) {
	var tu *harness.TargetUnparsedError
	if _, err := a.Parse(pre("execute_code", map[string]any{"code": "import os"})); !errors.As(err, &tu) {
		t.Errorf("execute_code: %v", err)
	}
	_, err := a.Parse(pre("process_manage", map[string]any{"action": "submit", "session_id": "p1", "data": "rm -rf ~/.hermes"}))
	if !errors.As(err, &tu) || len(tu.Event.Actions) != 1 || tu.Event.Actions[0].Exec.Command != "rm -rf ~/.hermes" {
		t.Errorf("process_manage submit: %v %+v", err, tu)
	}
	var ut *harness.UnknownToolError
	if _, err := a.Parse(pre("process", map[string]any{"action": "kill", "session_id": "p1"})); !errors.As(err, &ut) || ut.Event.Tool != "process_manage" {
		t.Errorf("legacy process kill: %v", err)
	}
	if _, err := a.Parse(pre("process_manage", map[string]any{"action": "poll", "session_id": "p1"})); !errors.Is(err, harness.ErrNoAction) {
		t.Errorf("poll: %v", err)
	}
	if _, err := a.Parse(pre("terminal", map[string]any{"command": []int{1}})); !errors.As(err, &tu) {
		t.Errorf("terminal with a wrong type: %v", err)
	}
}

// TestToolLists：只读的自带工具、MCP 与连接器不产生动作；其余 h-guard 不认识的工具（包括有副作用的子命令）返回
// UnknownToolError。
func TestToolLists(t *testing.T) {
	for tool, args := range map[string]map[string]any{
		"web_search": {}, "delegate_task": {"tasks": []any{}}, "skill_view": {"name": "x"}, "browser_navigate": {"url": "https://example.com"},
		"mcp__fs__read_file": {"path": "x"}, "connectors__gmail__search": {}, "cronjob_manage": {"action": "list"},
		"browser_console": {}, "manage_connections": {"action": "status"}, "drive_preview": {"action": "elements"}, "todo": {},
		"ha_list_entities": {}, "ha_get_state": {"entity_id": "light.kitchen"}, "ha_list_services": {},
	} {
		if _, err := a.Parse(pre(tool, args)); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", tool, err)
		}
	}
	var ut *harness.UnknownToolError
	for tool, args := range map[string]map[string]any{
		"memory": {"action": "add"}, "skill_manage": {}, "computer_use": {}, "browser_click": {"ref": "@e1"}, "browser_cdp": {},
		"cronjob_manage": {"action": "create", "script": "x.sh"}, "browser_console": {"expression": "document.cookie"},
		"manage_connections": {"action": "install"}, "drive_preview": {"action": "click"}, "close_terminal": {}, "manage_catalog": {},
		"some_plugin_tool": {}, "ha_call_service": {"domain": "lock", "service": "unlock"},
	} {
		if _, err := a.Parse(pre(tool, args)); !errors.As(err, &ut) {
			t.Errorf("%s %v: %v, want UnknownToolError", tool, args, err)
		}
	}
}

// TestApprovalCaps：approve 指令只在会有人回答或 Hermes 会拒绝时算作能请求确认；YOLO、自动批准与读不出时不算。
func TestApprovalCaps(t *testing.T) {
	for approval, want := range map[string]bool{"prompt": true, "blocked": true, "auto": false, "": false, "other": false} {
		ev, err := a.Parse(preWith("terminal", map[string]string{"command": "ls"}, approval))
		if err != nil {
			t.Fatal(err)
		}
		if c := a.CapsFor(ev); c.Ask != want || !c.Block {
			t.Errorf("approval %q: %+v", approval, c)
		}
	}
	var ut *harness.UnknownToolError
	if _, err := a.Parse(preWith("memory", map[string]string{}, "auto")); !errors.As(err, &ut) || a.CapsFor(ut.Event).Ask {
		t.Errorf("unknown tool under auto: %v", err)
	}
}

// TestPrompts：post_gateway_admission 能挡下提示词，pre_llm_call 不能；子 agent、定时任务、webhook 与机器人的消息是自动消息。
func TestPrompts(t *testing.T) {
	ev, err := a.Parse(prompt(hermes.HookAdmission, "deploy", "telegram", ""))
	if err != nil || ev.Text != "deploy" || ev.Requests[0].Source != guard.SourceUser || !a.CapsFor(ev).Block {
		t.Fatalf("admission: %+v %v", ev, err)
	}
	ev, err = a.Parse(prompt(hermes.HookPreLLMCall, "deploy", "cli", ""))
	if c := a.CapsFor(ev); err != nil || c.Block || !c.Warn {
		t.Fatalf("pre_llm_call: %+v %v", c, err)
	}
	for _, in := range [][]byte{
		prompt(hermes.HookPreLLMCall, "task", "subagent", "parent-1"), prompt(hermes.HookPreLLMCall, "task", "cli", "parent-1"),
		prompt(hermes.HookPreLLMCall, "nightly", "cron", ""), prompt(hermes.HookPreLLMCall, "payload", "webhook", ""),
		req(hermes.HookAdmission, map[string]any{"text": "hi", "platform": "discord", "is_bot": true}, nil),
		req(hermes.HookPreLLMCall, map[string]any{"text": "push main", "platform": "discord", "is_bot": true}, nil),
	} {
		if ev, err := a.Parse(in); err != nil || ev.Requests[0].Source != guard.SourceAutomated {
			t.Errorf("automated: %+v %v", ev, err)
		}
	}
}

// TestToolOutput：JSON 的工具结果取出其中的字符串（转义的换行还原）；读文件的工具与读文件的命令是文件内容；后台进程的
// 输出按文件内容扫描。
func TestToolOutput(t *testing.T) {
	ev, err := a.Parse(post("terminal", map[string]any{"command": "cat .env"}, `{"output":"A=1\nB=2","exit_code":0,"error":null}`))
	if err != nil || ev.Text != "error\nexit_code\n0\noutput\nA=1\nB=2" || !ev.FileContent || ev.Kind != guard.EventToolOutput {
		t.Fatalf("%q %v", ev.Text, err)
	}
	// 键与数同样扫描（键里的邮箱、按数写出的账号）
	ev, _ = a.Parse(post("web_extract", map[string]any{}, `{"alice@example.com":{"account":4111111111111111,"ok":true}}`))
	if ev.Text != "alice@example.com\naccount\n4111111111111111\nok\ntrue" {
		t.Errorf("keys and scalars: %q", ev.Text)
	}
	ev, err = a.Parse(post("web_extract", map[string]any{"urls": []string{"https://example.com"}}, "plain page"))
	if err != nil || ev.FileContent || ev.Text != "plain page" {
		t.Fatalf("%+v %v", ev, err)
	}
	if ev, err := a.Parse(post("read_file", map[string]any{"path": "a"}, `{"content":"1|K"}`)); err != nil || !ev.FileContent {
		t.Errorf("read_file: %+v %v", ev, err)
	}
	ev, err = a.Parse(req(hermes.HookTerminalOutput, map[string]any{"command": "npm start", "returncode": nil, "env_type": ""}, map[string]any{"content": "KEY"}))
	if err != nil || ev.Text != "KEY" || !ev.FileContent || ev.Tool != "process_manage" || !a.CapsFor(ev).Replace {
		t.Errorf("terminal output: %+v %v", ev, err)
	}
}

// TestNotify：配置了通知时，结论（降级前或降级后）在 on 里的回复带 notify；pass 与不在 on 里的结论不带。
func TestNotify(t *testing.T) {
	n := a.WithNotify([]guard.Decision{guard.DecisionDeny}, "telegram")
	ev, _ := n.Parse(pre("terminal", map[string]string{"command": "rm -rf /"}))
	render := func(d, raw guard.Decision) map[string]any {
		out, _ := n.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: d}, Raw: raw, Message: "why"})
		if _, err := extproto.ParseReply(out); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		return m
	}
	if m := render(guard.DecisionDeny, guard.DecisionDeny); asJSON(m["notify"]) != `{"to":"telegram"}` {
		t.Errorf("deny: %v", m)
	}
	if m := render(guard.DecisionWarn, guard.DecisionDeny); m["notify"] == nil { // 提示词挡不住时 deny 降级为 warn
		t.Errorf("deny degraded to warn: %v", m)
	}
	if m := render(guard.DecisionWarn, guard.DecisionWarn); m["notify"] != nil {
		t.Errorf("warn not in on: %v", m)
	}
	if m := render(guard.DecisionPass, guard.DecisionPass); m["notify"] != nil {
		t.Errorf("pass: %v", m)
	}
	out, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionDeny}, Message: "why"})
	if m := map[string]any{}; json.Unmarshal(out, &m) != nil || m["notify"] != nil {
		t.Errorf("without notify config: %s", out)
	}
}

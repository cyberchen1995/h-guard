package pi_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
	"github.com/cyberchen1995/h-guard/pkg/harness/pi"
)

func req(h, hook string, data, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": h, "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	b, _ := json.Marshal(r)
	return b
}

func call(h, tool string, input any) []byte {
	return req(h, "tool_call", map[string]any{"type": "tool_call", "toolCallId": "c1", "toolName": tool, "input": input}, nil)
}

func result(h, tool string, input any, text string) []byte {
	return req(h, "tool_result", map[string]any{"toolCallId": "c1", "toolName": tool, "input": input, "isError": false},
		map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestConformance(t *testing.T) {
	for _, a := range []pi.Adapter{pi.Pi, pi.OMP} {
		t.Run(a.Name(), func(t *testing.T) {
			h := a.Name()
			harnesstest.Run(t, a, []harnesstest.Case{
				{Name: "bash", Input: call(h, "bash", map[string]string{"command": "git push"}), WantKind: guard.EventAction, Check: checkReply},
				{Name: "result", Input: result(h, "read", map[string]string{"path": "a"}, "x"), WantKind: guard.EventToolOutput, Check: checkReply},
				{Name: "input", Input: req(h, "input", map[string]string{"text": "hi", "source": "interactive"}, nil), WantKind: guard.EventPrompt, Check: checkReply},
			})
		})
	}
}

func actions(t *testing.T, a pi.Adapter, tool string, input any) ([]guard.Action, guard.Event) {
	t.Helper()
	ev, err := a.Parse(call(a.Name(), tool, input))
	if err != nil {
		t.Fatalf("%s %s: %v", a.Name(), tool, err)
	}
	return ev.Actions, ev
}

func asJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// TestPiTools：pi 的内置工具映射为动作。
func TestPiTools(t *testing.T) {
	tests := []struct {
		tool  string
		input any
		want  []guard.Action
	}{
		{"bash", map[string]any{"command": "rm -rf ~", "timeout": 5}, []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf ~", Shell: guard.ShellPOSIX}}}},
		{"powershell", map[string]any{"command": "Remove-Item x"}, []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "Remove-Item x", Shell: guard.ShellPowerShell}}}},
		{"read", map[string]any{"path": ".env", "offset": 1}, []guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: ".env"}}}},
		{"grep", map[string]any{"pattern": "k", "path": "/etc"}, []guard.Action{{Kind: guard.ActionFileRead, File: &guard.FileAction{Path: "/etc"}}}},
		{"write", map[string]any{"path": "a", "content": "x"}, []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "a"}}}},
		{"edit", map[string]any{"path": "b", "edits": []map[string]string{{"oldText": "x", "newText": "y"}}}, []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "b"}}}},
	}
	for _, tt := range tests {
		got, _ := actions(t, pi.Pi, tt.tool, tt.input)
		if asJSON(got) != asJSON(tt.want) {
			t.Errorf("%s: %s, want %s", tt.tool, asJSON(got), asJSON(tt.want))
		}
	}
	for _, tool := range []string{"ls", "find", "mcp__srv_query"} {
		if _, err := pi.Pi.Parse(call("pi", tool, map[string]any{"path": "x"})); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("pi %s: %v, want ErrNoAction", tool, err)
		}
	}
}

// TestOMPTools：omp 的 bash 带 cwd，read 的路径去掉行选择，edit 的补丁读出补丁头里的文件，eval 执行代码要求确认。
func TestOMPTools(t *testing.T) {
	got, ev := actions(t, pi.OMP, "bash", map[string]any{"command": "make", "cwd": "sub"})
	if ev.Cwd != "/w/sub" || got[0].Exec.Command != "make" {
		t.Errorf("bash: %+v cwd %q", got, ev.Cwd)
	}
	for in, want := range map[string]string{"src/a.go:10-20": "src/a.go", "a.go:-5": "a.go", `C:\x\a.go`: `C:\x\a.go`, "notes:": "notes:",
		".env:raw": ".env", "~/.ssh/id_rsa:conflicts": "~/.ssh/id_rsa", ".env:10-": ".env", "a.go:1-20:raw": "a.go", "a.go:raw:5+3": "a.go"} {
		got, _ := actions(t, pi.OMP, "read", map[string]any{"path": in})
		if got[0].File.Path != want {
			t.Errorf("read %q: %q, want %q", in, got[0].File.Path, want)
		}
	}
	hashline := "[src/a.go#1a2b]\n+ line\n[old.txt#ffff]\nREM\n[b.go]\nMV c.go\n"
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"input": hashline, "paths": []string{"src/a.go", "old.txt", "b.go"}})
	want := []guard.Action{
		{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "src/a.go"}},
		{Kind: guard.ActionFileDelete, File: &guard.FileAction{Path: "old.txt"}},
		{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "b.go", To: "c.go"}},
	}
	if asJSON(got) != asJSON(want) {
		t.Errorf("hashline edit: %s, want %s", asJSON(got), asJSON(want))
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"path": "x.go", "old_string": "a", "new_string": "b"})
	if len(got) != 1 || got[0].File.Path != "x.go" {
		t.Errorf("replace edit: %+v", got)
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"input": "*** Begin Patch\n*** Add File: n.txt\n+x\n*** End Patch"})
	if len(got) != 1 || got[0].File.Path != "n.txt" {
		t.Errorf("apply_patch edit: %+v", got)
	}
	got, _ = actions(t, pi.OMP, "ast_edit", map[string]any{"ops": []any{}, "paths": []string{"a.ts", "b.ts"}})
	if len(got) != 2 {
		t.Errorf("ast_edit: %+v", got)
	}
	var tu *harness.TargetUnparsedError
	for name, in := range map[string]any{
		"eval":            map[string]any{"language": "py", "code": "import os"},
		"edit no targets": map[string]any{"input": "garbage"},
		"bad patch":       map[string]any{"input": "*** Begin Patch\n*** Nope\n*** End Patch"},
	} {
		tool := "edit"
		if name == "eval" {
			tool = "eval"
		}
		if _, err := pi.OMP.Parse(call("omp", tool, in)); !errors.As(err, &tu) || tu.Event.Harness != "omp" {
			t.Errorf("%s: %v, want TargetUnparsedError", name, err)
		}
	}
	if _, err := pi.OMP.Parse(call("omp", "write", map[string]any{"path": []int{1}})); !errors.As(err, &tu) {
		t.Errorf("write with a wrong type: %v, want TargetUnparsedError", err)
	}
}

// TestHarnessField：请求里的 harness 要与 adapter 一致，pi 的请求不能交给 omp。
func TestHarnessField(t *testing.T) {
	if _, err := pi.OMP.Parse(call("pi", "bash", map[string]string{"command": "ls"})); err == nil {
		t.Error("omp accepted a pi request")
	}
}

// TestInput：input 的 source 为 extension 是扩展发出的自动消息，其余按用户本人。
func TestInput(t *testing.T) {
	for src, want := range map[string]guard.Source{"interactive": guard.SourceUser, "rpc": guard.SourceUser, "extension": guard.SourceAutomated, "subagent": guard.SourceAutomated, "context": guard.SourceUser, "": guard.SourceUser} {
		ev, err := pi.Pi.Parse(req("pi", "input", map[string]string{"text": "do it", "source": src}, nil))
		if err != nil || ev.Text != "do it" || ev.Requests[0].Source != want {
			t.Errorf("%q: %+v %v", src, ev, err)
		}
	}
}

// TestToolResult：结果取文本块；读文件的工具与命令是文件内容。
func TestToolResult(t *testing.T) {
	ev, err := pi.Pi.Parse(result("pi", "bash", map[string]string{"command": "cat .env"}, "K=V"))
	if err != nil || ev.Text != "K=V" || !ev.FileContent || ev.Kind != guard.EventToolOutput {
		t.Fatalf("%+v %v", ev, err)
	}
	ev, err = pi.Pi.Parse(result("pi", "bash", map[string]string{"command": "make"}, "ok"))
	if err != nil || ev.FileContent {
		t.Fatalf("%+v %v", ev, err)
	}
}

// TestOMPEditModes：apply_patch 模式下工具名是 apply_patch；patch 模式的各项可以删除或改名（目标同样检查）。
func TestOMPEditModes(t *testing.T) {
	got, _ := actions(t, pi.OMP, "apply_patch", map[string]any{"input": "*** Begin Patch\n*** Delete File: old.txt\n*** End Patch"})
	if asJSON(got) != asJSON([]guard.Action{{Kind: guard.ActionFileDelete, File: &guard.FileAction{Path: "old.txt"}}}) {
		t.Errorf("apply_patch: %s", asJSON(got))
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"path": "a.txt", "edits": []map[string]string{{"op": "update", "diff": "x"}, {"rename": "~/.omp/agent/config.yml"}}})
	if asJSON(got) != asJSON([]guard.Action{{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a.txt", To: "~/.omp/agent/config.yml"}}}) {
		t.Errorf("patch rename: %s", asJSON(got))
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"path": "a.txt", "edits": []map[string]string{{"op": "delete"}}})
	if len(got) != 1 || got[0].Kind != guard.ActionFileDelete {
		t.Errorf("patch delete: %s", asJSON(got))
	}
	var ut *harness.UnknownToolError
	if _, err := pi.Pi.Parse(call("pi", "apply_patch", map[string]any{"input": "x"})); !errors.As(err, &ut) {
		t.Errorf("pi apply_patch: %v", err)
	}
}

// TestOMPLSP：lsp 的改名与应用的代码操作改动文件（请求确认，能读出的文件照常检查）；只读的动作不产生动作。
func TestOMPLSP(t *testing.T) {
	var tu *harness.TargetUnparsedError
	for name, in := range map[string]map[string]any{
		"rename":       {"action": "rename", "file": "a.go", "line": 3, "symbol": "x", "new_name": "y"},
		"rename_file":  {"action": "rename_file", "file": "a.go", "new_name": "b.go"},
		"code_actions": {"action": "code_actions", "file": "a.go", "apply": true},
		"request":      {"action": "request", "query": "workspace/executeCommand"},
	} {
		_, err := pi.OMP.Parse(call("omp", "lsp", in))
		if !errors.As(err, &tu) {
			t.Errorf("%s: %v, want TargetUnparsedError", name, err)
			continue
		}
		if name == "rename_file" && asJSON(tu.Event.Actions) != asJSON([]guard.Action{{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a.go", To: "b.go"}}}) {
			t.Errorf("rename_file actions: %s", asJSON(tu.Event.Actions))
		}
	}
	for name, in := range map[string]map[string]any{
		"diagnostics":       {"action": "diagnostics", "file": "a.go"},
		"rename preview":    {"action": "rename", "file": "a.go", "new_name": "y", "apply": false},
		"code_actions list": {"action": "code_actions", "file": "a.go"},
	} {
		if _, err := pi.OMP.Parse(call("omp", "lsp", in)); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", name, err)
		}
	}
}

// TestOMPToolLists：omp 自带的只读工具与 MCP 工具不产生动作；其余 h-guard 不认识的工具返回 UnknownToolError
// （调用方按 read_only_tools 判断）；pi 上扩展提供的工具同样如此。
func TestOMPToolLists(t *testing.T) {
	for _, tool := range []string{"todo", "web_search", "ast_grep", "task", "recall", "mcp__srv_query"} {
		if _, err := pi.OMP.Parse(call("omp", tool, map[string]any{})); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("%s: %v, want ErrNoAction", tool, err)
		}
	}
	var ut *harness.UnknownToolError
	for _, tool := range []string{"debug", "github", "ida", "manage_skill", "retain", "memory_edit", "my_extension_tool"} {
		_, err := pi.OMP.Parse(call("omp", tool, map[string]any{"x": 1}))
		if !errors.As(err, &ut) || ut.Event.Tool != tool || ut.Event.Harness != "omp" || ut.Event.SessionID != "s1" {
			t.Errorf("%s: %v, want UnknownToolError", tool, err)
		}
	}
	for _, tool := range []string{"my_extension_tool", "eval", "ast_edit", "lsp"} {
		_, err := pi.Pi.Parse(call("pi", tool, map[string]any{"x": 1}))
		if !errors.As(err, &ut) || ut.Event.Tool != tool || ut.Event.Harness != "pi" {
			t.Errorf("pi %s: %v, want UnknownToolError", tool, err)
		}
	}
	got, _ := actions(t, pi.OMP, "search", map[string]any{"pattern": "k", "path": "/etc"})
	if len(got) != 1 || got[0].Kind != guard.ActionFileRead || got[0].File.Path != "/etc" {
		t.Errorf("search: %+v", got)
	}
}

// TestOMPWriteTargets：omp 的 write 目标还原成实际改动的文件；应用预览的 xd://resolve 等内部 URL 请求确认；
// 严格语法包了 *** Begin Patch 的 hashline 补丁照样按段头读。
func TestOMPWriteTargets(t *testing.T) {
	for in, want := range map[string]string{
		"src/config.json":                  "src/config.json",
		"fixtures/archive.zip:templates/x": "fixtures/archive.zip",
		"data/app.sqlite:users:42":         "data/app.sqlite",
		"[src/a.go#1a2b]":                  "src/a.go",
		`C:\work\a.txt`:                    `C:\work\a.txt`,
	} {
		got, _ := actions(t, pi.OMP, "write", map[string]any{"path": in, "content": "x"})
		if len(got) != 1 || got[0].File.Path != want {
			t.Errorf("write %q: %+v, want %q", in, got, want)
		}
	}
	var tu *harness.TargetUnparsedError
	for _, in := range []string{"xd://resolve", "xd://some_tool", "conflict://*", "memory://x"} {
		if _, err := pi.OMP.Parse(call("omp", "write", map[string]any{"path": in, "content": "x"})); !errors.As(err, &tu) {
			t.Errorf("write %q: %v, want TargetUnparsedError", in, err)
		}
	}
	if _, err := pi.OMP.Parse(call("omp", "write", map[string]any{"path": "proc://12/kill"})); !errors.As(err, &tu) {
		t.Errorf("write proc kill: %v, want TargetUnparsedError", err)
	}
	for _, in := range []string{"xd://reject"} {
		if _, err := pi.OMP.Parse(call("omp", "write", map[string]any{"path": in})); !errors.Is(err, harness.ErrNoAction) {
			t.Errorf("write %q: %v, want ErrNoAction", in, err)
		}
	}
	got, _ := actions(t, pi.OMP, "read", map[string]any{"path": "secrets.zip:keys/id_rsa"})
	if got[0].File.Path != "secrets.zip" {
		t.Errorf("read archive entry: %+v", got)
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"input": "*** Begin Patch\n[src/a.go#1a2b]\n+ x\n*** End Patch"})
	if asJSON(got) != asJSON([]guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "src/a.go"}}}) {
		t.Errorf("wrapped hashline: %s", asJSON(got))
	}
}

// TestOMPSearchIsFileContent：omp 的 search（grep 的旧名）的结果同样是文件内容。
func TestOMPSearchIsFileContent(t *testing.T) {
	ev, err := pi.OMP.Parse(result("omp", "search", map[string]string{"pattern": "k", "path": "."}, "K=V"))
	if err != nil || !ev.FileContent {
		t.Fatalf("%+v %v", ev, err)
	}
}

// TestOMPPaths：omp 的路径与 omp 一样规范化（误加的 :、表示路径的 @、file:// URL）；sloppy 模式的补丁按 *** Edit File: 行读。
func TestOMPPaths(t *testing.T) {
	for in, want := range map[string]string{
		"file:///home/u/.ssh/id_rsa": "/home/u/.ssh/id_rsa",
		"FILE:///w/a%20b.txt":        "/w/a b.txt",
		"file:///C:/Users/u/.env":    "C:/Users/u/.env",
		"file://localhost/etc/hosts": "/etc/hosts",
		"@~/.ssh/id_rsa:raw":         "~/.ssh/id_rsa",
		"@/etc/shadow":               "/etc/shadow",
		":~/.aws/credentials":        "~/.aws/credentials",
		":./.env":                    "./.env",
		"@my-file.txt":               "@my-file.txt",
		"a:b":                        "a:b",
	} {
		got, _ := actions(t, pi.OMP, "read", map[string]any{"path": in})
		if len(got) != 1 || got[0].File.Path != want {
			t.Errorf("read %q: %+v, want %q", in, got, want)
		}
	}
	got, _ := actions(t, pi.OMP, "write", map[string]any{"path": "file:///w/.env", "content": "x"})
	if len(got) != 1 || got[0].File.Path != "/w/.env" {
		t.Errorf("write file URL: %+v", got)
	}
	sloppy := "*** Edit File: ~/.dsh/cordis.patch.yml\n*** Find\n[section]\n*** Replace\n[other]\n*** Edit File:\n*** Find\nx\n*** Insert After\ny\n*** Edit File: \"src/a b.ts\" all\n*** Find\n[x]\n*** Replace\n[y]\n"
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"input": sloppy})
	want := []guard.Action{
		{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "~/.dsh/cordis.patch.yml"}},
		{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "src/a b.ts"}},
	}
	if asJSON(got) != asJSON(want) {
		t.Errorf("sloppy edit: %s, want %s", asJSON(got), asJSON(want))
	}
	got, _ = actions(t, pi.OMP, "edit", map[string]any{"input": "[@~/.dsh/cordis.patch.yml#1a2b]\n+ x\n[a.txt]\nMV file:///w/b.txt\n"})
	want = []guard.Action{
		{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "~/.dsh/cordis.patch.yml"}},
		{Kind: guard.ActionFileRename, File: &guard.FileAction{Path: "a.txt", To: "/w/b.txt"}},
	}
	if asJSON(got) != asJSON(want) {
		t.Errorf("normalized patch targets: %s, want %s", asJSON(got), asJSON(want))
	}
	var tu *harness.TargetUnparsedError
	for name, in := range map[string]map[string]any{
		"hashline local URL": {"input": "[local://plan.md#1a2b]\n+ x\n"},
		"sloppy vault URL":   {"input": "*** Edit File: vault://notes/a.md\n*** Find\nx\n*** Replace\ny\n"},
		"replace URL":        {"path": "local://plan.md", "old_string": "a", "new_string": "b"},
	} {
		if _, err := pi.OMP.Parse(call("omp", "edit", in)); !errors.As(err, &tu) {
			t.Errorf("edit %s: %v, want TargetUnparsedError", name, err)
		}
	}
	for name, in := range map[string]map[string]any{
		"single": {"task": "x", "isolated": true},
		"batch":  {"context": "c", "tasks": []map[string]any{{"task": "a"}, {"task": "b", "isolated": true}}},
	} {
		if _, err := pi.OMP.Parse(call("omp", "task", in)); !errors.As(err, &tu) {
			t.Errorf("isolated task %s: %v, want TargetUnparsedError", name, err)
		}
	}
	if _, err := pi.OMP.Parse(call("omp", "task", map[string]any{"context": "c", "tasks": []map[string]any{{"task": "a"}}})); !errors.Is(err, harness.ErrNoAction) {
		t.Errorf("task: %v, want ErrNoAction", err)
	}
	for name, in := range map[string]map[string]any{
		"reload":                {"action": "reload", "file": "*"},
		"workspace diagnostics": {"action": "diagnostics", "file": "*"},
	} {
		if _, err := pi.OMP.Parse(call("omp", "lsp", in)); !errors.As(err, &tu) {
			t.Errorf("lsp %s: %v, want TargetUnparsedError", name, err)
		}
	}
	if _, err := pi.OMP.Parse(call("omp", "lsp", map[string]any{"action": "diagnostics", "file": "a.go"})); !errors.Is(err, harness.ErrNoAction) {
		t.Errorf("lsp file diagnostics: %v, want ErrNoAction", err)
	}
	for in, want := range map[string]string{"backup.7z:keys/id_rsa": "backup.7z", "b.tar.bz2:config": "b.tar.bz2", "x.vsix:a": "x.vsix", "d.db3:t": "d.db3"} {
		got, _ := actions(t, pi.OMP, "read", map[string]any{"path": in})
		if len(got) != 1 || got[0].File.Path != want {
			t.Errorf("read %q: %+v, want %q", in, got, want)
		}
	}
	if ev, err := pi.OMP.Parse(result("omp", "lsp", map[string]any{"action": "references", "file": "a.go"}, "K=V")); err != nil || !ev.FileContent {
		t.Errorf("lsp result: %+v %v", ev, err)
	}
	for _, tool := range []string{"ast_grep", "ast_edit"} {
		if ev, err := pi.OMP.Parse(result("omp", tool, map[string]any{"pat": "x"}, "K=V")); err != nil || !ev.FileContent {
			t.Errorf("%s result: %+v %v", tool, ev, err)
		}
	}
	var ut *harness.UnknownToolError
	if _, err := pi.OMP.Parse(call("omp", "security_scan", map[string]any{"action": "start"})); !errors.As(err, &ut) {
		t.Errorf("security_scan: %v, want UnknownToolError", err)
	}
}

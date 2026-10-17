package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

func extReq(harness, hook string, data any) []byte {
	b, _ := json.Marshal(map[string]any{"protocol": extproto.Protocol, "harness": harness, "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data})
	return b
}

func extAction(t *testing.T, out string) string {
	t.Helper()
	r, err := extproto.ParseReply([]byte(out))
	if err != nil {
		t.Fatalf("reply %q: %v", out, err)
	}
	return string(r.Action)
}

// TestExtHarnessHooks：opencode、pi、omp、dsh 的扩展请求得到扩展协议的回复。灾难性命令拒绝；读 .env 请求确认
// （opencode 不能请求确认，按 when_ask_unsupported 降级为拒绝）；不产生动作的工具调用回复放行；带凭据的提示词拒绝。
func TestExtHarnessHooks(t *testing.T) {
	e := newEnv(t)
	type tc struct {
		harness, hook string
		data          any
		want          string
	}
	key := "deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0"
	for _, c := range []tc{
		{"opencode", "tool.execute.before", map[string]any{"tool": "bash", "callID": "c", "args": map[string]string{"command": "rm -rf /"}}, "deny"},
		{"opencode", "tool.execute.before", map[string]any{"tool": "read", "callID": "c", "args": map[string]string{"filePath": "/w/.env"}}, "deny"},
		{"opencode", "tool.execute.before", map[string]any{"tool": "glob", "callID": "c", "args": map[string]string{"pattern": "*"}}, "pass"},
		{"opencode", "tool.execute.before", map[string]any{"tool": "bash", "callID": "c", "args": map[string]string{"command": "ls"}}, "pass"},
		{"opencode", "chat.message", map[string]any{"parts": []map[string]any{{"type": "text", "text": key}}}, "deny"},
		{"pi", "tool_call", map[string]any{"toolCallId": "c", "toolName": "bash", "input": map[string]string{"command": "rm -rf /"}}, "deny"},
		{"pi", "tool_call", map[string]any{"toolCallId": "c", "toolName": "read", "input": map[string]string{"path": ".env"}}, "ask"},
		{"pi", "tool_call", map[string]any{"toolCallId": "c", "toolName": "ls", "input": map[string]string{}}, "pass"},
		{"pi", "input", map[string]any{"text": key, "source": "interactive"}, "deny"},
		{"omp", "tool_call", map[string]any{"toolCallId": "c", "toolName": "eval", "input": map[string]string{"language": "py", "code": "1"}}, "ask"},
		{"dsh", "tools/pre-execute", map[string]any{"name": "pwsh", "callId": "c", "arguments": map[string]string{"command": "Remove-Item -Recurse -Force C:\\"}}, "deny"},
		{"dsh", "tools/pre-execute", map[string]any{"name": "read", "callId": "c", "arguments": map[string]string{"file_path": "/w/.env"}}, "ask"},
		{"dsh", "agent/pre-step", map[string]any{"messages": []map[string]any{{"source": map[string]string{"kind": "user"}, "content": []map[string]string{{"type": "text", "text": key}}}}}, "deny"},
	} {
		out, errs, code := e.run(extReq(c.harness, c.hook, c.data), "hook", c.harness, "--event", c.hook)
		if code != 0 {
			t.Errorf("%s %s: exit %d, stderr %s", c.harness, c.hook, code, errs)
			continue
		}
		if got := extAction(t, out); got != c.want {
			t.Errorf("%s %s %v: %s, want %s (%s)", c.harness, c.hook, c.data, got, c.want, out)
		}
	}
	// 读不懂的请求什么都不输出：扩展把它当作 h-guard 无法运行（动作请求确认或阻止）
	if out, _, _ := e.run([]byte(`{"protocol":"h-guard.ext/v1"}`), "hook", "pi", "--event", "tool_call"); out != "" {
		t.Errorf("unreadable request: %q", out)
	}
}

// TestExtToolOutput：outbound 第 2 档扫描文件内容：读文件的命令输出里的凭据让结果被替换（deny）。
func TestExtToolOutput(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\noutbound: {tier: 2}\n")
	secret := "aws_access_key_id = AKIAIOSFODNN7EXAMPL0"
	for harness, in := range map[string][]byte{
		"opencode": mustJSON(map[string]any{"protocol": extproto.Protocol, "harness": "opencode", "hook": "tool.execute.after",
			"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": map[string]any{"tool": "bash", "args": map[string]string{"command": "cat .env"}},
			"result": map[string]any{"output": secret}}),
		"pi": mustJSON(map[string]any{"protocol": extproto.Protocol, "harness": "pi", "hook": "tool_result",
			"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": map[string]any{"toolName": "bash", "input": map[string]string{"command": "cat .env"}},
			"result": map[string]any{"content": []map[string]string{{"type": "text", "text": secret}}}}),
		"dsh": mustJSON(map[string]any{"protocol": extproto.Protocol, "harness": "dsh", "hook": "tools/post-execute",
			"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": map[string]any{"name": "bash", "arguments": map[string]string{"command": "cat .env"}},
			"result": map[string]any{"content": []map[string]string{{"type": "text", "text": secret}}}}),
	} {
		event := map[string]string{"opencode": "tool.execute.after", "pi": "tool_result", "dsh": "tools/post-execute"}[harness]
		out, _, _ := e.run(in, "hook", harness, "--event", event)
		if got := extAction(t, out); got != "deny" {
			t.Errorf("%s: %s", harness, out)
		}
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

// TestInstallExtHarnesses：install 写出 opencode、pi、omp、dsh 的扩展，status 报告已安装，重装不改动，移除删掉。
func TestInstallExtHarnesses(t *testing.T) {
	e := installEnv(t, nil)
	files := map[string]string{
		"opencode": filepath.Join(e.home, ".config", "opencode", "plugins", "h-guard.js"),
		"pi":       filepath.Join(e.home, ".pi", "agent", "extensions", "h-guard.js"),
		"omp":      filepath.Join(e.home, ".omp", "agent", "extensions", "h-guard-omp.js"),
		"dsh":      filepath.Join(e.configDir, "extensions", "dsh", "h-guard.mjs"),
	}
	for h, path := range files {
		out, errs, code := e.run(nil, "install", h)
		if code != 0 || !strings.Contains(out, "would write") || !strings.Contains(out, path) {
			t.Errorf("%s dry run: exit %d\n%s\n%s", h, code, out, errs)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s: dry run wrote %s", h, path)
		}
		out, errs, code = e.run(nil, "install", h, "--write")
		if code != 0 || !strings.Contains(out, "wrote") || !strings.Contains(out, "restart") {
			t.Errorf("%s: exit %d\n%s\n%s", h, code, out, errs)
		}
		if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), `"/opt/bin/h-guard","hook","`+h+`"`) {
			t.Errorf("%s: %s: %v", h, b, err)
		}
		if out, _, _ := e.run(nil, "install", h, "--write"); !strings.Contains(out, "already installed") {
			t.Errorf("%s reinstall: %s", h, out)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(e.home, ".dsh", "cordis.patch.yml")); !strings.Contains(string(b), files["dsh"]) {
		t.Errorf("dsh patch: %s", b)
	}
	out, _, _ := e.run(nil, "status")
	for _, h := range []string{"opencode", "pi", "omp", "dsh"} {
		if !strings.Contains(out, h+": installed") {
			t.Errorf("status lacks %s:\n%s", h, out)
		}
	}
	if !strings.Contains(out, "opencode commands are checked as posix (harnesses.opencode.shell)") {
		t.Errorf("status lacks the opencode shell:\n%s", out)
	}
	for h, path := range files {
		if _, _, code := e.run(nil, "install", h, "--remove", "--write"); code != 0 {
			t.Errorf("%s remove: exit %d", h, code)
		}
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s: %s left after remove", h, path)
		}
	}
}

// TestInstallOpenCodeShell：opencode 标不出 shell：--shell 写进 harnesses.opencode.shell；Windows 上非交互时要求 --shell。
func TestInstallOpenCodeShell(t *testing.T) {
	e := installEnv(t, nil)
	if _, errs, code := e.run(nil, "install", "pi", "--shell", "posix"); code != 2 || !strings.Contains(errs, "only for codex and opencode") {
		t.Errorf("--shell for pi: exit %d %s", code, errs)
	}
	e.goos = "windows"
	if _, errs, code := e.run(nil, "install", "opencode", "--write"); code != 2 || !strings.Contains(errs, "which shell opencode runs commands with") {
		t.Errorf("windows without --shell: exit %d %s", code, errs)
	}
	out, errs, code := e.run(nil, "install", "opencode", "--write", "--shell", "powershell")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml")); !strings.Contains(string(b), "opencode:") || !strings.Contains(string(b), "shell: powershell") {
		t.Errorf("config.yaml:\n%s", b)
	}
}

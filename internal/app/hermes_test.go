package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

func hermesReq(hook string, data any, result any) []byte {
	r := map[string]any{"protocol": extproto.Protocol, "harness": "hermes", "hook": hook,
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		r["result"] = result
	}
	return mustJSON(r)
}

// TestHermesHooks：Hermes 的插件请求。灾难性命令拒绝；读 .env 在会有人回答（或 Hermes 会拒绝）时请求确认，Hermes 会
// 自动批准（YOLO 等）或读不出时按 when_ask_unsupported 降级为拒绝；消息平台上带凭据的提示词拒绝，pre_llm_call 挡不住，
// 降级为提示并记 prompt_not_blocked；工具结果与后台进程输出里的凭据让结果被替换。
func TestHermesHooks(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\noutbound: {tier: 2}\n")
	key := "deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0"
	tool := func(name string, args any, approval string) []byte {
		return hermesReq("pre_tool_call", map[string]any{"tool_name": name, "args": args, "tool_call_id": "c", "approval": approval}, nil)
	}
	for _, c := range []struct {
		hook string
		in   []byte
		want string
	}{
		{"pre_tool_call", tool("terminal", map[string]string{"command": "rm -rf /"}, "prompt"), "deny"},
		{"pre_tool_call", tool("read_file", map[string]string{"path": "/w/.env"}, "prompt"), "ask"},
		{"pre_tool_call", tool("read_file", map[string]string{"path": "/w/.env"}, "blocked"), "ask"},
		{"pre_tool_call", tool("read_file", map[string]string{"path": "/w/.env"}, "auto"), "deny"},
		{"pre_tool_call", tool("read_file", map[string]string{"path": "/w/.env"}, ""), "deny"},
		{"pre_tool_call", tool("web_search", map[string]string{"query": "x"}, "prompt"), "pass"},
		{"pre_tool_call", tool("execute_code", map[string]string{"code": "print(1)"}, "prompt"), "ask"},
		{"pre_gateway_dispatch", hermesReq("pre_gateway_dispatch", map[string]any{"text": key, "platform": "telegram"}, nil), "deny"},
		{"pre_llm_call", hermesReq("pre_llm_call", map[string]any{"text": key, "platform": "cli"}, nil), "warn"},
		{"transform_tool_result", hermesReq("transform_tool_result", map[string]any{"tool_name": "terminal", "args": map[string]string{"command": "cat .env"}},
			map[string]any{"content": `{"output":"aws_access_key_id = AKIAIOSFODNN7EXAMPL0","exit_code":0}`}), "deny"},
		{"transform_terminal_output", hermesReq("transform_terminal_output", map[string]any{"command": "./run.sh", "env_type": ""},
			map[string]any{"content": "aws_access_key_id = AKIAIOSFODNN7EXAMPL0"}), "deny"},
	} {
		out, errs, code := e.run(c.in, "hook", "hermes", "--event", c.hook)
		if code != 0 {
			t.Errorf("%s: exit %d, stderr %s", c.hook, code, errs)
			continue
		}
		if got := extAction(t, out); got != c.want {
			t.Errorf("%s %s: %s, want %s (%s)", c.hook, c.in, got, c.want, out)
		}
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"prompt_not_blocked"`) || !strings.Contains(h, `"code":"ask_unsupported"`) {
		t.Errorf("health = %s", h)
	}
}

// TestHermesNotify：harnesses.hermes.notify 开启时，deny 的回复带 notify（目标是配置的 to）；没有开启时与 pass 不带。
func TestHermesNotify(t *testing.T) {
	e := newEnv(t)
	in := hermesReq("pre_tool_call", map[string]any{"tool_name": "terminal", "args": map[string]string{"command": "rm -rf /"}, "approval": "prompt"}, nil)
	if out := mustOut(e, in, "hermes", "pre_tool_call"); strings.Contains(out, "notify") {
		t.Errorf("notify without config: %s", out)
	}
	e.config("version: 1\nharnesses:\n  hermes: {notify: {enabled: true, to: 'telegram:-100123'}}\n")
	out := mustOut(e, in, "hermes", "pre_tool_call")
	var r struct {
		Action string
		Notify *struct{ To string }
	}
	if json.Unmarshal([]byte(out), &r) != nil || r.Action != "deny" || r.Notify == nil || r.Notify.To != "telegram:-100123" {
		t.Errorf("notify: %s", out)
	}
	ls := hermesReq("pre_tool_call", map[string]any{"tool_name": "terminal", "args": map[string]string{"command": "ls"}, "approval": "prompt"}, nil)
	if out := mustOut(e, ls, "hermes", "pre_tool_call"); strings.Contains(out, "notify") {
		t.Errorf("pass carries notify: %s", out)
	}
}

// TestInstallHermes：install hermes 写出插件目录并在 config.yaml 的 plugins.enabled 里启用它（从 plugins.disabled 里去掉），
// 其他设置保留；status 报告已安装；重装不改动；移除不读 h-guard 的配置，只去掉 h-guard。
func TestInstallHermes(t *testing.T) {
	e := installEnv(t, func(name string, args ...string) ([]byte, error) {
		if name == "hermes" {
			return []byte("Hermes Agent v2026.9.24 (2026.9.24)\nInstall directory: /opt/hermes\n"), nil
		}
		return nil, os.ErrNotExist
	})
	e.bin = filepath.Join(t.TempDir(), "h-guard")
	if err := os.WriteFile(e.bin, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(e.home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(cfg), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("# my settings\nmodel: {default: some-model}\nplugins:\n  enabled: [disk-cleanup]\n  disabled: [h-guard]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, errs, code := e.run(nil, "install", "hermes"); code != 0 || !strings.Contains(out, "would write") || strings.Contains(out, "some-model") {
		t.Errorf("dry run: exit %d\n%s\n%s", code, out, errs)
	}
	out, errs, code := e.run(nil, "install", "hermes", "--write")
	if code != 0 || !strings.Contains(out, "restart Hermes") {
		t.Fatalf("install: exit %d\n%s\n%s", code, out, errs)
	}
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "h-guard") || strings.Contains(string(b), "disabled: [h-guard]") || !strings.Contains(string(b), "# my settings") {
		t.Errorf("config.yaml:\n%s", b)
	}
	plugin := filepath.Join(e.home, ".hermes", "plugins", "h-guard", "__init__.py")
	if b, err := os.ReadFile(plugin); err != nil || !strings.Contains(string(b), `"hook","hermes","--timeout","20"`) {
		t.Errorf("plugin: %v\n%s", err, b)
	}
	if out, _, _ := e.run(nil, "install", "hermes", "--write"); !strings.Contains(out, "already installed") {
		t.Errorf("reinstall: %s", out)
	}
	out, _, _ = e.run(nil, "status")
	if !strings.Contains(out, "hermes: installed (Hermes Agent 2026.9.24)\n") || strings.Contains(out, "hermes: problem") {
		t.Errorf("status:\n%s", out)
	}
	// 保护摘要：扩展协议的 harness 只有「配置已写入」这一层；Hermes 另说明自动批准时的确认与挡不住的提示词
	for _, want := range []string{"  hermes: config written: yes | hook running: not tracked for hermes | self-test: not available for hermes\n",
		"  hermes: asks go to Hermes's own approval; every ask in a session that Hermes would approve without asking"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	e.config("version: 1\nnot valid: [\n")
	if _, errs, code := e.run(nil, "install", "hermes", "--remove", "--write"); code != 0 {
		t.Fatalf("remove: exit %d %s", code, errs)
	}
	b, _ = os.ReadFile(cfg)
	if strings.Contains(string(b), "h-guard") || !strings.Contains(string(b), "disk-cleanup") {
		t.Errorf("config.yaml after remove:\n%s", b)
	}
	if _, err := os.Stat(filepath.Dir(plugin)); err == nil {
		t.Errorf("plugin directory left after remove")
	}
}

// TestHermesHomeProtected：HERMES_HOME 指定的目录里的 config.yaml 与 h-guard 的插件受防篡改规则保护：文件工具，以及
// 命令里直接写出的实际路径（exec 模式里的 {hermes_home}）。
func TestHermesHomeProtected(t *testing.T) {
	e := newEnv(t)
	e.vars["HERMES_HOME"] = "~/hh"
	for _, p := range []string{filepath.Join(e.home, "hh", "config.yaml"), filepath.Join(e.home, "hh", "plugins", "h-guard", "__init__.py")} {
		in := hermesReq("pre_tool_call", map[string]any{"tool_name": "write_file", "args": map[string]string{"path": p, "content": "x"}, "approval": "prompt"}, nil)
		if got := extAction(t, mustOut(e, in, "hermes", "pre_tool_call")); got == "pass" {
			t.Errorf("write %s: %s", p, got)
		}
	}
	e.vars["HERMES_HOME"] = "/opt/data"
	terminal := func(cmd string) string {
		in := hermesReq("pre_tool_call", map[string]any{"tool_name": "terminal", "args": map[string]string{"command": cmd}, "approval": "prompt"}, nil)
		return extAction(t, mustOut(e, in, "hermes", "pre_tool_call"))
	}
	for _, cmd := range []string{"rm -rf /opt/data/plugins/h-guard", "sed -i '/h-guard/d' /opt/data/config.yaml", "mv /opt/data/plugins /tmp/x"} {
		if got := terminal(cmd); got == "pass" {
			t.Errorf("%s: %s", cmd, got)
		}
	}
	if got := terminal("ls /opt/data/plugins/h-guard"); got != "pass" {
		t.Errorf("reading the plugin directory: %s", got)
	}
	// 托管范围的配置（HERMES_MANAGED_DIR）同样受保护：命令里的实际路径与文件工具
	e.vars["HERMES_MANAGED_DIR"] = "/srv/policy"
	if got := terminal("sudo tee /srv/policy/config.yaml < /tmp/x"); got == "pass" {
		t.Errorf("managed config: %s", got)
	}
	in := hermesReq("pre_tool_call", map[string]any{"tool_name": "write_file", "args": map[string]string{"path": "/srv/policy/config.yaml", "content": "x"}, "approval": "prompt"}, nil)
	if got := extAction(t, mustOut(e, in, "hermes", "pre_tool_call")); got == "pass" {
		t.Errorf("write the managed config: %s", got)
	}
}

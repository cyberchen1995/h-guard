package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type codexHooks struct {
	Hooks map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Timeout int    `json:"timeout"`
		} `json:"hooks"`
	} `json:"hooks"`
}

func readHooks(t *testing.T, path string) codexHooks {
	t.Helper()
	var h codexHooks
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestCodexInstall：~/.codex/hooks.json 注册 PreToolUse（全部工具）、PostToolUse、UserPromptSubmit，每个命令带
// 自己的 --event 与 --timeout，超时写进 hook（秒）（spec §12；Codex 官方文档：hooks.json、timeout 以秒计）。
func TestCodexInstall(t *testing.T) {
	tg := target(t, "linux")
	steps, err := Codex(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	h := readHooks(t, filepath.Join(tg.Home, ".codex", "hooks.json"))
	for _, ev := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		g := h.Hooks[ev]
		if len(g) != 1 || g[0].Matcher != "" || len(g[0].Hooks) != 1 {
			t.Fatalf("%s: %+v", ev, g)
		}
		if c := g[0].Hooks[0]; c.Type != "command" || c.Timeout != 20 || c.Command != "'/opt/bin/h-guard' hook codex --event "+ev+" --timeout 20" {
			t.Errorf("%s: %+v", ev, c)
		}
	}
	steps, _ = Codex(tg, false)
	for _, s := range steps {
		if s.Changes() {
			t.Errorf("reinstall changes %s", s.Path)
		}
	}
}

// TestCodexKeepsOtherHooks：已有的其他 hook 原样保留；重装时替换本项目旧的入口（如超时变了），不新增；
// 移除只删本项目的入口，删空的组与事件。CODEX_HOME 指定 Codex 的目录。
func TestCodexKeepsOtherHooks(t *testing.T) {
	tg := target(t, "linux")
	codexHome := t.TempDir()
	tg.Getenv = func(k string) string {
		if k == "CODEX_HOME" {
			return codexHome
		}
		return ""
	}
	path := filepath.Join(codexHome, "hooks.json")
	other := `{"description":"mine","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"audit.sh","timeout":5}]},` +
		`{"hooks":[{"type":"command","command":"'/old/h-guard' hook codex --event PreToolUse --timeout 10","timeout":10}]}],"Stop":[{"hooks":[{"type":"command","command":"notify.sh"}]}]}}`
	os.WriteFile(path, []byte(other), 0o600)
	steps, err := Codex(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	b, _ := os.ReadFile(path)
	h := readHooks(t, path)
	pre := h.Hooks["PreToolUse"]
	if len(pre) != 2 || pre[0].Hooks[0].Command != "audit.sh" || !strings.Contains(pre[1].Hooks[0].Command, "/opt/bin/h-guard' hook codex") ||
		len(h.Hooks["Stop"]) != 1 || !strings.HasPrefix(string(b), "{\n  \"description\": \"mine\",") {
		t.Errorf("hooks.json =\n%s", b)
	}
	steps, err = Codex(tg, true)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	h = readHooks(t, path)
	if len(h.Hooks["PreToolUse"]) != 1 || h.Hooks["PreToolUse"][0].Hooks[0].Command != "audit.sh" ||
		h.Hooks["PostToolUse"] != nil || h.Hooks["UserPromptSubmit"] != nil || len(h.Hooks["Stop"]) != 1 {
		t.Errorf("after remove: %+v", h)
	}
}

// TestCodexCommandQuoting：POSIX 上路径一律加单引号（Codex 用 sh -c 运行，* ? [ ~ 这类字符不能被展开，审查次要 5）；
// Windows 上 Codex 用哪种 shell 运行 hook 没有核实，cmd 与 PowerShell 对带引号的程序路径写法不同，所以要加引号的
// 路径拒绝安装（审查 I7），不带特殊字符的路径照写。
func TestCodexCommandQuoting(t *testing.T) {
	for _, c := range []struct{ goos, bin, want string }{
		{"darwin", "/Users/me/Library/Application Support/bin/h-guard", `'/Users/me/Library/Application Support/bin/h-guard' hook codex --event PreToolUse --timeout 20`},
		{"linux", "/usr/local/bin/h-guard", `'/usr/local/bin/h-guard' hook codex --event PreToolUse --timeout 20`},
		{"linux", "/x/hg*x/it's/h-guard", `'/x/hg*x/it'\''s/h-guard' hook codex --event PreToolUse --timeout 20`},
		{"windows", `C:\Tools\h-guard.exe`, `C:\Tools\h-guard.exe hook codex --event PreToolUse --timeout 20`},
	} {
		tg := target(t, c.goos)
		tg.Bin = c.bin
		if got, err := codexCommand(tg, "PreToolUse"); err != nil || got != c.want {
			t.Errorf("%s %s: %s, %v", c.goos, c.bin, got, err)
		}
	}
	tg := target(t, "windows")
	tg.Bin = `C:\Program Files\h-guard\h-guard.exe`
	if _, err := Codex(tg, false); err == nil || !strings.Contains(err.Error(), "without spaces") {
		t.Errorf("a Windows path with spaces was accepted: %v", err)
	}
	if _, err := Codex(tg, true); err != nil {
		t.Errorf("removal needs no command: %v", err)
	}
}

// TestCodexKeepsOtherEntriesVerbatim：同一事件下别人的 hook 组按原文保留（键的顺序、<、& 不被转义）；别人的包装
// 脚本即使带着 hook codex --event 也不是本项目的入口（第一个词不是 h-guard），安装与移除都不动它；只打印时只显示
// 本项目的入口（审查次要 3、9）。
func TestCodexKeepsOtherEntriesVerbatim(t *testing.T) {
	tg := target(t, "linux")
	path := CodexHooks(tg)
	os.MkdirAll(filepath.Dir(path), 0o700)
	orig := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"a < b && c","timeout":5e0}]},` +
		`{"hooks":[{"type":"command","command":"wrap.sh hook codex --event PreToolUse"}]}]}}`
	os.WriteFile(path, []byte(orig), 0o600)
	steps, err := Codex(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := string(steps[0].Preview); !strings.Contains(p, "PreToolUse: '/opt/bin/h-guard' hook codex --event PreToolUse --timeout 20") || strings.Contains(p, "wrap.sh") {
		t.Errorf("preview = %q", p)
	}
	apply(t, steps)
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"matcher": "Bash",`) || !strings.Contains(string(b), `"command": "a < b && c",`) ||
		!strings.Contains(string(b), `"timeout": 5e0`) || !strings.Contains(string(b), "wrap.sh hook codex") {
		t.Errorf("after install:\n%s", b)
	}
	steps, _ = Codex(tg, true)
	apply(t, steps)
	b, _ = os.ReadFile(path)
	if !strings.Contains(string(b), "wrap.sh hook codex") || strings.Contains(string(b), "/opt/bin/h-guard") {
		t.Errorf("after remove:\n%s", b)
	}
}

// TestCodexUnreadableHooks：读不懂的 hooks.json 不覆盖。
func TestCodexUnreadableHooks(t *testing.T) {
	tg := target(t, "linux")
	path := filepath.Join(tg.Home, ".codex", "hooks.json")
	os.MkdirAll(filepath.Dir(path), 0o700)
	for _, bad := range []string{`{"hooks": []}`, `{"hooks": {"PreToolUse": {}}}`, `not json`} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := Codex(tg, false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestCodexShellInConfig：--shell 写进 h-guard 配置的 harnesses.codex.shell；已有的配置与注释保留。
func TestCodexShellInConfig(t *testing.T) {
	tg := target(t, "windows")
	cfg := filepath.Join(tg.ConfigDir, "config.yaml")
	step, err := HarnessShell(tg, "codex", "powershell")
	if err != nil {
		t.Fatal(err)
	}
	apply(t, []Step{step})
	if b, _ := os.ReadFile(cfg); string(b) != "version: 1\nharnesses:\n  codex:\n    shell: powershell\n" {
		t.Errorf("new config =\n%s", b)
	}
	os.WriteFile(cfg, []byte("version: 1\n# my judge\njudge: {enabled: true, backend: jev}\nharnesses:\n  codex: {shell: posix}\n"), 0o600)
	step, _ = HarnessShell(tg, "codex", "powershell")
	apply(t, []Step{step})
	b, _ := os.ReadFile(cfg)
	if !strings.Contains(string(b), "# my judge") || !strings.Contains(string(b), "judge: {enabled: true, backend: jev}") ||
		!strings.Contains(string(b), "shell: powershell") || strings.Contains(string(b), "posix") {
		t.Errorf("edited config =\n%s", b)
	}
	step, _ = HarnessShell(tg, "codex", "powershell")
	if step.Changes() {
		t.Error("setting the same shell again changes the config")
	}
	os.WriteFile(cfg, []byte("- not a mapping\n"), 0o600)
	if _, err := HarnessShell(tg, "codex", "posix"); err == nil {
		t.Error("a config that is not a mapping was accepted")
	}
}

// TestCodexVersionNotes：低于 0.162.1 未经验证；装好后提醒在 Codex 里用 /hooks 信任新的 hook。
func TestCodexVersionNotes(t *testing.T) {
	tg := target(t, "linux")
	tg.Run = func(string, ...string) ([]byte, error) { return []byte("codex-cli 0.150.0\n"), nil }
	notes := strings.Join(CodexNotes(tg), "\n")
	if !strings.Contains(notes, "0.150.0 has not been verified") || !strings.Contains(notes, "/hooks") {
		t.Errorf("notes = %s", notes)
	}
	tg.Run = func(string, ...string) ([]byte, error) { return []byte("codex-cli 0.162.1\n"), nil }
	if notes := CodexNotes(tg); len(notes) != 1 || !strings.Contains(notes[0], "/hooks") {
		t.Errorf("notes = %q", notes)
	}
}

// TestCodexRenamedBinary：本项目的入口按程序名 h-guard 认出；改了名的 h-guard 写进去以后既不能重装也不能移除，
// 所以拒绝安装、什么都不写（计划评审 M3D-02）。
func TestCodexRenamedBinary(t *testing.T) {
	tg := target(t, "linux")
	tg.Bin = "/opt/bin/h-guard-dev"
	if _, err := Codex(tg, false); err == nil || !strings.Contains(err.Error(), "named h-guard") {
		t.Errorf("err = %v", err)
	}
	if _, err := os.Stat(CodexHooks(tg)); !os.IsNotExist(err) {
		t.Errorf("hooks.json written: %v", err)
	}
}

// TestCodexOwnershipIsExact：本项目的入口是「h-guard hook codex --event <事件> --timeout <秒>」这一整串；别的子命令、
// 引号里的文字、多出的参数都不算，安装与移除都不动它们（计划评审 M3D-03）。
func TestCodexOwnershipIsExact(t *testing.T) {
	tg := target(t, "linux")
	path := CodexHooks(tg)
	os.MkdirAll(filepath.Dir(path), 0o700)
	others := []string{
		`h-guard check --request 'please run hook codex --event PreToolUse' 'git status'`,
		`/usr/bin/h-guard hook codex --event PreToolUse --timeout 20 --config /x.yaml`,
		`h-guard hook claudecode --event PreToolUse`,
	}
	var groups []string
	for _, c := range others {
		b, _ := json.Marshal(c)
		groups = append(groups, `{"hooks":[{"type":"command","command":`+string(b)+`}]}`)
	}
	os.WriteFile(path, []byte(`{"hooks":{"PreToolUse":[`+strings.Join(groups, ",")+`]}}`), 0o600)
	steps, err := Codex(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	steps, _ = Codex(tg, true)
	apply(t, steps)
	b, _ := os.ReadFile(path)
	for _, c := range others {
		j, _ := json.Marshal(c)
		if !strings.Contains(string(b), string(j)) {
			t.Errorf("%s was removed:\n%s", c, b)
		}
	}
	if strings.Contains(string(b), "/opt/bin/h-guard") {
		t.Errorf("our entry is left:\n%s", b)
	}
	for cmd, want := range map[string]bool{
		"'/opt/bin/h-guard' hook codex --event PreToolUse --timeout 20":  true,
		`C:\h-guard.exe hook codex --event UserPromptSubmit --timeout 5`: true,
		"h-guard hook codex --event Stop --timeout 20":                   false,
		"h-guard hook codex --event PreToolUse --timeout x":              false,
		others[0]: false, others[1]: false,
	} {
		if got := isOurCodexHook(cmd); got != want {
			t.Errorf("isOurCodexHook(%q) = %v", cmd, got)
		}
	}
}

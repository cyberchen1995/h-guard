package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
)

func target(t *testing.T, goos string) Target {
	home := t.TempDir()
	return Target{
		Home: home, ConfigDir: filepath.Join(home, ".config", "h-guard"), CacheDir: filepath.Join(home, ".cache", "h-guard"),
		Bin: "/opt/bin/h-guard", Timeout: 20, GOOS: goos, Getenv: func(string) string { return "" },
		Now: func() time.Time { return time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC) },
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	var m map[string]any
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

func apply(t *testing.T, steps []Step) {
	t.Helper()
	if err := Apply(steps); err != nil {
		t.Fatal(err)
	}
}

// TestClaudeCodeInstall：插件写到 <config_dir>/extensions/claudecode，经典 PreToolUse 与 mod 的命令、超时一致；
// 插件目录加入 settings.json 的 env.CLAUDE_CODE_PLUGIN_DIRS。
func TestClaudeCodeInstall(t *testing.T) {
	tg := target(t, "darwin")
	steps, err := ClaudeCode(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(tg.ConfigDir, "extensions", "claudecode")
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("planning wrote files")
	}
	apply(t, steps)
	for _, f := range []string{".claude-plugin/plugin.json", "hooks/register.js", "hooks/pretooluse.sh", "hooks/pretooluse.ps1"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hguard-bin")); string(b) != "/opt/bin/h-guard\n" {
		t.Errorf("hguard-bin = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hguard-timeout")); string(b) != "20\n" {
		t.Errorf("hguard-timeout = %q", b)
	}
	cfg := readJSON(t, filepath.Join(dir, "hguard.json"))
	want := []any{"/opt/bin/h-guard", "hook", "claudecode", "--timeout", "20"}
	cmds := cfg["commands"].(map[string]any)
	if !slices.Equal(cmds["tool.result"].([]any), want) || !slices.Equal(cmds["prompt.submit"].([]any), want) || cfg["timeout_ms"] != 20000.0 {
		t.Errorf("hguard.json = %v", cfg)
	}
	hooks := readJSON(t, filepath.Join(dir, "hooks", "hooks.json"))
	h := hooks["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if h["timeout"] != 20.0 || h["command"] != `sh "${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.sh"` {
		t.Errorf("PreToolUse hook = %v", h)
	}
	settings := readJSON(t, filepath.Join(tg.Home, ".claude", "settings.json"))
	if got := settings["env"].(map[string]any)["CLAUDE_CODE_PLUGIN_DIRS"]; got != dir {
		t.Errorf("CLAUDE_CODE_PLUGIN_DIRS = %v", got)
	}
	// 重复安装只更新、不新增
	steps, _ = ClaudeCode(tg, false)
	for _, s := range steps {
		if s.Changes() {
			t.Errorf("reinstall changes %s", s.Path)
		}
	}
}

// TestClaudeCodeKeepsOtherSettings：已有的其他设置与插件目录原样保留，只加本项目的目录。
func TestClaudeCodeKeepsOtherSettings(t *testing.T) {
	tg := target(t, "linux")
	settings := filepath.Join(tg.Home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(settings), 0o700)
	os.WriteFile(settings, []byte(`{"model":"opus","env":{"FOO":"1","CLAUDE_CODE_PLUGIN_DIRS":"/a:/b"},"hooks":{"Stop":[]}}`), 0o644)
	steps, err := ClaudeCode(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	b, _ := os.ReadFile(settings)
	dir := filepath.Join(tg.ConfigDir, "extensions", "claudecode")
	if !strings.HasPrefix(string(b), "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"FOO\": \"1\",") ||
		!strings.Contains(string(b), `"CLAUDE_CODE_PLUGIN_DIRS": "/a:/b:`+dir+`"`) || !strings.Contains(string(b), `"Stop": []`) {
		t.Errorf("settings.json =\n%s", b)
	}
	if backups, _ := os.ReadDir(filepath.Join(tg.CacheDir, "backups")); len(backups) != 1 {
		t.Errorf("backups = %v", backups)
	}
	// 移除只删本项目的目录与插件文件
	steps, err = ClaudeCode(tg, true)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	b, _ = os.ReadFile(settings)
	if !strings.Contains(string(b), `"CLAUDE_CODE_PLUGIN_DIRS": "/a:/b"`) || !strings.Contains(string(b), `"FOO": "1"`) {
		t.Errorf("after remove:\n%s", b)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin dir still there: %v", err)
	}
}

// TestClaudeCodeRemoveDropsEmptyEntries：移除后列表空了就删掉这个键，env 空了也删掉；没有安装时移除不改任何东西。
func TestClaudeCodeRemoveDropsEmptyEntries(t *testing.T) {
	tg := target(t, "linux")
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	steps, _ = ClaudeCode(tg, true)
	apply(t, steps)
	settings := readJSON(t, filepath.Join(tg.Home, ".claude", "settings.json"))
	if _, ok := settings["env"]; ok {
		t.Errorf("settings = %v", settings)
	}
	steps, err := ClaudeCode(tg, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range steps {
		if s.Changes() {
			t.Errorf("removing again changes %s", s.Path)
		}
	}
}

// TestClaudeCodeOptions：--timeout 同时写进 hooks.json、hguard-timeout 与 hguard.json；Windows 上 PreToolUse 用
// PowerShell 外包、插件目录以 ; 分隔；CLAUDE_CONFIG_DIR 指定 Claude Code 的配置目录。
func TestClaudeCodeOptions(t *testing.T) {
	tg := target(t, "windows")
	tg.Timeout = 30
	claudeDir := t.TempDir()
	tg.Getenv = func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return claudeDir
		}
		return ""
	}
	os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"env":{"CLAUDE_CODE_PLUGIN_DIRS":"C:\\a"}}`), 0o600)
	steps, err := ClaudeCode(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	dir := filepath.Join(tg.ConfigDir, "extensions", "claudecode")
	hooks := readJSON(t, filepath.Join(dir, "hooks", "hooks.json"))
	h := hooks["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if h["timeout"] != 30.0 || h["command"] != `powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.ps1"` {
		t.Errorf("PreToolUse hook = %v", h)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hguard-timeout")); string(b) != "30\n" {
		t.Errorf("hguard-timeout = %q", b)
	}
	if cfg := readJSON(t, filepath.Join(dir, "hguard.json")); cfg["timeout_ms"] != 30000.0 {
		t.Errorf("hguard.json = %v", cfg)
	}
	settings := readJSON(t, filepath.Join(claudeDir, "settings.json"))
	if got := settings["env"].(map[string]any)["CLAUDE_CODE_PLUGIN_DIRS"]; got != `C:\a;`+dir {
		t.Errorf("CLAUDE_CODE_PLUGIN_DIRS = %v", got)
	}
}

// TestClaudeCodeUnreadableSettings：读不懂的 settings.json 不覆盖。
func TestClaudeCodeUnreadableSettings(t *testing.T) {
	tg := target(t, "linux")
	settings := filepath.Join(tg.Home, ".claude", "settings.json")
	os.MkdirAll(filepath.Dir(settings), 0o700)
	os.WriteFile(settings, []byte(`{"env": [1, 2]}`), 0o600)
	steps, err := ClaudeCode(tg, false)
	if err == nil {
		err = Apply(steps)
	}
	if err == nil {
		t.Fatal("an env that is not an object was accepted")
	}
	if b, _ := os.ReadFile(settings); string(b) != `{"env": [1, 2]}` {
		t.Errorf("settings.json changed: %s", b)
	}
}

// TestClaudeCodeVersionNotes：Claude Code 低于 2.1.290 没有 mods；低于 2.1.296 未经验证；找不到 claude 时说明。
func TestClaudeCodeVersionNotes(t *testing.T) {
	for out, want := range map[string]string{
		"2.1.280 (Claude Code)": "needs Claude Code 2.1.290 or later",
		"2.1.293 (Claude Code)": "has not been verified",
		"2.1.296 (Claude Code)": "",
		"2.2.0 (Claude Code)":   "",
	} {
		tg := target(t, "linux")
		tg.Run = func(name string, args ...string) ([]byte, error) { return []byte(out + "\n"), nil }
		notes := ClaudeCodeNotes(tg)
		if want == "" && len(notes) != 0 || want != "" && !strings.Contains(strings.Join(notes, "\n"), want) {
			t.Errorf("%s: notes %q", out, notes)
		}
	}
	tg := target(t, "linux")
	tg.Run = func(string, ...string) ([]byte, error) { return nil, errors.New("not found") }
	if notes := ClaudeCodeNotes(tg); len(notes) != 1 || !strings.Contains(notes[0], "claude was not found") {
		t.Errorf("notes = %q", notes)
	}
}

// TestPowerShellWrapper：Windows 外包与 sh 外包的行为一致（读 hguard-bin、hguard-timeout，失败时输出同样的 ask），
// 只用 Windows PowerShell 5.1 也有的写法。实际运行随版本最后的 Windows 实机验证。
func TestPowerShellWrapper(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "extensions", "claudecode", "hooks", "pretooluse.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	sh, _ := os.ReadFile(filepath.Join("..", "..", "extensions", "claudecode", "hooks", "pretooluse.sh"))
	ps := string(b)
	const ask = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"h-guard could not run its check, so this tool call needs your confirmation."}}`
	// Windows PowerShell 5.1 的 Get-Content 默认按系统代码页读，路径含中文时读成乱码（审查 I8）
	for _, want := range []string{ask, "hguard-bin", "hguard-timeout", "hook claudecode --event PreToolUse --timeout $timeout", "$LASTEXITCODE -eq 0", "UTF8Encoding", "-Encoding UTF8"} {
		if !strings.Contains(ps, want) {
			t.Errorf("pretooluse.ps1 lacks %q", want)
		}
	}
	if !strings.Contains(string(sh), ask) {
		t.Error("the sh wrapper's ask differs")
	}
	// 调用 h-guard 时不能是 ErrorActionPreference = 'Stop'：5.1 里原生程序重定向的 stderr 也会变成错误记录，Stop 下
	// 第一条就终止，有效的回答（含 deny）被换成兜底的 ask
	call := strings.Index(ps, "& $bin hook claudecode")
	cont := strings.LastIndex(ps[:max(call, 0)], "$ErrorActionPreference = 'Continue'")
	if call < 0 || cont < 0 || strings.Contains(ps[cont:call], "$ErrorActionPreference = 'Stop'") {
		t.Error("pretooluse.ps1 must call h-guard with $ErrorActionPreference = 'Continue'")
	}
	for _, ps7 := range []string{"??", "&&", "||", "?."} {
		if strings.Contains(ps, ps7) {
			t.Errorf("pretooluse.ps1 uses %q, which Windows PowerShell 5.1 lacks", ps7)
		}
	}
}

// TestClaudeCodeRemoveOrder：移除时先从 settings.json 去掉登记、再删插件目录：第二步失败时不会留下指向不存在
// 目录的登记（审查 I9）。
func TestClaudeCodeRemoveOrder(t *testing.T) {
	tg := target(t, "linux")
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	steps, _ = ClaudeCode(tg, true)
	if len(steps) != 2 || steps[0].Path != ClaudeSettings(tg) || steps[1].Path != ClaudePluginDir(tg) {
		t.Errorf("remove steps = %v, %v", steps[0].Path, steps[1].Path)
	}
}

// TestClaudeCodePreviewShowsOnlyOurEntry：只打印不写入时，只显示 env.CLAUDE_CODE_PLUGIN_DIRS 改动前后的值，
// settings.json 的其他内容（可能有认不出的秘密）不显示（审查次要 10）。
func TestClaudeCodePreviewShowsOnlyOurEntry(t *testing.T) {
	tg := target(t, "linux")
	settings := ClaudeSettings(tg)
	os.MkdirAll(filepath.Dir(settings), 0o700)
	os.WriteFile(settings, []byte(`{"env":{"DB_PASSWORD":"hunter2-not-a-real-one","CLAUDE_CODE_PLUGIN_DIRS":"/a"}}`), 0o600)
	steps, _ := ClaudeCode(tg, false)
	p := string(steps[1].Preview)
	if !strings.Contains(p, "env.CLAUDE_CODE_PLUGIN_DIRS: /a -> /a:"+ClaudePluginDir(tg)) || strings.Contains(p, "hunter2") {
		t.Errorf("preview = %q", p)
	}
}

// TestClaudeCodeWindowsPathCase：Windows 上路径不区分大小写，已登记的同一目录不重复登记（审查次要 16）。
func TestClaudeCodeWindowsPathCase(t *testing.T) {
	tg := target(t, "windows")
	tg.ConfigDir = `C:\Users\me\AppData\Roaming\h-guard`
	settings := ClaudeSettings(tg)
	os.MkdirAll(filepath.Dir(settings), 0o700)
	os.WriteFile(settings, []byte(`{"env":{"CLAUDE_CODE_PLUGIN_DIRS":"`+strings.ReplaceAll(strings.ToLower(ClaudePluginDir(tg)), `\`, `\\`)+`"}}`), 0o600)
	steps, err := ClaudeCode(tg, false)
	if err != nil || steps[1].Changes() {
		t.Errorf("the same directory in another case was registered again: %v, %q", err, steps[1].Preview)
	}
}

// TestApplyHoldsTheLock：另一个 install 持有锁时，任何文件都不改动（曾经插件照样写出，直到改
// settings.json 才报错，留下一半的安装）。
func TestApplyHoldsTheLock(t *testing.T) {
	tg := target(t, "linux")
	steps, err := ClaudeCode(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := store.Lock(tg.editor().LockDir)
	if err != nil {
		t.Skip("locking unsupported:", err)
	}
	defer unlock()
	if err := Apply(steps); !errors.Is(err, store.ErrLocked) {
		t.Errorf("Apply = %v", err)
	}
	for _, p := range []string{ClaudePluginDir(tg), ClaudeSettings(tg)} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was written while another install held the lock", p)
		}
	}
}

// TestPluginChangedAfterPlanning：计划之后插件目录被换成别的东西或被改动，执行时报冲突，不删除、不覆盖。
func TestPluginChangedAfterPlanning(t *testing.T) {
	tg := target(t, "linux")
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	dir := ClaudePluginDir(tg)
	steps, _ = ClaudeCode(tg, true)
	os.WriteFile(filepath.Join(dir, ".claude-plugin", "plugin.json"), []byte(`{"name":"not-h-guard"}`), 0o600)
	if err := Apply(steps); !errors.Is(err, store.ErrConflict) {
		t.Errorf("remove after the plugin was replaced: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude-plugin", "plugin.json")); err != nil {
		t.Errorf("the replaced plugin was deleted: %v", err)
	}
	tg2 := target(t, "linux")
	steps, _ = ClaudeCode(tg2, false)
	apply(t, steps)
	tg2.Timeout = 30
	steps, _ = ClaudeCode(tg2, false)
	os.WriteFile(filepath.Join(ClaudePluginDir(tg2), "hooks", "register.js"), []byte("// mine"), 0o600)
	if err := Apply(steps); !errors.Is(err, store.ErrConflict) {
		t.Errorf("reinstall after a file was edited: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(ClaudePluginDir(tg2), "hooks", "register.js")); string(b) != "// mine" {
		t.Errorf("the edited file was overwritten")
	}
}

// TestPluginBackup：覆盖或删除插件目录之前，把原来的文件备份到 <cache_dir>/backups。
func TestPluginBackup(t *testing.T) {
	tg := target(t, "linux")
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	tg.Timeout = 30
	steps, _ = ClaudeCode(tg, false)
	apply(t, steps)
	matches, _ := filepath.Glob(filepath.Join(tg.CacheDir, "backups", "claudecode-plugin.*", "hguard-timeout"))
	if len(matches) != 1 {
		t.Fatalf("backups = %v", matches)
	}
	if b, _ := os.ReadFile(matches[0]); string(b) != "20\n" {
		t.Errorf("backup = %q", b)
	}
}

// TestStalePlanChecksUnchangedSteps：计划里不需要改动的步骤同样在执行时复核：修复登记的计划（插件不变、只改
// settings.json）规划之后，插件被另一个 install 卸载，执行时报冲突，不登记一个不存在的插件。
// 普通的重复安装仍然什么都不写、不备份。
func TestStalePlanChecksUnchangedSteps(t *testing.T) {
	tg := target(t, "linux")
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	settings := ClaudeSettings(tg)
	os.WriteFile(settings, []byte("{}"), 0o600) // 登记被去掉，插件还在
	repair, err := ClaudeCode(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	if repair[0].Changes() || !repair[1].Changes() {
		t.Fatalf("repair plan: plugin %v, settings %v", repair[0].Changes(), repair[1].Changes())
	}
	if err := os.RemoveAll(ClaudePluginDir(tg)); err != nil { // 另一个 install 卸载了插件
		t.Fatal(err)
	}
	if err := Apply(repair); !errors.Is(err, store.ErrConflict) {
		t.Errorf("Apply = %v", err)
	}
	if b, _ := os.ReadFile(settings); string(b) != "{}" {
		t.Errorf("the missing plugin was registered: %s", b)
	}
	// 没有改动的重复安装：不写、不备份
	steps, _ = ClaudeCode(tg, false)
	apply(t, steps)
	backups, _ := os.ReadDir(filepath.Join(tg.CacheDir, "backups"))
	before := len(backups)
	steps, _ = ClaudeCode(tg, false)
	apply(t, steps)
	if after, _ := os.ReadDir(filepath.Join(tg.CacheDir, "backups")); len(after) != before {
		t.Errorf("an unchanged reinstall made backups: %d -> %d", before, len(after))
	}
}

package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/store"
)

func hermesPlan(t *testing.T, tg Target, remove bool) []Step {
	t.Helper()
	steps, err := Hermes(tg, remove)
	if err != nil {
		t.Fatal(err)
	}
	return steps
}

// TestHermesPaths：$HERMES_HOME（开头的 ~ 展开）、$HERMES_DATA_DIR_SUFFIX 与 Windows 的 %LOCALAPPDATA%\hermes。
func TestHermesPaths(t *testing.T) {
	tg := target(t, "linux")
	if got, want := HermesPluginDir(tg), filepath.Join(tg.Home, ".hermes", "plugins", "h-guard"); got != want {
		t.Errorf("default: %s, want %s", got, want)
	}
	tg.Getenv = env(map[string]string{"HERMES_HOME": "~/hh"})
	if got := HermesConfig(tg); got != filepath.Join(tg.Home, "hh", "config.yaml") {
		t.Errorf("HERMES_HOME with ~: %s", got)
	}
	tg.Getenv = env(map[string]string{"HERMES_HOME": "  ", "HERMES_DATA_DIR_SUFFIX": "-dev"})
	if got := HermesHome(tg); got != filepath.Join(tg.Home, ".hermes-dev") {
		t.Errorf("suffix: %s", got)
	}
	win := target(t, "windows")
	win.Getenv = env(map[string]string{"LOCALAPPDATA": filepath.Join(win.Home, "LAD")})
	if got := HermesHome(win); got != filepath.Join(win.Home, "LAD", "hermes") {
		t.Errorf("windows: %s", got)
	}
}

// TestHermesInstall：插件目录（plugin.yaml 与 __init__.py）写出，CONFIG 一行可读回；config.yaml 的其他内容与注释保留，
// h-guard 加进 plugins.enabled、从 plugins.disabled 去掉；重装不改动；Python 生成的 __pycache__ 不算改动；status 没有问题。
func TestHermesInstall(t *testing.T) {
	tg := target(t, "linux")
	tg.Bin = filepath.Join(tg.Home, "bin", "h-guard")
	os.MkdirAll(filepath.Dir(tg.Bin), 0o700)
	os.WriteFile(tg.Bin, nil, 0o700)
	cfg := HermesConfig(tg)
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("# mine\nmodel: {default: m}\nplugins:\n  enabled: [disk-cleanup]\n  disabled: [noisy, h-guard]\ncommand_allowlist: [rm_rf]\n"), 0o600)
	apply(t, hermesPlan(t, tg, false))
	b, _ := os.ReadFile(cfg)
	st, err := readHermesState(b)
	if err != nil || !st.enabled || st.disabled {
		t.Fatalf("state %+v %v:\n%s", st, err, b)
	}
	for _, keep := range []string{"# mine", "default: m", "disk-cleanup", "noisy", "rm_rf"} {
		if !strings.Contains(string(b), keep) {
			t.Errorf("lost %q:\n%s", keep, b)
		}
	}
	if strings.Contains(string(b), "hook_callback_timeout") {
		t.Errorf("the default hook timeout is long enough, but it was set:\n%s", b)
	}
	initPy, _ := os.ReadFile(filepath.Join(HermesPluginDir(tg), "__init__.py"))
	if bin, timeout, ok := installedHermes(initPy); !ok || bin != tg.Bin || timeout != 20 {
		t.Errorf("installedHermes = %q %d %v", bin, timeout, ok)
	}
	os.MkdirAll(filepath.Join(HermesPluginDir(tg), "__pycache__"), 0o700)
	os.WriteFile(filepath.Join(HermesPluginDir(tg), "__pycache__", "__init__.cpython-312.pyc"), []byte("x"), 0o600)
	noChanges(t, hermesPlan(t, tg, false))
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); strings.Contains(lines, "problem") || strings.Contains(lines, "not installed") {
		t.Errorf("status:\n%s", lines)
	}

	apply(t, hermesPlan(t, tg, true))
	b, _ = os.ReadFile(cfg)
	if st, _ := readHermesState(b); st.enabled || !strings.Contains(string(b), "disk-cleanup") {
		t.Errorf("after remove:\n%s", b)
	}
	if _, err := os.Stat(HermesPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin directory left: %v", err)
	}
	if backups, _ := filepath.Glob(filepath.Join(tg.CacheDir, "backups", "hermes-plugin.*", "__init__.py")); len(backups) != 1 {
		t.Errorf("backups: %v", backups)
	}
	noChanges(t, hermesPlan(t, tg, true))
	if lines := Inspect(tg, "hermes"); len(lines) != 1 || !strings.HasPrefix(lines[0], "not installed") {
		t.Errorf("status after remove: %v", lines)
	}
}

// TestHermesNewConfig：没有 config.yaml 时新建，只有 plugins.enabled；移除时去掉它（空了的 plugins 一并去掉）；没有安装时
// 移除不新建文件。
func TestHermesNewConfig(t *testing.T) {
	tg := target(t, "linux")
	apply(t, hermesPlan(t, tg, false))
	b, _ := os.ReadFile(HermesConfig(tg))
	if string(b) != "plugins:\n  enabled:\n    - h-guard\n" {
		t.Errorf("new config:\n%s", b)
	}
	apply(t, hermesPlan(t, tg, true))
	if b, _ := os.ReadFile(HermesConfig(tg)); strings.TrimSpace(string(b)) != "{}" {
		t.Errorf("after remove: %q", b)
	}
	tg2 := target(t, "linux")
	noChanges(t, hermesPlan(t, tg2, true))
	if _, err := os.Stat(HermesConfig(tg2)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove created the config: %v", err)
	}
}

// TestHermesHookTimeout：plugins.hook_callback_timeout 不到 h-guard 的超时加 5 秒时调高（0 表示不限时，不改）；status 报告太短的值。
func TestHermesHookTimeout(t *testing.T) {
	for body, want := range map[string]string{
		"plugins: {hook_callback_timeout: 10}\n": "hook_callback_timeout: 25",
		"plugins: {hook_callback_timeout: 0}\n":  "hook_callback_timeout: 0",
		"plugins: {hook_callback_timeout: 90}\n": "hook_callback_timeout: 90",
	} {
		got, err := hermesConfigEdit([]byte(body), true, 20, false)
		if err != nil || !strings.Contains(string(got), want) {
			t.Errorf("%q: %v\n%s", body, err, got)
		}
	}
	got, _ := hermesConfigEdit(nil, false, 40, false)
	if !strings.Contains(string(got), "hook_callback_timeout: 45") {
		t.Errorf("--timeout 40:\n%s", got)
	}
	tg := target(t, "linux")
	apply(t, hermesPlan(t, tg, false))
	os.WriteFile(HermesConfig(tg), []byte("plugins: {enabled: [h-guard], hook_callback_timeout: 12}\n"), 0o600)
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, "waits 12s") {
		t.Errorf("status:\n%s", lines)
	}
}

// TestHermesConfigErrors：plugins 或 plugins.enabled 不是期望的类型时报错，不写入。
func TestHermesConfigErrors(t *testing.T) {
	for _, body := range []string{"- a\n", "plugins: [x]\n", "plugins: {enabled: h-guard}\n"} {
		if _, err := hermesConfigEdit([]byte(body), true, 20, false); err == nil {
			t.Errorf("%q: no error", body)
		}
	}
}

// TestHermesNotOurs：别人的同名插件目录不覆盖；移除时不删它，但 plugins.enabled 里的 h-guard 照样去掉。
func TestHermesNotOurs(t *testing.T) {
	tg := target(t, "linux")
	dir := HermesPluginDir(tg)
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "__init__.py"), []byte("def register(ctx): pass\n"), 0o600)
	os.WriteFile(HermesConfig(tg), []byte("plugins: {enabled: [h-guard]}\n"), 0o600)
	if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), "not h-guard's Hermes plugin") {
		t.Errorf("install over a foreign plugin: %v", err)
	}
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, "is not h-guard's plugin") {
		t.Errorf("status:\n%s", lines)
	}
	apply(t, hermesPlan(t, tg, true))
	if b, _ := os.ReadFile(filepath.Join(dir, "__init__.py")); string(b) != "def register(ctx): pass\n" {
		t.Errorf("the foreign plugin was changed: %q", b)
	}
	if b, _ := os.ReadFile(HermesConfig(tg)); strings.Contains(string(b), "h-guard") {
		t.Errorf("still enabled:\n%s", b)
	}
}

// TestHermesStale：改过的插件、换了位置的 h-guard、被停用的插件在 status 里报告；计划之后被改动时执行报冲突。
func TestHermesStale(t *testing.T) {
	tg := target(t, "linux")
	bin := filepath.Join(tg.Home, "bin", "h-guard")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, nil, 0o700)
	tg.Bin = bin
	apply(t, hermesPlan(t, tg, false))
	initPy := filepath.Join(HermesPluginDir(tg), "__init__.py")
	b, _ := os.ReadFile(initPy)
	os.WriteFile(initPy, []byte(strings.Replace(string(b), "'block'", "'pass'", 1)), 0o600)
	os.Remove(bin)
	os.WriteFile(HermesConfig(tg), []byte("plugins: {enabled: [h-guard], disabled: [h-guard], isolation: host}\n"), 0o600)
	lines := strings.Join(Inspect(tg, "hermes"), "\n")
	for _, want := range []string{"problem: the plugin differs", "problem: h-guard is not at " + bin, "plugins.disabled", "isolation is host"} {
		if !strings.Contains(lines, want) {
			t.Errorf("status lacks %q:\n%s", want, lines)
		}
	}
	tg.Timeout = 30
	steps := hermesPlan(t, tg, false)
	os.WriteFile(initPy, append(b, '\n'), 0o600)
	if err := Apply(steps); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Apply = %v, want ErrConflict", err)
	}
}

// TestHermesVersion：hermes --version 打印 Hermes Agent v<版本>[+<提交>] (<日期>)。
func TestHermesVersion(t *testing.T) {
	tg := target(t, "linux")
	out := "Hermes Agent v2026.9.1+12.gabc1234\n"
	tg.Run = func(name string, args ...string) ([]byte, error) { return []byte(out), nil }
	if n := ExtNotes(tg, "hermes"); len(n) != 1 || !strings.Contains(n[0], "Hermes Agent 2026.9.1 is older") {
		t.Errorf("notes: %v", n)
	}
	// 正常的安装：版本号是语义化版本，比较的是括号里的发布日期
	out = "Hermes Agent v0.21.6 (2026.9.1)\n"
	if n := ExtNotes(tg, "hermes"); len(n) != 1 || !strings.Contains(n[0], "Hermes Agent 2026.9.1 is older") {
		t.Errorf("semver with an older date: %v", n)
	}
	for _, out = range []string{"Hermes Agent v2026.9.24 (2026.9.24) · main\n", "Hermes Agent vunknown (2026.9.24)\nInstall directory: /x\n",
		"Hermes Agent v0.21.6 (2026.9.24)\n", "Hermes Agent v0.21.6+3.gabc1234 (2026.10.2) · main\n", "Hermes Agent v0.19.0 · stable\n"} {
		if n := ExtNotes(tg, "hermes"); len(n) != 0 {
			t.Errorf("%q: notes %v", out, n)
		}
	}
}

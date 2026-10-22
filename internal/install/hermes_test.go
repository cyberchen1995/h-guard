package install

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
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

// TestHermesPaths：$HERMES_HOME（与 Hermes 一样先展开环境变量，再展开开头的 ~）与 Windows 的 %LOCALAPPDATA%\hermes。
func TestHermesPaths(t *testing.T) {
	tg := target(t, "linux")
	if got, want := HermesPluginDir(tg), filepath.Join(tg.Home, ".hermes", "plugins", "h-guard"); got != want {
		t.Errorf("default: %s, want %s", got, want)
	}
	tg.Getenv = env(map[string]string{"HERMES_HOME": "~/hh"})
	if got := HermesConfig(tg); got != filepath.Join(tg.Home, "hh", "config.yaml") {
		t.Errorf("HERMES_HOME with ~: %s", got)
	}
	tg.Getenv = env(map[string]string{"HERMES_HOME": "  "})
	if got := HermesHome(tg); got != filepath.Join(tg.Home, ".hermes") {
		t.Errorf("blank HERMES_HOME: %s", got)
	}
	for in, want := range map[string]string{
		"$DATA/hermes":   "/srv/data/hermes",
		"${DATA}/hermes": "/srv/data/hermes",
		"$NOPE/hermes":   "$NOPE/hermes",                         // 没有设置的变量原样保留
		"%DATA%/hermes":  "%DATA%/hermes",                        // POSIX 上 %…% 不是变量
		"$TILDE/hermes":  filepath.Join(tg.Home, "hh", "hermes"), // 先展开变量，再展开 ~
		"~other/hermes":  "~other/hermes",
		"/opt/$DATA_X/x": "/opt/$DATA_X/x",
	} {
		tg.Getenv = env(map[string]string{"HERMES_HOME": in, "DATA": "/srv/data", "TILDE": "~/hh"})
		if got := HermesHome(tg); got != filepath.Clean(want) {
			t.Errorf("HERMES_HOME=%s: %s, want %s", in, got, want)
		}
	}
	win := target(t, "windows")
	win.Getenv = env(map[string]string{"LOCALAPPDATA": filepath.Join(win.Home, "LAD")})
	if got := HermesHome(win); got != filepath.Join(win.Home, "LAD", "hermes") {
		t.Errorf("windows: %s", got)
	}
	// ntpath.expandvars 与 expanduser
	wenv := map[string]string{"DATA": `D:\data`, "USERPROFILE": `C:\Users\me`}
	for in, want := range map[string]string{
		`%DATA%\hermes`:   `D:\data\hermes`,
		`$DATA\hermes`:    `D:\data\hermes`,
		`${DATA}\hermes`:  `D:\data\hermes`,
		`%NOPE%\hermes`:   `%NOPE%\hermes`,
		`'%DATA%'\hermes`: `'%DATA%'\hermes`,
		`100%%\hermes`:    `100%\hermes`,
		`~\hermes`:        `C:\Users\me\hermes`,
		`~bob\hermes`:     `C:\Users\bob\hermes`,
	} {
		win.Getenv = env(map[string]string{"HERMES_HOME": in, "DATA": wenv["DATA"], "USERPROFILE": wenv["USERPROFILE"]})
		got := expandUser(win, expandVars(win, in))
		if got != want {
			t.Errorf("windows HERMES_HOME=%s: %s, want %s", in, got, want)
		}
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
	st, err := readHermesState(tg, b)
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
	if st, _ := readHermesState(tg, b); st.enabled || !strings.Contains(string(b), "disk-cleanup") {
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
		got, err := hermesConfigEdit(Target{}, []byte(body), true, 20, false)
		if err != nil || !strings.Contains(string(got), want) {
			t.Errorf("%q: %v\n%s", body, err, got)
		}
	}
	got, _ := hermesConfigEdit(Target{}, nil, false, 40, false)
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

// TestHermesTimeoutLimit：Hermes 把 plugins.hook_callback_timeout 截到 600 秒，它要比 h-guard 的超时多 5 秒，所以
// --timeout 最多 595；移除不受限制。
func TestHermesTimeoutLimit(t *testing.T) {
	tg := target(t, "linux")
	tg.Timeout = HermesMaxTimeout
	steps := hermesPlan(t, tg, false)
	apply(t, steps)
	if b, _ := os.ReadFile(HermesConfig(tg)); !strings.Contains(string(b), "hook_callback_timeout: 600") {
		t.Errorf("config:\n%s", b)
	}
	tg.Timeout = HermesMaxTimeout + 1
	if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), "at most 595 seconds") {
		t.Errorf("--timeout 596: %v", err)
	}
	if _, err := Hermes(tg, true); err != nil {
		t.Errorf("remove: %v", err)
	}
}

// TestHermesTimeoutValues：plugins.hook_callback_timeout 按 Hermes 的读法取值；不是数的值 status 报告，install 换成数。
func TestHermesTimeoutValues(t *testing.T) {
	for body, want := range map[string]float64{
		"{}": 30, "{hook_callback_timeout: null}": 30, "{hook_callback_timeout: 45}": 45, `{hook_callback_timeout: "45"}`: 45,
		"{hook_callback_timeout: 0}": 0, "{hook_callback_timeout: -5}": 30, "{hook_callback_timeout: 900}": 600,
		"{hook_callback_timeout: true}": 1, "{hook_callback_timeout: nope}": 30, "{hook_callback_timeout: [1]}": 30,
	} {
		st, err := readHermesState(Target{}, []byte("plugins: "+body+"\n"))
		if err != nil || st.timeout != want {
			t.Errorf("%s: %v %v, want %v", body, st.timeout, err, want)
		}
	}
	tg := target(t, "linux")
	cfg := HermesConfig(tg)
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("plugins: {enabled: [h-guard], hook_callback_timeout: nope}\n"), 0o600)
	apply(t, hermesPlan(t, tg, false))
	b, _ := os.ReadFile(cfg)
	if st, _ := readHermesState(tg, b); !st.timeoutOK || st.timeout < float64(max(tg.Timeout+5, 30)) {
		t.Errorf("install left the timeout:\n%s", b)
	}
	os.WriteFile(cfg, []byte("plugins: {enabled: [h-guard], hook_callback_timeout: nope}\n"), 0o600)
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, "not a number") {
		t.Errorf("status:\n%s", lines)
	}
}

// TestHermesBusySteer：display.busy_input_mode: steer 时 install 与 status 说明运行中收到的消息不经检查；
// $HERMES_GATEWAY_BUSY_INPUT_MODE 优先，托管范围覆盖用户的配置。
func TestHermesBusySteer(t *testing.T) {
	tg := target(t, "linux")
	apply(t, hermesPlan(t, tg, false))
	steer := func() bool {
		return strings.Contains(strings.Join(Inspect(tg, "hermes"), "\n"), "busy_input_mode is steer")
	}
	if steer() {
		t.Error("note with the default interrupt")
	}
	os.WriteFile(HermesConfig(tg), []byte("plugins: {enabled: [h-guard]}\ndisplay: {busy_input_mode: Steer}\n"), 0o600)
	if !steer() || !slices.Contains(ExtNotes(tg, "hermes"), hermesSteerNote) {
		t.Errorf("no note for steer:\n%s", strings.Join(Inspect(tg, "hermes"), "\n"))
	}
	tg.Getenv = env(map[string]string{"HERMES_GATEWAY_BUSY_INPUT_MODE": "queue"})
	if steer() {
		t.Error("the environment variable does not win")
	}
	managed := filepath.Join(tg.Home, "managed")
	os.MkdirAll(managed, 0o700)
	os.WriteFile(filepath.Join(managed, "config.yaml"), []byte("display: {busy_input_mode: interrupt}\n"), 0o600)
	tg.Getenv = env(map[string]string{"HERMES_MANAGED_DIR": managed})
	if steer() {
		t.Error("the managed scope does not win")
	}
}

// TestHermesManagedScope：托管范围（$HERMES_MANAGED_DIR/config.yaml，默认 /etc/hermes）写下的键覆盖用户的配置。
// 它的 plugins.enabled 不含 h-guard、plugins.disabled 含 h-guard，或 hook_callback_timeout 太短时，install 报错（不改托管
// 文件，也不改用户的），status 报告问题；托管的 plugins.enabled 含 h-guard 时照常安装、没有问题。
func TestHermesManagedScope(t *testing.T) {
	for body, want := range map[string]string{
		"plugins: {enabled: [disk-cleanup]}\n":   "sets plugins.enabled without h-guard",
		"plugins: {disabled: [h-guard]}\n":       "lists h-guard in plugins.disabled",
		"plugins: {hook_callback_timeout: 10}\n": "sets plugins.hook_callback_timeout to 10s",
	} {
		tg := target(t, "linux")
		managed := filepath.Join(tg.Home, "managed")
		os.MkdirAll(managed, 0o700)
		os.WriteFile(filepath.Join(managed, "config.yaml"), []byte(body), 0o600)
		tg.Getenv = env(map[string]string{"HERMES_MANAGED_DIR": managed})
		if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "administrator") {
			t.Errorf("%q: install error %v", body, err)
		}
		// 先不经托管范围装好，再看 status
		apply(t, hermesPlan(t, Target{Home: tg.Home, ConfigDir: tg.ConfigDir, CacheDir: tg.CacheDir, Bin: tg.Bin, Timeout: tg.Timeout, GOOS: "linux",
			Getenv: env(map[string]string{}), Now: tg.Now}, false))
		lines := strings.Join(Inspect(tg, "hermes"), "\n")
		if !strings.Contains(lines, "problem: "+filepath.Join(managed, "config.yaml")) || !strings.Contains(lines, want) {
			t.Errorf("%q: status:\n%s", body, lines)
		}
		if strings.Contains(lines, HermesConfig(tg)+" does not list it") {
			t.Errorf("%q: status blames the user config:\n%s", body, lines)
		}
		if _, err := Hermes(tg, true); err != nil { // 移除不受托管范围影响
			t.Errorf("%q: remove: %v", body, err)
		}
	}
	tg := target(t, "linux")
	managed := filepath.Join(tg.Home, "managed")
	os.MkdirAll(managed, 0o700)
	os.WriteFile(filepath.Join(managed, "config.yaml"), []byte("plugins: {enabled: [h-guard]}\n"), 0o600)
	tg.Getenv = env(map[string]string{"HERMES_MANAGED_DIR": managed})
	apply(t, hermesPlan(t, tg, false))
	os.WriteFile(HermesConfig(tg), []byte("plugins: {enabled: []}\n"), 0o600) // 托管的列表替换用户的
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); strings.Contains(lines, "plugins.enabled") || strings.Contains(lines, "administrator") {
		t.Errorf("managed list with h-guard:\n%s", lines)
	}
	tg.Getenv = env(map[string]string{"HERMES_MANAGED_DIR": filepath.Join(tg.Home, "missing")}) // 目录不存在时没有托管范围
	if HermesManagedConfig(tg) != "" {
		t.Error("a missing managed directory counts")
	}
}

// TestHermesConfigErrors：plugins 或 plugins.enabled 不是期望的类型时报错，不写入。
func TestHermesConfigErrors(t *testing.T) {
	for _, body := range []string{"- a\n", "plugins: [x]\n", "plugins: {enabled: h-guard}\n"} {
		if _, err := hermesConfigEdit(Target{}, []byte(body), true, 20, false); err == nil {
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

func lookup(vals map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := vals[k]; return v, ok }
}

// TestHermesEmptyVar：与 Python 的 os.path.expandvars 一样，设置为空的变量展开为空，没有设置的才原样保留。
func TestHermesEmptyVar(t *testing.T) {
	tg := target(t, "linux")
	vars := map[string]string{"HERMES_HOME": "${EMPTY}/srv/hermes$NOPE", "EMPTY": ""}
	tg.Getenv, tg.LookupEnv = env(vars), lookup(vars)
	if got := HermesHome(tg); got != filepath.Clean("/srv/hermes$NOPE") {
		t.Errorf("HERMES_HOME with an empty variable: %s", got)
	}
	win := target(t, "windows")
	wvars := map[string]string{"E": ""}
	win.Getenv, win.LookupEnv = env(wvars), lookup(wvars)
	if got := expandVars(win, `C:\%E%x$E\${E}y%NOPE%`); got != `C:\x\y%NOPE%` {
		t.Errorf("windows: %s", got)
	}
}

// TestHermesPluginListVars：Hermes 展开配置值里的环境变量。plugins.disabled 里展开后是 h-guard 的项按停用处理：status
// 报告，install 去掉它；引用了没有设置的变量、看不出是什么的项 status 报告、install 报错（不猜）；设成别的插件的项保留。
// plugins.enabled 里展开后是 h-guard 的项算作启用。托管范围同样展开。
func TestHermesPluginListVars(t *testing.T) {
	tg := target(t, "linux")
	vars := map[string]string{"HG_PLUGIN": "h-guard", "OTHER": "noisy"}
	tg.Getenv, tg.LookupEnv = env(vars), lookup(vars)
	tg.Bin = filepath.Join(tg.Home, "bin", "h-guard")
	os.MkdirAll(filepath.Dir(tg.Bin), 0o700)
	os.WriteFile(tg.Bin, nil, 0o700)
	apply(t, hermesPlan(t, tg, false))
	cfg := HermesConfig(tg)
	os.WriteFile(cfg, []byte("plugins:\n  enabled: [h-guard]\n  disabled: ['${HG_PLUGIN}', '$OTHER']\n"), 0o600)
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, "lists h-guard in plugins.disabled") {
		t.Errorf("status misses the disabled entry:\n%s", lines)
	}
	apply(t, hermesPlan(t, tg, false))
	b, _ := os.ReadFile(cfg)
	if st, _ := readHermesState(tg, b); st.disabled || !strings.Contains(string(b), "$OTHER") || strings.Contains(string(b), "HG_PLUGIN") {
		t.Errorf("install kept h-guard disabled or dropped another entry:\n%s", b)
	}
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); strings.Contains(lines, "problem") {
		t.Errorf("status after install:\n%s", lines)
	}

	os.WriteFile(cfg, []byte("plugins:\n  enabled: [h-guard]\n  disabled: ['${UNSET_PLUGIN}']\n"), 0o600)
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, `"${UNSET_PLUGIN}" in plugins.disabled`) {
		t.Errorf("status misses the unknown entry:\n%s", lines)
	}
	if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), "${UNSET_PLUGIN}") {
		t.Errorf("install with an unknown entry: %v", err)
	}
	// 设置为空也是设置了：展开为空串，不是 h-guard
	vars["UNSET_PLUGIN"] = ""
	if _, err := Hermes(tg, false); err != nil {
		t.Errorf("install with an empty variable: %v", err)
	}

	os.WriteFile(cfg, []byte("plugins:\n  enabled: ['${HG_PLUGIN}']\n"), 0o600)
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); strings.Contains(lines, "problem") {
		t.Errorf("enabled through a variable:\n%s", lines)
	}

	managed := filepath.Join(tg.Home, "managed")
	os.MkdirAll(managed, 0o700)
	os.WriteFile(filepath.Join(managed, "config.yaml"), []byte("plugins: {disabled: ['${HG_PLUGIN}']}\n"), 0o600)
	vars["HERMES_MANAGED_DIR"] = managed
	if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), "lists h-guard in plugins.disabled") {
		t.Errorf("managed disabled through a variable: %v", err)
	}
	os.WriteFile(filepath.Join(managed, "config.yaml"), []byte("plugins: {disabled: ['${NOT_SET}']}\n"), 0o600)
	if _, err := Hermes(tg, false); err == nil || !strings.Contains(err.Error(), "administrator") {
		t.Errorf("managed unknown entry: %v", err)
	}
}

// TestHermesOtherPlugins：另外启用的插件的源码注册了 transform_tool_result（或 transform_terminal_output）、pre_tool_call
// 时，install 与 status 说明它们可能让 h-guard 的替换或检查落空；停用的、没有启用的、不注册这些 hook 的插件不提。
func TestHermesOtherPlugins(t *testing.T) {
	tg := target(t, "linux")
	apply(t, hermesPlan(t, tg, false))
	plugins := filepath.Dir(HermesPluginDir(tg))
	write := func(dir, name, src string) {
		os.MkdirAll(filepath.Join(plugins, dir, "lib"), 0o700)
		os.WriteFile(filepath.Join(plugins, dir, "plugin.yaml"), []byte("name: "+name+"\n"), 0o600)
		os.WriteFile(filepath.Join(plugins, dir, "lib", "hooks.py"), []byte(src), 0o600)
	}
	write("redact-dir", "redact", "def register(ctx):\n    ctx.register_hook('transform_tool_result', f)\n")
	write("rewrite", "rewrite", "def register(ctx):\n    ctx.register_hook(\"pre_tool_call\", g)\n")
	write("quiet", "quiet", "def register(ctx):\n    ctx.register_hook('post_tool_call', h)\n")
	write("off", "off", "def register(ctx):\n    ctx.register_hook('transform_terminal_output', f)\n")
	write("idle", "idle", "def register(ctx):\n    ctx.register_hook('transform_tool_result', f)\n")
	os.WriteFile(HermesConfig(tg), []byte("plugins:\n  enabled: [h-guard, redact, rewrite, quiet, off, bundled]\n  disabled: [off]\n"), 0o600)
	notes := strings.Join(ExtNotes(tg, "hermes"), "\n")
	if !strings.Contains(notes, "replace tool results (redact)") || !strings.Contains(notes, "hook tool calls (rewrite)") {
		t.Errorf("notes:\n%s", notes)
	}
	for _, name := range []string{"quiet", "off", "idle", "bundled"} {
		if strings.Contains(notes, name) {
			t.Errorf("note mentions %s:\n%s", name, notes)
		}
	}
	if lines := strings.Join(Inspect(tg, "hermes"), "\n"); !strings.Contains(lines, "note: other enabled plugins also replace tool results") {
		t.Errorf("status:\n%s", lines)
	}
	os.WriteFile(HermesConfig(tg), []byte("plugins:\n  enabled: [h-guard]\n"), 0o600)
	if notes := strings.Join(ExtNotes(tg, "hermes"), "\n"); strings.Contains(notes, "other enabled plugins") {
		t.Errorf("notes without other plugins:\n%s", notes)
	}
}

package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/store"
)

func noChanges(t *testing.T, steps []Step) {
	t.Helper()
	for _, s := range steps {
		if s.Changes() {
			t.Errorf("unexpected change to %s", s.Path)
		}
	}
}

func env(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

// TestExtRender：CONFIG 一行是 h-guard 的命令与超时，pi 的模板另写 HARNESS；其余内容与内嵌的模板相同，读得回来。
func TestExtRender(t *testing.T) {
	tg := target(t, "linux")
	tg.Bin = filepath.Join(tg.Home, "bin", "h-guard")
	os.MkdirAll(filepath.Dir(tg.Bin), 0o700)
	os.WriteFile(tg.Bin, nil, 0o700)
	for _, h := range []string{"opencode", "pi", "omp", "dsh"} {
		steps := plan(t, tg, h, false)
		apply(t, steps)
		path := map[string]string{"opencode": OpenCodePlugin(tg), "pi": PiExtension(tg), "omp": OMPExtension(tg), "dsh": DSHPlugin(tg)}[h]
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `const CONFIG = {"command":[`+jsonString(tg.Bin)+`,"hook","`+h+`","--timeout","20"],"timeout_ms":20000} // h-guard install`) {
			t.Errorf("%s: CONFIG line not written:\n%s", h, b)
		}
		if bin, timeout, ok := installedExt(b, h); !ok || bin != tg.Bin || timeout != 20 {
			t.Errorf("%s: installedExt = %q %d %v", h, bin, timeout, ok)
		}
		if (h == "pi" || h == "omp") && extHarness(b) != h {
			t.Errorf("%s: HARNESS = %q", h, extHarness(b))
		}
		if lines := strings.Join(Inspect(tg, h), "\n"); strings.Contains(lines, "problem") || strings.Contains(lines, "not installed") {
			t.Errorf("%s: status after install:\n%s", h, lines)
		}
		noChanges(t, plan(t, tg, h, false))
	}
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }

func plan(t *testing.T, tg Target, h string, remove bool) []Step {
	t.Helper()
	var steps []Step
	var err error
	switch h {
	case "opencode":
		steps, err = OpenCode(tg, remove)
	case "pi", "omp":
		steps, err = Pi(tg, h, remove)
	case "dsh":
		steps, err = DSH(tg, remove)
	}
	if err != nil {
		t.Fatal(err)
	}
	return steps
}

// TestExtPaths：各 harness 的扩展目录与环境变量（XDG_CONFIG_HOME、PI_CODING_AGENT_DIR、PI_CONFIG_DIR、DSH_HOME）。
func TestExtPaths(t *testing.T) {
	tg := target(t, "linux")
	if got, want := OpenCodePlugin(tg), filepath.Join(tg.Home, ".config", "opencode", "plugins", "h-guard.js"); got != want {
		t.Errorf("opencode: %s, want %s", got, want)
	}
	if got, want := PiExtension(tg), filepath.Join(tg.Home, ".pi", "agent", "extensions", "h-guard.js"); got != want {
		t.Errorf("pi: %s, want %s", got, want)
	}
	if got, want := OMPExtension(tg), filepath.Join(tg.Home, ".omp", "agent", "extensions", "h-guard-omp.js"); got != want {
		t.Errorf("omp: %s, want %s", got, want)
	}
	if got, want := DSHPatch(tg), filepath.Join(tg.Home, ".dsh", "cordis.patch.yml"); got != want {
		t.Errorf("dsh: %s, want %s", got, want)
	}
	tg.Getenv = env(map[string]string{"XDG_CONFIG_HOME": "/x", "PI_CONFIG_DIR": ".omp2", "DSH_HOME": "/d"})
	if got := OpenCodePlugin(tg); got != filepath.Join("/x", "opencode", "plugins", "h-guard.js") {
		t.Errorf("opencode with XDG_CONFIG_HOME: %s", got)
	}
	if got := OMPExtension(tg); got != filepath.Join(tg.Home, ".omp2", "agent", "extensions", "h-guard-omp.js") {
		t.Errorf("omp with PI_CONFIG_DIR: %s", got)
	}
	if got := DSHPatch(tg); got != filepath.Join("/d", "cordis.patch.yml") {
		t.Errorf("dsh with DSH_HOME: %s", got)
	}
	tg.Getenv = env(map[string]string{"PI_CODING_AGENT_DIR": "/a"})
	if PiExtension(tg) != filepath.Join("/a", "extensions", "h-guard.js") || OMPExtension(tg) != filepath.Join("/a", "extensions", "h-guard-omp.js") {
		t.Errorf("PI_CODING_AGENT_DIR: %s %s", PiExtension(tg), OMPExtension(tg))
	}
}

// TestExtRemove：移除删掉扩展（备份原文件）；没有安装时移除不改动。
func TestExtRemove(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "opencode", false))
	apply(t, plan(t, tg, "opencode", true))
	if _, err := os.Stat(OpenCodePlugin(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin still there: %v", err)
	}
	if backups, _ := filepath.Glob(filepath.Join(tg.CacheDir, "backups", "opencode-plugin.*", "h-guard.js")); len(backups) != 1 {
		t.Errorf("backups: %v", backups)
	}
	noChanges(t, plan(t, tg, "opencode", true))
	if lines := Inspect(tg, "opencode"); len(lines) != 1 || !strings.HasPrefix(lines[0], "not installed") {
		t.Errorf("status after remove: %v", lines)
	}
}

// TestExtNotOurs：别人的同名文件不覆盖、不删除。
func TestExtNotOurs(t *testing.T) {
	tg := target(t, "linux")
	path := PiExtension(tg)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("export default function (pi) {}\n"), 0o600)
	for _, remove := range []bool{false, true} {
		if _, err := Pi(tg, "pi", remove); err == nil {
			t.Errorf("remove=%v: no error for a foreign file", remove)
		}
	}
	if lines := strings.Join(Inspect(tg, "pi"), "\n"); !strings.Contains(lines, "is not h-guard's extension") {
		t.Errorf("status: %s", lines)
	}
}

// TestExtConflict：计划之后、执行之前文件被改动时，执行报冲突，不覆盖。
func TestExtConflict(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "pi", false))
	tg.Timeout = 30
	steps := plan(t, tg, "pi", false)
	b, _ := os.ReadFile(PiExtension(tg))
	os.WriteFile(PiExtension(tg), append(b, '\n'), 0o600)
	if err := Apply(steps); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Apply = %v, want ErrConflict", err)
	}
}

// TestExtStale：改过的扩展、换了位置的 h-guard 在 status 里报告；重装修复。
func TestExtStale(t *testing.T) {
	tg := target(t, "linux")
	bin := filepath.Join(tg.Home, "bin", "h-guard")
	os.MkdirAll(filepath.Dir(bin), 0o700)
	os.WriteFile(bin, nil, 0o700)
	tg.Bin = bin
	apply(t, plan(t, tg, "omp", false))
	if lines := strings.Join(Inspect(tg, "omp"), "\n"); strings.Contains(lines, "problem") {
		t.Fatalf("fresh install reports a problem:\n%s", lines)
	}
	b, _ := os.ReadFile(OMPExtension(tg))
	os.WriteFile(OMPExtension(tg), bytes.Replace(b, []byte("block: true"), []byte("block: false"), 1), 0o600)
	os.Remove(bin)
	lines := strings.Join(Inspect(tg, "omp"), "\n")
	if !strings.Contains(lines, "problem: the extension differs") || !strings.Contains(lines, "problem: h-guard is not at "+bin) {
		t.Errorf("status:\n%s", lines)
	}
}

// TestPiOMPShareDir：PI_CODING_AGENT_DIR 让 pi 与 omp 共用扩展目录时，装了一个就不能再装另一个。
func TestPiOMPShareDir(t *testing.T) {
	tg := target(t, "linux")
	tg.Getenv = env(map[string]string{"PI_CODING_AGENT_DIR": filepath.Join(tg.Home, "agent")})
	apply(t, plan(t, tg, "pi", false))
	if _, err := Pi(tg, "omp", false); err == nil || !strings.Contains(err.Error(), "pi extension") {
		t.Fatalf("omp install into the shared directory: %v", err)
	}
	if _, err := Pi(tg, "omp", true); err != nil { // 移除 omp 不受影响
		t.Fatal(err)
	}
}

// TestDSHPatch：补丁里插入挂载插件的一行，其他内容保留；重装不改动；路径变了就更新；重复的删掉；移除只删本项目的行。
func TestDSHPatch(t *testing.T) {
	tg := target(t, "linux")
	patch := DSHPatch(tg)
	os.MkdirAll(filepath.Dir(patch), 0o700)
	other := "# my overrides\n- id: tool-bash\n  config:\n    timeoutMs: 5000\n- insert:\n    - id: hooks\n      name: '@deepseek-ai/dsh-hooks-claude-code'\n"
	os.WriteFile(patch, []byte(other), 0o600)
	apply(t, plan(t, tg, "dsh", false))
	b, _ := os.ReadFile(patch)
	found, name, err := dshMounted(b)
	if err != nil || found != 1 || name != DSHPlugin(tg) {
		t.Fatalf("mounted %d %q %v:\n%s", found, name, err, b)
	}
	for _, keep := range []string{"# my overrides", "id: tool-bash", "timeoutMs: 5000", "dsh-hooks-claude-code"} {
		if !strings.Contains(string(b), keep) {
			t.Errorf("lost %q:\n%s", keep, b)
		}
	}
	noChanges(t, plan(t, tg, "dsh", false))

	// 别人改了这一行（加了 disabled），又多了一行：重装恢复成一行
	os.WriteFile(patch, append(b, []byte("- insert:\n    - id: h-guard\n      name: /elsewhere.mjs\n      disabled: true\n")...), 0o600)
	if lines := strings.Join(Inspect(tg, "dsh"), "\n"); !strings.Contains(lines, "mounts h-guard 2 times") {
		t.Errorf("status:\n%s", lines)
	}
	apply(t, plan(t, tg, "dsh", false))
	b, _ = os.ReadFile(patch)
	if found, _, _ := dshMounted(b); found != 1 || strings.Contains(string(b), "disabled") || strings.Contains(string(b), "/elsewhere.mjs") {
		t.Errorf("after reinstall:\n%s", b)
	}

	apply(t, plan(t, tg, "dsh", true))
	b, _ = os.ReadFile(patch)
	if found, _, _ := dshMounted(b); found != 0 || !strings.Contains(string(b), "dsh-hooks-claude-code") || !strings.Contains(string(b), "id: tool-bash") {
		t.Errorf("after remove:\n%s", b)
	}
	if strings.Count(string(b), "insert") != 1 {
		t.Errorf("the emptied insert is left behind:\n%s", b)
	}
	if _, err := os.Stat(DSHPlugin(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin still there: %v", err)
	}
}

// TestDSHNewPatch：没有补丁文件时新建；补丁不是列表时报错，不写入。
func TestDSHNewPatch(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "dsh", false))
	b, _ := os.ReadFile(DSHPatch(tg))
	want := "- insert:\n    - id: h-guard\n      name: " + DSHPlugin(tg) + "\n"
	if found, name, _ := dshMounted(b); found != 1 || name != DSHPlugin(tg) || (runtime.GOOS != "windows" && string(b) != want) {
		t.Errorf("new patch:\n%s\nwant:\n%s", b, want)
	}
	os.WriteFile(DSHPatch(tg), []byte("a: 1\n"), 0o600)
	if _, err := DSH(tg, false); err == nil {
		t.Error("no error for a patch that is not a list")
	}
	tg2 := target(t, "linux")
	noChanges(t, plan(t, tg2, "dsh", true)) // 没有安装时移除不新建补丁
	if _, err := os.Stat(DSHPatch(tg2)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove created the patch: %v", err)
	}
	if lines := Inspect(tg2, "dsh"); len(lines) != 1 || !strings.HasPrefix(lines[0], "not installed") {
		t.Errorf("status: %v", lines)
	}
}

// TestExtVersionNotes：opencode 2.x 不受支持；比扩展编写时旧的版本提醒；omp 的版本带 omp/ 前缀；找不到命令时提醒。
func TestExtVersionNotes(t *testing.T) {
	tg := target(t, "linux")
	versions := map[string]string{"opencode": "2.0.32\n", "pi": "1.2.0\n", "omp": "omp/18.11.3\n"}
	tg.Run = func(name string, args ...string) ([]byte, error) {
		if v, ok := versions[name]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("not found")
	}
	if n := ExtNotes(tg, "opencode"); len(n) != 1 || !strings.Contains(n[0], "opencode 2.0.32 is not supported") {
		t.Errorf("opencode: %v", n)
	}
	if n := ExtNotes(tg, "pi"); len(n) != 1 || !strings.Contains(n[0], "older than") {
		t.Errorf("pi: %v", n)
	}
	if n := ExtNotes(tg, "omp"); len(n) != 0 {
		t.Errorf("omp: %v", n)
	}
	if n := ExtNotes(tg, "dsh"); len(n) != 1 || !strings.Contains(n[0], "dsh was not found") {
		t.Errorf("dsh: %v", n)
	}
}

// TestDSHModule：Windows 上补丁里写 file: URL（dsh 把非相对的模块名直接交给 import()），其余平台写路径；status 能换回路径。
func TestDSHModule(t *testing.T) {
	win := Target{GOOS: "windows"}
	if got := DSHModule(win, `C:\Users\a b\h-guard.mjs`); got != "file:///C:/Users/a%20b/h-guard.mjs" {
		t.Errorf("windows: %s", got)
	}
	if got := dshModulePath(win, "file:///C:/Users/a%20b/h-guard.mjs"); got != filepath.FromSlash("C:/Users/a b/h-guard.mjs") {
		t.Errorf("windows path: %s", got)
	}
	lin := Target{GOOS: "linux"}
	if got := DSHModule(lin, "/home/u/h-guard.mjs"); got != "/home/u/h-guard.mjs" {
		t.Errorf("linux: %s", got)
	}
	if got := dshModulePath(lin, "/home/u/h-guard.mjs"); got != "/home/u/h-guard.mjs" {
		t.Errorf("linux path: %s", got)
	}
}

// TestDSHRemoveForeignPlugin：插件文件被换掉时，移除照样删掉补丁里本项目的那一行，换上的文件不动。
func TestDSHRemoveForeignPlugin(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "dsh", false))
	os.WriteFile(DSHPlugin(tg), []byte("export function apply() {}\n"), 0o600)
	apply(t, plan(t, tg, "dsh", true))
	b, _ := os.ReadFile(DSHPatch(tg))
	if found, _, _ := dshMounted(b); found != 0 {
		t.Errorf("the row is still mounted:\n%s", b)
	}
	if b, _ := os.ReadFile(DSHPlugin(tg)); string(b) != "export function apply() {}\n" {
		t.Errorf("the foreign plugin file was changed: %q", b)
	}
}

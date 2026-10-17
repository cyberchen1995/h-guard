package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestInspectStalePlugin：插件文件缺失、被改动或是旧版 h-guard 写出的内容时报告，不显示为正常（审查次要 8）。
func TestInspectStalePlugin(t *testing.T) {
	tg := target(t, runtime.GOOS) // 本机路径按本机平台的列表分隔符拆分
	tg.Bin = filepath.Join(t.TempDir(), "h-guard")
	os.WriteFile(tg.Bin, []byte("x"), 0o700)
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	if lines := strings.Join(Inspect(tg, "claudecode"), "\n"); strings.Contains(lines, "problem") {
		t.Errorf("fresh install:\n%s", lines)
	}
	os.Remove(filepath.Join(ClaudePluginDir(tg), "hooks", "pretooluse.sh"))
	if lines := strings.Join(Inspect(tg, "claudecode"), "\n"); !strings.Contains(lines, "problem: the plugin files differ from this h-guard version") {
		t.Errorf("missing wrapper:\n%s", lines)
	}
}

// TestInspectWindowsPathCase：Windows 上路径不区分大小写，status 与 install 用同一个比较；登记写成别的大小写时
// install 认为已装好，status 也不能报「没有加载」。
func TestInspectWindowsPathCase(t *testing.T) {
	tg := target(t, "windows")
	tg.Bin = filepath.Join(t.TempDir(), "h-guard.exe")
	os.WriteFile(tg.Bin, []byte("x"), 0o700)
	steps, _ := ClaudeCode(tg, false)
	apply(t, steps)
	settings := ClaudeSettings(tg)
	b, _ := os.ReadFile(settings)
	dir, _ := json.Marshal(ClaudePluginDir(tg))
	os.WriteFile(settings, []byte(strings.Replace(string(b), string(dir), strings.ToUpper(string(dir)), 1)), 0o600)
	if lines := strings.Join(Inspect(tg, "claudecode"), "\n"); strings.Contains(lines, "does not load it") {
		t.Errorf("upper-case registration:\n%s", lines)
	}
}

// TestInspectCodexMatcher：本项目的 Codex 入口被加了 matcher（只对部分工具生效）时报告；install 会把它改回不带
// matcher 的入口。
func TestInspectCodexMatcher(t *testing.T) {
	tg := target(t, "linux")
	tg.Bin = filepath.Join(t.TempDir(), "h-guard")
	os.WriteFile(tg.Bin, []byte("x"), 0o700)
	steps, err := Codex(tg, false)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, steps)
	path := CodexHooks(tg)
	var m map[string]any
	b, _ := os.ReadFile(path)
	json.Unmarshal(b, &m)
	m["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["matcher"] = "Bash"
	b, _ = json.Marshal(m)
	os.WriteFile(path, b, 0o600)
	if lines := strings.Join(Inspect(tg, "codex"), "\n"); !strings.Contains(lines, "problem: the h-guard hook for PreToolUse only runs for tools matching") {
		t.Errorf("narrowed matcher:\n%s", lines)
	}
}

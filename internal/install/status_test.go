package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInspectStalePlugin：插件文件缺失、被改动或是旧版 h-guard 写出的内容时报告，不显示为正常（审查次要 8）。
func TestInspectStalePlugin(t *testing.T) {
	tg := target(t, "linux")
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

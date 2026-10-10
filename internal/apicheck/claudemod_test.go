package apicheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeCodeMod 用本机的 claude CLI 校验并离线测试 Claude Code mod（spec §7.7）。
// 没有 claude CLI、没有 mod 源码或使用 -short 时跳过。
func TestClaudeCodeMod(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the claude CLI")
	}
	dir := filepath.Join("..", "..", "extensions", "claudecode")
	if _, err := os.Stat(filepath.Join(dir, "hooks", "register.js")); err != nil {
		t.Skip("mod sources not present")
	}
	claude, err := exec.LookPath("claude")
	if err != nil {
		t.Skip("claude CLI not found; mod tests not run")
	}
	for _, args := range [][]string{{"plugin", "validate", "--strict", "."}, {"plugin", "test"}} {
		cmd := exec.Command(claude, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("claude %s failed: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
}

package extensions

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestExtensions 用 node 运行 opencode、pi/omp、dsh 与 openclaw 扩展的测试（*/tests/*.test.mjs），h-guard 是这次编译的二进制，
// 配置与缓存目录都在临时目录里（outbound 第 2 档，扫描文件内容）。没有 node 时跳过；-short 时跳过（要编译）。
// Claude Code 插件的测试要 claude CLI，不在这里运行。
func TestExtensions(t *testing.T) {
	if testing.Short() {
		t.Skip("builds h-guard")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found")
	}
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "h-guard")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "../cmd/h-guard").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	home := filepath.Join(tmp, "home")
	cfg := filepath.Join(home, "config")
	for _, d := range []string{filepath.Join(cfg, "h-guard"), filepath.Join(home, "AppData", "Roaming", "h-guard")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "config.yaml"), []byte("version: 1\noutbound: {tier: 2}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var files []string
	for _, dir := range []string{"opencode", "pi", "dsh", "openclaw"} {
		m, _ := filepath.Glob(filepath.Join(dir, "tests", "*.test.mjs"))
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no extension tests found")
	}
	cmd := exec.Command(node, append([]string{"--test"}, files...)...)
	cmd.Env = append(os.Environ(), "HGUARD_BIN="+bin, "HOME="+home, "USERPROFILE="+home,
		"XDG_CONFIG_HOME="+cfg, "XDG_CACHE_HOME="+filepath.Join(home, "cache"),
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node --test: %v\n%s", err, out)
	}
}

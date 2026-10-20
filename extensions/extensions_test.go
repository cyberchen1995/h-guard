package extensions

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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
	var files []string
	for _, dir := range []string{"opencode", "pi", "dsh", "openclaw"} {
		m, _ := filepath.Glob(filepath.Join(dir, "tests", "*.test.mjs"))
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no extension tests found")
	}
	cmd := exec.Command(node, append([]string{"--test"}, files...)...)
	cmd.Env = guardEnv(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node --test: %v\n%s", err, out)
	}
}

// TestHermesPlugin 用 Python（3.9 或更新，Hermes 本身要求 3.11）运行 Hermes 插件的测试（hermes/tests/test_*.py，标准库
// unittest），环境与 TestExtensions 相同。没有 Python 时跳过；-short 时跳过。
func TestHermesPlugin(t *testing.T) {
	if testing.Short() {
		t.Skip("builds h-guard")
	}
	python := findPython()
	if python == "" {
		t.Skip("python 3.9 or later not found")
	}
	cmd := exec.Command(python, "-m", "unittest", "discover", "-v", "-s", filepath.Join("hermes", "tests"), "-p", "test_*.py")
	cmd.Env = guardEnv(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python -m unittest: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "skipped 'HGUARD_BIN not set'") {
		t.Fatalf("the tests did not see the built h-guard:\n%s", out)
	}
}

// findPython 返回 PATH 上的 python3 或 python（3.9 或更新）；Windows 上的 python3 可能只是应用商店的占位程序，运行一次确认。
func findPython() string {
	for _, name := range []string{"python3", "python"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if out, err := exec.Command(p, "-c", "import sys; print(sys.version_info >= (3, 9))").Output(); err == nil && strings.TrimSpace(string(out)) == "True" {
			return p
		}
	}
	return ""
}

// guardEnv 编译 h-guard，返回测试用的环境：HGUARD_BIN 是这个二进制，主目录、配置与缓存目录都在临时目录里，
// 配置为 outbound 第 2 档。
func guardEnv(t *testing.T) []string {
	t.Helper()
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
	return append(os.Environ(), "HGUARD_BIN="+bin, "HOME="+home, "USERPROFILE="+home,
		"XDG_CONFIG_HOME="+cfg, "XDG_CACHE_HOME="+filepath.Join(home, "cache"),
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"), "LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
		"HERMES_HOME="+filepath.Join(home, ".hermes"), "PYTHONDONTWRITEBYTECODE=1")
}

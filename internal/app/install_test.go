package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installEnv 是装 harness 的测试环境：h-guard 的路径固定，harness 的命令行由 run 模拟（nil 为找不到）。
func installEnv(t *testing.T, run func(name string, args ...string) ([]byte, error)) *env {
	e := newEnv(t)
	e.bin, e.harnessRun, e.goos = "/opt/bin/h-guard", run, "linux"
	return e
}

func claudeOK(name string, args ...string) ([]byte, error) {
	if name != "claude" {
		return nil, errors.New("not found")
	}
	if len(args) > 0 && args[0] == "--version" {
		return []byte("2.1.296 (Claude Code)\n"), nil
	}
	return []byte("Validation passed\n"), nil
}

// TestInstallClaudeCodeDryRun：默认只打印将要写入的内容，什么都不写。
func TestInstallClaudeCodeDryRun(t *testing.T) {
	e := installEnv(t, claudeOK)
	out, errs, code := e.run(nil, "install", "claudecode")
	dir := filepath.Join(e.configDir, "extensions", "claudecode")
	settings := filepath.Join(e.home, ".claude", "settings.json")
	if code != 0 || !strings.Contains(out, "would write the h-guard plugin") || !strings.Contains(out, settings) ||
		!strings.Contains(out, "env.CLAUDE_CODE_PLUGIN_DIRS: (unset) -> "+dir) || !strings.Contains(out, "--write") {
		t.Errorf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	for _, p := range []string{dir, settings} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was written: %v", p, err)
		}
	}
}

// TestInstallClaudeCodeWrite：--write 写入并运行 claude plugin validate；--remove --write 只删本项目的入口。
func TestInstallClaudeCodeWrite(t *testing.T) {
	var calls []string
	e := installEnv(t, func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return claudeOK(name, args...)
	})
	out, errs, code := e.run(nil, "install", "claudecode", "--write", "--timeout", "25")
	dir := filepath.Join(e.configDir, "extensions", "claudecode")
	if code != 0 || !strings.Contains(out, "wrote") || !strings.Contains(out, "restart Claude Code") {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hguard-timeout")); string(b) != "25\n" {
		t.Errorf("hguard-timeout = %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "hguard-bin")); string(b) != "/opt/bin/h-guard\n" {
		t.Errorf("hguard-bin = %q", b)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "claude plugin validate "+dir) {
		t.Errorf("calls = %q", calls)
	}
	out, _, code = e.run(nil, "install", "claudecode", "--write", "--timeout", "25")
	if code != 0 || !strings.Contains(out, "already") {
		t.Errorf("reinstall: exit %d\n%s", code, out)
	}
	out, _, code = e.run(nil, "install", "claudecode", "--remove", "--write")
	if code != 0 {
		t.Fatalf("remove: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin dir after remove: %v", err)
	}
}

// TestInstallClaudeCodeValidateFails：校验失败时报告并以 1 退出（文件已写入，提示用 --remove 撤回）。
func TestInstallClaudeCodeValidateFails(t *testing.T) {
	e := installEnv(t, func(name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "plugin" {
			return []byte("bad manifest"), errors.New("exit status 1")
		}
		return claudeOK(name, args...)
	})
	_, errs, code := e.run(nil, "install", "claudecode", "--write")
	if code != 1 || !strings.Contains(errs, "claude plugin validate failed") || !strings.Contains(errs, "bad manifest") {
		t.Errorf("exit %d, stderr %s", code, errs)
	}
}

// TestInstallUsage：不认识的 harness、缺参数、--timeout 不合法都是用法错误；配置目录取不到时报错。
func TestInstallUsage(t *testing.T) {
	e := installEnv(t, claudeOK)
	for _, args := range [][]string{{"install"}, {"install", "vim"}, {"install", "claudecode", "--timeout", "0"}, {"install", "claudecode", "codex"}} {
		if _, _, code := e.run(nil, args...); code != 2 {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}

// TestInstallRefusesTemporaryBuild：go run 编出的 h-guard 在临时目录里，程序退出就不在了，写进入口会让 Codex 静默
// 放行、Claude Code 每次都请求确认（审查 I3）。
func TestInstallRefusesTemporaryBuild(t *testing.T) {
	e := installEnv(t, claudeOK)
	e.bin = "/var/folders/x/T/go-build1234/b001/exe/h-guard"
	if _, errs, code := e.run(nil, "install", "claudecode"); code != 1 || !strings.Contains(errs, "go run") {
		t.Errorf("exit %d\n%s", code, errs)
	}
}

// TestInstallChecksTheConfig：安装前读配置（与 hook 相同）：配置非法时不写入（hook 会遇到同样的错误）；停用了硬规则
// 时显著提示；移除不受配置错误阻挡。
func TestInstallChecksTheConfig(t *testing.T) {
	e := installEnv(t, claudeOK)
	e.config("version: 1\npolicy: {request_window: 0}\n")
	if _, errs, code := e.run(nil, "install", "claudecode", "--write"); code != 1 || !strings.Contains(errs, "request_window") {
		t.Errorf("invalid config: exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(e.configDir, "extensions")); !errors.Is(err, os.ErrNotExist) {
		t.Error("written despite an invalid config")
	}
	if _, errs, code := e.run(nil, "install", "claudecode", "--remove", "--write"); code != 0 {
		t.Errorf("remove with an invalid config: exit %d\n%s", code, errs)
	}
	e.config("version: 1\nrules: {guard_tampering: {enabled: false}}\n")
	if out, _, code := e.run(nil, "install", "claudecode"); code != 0 || !strings.Contains(out, `warning: hard rule "guard_tampering" is disabled`) {
		t.Errorf("disabled hard rule: exit %d\n%s", code, out)
	}
}

// TestInstallCodex：--write 写入 ~/.codex/hooks.json 并提醒在 Codex 里信任；--shell 写进 harnesses.codex.shell；
// --remove 只删本项目的入口。
func TestInstallCodex(t *testing.T) {
	e := installEnv(t, func(name string, args ...string) ([]byte, error) { return []byte("codex-cli 0.162.1\n"), nil })
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	out, _, code := e.run(nil, "install", "codex")
	if code != 0 || !strings.Contains(out, "would register h-guard") || !strings.Contains(out, "hook codex --event PreToolUse --timeout 20") {
		t.Errorf("dry run: exit %d\n%s", code, out)
	}
	if _, err := os.Stat(hooks); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("dry run wrote hooks.json: %v", err)
	}
	out, errs, code := e.run(nil, "install", "codex", "--write", "--shell", "powershell")
	if code != 0 || !strings.Contains(out, "/hooks") {
		t.Fatalf("write: exit %d\n%s\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(hooks); !strings.Contains(string(b), "'/opt/bin/h-guard' hook codex --event UserPromptSubmit --timeout 20") {
		t.Errorf("hooks.json =\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml")); !strings.Contains(string(b), "shell: powershell") {
		t.Errorf("config.yaml =\n%s", b)
	}
	out, _, code = e.run(nil, "install", "codex", "--remove", "--write")
	if b, _ := os.ReadFile(hooks); code != 0 || strings.Contains(string(b), "hook codex") {
		t.Errorf("remove: exit %d\n%s\nhooks.json:\n%s", code, out, b)
	}
}

// TestInstallCodexWindowsShell：Windows 上安装 Codex 要知道它用哪种 shell：终端里询问（默认
// powershell），非交互时必须给 --shell；其他平台不问。--shell 只用于 codex。
func TestInstallCodexWindowsShell(t *testing.T) {
	e := installEnv(t, nil)
	e.goos = "windows"
	if _, errs, code := e.run(nil, "install", "codex"); code != 2 || !strings.Contains(errs, "--shell") {
		t.Errorf("non-interactive: exit %d, %s", code, errs)
	}
	e.tty = true
	out, _, code := e.run([]byte("\n"), "install", "codex")
	if code != 0 || !strings.Contains(out, "Which shell") || !strings.Contains(out, "set harnesses.codex.shell to powershell") {
		t.Errorf("default answer: exit %d\n%s", code, out)
	}
	out, _, _ = e.run([]byte("posix\n"), "install", "codex")
	if !strings.Contains(out, "set harnesses.codex.shell to posix") {
		t.Errorf("posix answer:\n%s", out)
	}
	if _, _, code := e.run([]byte("cmd\n"), "install", "codex"); code != 2 {
		t.Errorf("unknown answer: exit %d", code)
	}
	if _, _, code := e.run(nil, "install", "claudecode", "--shell", "posix"); code != 2 {
		t.Errorf("--shell with claudecode: exit %d", code)
	}
	if _, _, code := e.run(nil, "install", "codex", "--shell", "cmd"); code != 2 {
		t.Errorf("--shell cmd: exit %d", code)
	}
}

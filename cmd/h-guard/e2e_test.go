package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildBinary 编译 h-guard 到临时目录。
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "h-guard")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// isolated 返回只指向临时配置与缓存目录的环境变量。
func isolated(t *testing.T) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "LANG=en_US.UTF-8",
		"XDG_CONFIG_HOME=" + t.TempDir(), "XDG_CACHE_HOME=" + t.TempDir()}
	return env
}

func preToolUse(cmd string) []byte {
	b, _ := json.Marshal(map[string]any{"session_id": "s1", "transcript_path": "", "cwd": "/w", "hook_event_name": "PreToolUse",
		"permission_mode": "default", "tool_name": "Bash", "tool_input": map[string]string{"command": cmd}, "tool_use_id": "t1"})
	return b
}

func decision(t *testing.T, stdout []byte) string {
	t.Helper()
	if len(bytes.TrimSpace(stdout)) == 0 {
		return "pass"
	}
	var o struct {
		HookSpecificOutput struct {
			HookEventName      string `json:"hookEventName"`
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout, &o); err != nil || o.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	return o.HookSpecificOutput.PermissionDecision
}

func TestBinaryHook(t *testing.T) {
	bin := buildBinary(t)
	env := isolated(t)
	for cmd, want := range map[string]string{"rm -rf /": "deny", "ls": "pass", "rm ~/.claude/settings.json": "ask"} {
		c := exec.Command(bin, "hook", "claudecode", "--event", "PreToolUse")
		c.Env, c.Stdin = env, bytes.NewReader(preToolUse(cmd))
		out, err := c.Output()
		if err != nil {
			t.Fatalf("%q: %v", cmd, err)
		}
		if got := decision(t, out); got != want {
			t.Errorf("%q: %s, want %s", cmd, got, want)
		}
	}
}

// TestPluginWrapper 覆盖插件内经典 PreToolUse 的外包脚本（spec §7.7、§13）：正常时转交 h-guard 的输出，
// h-guard 无法运行时输出 ask。
func TestPluginWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX wrapper is not used on Windows (M3)")
	}
	bin := buildBinary(t)
	script, _ := filepath.Abs(filepath.Join("..", "..", "extensions", "claudecode", "hooks", "pretooluse.sh"))
	run := func(binPath, cmd string) string {
		root := t.TempDir()
		if binPath != "" {
			os.WriteFile(filepath.Join(root, "hguard-bin"), []byte(binPath+"\n"), 0o600)
		}
		c := exec.Command("sh", script)
		c.Env = append(isolated(t), "CLAUDE_PLUGIN_ROOT="+root)
		c.Stdin = bytes.NewReader(preToolUse(cmd))
		out, err := c.Output()
		if err != nil {
			t.Fatalf("wrapper exited with %v", err)
		}
		return decision(t, out)
	}
	if got := run(bin, "rm -rf /"); got != "deny" {
		t.Errorf("deny through the wrapper = %s", got)
	}
	if got := run(bin, "ls"); got != "pass" {
		t.Errorf("pass through the wrapper = %s", got)
	}
	if got := run(filepath.Join(t.TempDir(), "missing"), "ls"); got != "ask" {
		t.Errorf("a missing binary must ask, got %s", got)
	}
	failing := filepath.Join(t.TempDir(), "fail.sh")
	os.WriteFile(failing, []byte("#!/bin/sh\nexit 3\n"), 0o700)
	if got := run(failing, "ls"); got != "ask" {
		t.Errorf("a failing binary must ask, got %s", got)
	}
}

func TestBinaryVersion(t *testing.T) {
	out, err := exec.Command(buildBinary(t), "version").Output()
	if err != nil || !strings.HasPrefix(string(out), "h-guard ") {
		t.Errorf("version = %q, %v", out, err)
	}
}

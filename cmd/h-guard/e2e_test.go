package main_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
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

// TestPluginWrapper 覆盖插件内经典 PreToolUse 的外包脚本：正常时转交 h-guard 的输出，
// h-guard 无法运行时输出 ask。
func TestPluginWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the POSIX wrapper is not used on Windows")
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

// TestBinaryReplaysRecordedFixtures：把录制的真实 hook 输入（Codex 0.162.1、Claude Code 2.1.296）逐条交给
// 编译出的二进制（离线端到端）：退出码都是 0，输出为空或是合法 JSON；Codex 样本都是无害的测试
// 命令，全部无输出。再把录制的输入改成危险的命令或受保护的文件，确认真实的输入形状经二进制得到 deny。
func TestBinaryReplaysRecordedFixtures(t *testing.T) {
	bin := buildBinary(t)
	env := isolated(t)
	fs, err := fixtures.Load(filepath.Join("..", "..", "testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(harness, event string, stdin []byte) []byte {
		c := exec.Command(bin, "hook", harness, "--event", event)
		c.Env, c.Stdin = env, bytes.NewReader(stdin)
		out, err := c.Output()
		if err != nil {
			t.Fatalf("%s %s: %v", harness, event, err)
		}
		return out
	}
	n := map[string]int{}
	var bashPre, patchPre []byte
	for _, f := range fs {
		out := run(f.Harness, f.Event, f.Stdin)
		if len(out) > 0 && !json.Valid(out) {
			t.Errorf("%s: stdout %q", f.Path, out)
		}
		if f.Harness == "codex" && len(out) > 0 {
			t.Errorf("%s: recorded test commands must pass, got %s", f.Path, out)
		}
		n[f.Harness]++
		switch {
		case f.Harness == "codex" && f.Scenario == "bash-echo" && f.Event == "PreToolUse":
			bashPre = f.Stdin
		case f.Harness == "codex" && f.Scenario == "apply-patch" && f.Event == "PreToolUse" && patchPre == nil:
			patchPre = f.Stdin
		}
	}
	if n["codex"] != 45 || n["claudecode"] == 0 || bashPre == nil || patchPre == nil {
		t.Fatalf("replayed %v", n)
	}
	mutate := func(stdin []byte, input map[string]string) []byte {
		var m map[string]any
		json.Unmarshal(stdin, &m)
		m["tool_input"] = input
		b, _ := json.Marshal(m)
		return b
	}
	if d := codexDecision(t, run("codex", "PreToolUse", mutate(bashPre, map[string]string{"command": "rm -rf /"}))); d != "deny" {
		t.Errorf("recorded Bash input with rm -rf /: %s", d)
	}
	home := ""
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "HOME="); ok {
			home = v
		}
	}
	patch := "*** Begin Patch\n*** Update File: " + filepath.Join(home, ".claude", "settings.json") + "\n@@\n-{}\n+{}\n*** End Patch"
	if d := codexDecision(t, run("codex", "PreToolUse", mutate(patchPre, map[string]string{"command": patch}))); d != "deny" {
		t.Errorf("recorded apply_patch input on a guarded file: %s", d)
	}
}

// codexDecision 读 Codex PreToolUse 的输出：空为 pass，否则是 permissionDecision（Codex 上只会是 deny）。
func codexDecision(t *testing.T, stdout []byte) string {
	t.Helper()
	if len(bytes.TrimSpace(stdout)) == 0 {
		return "pass"
	}
	return decision(t, stdout)
}

// TestBinaryGeneric：generic 契约经二进制：pass 也输出 JSON；读不懂的输入退出码 1。
func TestBinaryGeneric(t *testing.T) {
	bin := buildBinary(t)
	env := isolated(t)
	for in, want := range map[string]string{
		`{"version":1,"kind":"action","actions":[{"kind":"exec","command":"rm -rf /"}],"cwd":"/w","session_id":"s1"}`: "deny",
		`{"version":1,"kind":"action","actions":[{"kind":"exec","command":"ls"}],"cwd":"/w","session_id":"s1"}`:       "pass",
		`{"version":1,"kind":"tool_output","text":"build ok","session_id":"s1"}`:                                      "pass",
	} {
		c := exec.Command(bin, "hook", "generic", "--event", "action")
		c.Env, c.Stdin = env, strings.NewReader(in)
		out, err := c.Output()
		var o struct{ Decision string }
		if err != nil || json.Unmarshal(out, &o) != nil || o.Decision != want {
			t.Errorf("%s: %s (%v), want %s", in, out, err, want)
		}
	}
	// 没有结论的路径都输出失败说明与退出码 1：读不懂的输入；不写 --event 时的输入超限与看门狗
	failing := func(name string, stdin io.Reader, args ...string) {
		c := exec.Command(bin, append([]string{"hook", "generic"}, args...)...)
		c.Env, c.Stdin = env, stdin
		out, err := c.Output()
		var ee *exec.ExitError
		var o struct{ Error string }
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || json.Unmarshal(out, &o) != nil || o.Error == "" {
			t.Errorf("%s: %s, %v", name, out, err)
		}
	}
	failing("unreadable input", strings.NewReader("not json"), "--event", "action")
	failing("oversize input without --event", bytes.NewReader(bytes.Repeat([]byte("x"), 16<<20+1)))
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	failing("stalled stdin without --event", r, "--timeout", "1")
	r.Close()
}

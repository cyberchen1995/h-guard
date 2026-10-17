//go:build darwin || linux

package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestBinaryInstallRoundTrip 用编译出的二进制在隔离的 HOME 里安装 Claude Code 与 Codex 的入口：
//   - 装好的入口真的能用：按 hooks.json 里写的命令运行 Codex 的入口、按插件目录运行 Claude Code 的外包脚本，
//     危险命令得到 deny；
//   - 用户已有的设置与 hook 保留；移除之后两个文件的内容（按取值比较）与安装前相同，插件目录删掉。
//
// harness 的命令行不可用（PATH 里没有 claude、codex），install 只说明、不校验插件。
func TestBinaryInstallRoundTrip(t *testing.T) {
	bin := buildBinary(t)
	home := t.TempDir()
	env := []string{"PATH=/usr/bin:/bin", "HOME=" + home, "LANG=en_US.UTF-8",
		"XDG_CONFIG_HOME=" + filepath.Join(home, ".config"), "XDG_CACHE_HOME=" + filepath.Join(home, ".cache")}
	settings := filepath.Join(home, ".claude", "settings.json")
	hooks := filepath.Join(home, ".codex", "hooks.json")
	os.MkdirAll(filepath.Dir(settings), 0o700)
	os.MkdirAll(filepath.Dir(hooks), 0o700)
	origSettings := `{"model": "opus", "env": {"FOO": "1"}, "permissions": {"allow": ["Bash(ls)"]}}`
	origHooks := `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "audit.sh", "timeout": 5}]}]}}`
	os.WriteFile(settings, []byte(origSettings), 0o600)
	os.WriteFile(hooks, []byte(origHooks), 0o600)
	run := func(stdin []byte, args ...string) string {
		t.Helper()
		c := exec.Command(bin, args...)
		c.Env, c.Stdin = env, bytes.NewReader(stdin)
		out, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("h-guard %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return string(out)
	}
	run(nil, "install", "claudecode", "--write")
	run(nil, "install", "codex", "--write")

	// Codex：按 hooks.json 里写的命令运行入口（Codex 用 sh -c 运行它）
	var h struct {
		Hooks map[string][]struct {
			Hooks []struct{ Command string } `json:"hooks"`
		} `json:"hooks"`
	}
	b, _ := os.ReadFile(hooks)
	json.Unmarshal(b, &h)
	cmd := ""
	for _, g := range h.Hooks["PreToolUse"] {
		for _, x := range g.Hooks {
			if strings.Contains(x.Command, "hook codex") {
				cmd = x.Command
			}
		}
	}
	in, _ := json.Marshal(map[string]any{"session_id": "s1", "transcript_path": "", "cwd": home, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_input": map[string]string{"command": "rm -rf /"}, "tool_use_id": "e1"})
	c := exec.Command("sh", "-c", cmd)
	c.Env, c.Stdin = env, bytes.NewReader(in)
	out, err := c.Output()
	if err != nil || decision(t, out) != "deny" {
		t.Errorf("installed Codex entry %q: %s, %v", cmd, out, err)
	}

	// Claude Code：插件目录里的外包脚本（Claude Code 以 CLAUDE_PLUGIN_ROOT 运行它）
	dir := filepath.Join(home, ".config", "h-guard", "extensions", "claudecode")
	c = exec.Command("sh", filepath.Join(dir, "hooks", "pretooluse.sh"))
	c.Env, c.Stdin = append(env, "CLAUDE_PLUGIN_ROOT="+dir), bytes.NewReader(preToolUse("rm -rf /"))
	out, err = c.Output()
	if err != nil || decision(t, out) != "deny" {
		t.Errorf("installed Claude Code wrapper: %s, %v", out, err)
	}
	run(nil, "install", "claudecode", "--remove", "--write")
	run(nil, "install", "codex", "--remove", "--write")
	for path, orig := range map[string]string{settings: origSettings, hooks: origHooks} {
		var want, got any
		json.Unmarshal([]byte(orig), &want)
		b, _ := os.ReadFile(path)
		if err := json.Unmarshal(b, &got); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s after install and remove:\n%s", path, b)
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("plugin dir after remove: %v", err)
	}
}

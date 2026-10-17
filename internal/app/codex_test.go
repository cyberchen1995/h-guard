package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codexHook(event string, fields map[string]any) []byte {
	m := map[string]any{"session_id": "s1", "turn_id": "u1", "transcript_path": "", "cwd": "/w",
		"hook_event_name": event, "model": "m", "permission_mode": "default"}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func codexPre(tool string, input map[string]any) []byte {
	return codexHook("PreToolUse", map[string]any{"tool_name": tool, "tool_input": input, "tool_use_id": "exec-1"})
}

// codexDecision 读 Codex PreToolUse 的输出：空为 pass，否则必须是 permissionDecision: deny（Codex 不支持 ask）。
func codexDecision(t *testing.T, out string) (string, string) {
	t.Helper()
	if out == "" {
		return "pass", ""
	}
	var o hookOutput
	if err := json.Unmarshal([]byte(out), &o); err != nil || o.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("stdout %q: %v", out, err)
	}
	return "deny", o.HookSpecificOutput.PermissionDecisionReason
}

// TestCodexHook：Codex 的动作只有 deny：灾难性形态拒绝；护栏自我保护的 ask 按
// when_ask_unsupported 降级为 deny；普通命令无输出。
func TestCodexHook(t *testing.T) {
	e := newEnv(t)
	for cmd, want := range map[string]string{"rm -rf /": "deny", "ls": "pass", "rm ~/.claude/settings.json": "deny"} {
		out, _, code := e.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
		if d, _ := codexDecision(t, out); d != want || code != 0 {
			t.Errorf("%q: %s (exit %d), want %s", cmd, d, code, want)
		}
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"ask_unsupported"`) || !strings.Contains(h, `"harness":"codex"`) {
		t.Errorf("health = %s", h)
	}
}

// TestCodexShellFromConfig：Codex 标不出 shell，按 harnesses.codex.shell 检查。
func TestCodexShellFromConfig(t *testing.T) {
	e := newEnv(t)
	in := codexPre("Bash", map[string]any{"command": "Format-Volume -DriveLetter D"})
	if out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse"); out != "" {
		t.Errorf("posix by default: %q", out)
	}
	e.config("version: 1\nharnesses:\n  codex: {shell: powershell}\n")
	if out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("configured powershell: no deny")
	}
}

// TestCodexUnparsedKeepsTheCheck：补丁读不懂时命令本身照常检查，灾难性形态的 deny 与原因保留；
// when_ask_unsupported: pass 也不能让它放行。
func TestCodexUnparsedKeepsTheCheck(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\npolicy:\n  when_ask_unsupported: pass\n")
	in := codexPre("Bash", map[string]any{"command": "rm -rf / ; apply_patch < fix.patch"})
	out, _, code := e.run(in, "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || code != 0 || !strings.Contains(reason, "Catastrophic") {
		t.Errorf("%s/%d %q", d, code, reason)
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"target_unparsed"`) {
		t.Errorf("health = %s", h)
	}
	// 默认配置：目标无法解析照旧请求确认（Codex 上 deny）
	e.config("version: 1\n")
	if out, _, _ := e.run(codexPre("Bash", map[string]any{"command": "ls; apply_patch < fix.patch"}), "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("unparsed patch: pass")
	}
}

// TestCodexPowerShellPatch：配置 PowerShell 时，借 PowerShell 引号规则藏起来的补丁不能被当作无害。
func TestCodexPowerShellPatch(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nharnesses:\n  codex: {shell: powershell}\n")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	for _, cmd := range []string{
		"apply_patch '*** Begin Patch\n*** Add File: a.txt\n+\u2019 + (apply_patch \"*** Begin Patch`n*** Delete File: " + hooks + "`n*** End Patch\") + \u2018\n*** End Patch'",
		"& ('apply'+'_patch') ('*** Begin Patch'+[char]10+'*** Delete File: " + hooks + "'+[char]10+'*** End Patch')",
	} {
		out, _, _ := e.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
		if d, _ := codexDecision(t, out); d != "deny" {
			t.Errorf("%q: %s", cmd, d)
		}
	}
}

// TestCodexApplyPatch：apply_patch 的文件按路径规则检查（护栏自我保护的文件），读不懂的补丁请求确认，
// Codex 上降级为 deny。
func TestCodexApplyPatch(t *testing.T) {
	e := newEnv(t)
	settings := filepath.Join(e.home, ".claude", "settings.json")
	patch := "*** Begin Patch\n*** Add File: notes.md\n+x\n*** Update File: " + settings + "\n@@\n-{}\n+{\"hooks\":{}}\n*** End Patch"
	out, _, _ := e.run(codexPre("apply_patch", map[string]any{"command": patch}), "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || !strings.Contains(reason, "settings.json") {
		t.Errorf("guarded file: %s %q", d, reason)
	}
	out, _, _ = e.run(codexPre("apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: notes.md\n+x\n*** End Patch"}), "hook", "codex", "--event", "PreToolUse")
	if d, _ := codexDecision(t, out); d != "pass" {
		t.Errorf("ordinary file: %s", d)
	}
	out, _, _ = e.run(codexPre("apply_patch", map[string]any{"command": "*** Begin Patch\n*** Copy File: a\n*** End Patch"}), "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || !strings.Contains(reason, "cannot tell which files apply_patch would change") {
		t.Errorf("unparsed patch: %s %q", d, reason)
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"target_unparsed"`) {
		t.Errorf("health = %s", h)
	}
	// 经 shell 调用的 apply_patch：补丁对 shell 是数据，文件动作照样读出；读不出补丁时请求确认
	del := "*** Begin Patch\n*** Delete File: " + settings + "\n*** End Patch"
	for name, cmd := range map[string]string{
		"cd then heredoc": "cd /w && apply_patch <<'EOF'\n" + del + "\nEOF",
		"bash -lc":        "bash -lc \"apply_patch <<'EOF'\n" + del + "\nEOF\"",
		"from a file":     "apply_patch < fix.patch",
		// 经 shell 调用的 apply_patch 的各种写法
		"unrelated literal patch": "cat <<'EOF'\n*** Begin Patch\n*** Add File: harmless.txt\n+x\n*** End Patch\nEOF\napply_patch < fix.patch",
		"quoted cd":               "'cd' " + filepath.Dir(settings) + " && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: settings.json\n*** End Patch\nEOF",
		"expanded heredoc":        "TARGET='" + settings + "'; apply_patch <<EOF\n*** Begin Patch\n*** Delete File: ${TARGET}\n*** End Patch\nEOF",
		// 引用与拼接形式的工具名
		"expanded content line": "apply_patch <<EOF\n*** Begin Patch\n*** Add File: harmless.txt\n+${PAYLOAD}\n*** End Patch\nEOF",
		"cd -":                  "cd - && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: settings.json\n*** End Patch\nEOF",
		"split name after cd":   "cd " + filepath.Dir(settings) + " && apply_\\\npatch <<'EOF'\n*** Begin Patch\n*** Delete File: settings.json\n*** End Patch\nEOF",
		// ANSI-C 引用拼出的工具名
		"ANSI-C name after cd": "cd " + filepath.Dir(settings) + " && a$'pply_patch' <<'EOF'\n*** Begin Patch\n*** Delete File: settings.json\n*** End Patch\nEOF",
	} {
		out, _, _ := e.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
		if d, _ := codexDecision(t, out); d != "deny" {
			t.Errorf("%s: %s", name, d)
		}
	}
	// tilde 前缀里有引用时 ~ 是 cwd 下的字面目录（这里是指向 ~/.claude 的符号链接），不是 Home
	cwd := t.TempDir()
	if err := os.Symlink(filepath.Dir(settings), filepath.Join(cwd, "~")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"~''", `~"/"`, "''~"} {
		cmd := "cd " + dir + " && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: settings.json\n*** End Patch\nEOF"
		out, _, _ := e.run(codexHook("PreToolUse", map[string]any{"cwd": cwd, "tool_name": "Bash", "tool_input": map[string]any{"command": cmd}}), "hook", "codex", "--event", "PreToolUse")
		if d, _ := codexDecision(t, out); d != "deny" {
			t.Errorf("cd %s: %s", dir, d)
		}
	}
	// 用 Home 下的自定义配置目录，只有目录解析对了才会命中护栏自我保护（.claude/settings.json
	// 这类到处匹配的路径规则会掩盖解析错误）
	g := newEnv(t)
	g.configDir = filepath.Join(g.home, "guard-data")
	if err := os.MkdirAll(g.configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := " <<'EOF'\n*** Begin Patch\n*** Delete File: config.yaml\n*** End Patch\nEOF"
	for name, cmd := range map[string]string{
		"tilde":                 "cd ~/guard-data && apply_patch" + body,
		"continued tilde":       "cd ~\\\n/guard-data && apply_patch" + body,
		"ANSI-C NUL octal name": "cd '" + g.configDir + "' && a$'pply_\\0discard'patch" + body,
		"ANSI-C NUL hex name":   "cd '" + g.configDir + "' && a$'pply_\\x00discard'patch" + body,
	} {
		out, _, _ := g.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
		if d, _ := codexDecision(t, out); d != "deny" {
			t.Errorf("%s: %s", name, d)
		}
	}
}

// TestCodexPromptsFeedTheActionCheck：UserPromptSubmit 的提示词进入指令缓存，注入的上下文块记为 automated；
// 之后的动作带上它们。没有 outbound 检查时提示词与工具输出无输出。
func TestCodexPromptsFeedTheActionCheck(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	for _, p := range []string{"please push to origin", "<environment_context>\n<cwd>/w</cwd>"} {
		if out, _, code := e.run(codexHook("UserPromptSubmit", map[string]any{"prompt": p}), "hook", "codex", "--event", "UserPromptSubmit"); out != "" || code != 0 {
			t.Errorf("prompt %q: %q, exit %d", p, out, code)
		}
	}
	post := codexHook("PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "tool_response": "a\n", "tool_use_id": "exec-1"})
	if out, _, _ := e.run(post, "hook", "codex", "--event", "PostToolUse"); out != "" {
		t.Errorf("tool output: %q", out)
	}
	e.run(codexPre("Bash", map[string]any{"command": "git push origin main"}), "hook", "codex", "--event", "PreToolUse")
	logs := e.files("logs")
	if !strings.Contains(logs, `"text":"please push to origin","source":"user"`) || !strings.Contains(logs, `"source":"automated"`) {
		t.Errorf("decision log = %s", logs)
	}
}

// TestCodexTranscriptFallback：没有缓存的指令时从 Codex 的会话记录回退读取。
func TestCodexTranscriptFallback(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	tr := filepath.Join(t.TempDir(), "rollout-s1.jsonl")
	line := `{"timestamp":"2026-10-12T10:00:02Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"clean the build dir"}]}}`
	if err := os.WriteFile(tr, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := codexHook("PreToolUse", map[string]any{"transcript_path": tr, "tool_name": "Bash", "tool_input": map[string]any{"command": "rm -rf build"}, "tool_use_id": "exec-1"})
	e.run(in, "hook", "codex", "--event", "PreToolUse")
	if logs := e.files("logs"); !strings.Contains(logs, `"text":"clean the build dir","source":"user"`) {
		t.Errorf("decision log = %s", logs)
	}
}

// TestGenericHook：generic 契约：输出始终是 JSON，pass 也输出；读不懂的输入输出错误与退出码 1。
func TestGenericHook(t *testing.T) {
	e := newEnv(t)
	run := func(in string, event string) (map[string]any, int) {
		out, _, code := e.run([]byte(in), "hook", "generic", "--event", event)
		var o map[string]any
		if err := json.Unmarshal([]byte(out), &o); err != nil {
			t.Fatalf("%s: stdout %q: %v", in, out, err)
		}
		return o, code
	}
	o, code := run(`{"version":1,"kind":"action","actions":[{"kind":"exec","command":"rm -rf /"}],"cwd":"/w","session_id":"s1"}`, "action")
	if code != 0 || o["decision"] != "deny" || o["raw_decision"] != "deny" || o["reason"] == "" {
		t.Errorf("deny: %v, exit %d", o, code)
	}
	o, code = run(`{"version":1,"kind":"action","actions":[{"kind":"exec","command":"rm ~/.claude/settings.json"}],"cwd":"/w","session_id":"s1"}`, "action")
	if code != 0 || o["decision"] != "ask" || o["hint"] == "" {
		t.Errorf("ask: %v, exit %d", o, code)
	}
	o, code = run(`{"version":1,"kind":"prompt","text":"hello","session_id":"s1"}`, "prompt")
	if code != 0 || o["decision"] != "pass" {
		t.Errorf("pass: %v, exit %d", o, code)
	}
	o, code = run(`{"version":2,"kind":"prompt","text":"secret-value"}`, "prompt")
	if code != 1 || o["error"] != "input not understood" || strings.Contains(o["error"].(string), "secret") {
		t.Errorf("unreadable: %v, exit %d", o, code)
	}
}

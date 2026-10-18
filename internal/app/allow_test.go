package app

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

var grantID = regexp.MustCompile("`h-guard allow ([0-9a-f]{10})`")

// TestCodexGrantOnce：Codex 不能请求确认，ask 变成 deny；原因写明操作、目标、后果、更稳妥的做法与 h-guard allow 的编号。
// 用户在终端里批准后，同一操作重试一次放行，再试又被拦下；换了命令或目录都对不上。
func TestCodexGrantOnce(t *testing.T) {
	e := newEnv(t)
	cmd := "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"
	ev := codexPre("Bash", map[string]any{"command": cmd})
	out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse")
	d, reason := codexDecision(t, out)
	for _, w := range []string{"Operation: `" + cmd + "` in /w.", "Impact: What actually runs is hidden", "Safer way: Decode it",
		"cannot ask for confirmation", "in their own terminal"} {
		if !strings.Contains(reason, w) {
			t.Errorf("reason lacks %q: %s", w, reason)
		}
	}
	m := grantID.FindStringSubmatch(reason)
	if d != "deny" || m == nil {
		t.Fatalf("decision %s, reason %s", d, reason)
	}
	id := m[1]

	list, _, _ := e.run(nil, "allow")
	if !strings.Contains(list, id) || !strings.Contains(list, "exec[posix] "+cmd) || !strings.Contains(list, "rules: obfuscated_exec") {
		t.Errorf("allow list:\n%s", list)
	}
	// 不在终端里（agent 经由 hook 运行）不能批准
	if _, errs, code := e.run([]byte("y\n"), "allow", id); code != 1 || !strings.Contains(errs, "interactive terminal") {
		t.Errorf("non-terminal approve: exit %d, %s", code, errs)
	}
	e.tty = true
	if out, _, code := e.run([]byte("n\n"), "allow", id); code != 1 || !strings.Contains(out, "not approved") {
		t.Errorf("declined: exit %d\n%s", code, out)
	}
	if out, _, code := e.run([]byte("y\n"), "allow", id, "--ttl", "2h"); code != 2 {
		t.Errorf("ttl over 1h: exit %d\n%s", code, out)
	}
	if out, _, code := e.run([]byte("y\n"), "allow", id, "--ttl", "500ms"); code != 2 {
		t.Errorf("ttl under 1s: exit %d\n%s", code, out)
	}
	if out, _, code := e.run([]byte("y\n"), "allow", id); code != 0 || !strings.Contains(out, "approved once until") {
		t.Fatalf("approve: exit %d\n%s", code, out)
	}
	// 换了目录或命令：对不上授权
	other := codexHook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": cmd}, "tool_use_id": "e2", "cwd": "/other"})
	if out, _, _ := e.run(other, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval let the operation run in another directory")
	}
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out != "" {
		t.Errorf("approved retry: %s", out)
	}
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval was used twice")
	}
	// 再次被拦下是一次新的打断，可以重新批准；没有被拦下过的编号批准不了
	if _, errs, code := e.run([]byte("y\n"), "allow", "0123456789"); code != 1 || !strings.Contains(errs, "no pending operation") {
		t.Errorf("approve unknown: exit %d, %s", code, errs)
	}
}

// TestGrantNotOfferedForHardRules：护栏自我保护（硬规则）与 deny 不提供单次授权；能请求确认的 harness
// （Claude Code）也不提供，用户直接在确认框里决定。
func TestGrantNotOfferedForHardRules(t *testing.T) {
	e := newEnv(t)
	for _, cmd := range []string{"rm ~/.claude/settings.json", "rm -rf /"} {
		out, _, _ := e.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
		if d, reason := codexDecision(t, out); d != "deny" || strings.Contains(reason, "h-guard allow") {
			t.Errorf("%s: %s %s", cmd, d, reason)
		}
	}
	out, _, _ := e.run(bash("echo cm0gLXJmIGJ1aWxk | base64 -d | sh"), "hook", "claudecode", "--event", "PreToolUse")
	if d, reason := decisionOf(t, out); d != "ask" || strings.Contains(reason, "h-guard allow") || !strings.Contains(reason, "Operation: `") {
		t.Errorf("claudecode: %s %s", d, reason)
	}
	if entries, _ := os.ReadDir(filepath.Join(e.cache, "grants", "pending")); len(entries) != 0 {
		t.Errorf("pending grants: %v", entries)
	}
}

// TestAllowRevoke：批准后还没用掉的授权可以撤销；撤销后重试照常被拦下。
func TestAllowRevoke(t *testing.T) {
	e := newEnv(t)
	ev := codexPre("Bash", map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"})
	out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	id := grantID.FindStringSubmatch(reason)[1]
	e.tty = true
	e.run([]byte("y\n"), "allow", id)
	if out, _, code := e.run(nil, "allow", "--revoke", id); code != 0 || !strings.Contains(out, "revoked") {
		t.Errorf("revoke: exit %d\n%s", code, out)
	}
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("a revoked approval let the operation run")
	}
	if _, _, code := e.run(nil, "allow", "--revoke", "0000000000"); code != 1 {
		t.Errorf("revoke unknown: exit %d", code)
	}
	if out, _, _ := newEnv(t).run(nil, "allow"); !strings.Contains(out, "nothing to approve") {
		t.Errorf("empty list:\n%s", out)
	}
}

// TestAllowEscapesControlCharacters：操作原文里的终端控制序列与双向文本控制符转义后才显示，不能改写确认时看到的内容。
func TestAllowEscapesControlCharacters(t *testing.T) {
	e := newEnv(t)
	cmd := "echo cm0gLXJmIGJ1aWxk | base64 -d | sh #\x1b[2J\x1b[Hls \u202e"
	e.run(codexPre("Bash", map[string]any{"command": cmd}), "hook", "codex", "--event", "PreToolUse")
	out, _, _ := e.run(nil, "allow")
	if strings.ContainsAny(out, "\x1b\u202e") || !strings.Contains(out, `\u001b[2J`) || !strings.Contains(out, "\\u202e") {
		t.Errorf("allow list: %q", out)
	}
}

// TestForgedApprovalInTheCacheIsRejected：agent 只往缓存目录写一条形状正确、但没有用配置目录里的密钥签名的授权，
// 重试照样被拦下。
func TestForgedApprovalInTheCacheIsRejected(t *testing.T) {
	e := newEnv(t)
	ev := codexPre("Bash", map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"})
	out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	id := grantID.FindStringSubmatch(reason)[1]
	pending, err := os.ReadFile(filepath.Join(e.cache, "grants", "pending", id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.TrimSuffix(string(pending), "}") + `,"approved":"2026-01-01T00:00:00Z","expires":"2999-01-01T00:00:00Z","mac":"00"}`
	os.MkdirAll(filepath.Join(e.cache, "grants", "active"), 0o700)
	os.WriteFile(filepath.Join(e.cache, "grants", "active", id+".json"), []byte(forged), 0o600)
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("a forged approval let the operation run")
	}
}

// TestNoGrantForUnparsedTargets：目标读不全的操作（命令里有读不出的补丁）不提供单次授权，用户不会白白用掉一次批准。
func TestNoGrantForUnparsedTargets(t *testing.T) {
	e := newEnv(t)
	in := codexPre("Bash", map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh; apply_patch < fix.patch"})
	out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || strings.Contains(reason, "h-guard allow") {
		t.Errorf("%s %s", d, reason)
	}
}

// TestInterruptionEscapesControlCharacters：拦截说明里的命令与目录同样转义控制字符，harness 显示时不会被改写。
func TestInterruptionEscapesControlCharacters(t *testing.T) {
	e := newEnv(t)
	out, _, _ := e.run(codexPre("Bash", map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh #\x1b[2J\u202e"}), "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	if strings.ContainsAny(reason, "\x1b\u202e") || !strings.Contains(reason, `\u001b[2J`) {
		t.Errorf("reason = %q", reason)
	}
}

// TestGrantBindsTheRawToolInput：授权绑定原始工具输入：同样的命令换了执行参数（超时）对不上授权。
func TestGrantBindsTheRawToolInput(t *testing.T) {
	e := newEnv(t)
	in := func(timeout int) []byte {
		return codexPre("Bash", map[string]any{"timeout_ms": timeout, "command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"})
	}
	out, _, _ := e.run(in(1), "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	m := grantID.FindStringSubmatch(reason)
	if m == nil {
		t.Fatalf("no grant offered: %s", reason)
	}
	e.tty = true
	if _, _, code := e.run([]byte("y\n"), "allow", m[1]); code != 0 {
		t.Fatal("approve failed")
	}
	if out, _, _ := e.run(in(2), "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval let the same command run with other execution parameters")
	}
	if out, _, _ := e.run(in(1), "hook", "codex", "--event", "PreToolUse"); out != "" {
		t.Errorf("approved retry: %s", out)
	}
}

// TestAllowShowsTheRawInputAndRealCwd：h-guard allow 原样显示原始工具输入（执行参数只在这里看得到）；
// 授权绑定工作目录的真实路径，批准之后把它改成指向别处的符号链接就对不上。
func TestAllowShowsTheRawInputAndRealCwd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	e := newEnv(t)
	base := t.TempDir()
	repoA, repoB, link := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "work")
	os.Mkdir(repoA, 0o700)
	os.Mkdir(repoB, 0o700)
	os.Symlink(repoA, link)
	in := codexHook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_use_id": "e1", "cwd": link,
		"tool_input": map[string]any{"timeout_ms": 42, "command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"}})
	out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	m := grantID.FindStringSubmatch(reason)
	if m == nil {
		t.Fatalf("no grant offered: %s", reason)
	}
	list, _, _ := e.run(nil, "allow")
	realA, _ := filepath.EvalSymlinks(repoA) // macOS 的临时目录本身在 /var -> /private/var 的符号链接下
	if !strings.Contains(list, `"timeout_ms":42`) || !strings.Contains(list, "(really "+realA+")") {
		t.Errorf("allow list:\n%s", list)
	}
	e.tty = true
	if _, _, code := e.run([]byte("y\n"), "allow", m[1]); code != 0 {
		t.Fatal("approve failed")
	}
	os.Remove(link)
	os.Symlink(repoB, link)
	if out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval followed a retargeted working directory")
	}
}

// TestGrantBindsTheDirectoryIdentity：授权绑定工作目录的文件身份，批准之后把目录挪走、在同一路径放上另一个目录就对不上。
func TestGrantBindsTheDirectoryIdentity(t *testing.T) {
	e := newEnv(t)
	base := t.TempDir()
	work, moved := filepath.Join(base, "work"), filepath.Join(base, "moved")
	os.Mkdir(work, 0o700)
	in := codexHook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_use_id": "e1", "cwd": work,
		"tool_input": map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"}})
	out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	m := grantID.FindStringSubmatch(reason)
	if m == nil {
		t.Fatalf("no grant offered: %s", reason)
	}
	e.tty = true
	if _, _, code := e.run([]byte("y\n"), "allow", m[1]); code != 0 {
		t.Fatal("approve failed")
	}
	if err := os.Rename(work, moved); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(work, 0o700)
	if out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval followed another directory placed at the same path")
	}
}

// TestNoGrantWithoutWorkingDirectory：没有工作目录的事件按 hook 进程所在的目录执行，绑不住，不提供授权。
func TestNoGrantWithoutWorkingDirectory(t *testing.T) {
	e := newEnv(t)
	in := codexHook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_use_id": "e1", "cwd": "",
		"tool_input": map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"}})
	out, _, _ := e.run(in, "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || grantID.MatchString(reason) {
		t.Errorf("decision %s, reason %s", d, reason)
	}
}

// TestGrantKeepsLargeIntegers：超出 float64 精度的整数原样绑定，相邻的会话编号对不上授权。
func TestGrantKeepsLargeIntegers(t *testing.T) {
	if got := toolInputText([]byte(`{"tool_input":{"session_id":9007199254740993}}`)); got != `{"session_id":9007199254740993}` {
		t.Errorf("toolInputText = %s", got)
	}
}

// TestNoGrantForInteractiveInput：写进交互式进程的输入（write_stdin）不提供授权：进程的工作目录与状态在批准之后还能被改掉。
func TestNoGrantForInteractiveInput(t *testing.T) {
	e := newEnv(t)
	// Codex 可能把 write_stdin 规范成 Bash 报上来：按 chars 字段认
	for _, tool := range []string{"write_stdin", "Bash"} {
		out, _, _ := e.run(codexPre(tool, map[string]any{"session_id": 1, "chars": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh\n"}),
			"hook", "codex", "--event", "PreToolUse")
		if d, reason := codexDecision(t, out); d != "deny" || grantID.MatchString(reason) {
			t.Errorf("%s: decision %s, reason %s", tool, d, reason)
		}
	}
}

// TestGrantBindsTheSession：授权绑定被拦下的会话，另一个会话（可能带着别的凭据）里同样的调用对不上。
func TestGrantBindsTheSession(t *testing.T) {
	e := newEnv(t)
	in := func(session string) []byte {
		return codexHook("PreToolUse", map[string]any{"session_id": session, "tool_name": "Bash", "tool_use_id": "e1",
			"tool_input": map[string]any{"command": "echo cm0gLXJmIGJ1aWxk | base64 -d | sh"}})
	}
	out, _, _ := e.run(in("s1"), "hook", "codex", "--event", "PreToolUse")
	_, reason := codexDecision(t, out)
	m := grantID.FindStringSubmatch(reason)
	if m == nil {
		t.Fatalf("no grant offered: %s", reason)
	}
	if list, _, _ := e.run(nil, "allow"); !strings.Contains(list, "codex (session s1) in") {
		t.Errorf("allow list:\n%s", list)
	}
	e.tty = true
	if _, _, code := e.run([]byte("y\n"), "allow", m[1]); code != 0 {
		t.Fatal("approve failed")
	}
	if out, _, _ := e.run(in("s2"), "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval was used by another session")
	}
	if out, _, _ := e.run(in("s1"), "hook", "codex", "--event", "PreToolUse"); out != "" {
		t.Errorf("approved retry: %s", out)
	}
}

// TestInterruptionClipsHugeWorkdirs：打断说明里的工作目录有长度上限。
func TestInterruptionClipsHugeWorkdirs(t *testing.T) {
	e := newEnv(t)
	cwd := "/" + strings.Repeat("d", 100000)
	out, _, _ := e.run(codexHook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_use_id": "e1", "cwd": cwd,
		"tool_input": map[string]any{"command": "rm -rf /"}}), "hook", "codex", "--event", "PreToolUse")
	if d, reason := codexDecision(t, out); d != "deny" || len(reason) > 5000 {
		t.Errorf("decision %s, reason length %d", d, len(reason))
	}
}

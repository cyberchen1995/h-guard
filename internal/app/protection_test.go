package app

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/seen"
)

// inProcessEntries 让 selftest 在进程内运行入口：插件的外包脚本按它会执行的 h-guard hook 处理，其余入口去掉程序名后
// 交给 Main，与 harness 运行它们时一样读 stdin、写 stdout。
func inProcessEntries(e *env, calls *[]string) func(argv, env []string, stdin []byte) ([]byte, error) {
	return func(argv, env []string, stdin []byte) ([]byte, error) {
		*calls = append(*calls, strings.Join(argv, " "))
		// 入口继承自测设置的环境变量
		for _, kv := range env {
			if k, v, ok := strings.Cut(kv, "="); ok {
				if e.vars == nil {
					e.vars = map[string]string{}
				}
				e.vars[k] = v
				defer delete(e.vars, k)
			}
		}
		args := argv[1:]
		if argv[0] == "sh" || argv[0] == "powershell" {
			args = []string{"hook", "claudecode", "--event", "PreToolUse", "--timeout", "20"}
		}
		out, _, code := e.run(stdin, args...)
		if code != 0 {
			return nil, errors.New("exit status " + string(rune('0'+code)))
		}
		return []byte(out), nil
	}
}

// fakeBin 是写进入口的 h-guard 路径：文件要存在，status 才不报「h-guard is not at」。
func fakeBin(t *testing.T) string {
	bin := filepath.Join(t.TempDir(), "h-guard")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

// hostInstallEnv 按本机平台安装（selftest 把 install 报告的问题算作失败，按别的平台安装在本机上读出来会有问题）。
func hostInstallEnv(t *testing.T) *env {
	e := installEnv(t, harnessVersions)
	e.bin, e.goos = fakeBin(t), runtime.GOOS
	return e
}

// TestSelftestRunsTheInstalledEntries：selftest 按两个 harness 写下的入口运行 h-guard，模拟的灾难性命令与带编造凭据的
// 提示词都被拦下；结果记在缓存目录，status 的保护摘要分开写配置、hook 运行与自测三层。自测的调用不算 harness 运行过 hook。
func TestSelftestRunsTheInstalledEntries(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	if out, _, code := e.run(nil, "selftest"); code != 1 || !strings.Contains(out, "nothing to test") {
		t.Errorf("before install: exit %d\n%s", code, out)
	}
	e.run(nil, "install", "claudecode", "--write")
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	out, errs, code := e.run(nil, "selftest")
	if code != 0 || strings.Count(out, "ok  ") != 4 || !strings.Contains(out, "self-test passed") ||
		!strings.Contains(out, "Codex trust: unverified") {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	claudePre := "sh " + filepath.Join(e.configDir, "extensions", "claudecode", "hooks", "pretooluse.sh")
	if runtime.GOOS == "windows" {
		claudePre = "powershell -NoProfile -ExecutionPolicy Bypass -File " + filepath.Join(e.configDir, "extensions", "claudecode", "hooks", "pretooluse.ps1")
	}
	want := []string{
		claudePre,
		e.bin + " hook claudecode --timeout 20 --event prompt.submit",
		e.bin + " hook codex --event PreToolUse --timeout 20",
		e.bin + " hook codex --event UserPromptSubmit --timeout 20",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("entries run:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
	if runs := seen.ReadRuns(seen.Dir(e.cache), "codex"); len(runs) != 0 {
		t.Errorf("the self-test counted as Codex running the hook: %v", runs)
	}
	status, _, _ := e.run(nil, "status")
	for _, w := range []string{
		"protection:",
		// 只看 hook 运行这一层：Windows 上测试按 linux 安装，盘符里的冒号让插件目录的登记读成「with problems」
		"| hook running: not seen since install (restart Claude Code",
		"  codex: config written: yes | hook running: unverified (Codex has not run the hooks since they were installed; trust them with /hooks in Codex) | self-test: passed",
		"interrupts: catastrophic (deny), fork_bomb (deny), guard_tampering (ask), obfuscated_exec (ask), sensitive_read (ask, file tools only)",
		"matched but not interrupting, and not recorded (log.decisions is off) (judge off; h-guard init turns it on): branch_ops, destructive_git, publish, recursive_delete, verify_bypass",
		"prompts and tool output: credentials deny, private_key deny (scans prompts)",
		"not covered: shell commands that read secret files",
		"approve one stopped operation with h-guard allow <id>",
	} {
		if !strings.Contains(status, w) {
			t.Errorf("status lacks %q:\n%s", w, status)
		}
	}
	// Codex 只运行了动作的 hook：部分生效；提示词的 hook 也运行之后才算 yes
	e.run(codexPre("Bash", map[string]any{"command": "ls"}), "hook", "codex", "--event", "PreToolUse")
	status, _, _ = e.run(nil, "status")
	if !strings.Contains(status, "hook running: partly; seen PreToolUse, not yet UserPromptSubmit, PostToolUse") {
		t.Errorf("after a Codex PreToolUse run:\n%s", status)
	}
	e.run(codexHook("UserPromptSubmit", map[string]any{"prompt": "hello"}), "hook", "codex", "--event", "UserPromptSubmit")
	// 工具输出的 hook 是另一个入口：它也运行过才算 yes
	e.run(codexHook("PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "tool_use_id": "e1", "tool_response": "ok"}),
		"hook", "codex", "--event", "PostToolUse")
	status, _, _ = e.run(nil, "status")
	if !regexp.MustCompile(`codex: config written: yes \| hook running: yes, last .* ago \(PreToolUse, UserPromptSubmit, PostToolUse\)`).MatchString(status) {
		t.Errorf("after both Codex hooks ran:\n%s", status)
	}
	// Claude Code 的提示词走 mod：只有经典 hook 运行过时提示 mod 可能被禁止
	e.run(bash("ls"), "hook", "claudecode", "--event", "PreToolUse")
	if status, _, _ = e.run(nil, "status"); !strings.Contains(status, "check that your organization allows user mods") {
		t.Errorf("claudecode partial:\n%s", status)
	}
	// 用 --config 叠加的配置自测没有用过
	extra := filepath.Join(t.TempDir(), "extra.yaml")
	os.WriteFile(extra, []byte("version: 1\n"), 0o600)
	if status, _, _ = e.run(nil, "status", "--config", extra); !strings.Contains(status, "(without --config "+extra) {
		t.Errorf("with --config:\n%s", status)
	}
}

// TestSelftestFailsWhenRulesDoNotStop：入口能运行、但本地规则不拦（凭据类别关掉了）时自测失败，并写明哪一项。
func TestSelftestFailsWhenRulesDoNotStop(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	e.config("version: 1\noutbound: {categories: {credentials: {enabled: false}}}\n")
	out, _, code := e.run(nil, "selftest", "codex")
	if code != 1 || !strings.Contains(out, "FAIL prompt check (made-up API key)") || !strings.Contains(out, "self-test failed") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if st, ok := seen.ReadSelftest(seen.Dir(e.cache), "codex"); !ok || st.Passed {
		t.Errorf("recorded %+v", st)
	}
	if status, _, _ := e.run(nil, "status"); !strings.Contains(status, "self-test: FAILED") {
		t.Errorf("status:\n%s", status)
	}
	// 入口本身运行失败（找不到 h-guard）同样失败
	e.runEntry = func([]string, []string, []byte) ([]byte, error) { return nil, os.ErrNotExist }
	if out, _, code := e.run(nil, "selftest", "codex"); code != 1 || !strings.Contains(out, "the entry did not run") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if out, _, code := e.run(nil, "selftest", "claudecode"); code != 1 || !strings.Contains(out, "claudecode: not installed") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// TestStatusProtectionWithTheJudgeOn：模型开启时依赖模型的规则写作「agent 自行决定时」打断，不再列为只记录。
func TestStatusProtectionWithTheJudgeOn(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\njudge: {enabled: true, backend: claude-haiku}\nrules: {publish: {enabled: false}}\n")
	out, _, _ := e.run(nil, "status")
	for _, w := range []string{"destructive_git (ask, when the agent chose it on its own)", "  off: publish (disabled)"} {
		if !strings.Contains(out, w) {
			t.Errorf("status lacks %q:\n%s", w, out)
		}
	}
	if strings.Contains(out, "matched but not interrupting") || strings.Contains(out, "no judge to catch them") {
		t.Errorf("status:\n%s", out)
	}
}

// TestHookRunRecordedEvenWhenTheConfigIsInvalid：配置有误时检查走兜底，但读懂了输入就说明 harness 运行了 hook。
func TestHookRunRecordedEvenWhenTheConfigIsInvalid(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\naction: {tier: 9}\n")
	out, _, _ := e.run(codexPre("Bash", map[string]any{"command": "ls"}), "hook", "codex", "--event", "PreToolUse")
	if d, _ := codexDecision(t, out); d != "deny" {
		t.Fatalf("invalid config = %s", d)
	}
	if _, _, ok := seen.ReadRuns(seen.Dir(e.cache), "codex").Latest(); !ok {
		t.Error("hook run not recorded")
	}
}

// TestSelftestSkipsSwappedCodexEntries：hooks.json 里 --event 与所在事件不一致的入口不算安装好，自测报出缺少的入口。
func TestSelftestSkipsSwappedCodexEntries(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	s := strings.ReplaceAll(string(b), "--event PreToolUse", "--event SWAP")
	s = strings.ReplaceAll(s, "--event UserPromptSubmit", "--event PreToolUse")
	s = strings.ReplaceAll(s, "--event SWAP", "--event UserPromptSubmit")
	os.WriteFile(hooks, []byte(s), 0o600)
	out, _, code := e.run(nil, "selftest", "codex")
	if code != 1 || !strings.Contains(out, "no h-guard entry for PreToolUse") || !strings.Contains(out, "no h-guard entry for UserPromptSubmit") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// TestSelftestRunsEveryCodexEntry：同一事件有多个 h-guard 入口时 Codex 每个都运行，自测也每个都跑；
// 带 matcher 的组只对部分工具运行，不算入口。
func TestSelftestRunsEveryCodexEntry(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	var file map[string]map[string][]map[string]any
	if err := json.Unmarshal(b, &file); err != nil {
		t.Fatal(err)
	}
	pre := file["hooks"]["PreToolUse"]
	file["hooks"]["PreToolUse"] = append(pre, pre[0])
	matched := map[string]any{"matcher": "^apply_patch$", "hooks": file["hooks"]["UserPromptSubmit"][0]["hooks"]}
	file["hooks"]["UserPromptSubmit"] = []map[string]any{matched}
	b, _ = json.Marshal(file)
	os.WriteFile(hooks, b, 0o600)
	out, _, code := e.run(nil, "selftest", "codex")
	if code != 1 || !strings.Contains(out, "reply: deny, deny") || !strings.Contains(out, "no h-guard entry for UserPromptSubmit that runs for every tool") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if n := strings.Count(strings.Join(calls, "\n"), "--event PreToolUse"); n != 2 {
		t.Errorf("PreToolUse entries run %d times", n)
	}
}

// TestSelftestFailsWhenClaudeDoesNotLoadThePlugin：插件文件还在、但 Claude Code 的设置不再加载它时，入口能跑也不算通过。
func TestSelftestFailsWhenClaudeDoesNotLoadThePlugin(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	if out, _, code := e.run(nil, "selftest", "claudecode"); code != 0 {
		t.Fatalf("installed: exit %d\n%s", code, out)
	}
	os.WriteFile(filepath.Join(e.home, ".claude", "settings.json"), []byte("{}\n"), 0o600)
	// 不再加载的插件里的入口不运行：其中的程序可能已被换掉
	calls = nil
	out, _, code := e.run(nil, "selftest", "claudecode")
	if code != 1 || !strings.Contains(out, "FAIL configuration: the plugin is written but") ||
		!strings.Contains(out, "entries not run") || len(calls) != 0 {
		t.Errorf("exit %d, entries run %v\n%s", code, calls, out)
	}
}

// TestSelftestRecordsEntryErrors：入口文件读不了时自测失败并记下，status 不再显示之前那次通过。
func TestSelftestRecordsEntryErrors(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	if _, _, code := e.run(nil, "selftest", "codex"); code != 0 {
		t.Fatal("first self-test failed")
	}
	os.WriteFile(filepath.Join(e.home, ".codex", "hooks.json"), []byte("{not json"), 0o600)
	if _, _, code := e.run(nil, "selftest", "codex"); code != 1 {
		t.Errorf("exit %d", code)
	}
	if st, ok := seen.ReadSelftest(seen.Dir(e.cache), "codex"); !ok || st.Passed {
		t.Errorf("recorded %+v", st)
	}
}

// TestSelftestNeverCallsTheJudge：模型开启、同意有效、灾难性规则又被停用时，模拟的 rm -rf / 会走到模型；
// 自测的调用照样不发请求。同样的命令在真实会话里会调用它（对照）。
func TestSelftestNeverCallsTheJudge(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	srv := newJevServer(t, 0.0)
	e.judgeConfig(srv, "")
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	e.config(string(b) + "rules: {catastrophic: {enabled: false}}\n")
	e.grant(srv)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	e.run(nil, "selftest", "codex")
	if srv.calls != 0 {
		t.Errorf("the self-test called the judge %d times", srv.calls)
	}
	e.run(codexPre("Bash", map[string]any{"command": "rm -rf /"}), "hook", "codex", "--event", "PreToolUse")
	if srv.calls == 0 {
		t.Error("control: a real session did not call the judge, so the test proves nothing")
	}
	// 只把会话编号写成自测的编号不能关掉判断后端：还要有自测设置的环境变量
	before := srv.calls
	e.run(codexHook("PreToolUse", map[string]any{"session_id": seen.SelftestSession, "tool_name": "Bash", "tool_use_id": "e9",
		"tool_input": map[string]any{"command": "rm -rf /"}}), "hook", "codex", "--event", "PreToolUse")
	if srv.calls == before {
		t.Error("a hook input with the self-test session id turned the judge off")
	}
}

// TestStatusFlagsSelftestsFromAnotherVersion：之前的版本记下的自测结果标为过时。
func TestStatusFlagsSelftestsFromAnotherVersion(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	seen.WriteSelftest(seen.Dir(e.cache), "codex", seen.Selftest{At: time.Now().Add(time.Minute).UTC(), Version: "0.0.1-old", Passed: true})
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "(tested h-guard 0.0.1-old, not this one; reinstall with this h-guard, then run h-guard selftest codex)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestStatusShowsHalfCoveredRules：同时写了命令与文件动作的规则在第 1 档只有命令那一半生效，摘要写明。
func TestStatusShowsHalfCoveredRules(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\naction: {tier: 1}\n")
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "guard_tampering (ask)") ||
		strings.Contains(out, "guard_tampering (ask, commands only") {
		t.Errorf("locked rules cover file actions at every tier:\n%s", out)
	}
	os.MkdirAll(filepath.Join(e.configDir, "rules"), 0o700)
	os.WriteFile(filepath.Join(e.configDir, "rules", "mine.yaml"), []byte(`schema: 1
id: mine
action: ask
on: [exec, file_write]
reason: {en: mine}
match:
  exec: {any: ['zzz-mine']}
  file: {paths: ['**/zzz-mine']}
examples:
  hit: [{shell: posix, command: zzz-mine}]
`), 0o600)
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "mine (ask, commands only; its file actions are off at action tier 1)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestStatusShowsFileSideOfJudgeRules：requires_judge 的规则模型关闭时命令不打断，但它的文件动作照样打断，摘要写明。
func TestStatusShowsFileSideOfJudgeRules(t *testing.T) {
	e := newEnv(t)
	os.MkdirAll(filepath.Join(e.configDir, "rules"), 0o700)
	os.WriteFile(filepath.Join(e.configDir, "rules", "mine.yaml"), []byte(`schema: 1
id: mine
action: ask
on: [exec, file_write]
requires_judge: true
reason: {en: mine}
match:
  exec: {any: ['zzz-mine']}
  file: {paths: ['**/zzz-mine']}
question:
  kind: probability
  instructions: {question: 'Does it run zzz-mine?', counts_as_yes: 'zzz-mine', counts_as_no: 'anything else'}
  criteria: {'true': 'runs it', 'false': 'does not'}
examples:
  hit: [{shell: posix, command: zzz-mine}]
`), 0o600)
	out, _, _ := e.run(nil, "status")
	if !strings.Contains(out, "mine (ask, file actions only; its commands need the judge)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestStatusFlagsSelftestsAfterConfigChanges：自测之后改了配置或规则，结果标为过时。
func TestStatusFlagsSelftestsAfterConfigChanges(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	e.run(nil, "selftest", "codex")
	if out, _, _ := e.run(nil, "status"); strings.Contains(out, "config or rules changed") {
		t.Fatalf("fresh self-test flagged:\n%s", out)
	}
	e.config("version: 1\nrules: {catastrophic: {enabled: false}}\n")
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "(the config or rules changed since; run h-guard selftest codex)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestAsyncCodexHooksDoNotCount：后台运行（async）的 h-guard hook 拦不住操作：status 报告问题，自测不算入口。
func TestAsyncCodexHooksDoNotCount(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	os.WriteFile(hooks, []byte(strings.Replace(string(b), `"type": "command"`, `"type": "command", "async": true`, 1)), 0o600)
	if out, _, code := e.run(nil, "selftest", "codex"); code != 1 {
		t.Errorf("exit %d\n%s", code, out)
	}
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "does not run as a blocking command hook") {
		t.Errorf("status:\n%s", out)
	}
}

// TestSelftestFailsWhenEntriesVanish：插件还登记着、入口文件却没了时自测失败并记下，status 不再显示之前那次通过。
func TestSelftestFailsWhenEntriesVanish(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	if _, _, code := e.run(nil, "selftest", "claudecode"); code != 0 {
		t.Fatal("first self-test failed")
	}
	os.Remove(filepath.Join(e.configDir, "extensions", "claudecode", "hguard.json"))
	out, _, code := e.run(nil, "selftest", "claudecode")
	if code != 1 || !strings.Contains(out, "registered but its entries are missing") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if st, ok := seen.ReadSelftest(seen.Dir(e.cache), "claudecode"); !ok || st.Passed {
		t.Errorf("recorded %+v", st)
	}
}

// TestHookRunsFromAnotherVersionDoNotCount：原地升级后，旧版本留下的运行记录不算「hook 真正运行」。
func TestHookRunsFromAnotherVersionDoNotCount(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	later := time.Now().Add(time.Minute)
	seen.Record(seen.Dir(e.cache), "codex", "PreToolUse", "0.0.1-old", later)
	seen.Record(seen.Dir(e.cache), "codex", "UserPromptSubmit", "0.0.1-old", later)
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "codex: config written: yes | hook running: unverified") {
		t.Errorf("status:\n%s", out)
	}
}

// TestSelftestRejectsIncompleteReplies：缺少 hookEventName 的回复 harness 不认，自测不能算通过。
func TestSelftestRejectsIncompleteReplies(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	e.runEntry = func(argv, _ []string, _ []byte) ([]byte, error) {
		if strings.Contains(strings.Join(argv, " "), "PreToolUse") {
			return []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}`), nil
		}
		return []byte(`{"decision":"block","reason":"x"}`), nil
	}
	if out, _, code := e.run(nil, "selftest", "codex"); code != 1 || !strings.Contains(out, "no hookEventName PreToolUse") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// stderr 里的控制字符转义后才显示
	e.runEntry = func([]string, []string, []byte) ([]byte, error) {
		return nil, errors.New("exit 1: \x1b[2Jfake ok")
	}
	if out, _, _ := e.run(nil, "selftest", "codex"); strings.Contains(out, "\x1b") {
		t.Errorf("control characters printed: %q", out)
	}
}

// TestStatusDropsRecordsWhenTheEntryFileIsGone：插件还登记着、入口文件却没了时，之前的运行与自测记录都不算数。
func TestStatusDropsRecordsWhenTheEntryFileIsGone(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	later := time.Now().Add(time.Minute)
	seen.Record(seen.Dir(e.cache), "claudecode", "PreToolUse", buildID(), later)
	seen.Record(seen.Dir(e.cache), "claudecode", "prompt.submit", buildID(), later)
	seen.Record(seen.Dir(e.cache), "claudecode", "tool.result", buildID(), later)
	if _, _, code := e.run(nil, "selftest", "claudecode"); code != 0 {
		t.Fatal("self-test failed")
	}
	os.Remove(filepath.Join(e.configDir, "extensions", "claudecode", "hguard.json"))
	out, _, _ := e.run(nil, "status")
	if strings.Contains(out, "hook running: yes") || !strings.Contains(out, "the installed entries are gone") {
		t.Errorf("status:\n%s", out)
	}
}

// TestSelftestReportsPartlyRunningHooks：只运行过一部分入口（Claude Code 的提示词检查走 mod，可能被禁止）时，
// 自测之后不说 harness 运行了 hook，写明还没运行过哪个入口。
func TestSelftestReportsPartlyRunningHooks(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	seen.Record(seen.Dir(e.cache), "claudecode", "PreToolUse", buildID(), time.Now().Add(time.Minute))
	out, _, _ := e.run(nil, "selftest", "claudecode")
	if !strings.Contains(out, "Claude Code ran the hook: partly; seen PreToolUse, not yet prompt.submit, tool.result") {
		t.Errorf("selftest:\n%s", out)
	}
}

// TestSelftestRecordsTheTestedVersion：入口运行的是另一个版本的 h-guard 时，自测记下被测的版本，status 不把它当成这个版本的自测。
func TestSelftestRecordsTheTestedVersion(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	inner := inProcessEntries(e, &calls)
	e.runEntry = func(argv, env []string, stdin []byte) ([]byte, error) {
		out, err := inner(argv, env, stdin)
		// 模拟旧版本的入口：它记下的是自己的版本
		for _, ev := range []string{"PreToolUse", "UserPromptSubmit"} {
			if runs := seen.ReadRuns(seen.Dir(e.cache), seen.SelftestRuns("codex")); runs[ev].Version != "" {
				seen.Clear(seen.Dir(e.cache), seen.SelftestRuns("codex"))
				seen.Record(seen.Dir(e.cache), seen.SelftestRuns("codex"), ev, "0.0.1-old", time.Now())
			}
		}
		return out, err
	}
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	out, _, _ := e.run(nil, "selftest", "codex")
	if !strings.Contains(out, "FAIL the installed entries run h-guard 0.0.1-old") || !strings.Contains(out, "self-test failed") {
		t.Errorf("selftest:\n%s", out)
	}
	if status, _, _ := e.run(nil, "status"); !strings.Contains(status, "(tested h-guard 0.0.1-old, not this one") {
		t.Errorf("status:\n%s", status)
	}
}

// TestStatusGapWhenTheJudgeCannotBeUsed：模型开启但还没同意时没有模型兜底，摘要照样写出这个缺口。
func TestStatusGapWhenTheJudgeCannotBeUsed(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\njudge: {enabled: true, backend: claude-haiku}\n")
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "the judge is on but cannot be used yet") {
		t.Errorf("status:\n%s", out)
	}
}

// TestInstallForgetsHookRuns：写入入口后删除之前的运行记录，新入口的第一次运行不会因为节流被丢掉。
func TestInstallForgetsHookRuns(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	seen.Record(seen.Dir(e.cache), "codex", "PreToolUse", buildID(), time.Now())
	os.Remove(filepath.Join(e.home, ".codex", "hooks.json"))
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	if runs := seen.ReadRuns(seen.Dir(e.cache), "codex"); len(runs) != 0 {
		t.Errorf("runs kept after reinstall: %v", runs)
	}
}

// TestStatusFlagsCodexHooksUnderTheWrongEvent：写在别的事件下的 h-guard 命令算作配置问题。
func TestStatusFlagsCodexHooksUnderTheWrongEvent(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	os.WriteFile(hooks, []byte(strings.ReplaceAll(string(b), "--event PreToolUse", "--event PostToolUse")), 0o600)
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "the h-guard hook under PreToolUse is the command for another event") ||
		!strings.Contains(out, "codex: config written: yes, with problems") {
		t.Errorf("status:\n%s", out)
	}
}

// TestStatusWatchesEveryClaudeEntryFile：插件里任何一个入口文件（外包脚本等）在自测之后被改动，自测结果标为过时。
func TestStatusWatchesEveryClaudeEntryFile(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	if _, _, code := e.run(nil, "selftest", "claudecode"); code != 0 {
		t.Fatal("self-test failed")
	}
	later := time.Now().Add(time.Hour)
	os.Chtimes(filepath.Join(e.configDir, "extensions", "claudecode", "hooks", "hooks.json"), later, later)
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "(before the last install") {
		t.Errorf("status:\n%s", out)
	}
}

// TestCodexHooksNeedAnExplicitCommandType：Codex 只认写明 type: command 的 hook，省略 type 的入口不算安装好。
func TestCodexHooksNeedAnExplicitCommandType(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	os.WriteFile(hooks, []byte(strings.ReplaceAll(string(b), `"type": "command"`, `"async": false`)), 0o600)
	if out, _, code := e.run(nil, "selftest", "codex"); code != 1 {
		t.Errorf("exit %d\n%s", code, out)
	}
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "does not run as a blocking command hook") {
		t.Errorf("status:\n%s", out)
	}
}

// TestSelftestRunsCommandWindowsOnWindows：Windows 上 Codex 运行 commandWindows，自测与检查都看它。
func TestSelftestRunsCommandWindowsOnWindows(t *testing.T) {
	e := hostInstallEnv(t)
	e.run(nil, "install", "codex", "--write", "--shell", "posix")
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	os.WriteFile(hooks, []byte(strings.ReplaceAll(string(b), `"type": "command"`, `"type": "command", "commandWindows": "other.exe"`)), 0o600)
	tgt := install.Target{Home: e.home, ConfigDir: e.configDir, CacheDir: e.cache, GOOS: "windows", Getenv: func(string) string { return "" }}
	if _, err := install.Entries(tgt, "codex"); !errors.Is(err, install.ErrNotInstalled) {
		t.Errorf("Windows entries with a foreign commandWindows: %v", err)
	}
	tgt.GOOS = "linux"
	if _, err := install.Entries(tgt, "codex"); err != nil {
		t.Errorf("other systems run command: %v", err)
	}
}

// TestStatusShowsJudgeOnlyCategories：只有类别题、没有本地规则的类别由模型检查，模型能用时摘要列出；
// 还没同意时没有检查，不列出。
func TestStatusShowsJudgeOnlyCategories(t *testing.T) {
	e := newEnv(t)
	srv := newJevServer(t, 0.9)
	e.judgeConfig(srv, "")
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	e.config(string(b) + "outbound: {categories: {acme-codename: {action: warn, question: {question: 'Does the text name Project Falcon?'}}}}\n")
	if out, _, _ := e.run(nil, "status"); strings.Contains(out, "acme-codename") && strings.Contains(out, "judge only") {
		t.Errorf("listed without consent:\n%s", out)
	}
	// 只同意了 action 范围：模型不检查提示词与工具输出
	e.grant(srv)
	if out, _, _ := e.run(nil, "status"); strings.Contains(out, "acme-codename warn (judge only") {
		t.Errorf("listed with action-only consent:\n%s", out)
	}
	id := consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}
	if err := (consent.Store{Dir: e.configDir}).Grant(id, []consent.Scope{consent.ScopeAction, consent.ScopeOutbound}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "acme-codename warn (judge only, not on Codex)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestSelftestDoesNotRunAChangedPlugin：插件文件与这个 h-guard 写的不一样时自测失败，也不运行其中的入口。
func TestSelftestDoesNotRunAChangedPlugin(t *testing.T) {
	e := hostInstallEnv(t)
	var calls []string
	e.runEntry = inProcessEntries(e, &calls)
	e.run(nil, "install", "claudecode", "--write")
	script := filepath.Join(e.configDir, "extensions", "claudecode", "hooks", "pretooluse.sh")
	if runtime.GOOS == "windows" {
		script = strings.TrimSuffix(script, ".sh") + ".ps1"
	}
	b, _ := os.ReadFile(script)
	os.WriteFile(script, append(b, "\n# edited\n"...), 0o700)
	out, _, code := e.run(nil, "selftest", "claudecode")
	if code != 1 || !strings.Contains(out, "so they are not run") || len(calls) != 0 {
		t.Errorf("exit %d, entries run %v\n%s", code, calls, out)
	}
	if status, _, _ := e.run(nil, "status"); strings.Contains(status, "self-test: passed") {
		t.Errorf("status:\n%s", status)
	}
}

// TestStatusListsExtensionHarnesses：装了扩展协议的 harness 时保护摘要也列出它，只有配置这一层；opencode 不能请求确认，
// 单次授权只在 Codex 上提供。
func TestStatusListsExtensionHarnesses(t *testing.T) {
	e := hostInstallEnv(t)
	if out, _, _ := e.run(nil, "status"); strings.Contains(out, "  opencode:") {
		t.Errorf("listed before install:\n%s", out)
	}
	e.run(nil, "install", "opencode", "--write", "--shell", "posix")
	out, _, _ := e.run(nil, "status")
	for _, w := range []string{
		// 只看后两层：Windows 上配置里的路径写法可能让配置这一层读成「with problems」
		"  opencode: config written: yes",
		"| hook running: not tracked for opencode | self-test: not available for opencode",
		"  opencode: cannot ask either, so every ask blocks; one-time approvals are only offered on Codex",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("status lacks %q:\n%s", w, out)
		}
	}
}

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	hglog "github.com/cyberchen1995/h-guard/internal/log"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

type env struct {
	t                *testing.T
	configDir, cache string
	vars             map[string]string
}

func newEnv(t *testing.T) *env {
	return &env{t: t, configDir: t.TempDir(), cache: t.TempDir(), vars: map[string]string{"LANG": "en_US.UTF-8"}}
}

func (e *env) config(body string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.configDir, "config.yaml"), []byte(body), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) run(stdin []byte, args ...string) (stdout, stderr string, code int) {
	var out, errb bytes.Buffer
	code = Main(args, Options{
		Stdin: bytes.NewReader(stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return e.vars[k] }, ConfigDir: e.configDir, CacheDir: e.cache,
	})
	return out.String(), errb.String(), code
}

func (e *env) files(sub string) string {
	var b strings.Builder
	filepath.WalkDir(filepath.Join(e.cache, sub), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(p)
			b.Write(data)
		}
		return nil
	})
	return b.String()
}

func pre(tool string, input map[string]any, transcript string) []byte {
	b, _ := json.Marshal(map[string]any{"session_id": "s1", "transcript_path": transcript, "cwd": "/w",
		"hook_event_name": "PreToolUse", "permission_mode": "default", "tool_name": tool, "tool_input": input, "tool_use_id": "t1"})
	return b
}

func bash(cmd string) []byte { return pre("Bash", map[string]any{"command": cmd}, "") }

func promptReq(text, kind string) []byte {
	b, _ := json.Marshal(map[string]any{"protocol": extproto.Protocol, "harness": "claudecode", "harness_version": "2.1.296",
		"hook": "prompt.submit", "session": map[string]string{"id": "s1", "cwd": "/w"},
		"data": map[string]any{"text": text, "origin": map[string]string{"kind": kind}}})
	return b
}

type hookOutput struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func decisionOf(t *testing.T, stdout string) (string, string) {
	t.Helper()
	if stdout == "" {
		return "pass", ""
	}
	var o hookOutput
	if err := json.Unmarshal([]byte(stdout), &o); err != nil {
		t.Fatalf("stdout %q: %v", stdout, err)
	}
	return o.HookSpecificOutput.PermissionDecision, o.HookSpecificOutput.PermissionDecisionReason
}

func TestHookPreToolUse(t *testing.T) {
	e := newEnv(t)
	tests := []struct {
		cmd, want string
	}{
		{"rm -rf /", "deny"},
		{"git push origin main", "pass"}, // 模型关闭：requires_judge 规则不打断
		{"rm ~/.claude/settings.json", "ask"},
		{"h-guard-probe", "ask"},
		{"ls -la", "pass"},
	}
	for _, tt := range tests {
		out, _, code := e.run(bash(tt.cmd), "hook", "claudecode", "--event", "PreToolUse")
		if d, _ := decisionOf(t, out); d != tt.want || code != 0 {
			t.Errorf("%q: decision %s (exit %d), want %s", tt.cmd, d, code, tt.want)
		}
	}
	if h := e.files("health"); h != "" {
		t.Errorf("normal decisions must not write health records: %s", h)
	}
}

func TestHookIgnoresWhatItCannotRead(t *testing.T) {
	e := newEnv(t)
	for _, in := range [][]byte{[]byte("not json"), pre("mcp__x__y", map[string]any{"a": 1}, ""), []byte(`{"hook_event_name":"Stop"}`)} {
		if out, _, code := e.run(in, "hook", "claudecode", "--event", "PreToolUse"); out != "" || code != 0 {
			t.Errorf("%s: stdout %q, exit %d", in, out, code)
		}
	}
	if _, _, code := e.run(nil, "hook", "nope", "--event", "PreToolUse"); code != 2 {
		t.Errorf("unknown harness exit = %d", code)
	}
}

func TestHookJudgeEnabledWithoutConsent(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\njudge: {enabled: true}\n")
	out, _, _ := e.run(bash("git push origin main"), "hook", "claudecode", "--event", "PreToolUse")
	d, reason := decisionOf(t, out)
	if d != "ask" || !strings.Contains(reason, "h-guard backend enable jev") {
		t.Errorf("decision %s, reason %q", d, reason)
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"judge_consent_missing"`) || strings.Contains(h, "git push") {
		t.Errorf("health = %s", h)
	}
	if out, _, _ := e.run(bash("ls"), "hook", "claudecode", "--event", "PreToolUse"); out != "" {
		t.Errorf("no hit without consent must pass, got %s", out)
	}
}

func TestPromptsFeedTheActionCheck(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	out, _, _ := e.run(promptReq("please push to origin", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if r, err := extproto.ParseReply([]byte(out)); err != nil || r.Action != extproto.ActionPass {
		t.Fatalf("reply %q, %v", out, err)
	}
	e.run(promptReq("<task-notification>x</task-notification>", "task-notification"), "hook", "claudecode", "--event", "prompt.submit")
	e.run(bash("git push origin main"), "hook", "claudecode", "--event", "PreToolUse")
	logs := e.files("logs")
	if !strings.Contains(logs, `"text":"please push to origin","source":"user"`) || !strings.Contains(logs, `"source":"automated"`) {
		t.Errorf("decision log = %s", logs)
	}
}

func TestTranscriptFallback(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	tr := filepath.Join(t.TempDir(), "s1.jsonl")
	os.WriteFile(tr, []byte(`{"type":"user","message":{"content":"delete the build dir"},"origin":{"kind":"human"}}`+"\n"), 0o600)
	e.run(pre("Bash", map[string]any{"command": "rm -rf build"}, tr), "hook", "claudecode", "--event", "PreToolUse")
	if logs := e.files("logs"); !strings.Contains(logs, "delete the build dir") {
		t.Errorf("decision log = %s", logs)
	}
}

// TestPromptAndToolOutputTextNotLogged：开启决策日志时，提示词与工具输出只记长度，不记正文（评审 M1-09）。
func TestPromptAndToolOutputTextNotLogged(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	text := "HG_PRIVATE_FULL_DOCUMENT\n" + strings.Repeat("unrelated private record\n", 100)
	result, _ := json.Marshal(map[string]any{"protocol": extproto.Protocol, "harness": "claudecode", "hook": "tool.result",
		"session": map[string]string{"id": "s1", "cwd": "/w"}, "data": map[string]string{"tool": "Read"}, "result": map[string]string{"text": text}})
	e.run(result, "hook", "claudecode", "--event", "tool.result")
	e.run(promptReq("HG_PRIVATE_PROMPT "+text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	logs := e.files("logs")
	if strings.Contains(logs, "HG_PRIVATE") || strings.Contains(logs, "unrelated private record") {
		t.Errorf("decision log contains prompt or tool output text: %.300s", logs)
	}
	if !strings.Contains(logs, fmt.Sprintf(`"text_bytes":%d`, len(text))) {
		t.Errorf("decision log lacks the text length: %.300s", logs)
	}
}

// TestConfigErrorsDoNotLeakValues：写错的配置值（如带密码的 base_url）不出现在 hook 输出、stderr 与日志里（评审 M1-06）。
func TestConfigErrorsDoNotLeakValues(t *testing.T) {
	const canary = "HG_FAKE_PASSWORD_987654"
	for _, body := range []string{
		"version: 1\nbackends: {jev: {type: typesafe, base_url: 'https://user:" + canary + "@example.invalid'}}\n",
		"version: 1\npolicy: {on_unavailable: " + canary + "}\n",
		"version: 1\naction: {tier: " + canary + "}\n",
	} {
		e := newEnv(t)
		e.config(body)
		out, stderr, _ := e.run(bash("ls"), "hook", "claudecode", "--event", "PreToolUse")
		d, reason := decisionOf(t, out)
		if d != "ask" || !strings.Contains(reason, "config.yaml") || strings.Contains(out+stderr+e.files(""), canary) {
			t.Errorf("hook: decision %s, reason %q, stderr %q", d, reason, stderr)
		}
		_, stderr, code := e.run(nil, "check", "ls")
		if code != 1 || strings.Contains(stderr, canary) {
			t.Errorf("check: exit %d, stderr %q", code, stderr)
		}
	}
}

// TestUserDataInErrorsIsMasked：后端名、规则 id、正则这类用户写下的内容出现在 hook 原因或 stderr 之前要遮蔽
// （评审 N04）。
func TestUserDataInErrorsIsMasked(t *testing.T) {
	const token = "sk-abcdefghijklmnopqrstuv"
	cases := []struct {
		name, config, ruleID, pattern string
	}{
		{name: "backend name", config: "version: 1\nbackends:\n  " + token + ": {type: missing}\n"},
		{name: "rule id", ruleID: token, pattern: "["},
		{name: "rule pattern", ruleID: "custom", pattern: token + "["},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.config != "" {
				e.config(tc.config)
			}
			if tc.ruleID != "" {
				dir := filepath.Join(e.configDir, "rules")
				os.MkdirAll(dir, 0o700)
				body := "schema: 1\nid: " + tc.ruleID + "\non: [exec]\naction: ask\nreason: {en: test}\nmatch: {exec: {any: ['" + tc.pattern + "']}}\n"
				os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(body), 0o600)
			}
			out, stderr, _ := e.run(bash("ls"), "hook", "claudecode", "--event", "PreToolUse")
			if d, _ := decisionOf(t, out); d != "ask" || strings.Contains(out+stderr, token) {
				t.Errorf("hook: decision %s, output %q %q", d, out, stderr)
			}
			_, stderr, code := e.run(nil, "check", "ls")
			if code != 1 || strings.Contains(stderr, token) {
				t.Errorf("check: exit %d, stderr %q", code, stderr)
			}
		})
	}
}

// TestHookAnswersBeforeTheOuterTimeout：读 stdin 阻塞时，看门狗在 --timeout 之前输出兜底的 ask（评审 M1-07）。
func TestHookAnswersBeforeTheOuterTimeout(t *testing.T) {
	e := newEnv(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	var out, errb bytes.Buffer
	start := time.Now()
	code := Main([]string{"hook", "claudecode", "--event", "PreToolUse", "--timeout", "2"},
		Options{Stdin: pr, Stdout: &out, Stderr: &errb, ConfigDir: e.configDir, CacheDir: e.cache, Getenv: func(string) string { return "" }})
	elapsed := time.Since(start)
	if d, reason := decisionOf(t, out.String()); code != 0 || d != "ask" || !strings.Contains(reason, "ran out of time") || elapsed >= 2*time.Second {
		t.Errorf("decision %s (%q) after %v, exit %d", d, reason, elapsed, code)
	}
	// 看门狗路径的健康记录在后台写入，有界等待
	if !eventually(func() bool { return strings.Contains(e.files("health"), `"code":"local_budget_exceeded"`) }) {
		t.Errorf("health = %s", e.files("health"))
	}
}

// eventually 在 2 秒内反复检查 cond。
func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

// gatedCheck 在内层 Check 提交 deny 之后暂停，模拟提交之后的剩余处理迟迟不结束。
type gatedCheck struct {
	guard.Check
	committed, release chan struct{}
}

func (g *gatedCheck) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	return g.Check.Evaluate(ctx, ev, func(v guard.Verdict) {
		commit(v)
		if v.Decision == guard.DecisionDeny {
			select {
			case <-g.committed:
			default:
				close(g.committed)
				<-g.release
			}
		}
	})
}

// TestWatchdogKeepsACommittedDeny：Check 已提交 deny、剩余处理还没结束时看门狗触发，输出仍为 deny（评审 N02）。
// Engine 用生产入口 hookRun.newEngine 组装。
func TestWatchdogKeepsACommittedDeny(t *testing.T) {
	e := newEnv(t)
	var out bytes.Buffer
	o := Options{Stdout: &out, Stderr: io.Discard, ConfigDir: e.configDir, CacheDir: e.cache, Getenv: func(string) string { return "" }, Now: time.Now}
	s, err := load(o, "")
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := harness.Lookup("claudecode")
	ev, err := ad.Parse(bash("rm -rf ~"))
	if err != nil {
		t.Fatal(err)
	}
	h := &hookRun{o: o, adapter: ad, event: "PreToolUse", start: time.Now(), logs: &hglog.Writer{Dir: e.cache}}
	h.setEvent(ev)
	eng := h.newEngine(s)
	gate := &gatedCheck{Check: eng.Checks[0], committed: make(chan struct{}), release: make(chan struct{})}
	eng.Checks[0] = gate
	done := make(chan struct{})
	go func() {
		defer close(done)
		res := eng.Evaluate(context.Background(), ev, ad.CapsFor(ev))
		h.write(ev, res.Outcome)
	}()
	select {
	case <-gate.committed:
	case <-time.After(time.Second):
		t.Fatal("the catastrophic deny was never committed")
	}
	h.expire()
	close(gate.release)
	<-done
	d, reason := decisionOf(t, out.String())
	if d != "deny" || !strings.Contains(reason, "Blocked") || strings.Count(out.String(), "hookSpecificOutput") != 1 {
		t.Errorf("decision %s (%q), output %q", d, reason, out.String())
	}
	if !eventually(func() bool { return strings.Contains(e.files("health"), "local_budget_exceeded") }) {
		t.Error("missing budget reason")
	}
}

// TestNoDirsMeansNoRelativePaths：配置目录、缓存目录都取不到（HOME 与 XDG 变量都没有）时，不从当前目录读配置、
// 规则与 .env，也不往当前目录写指令缓存与日志：项目里的 config.yaml 停用不了灾难性规则，提示词不会落到项目目录
// （评审 M1 终审）。
func TestNoDirsMeansNoRelativePaths(t *testing.T) {
	proj := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_CACHE_HOME", "")
	t.Chdir(proj)
	if err := os.WriteFile("config.yaml", []byte("version: 1\nrules: {catastrophic: {enabled: false}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(".env", []byte("HG_FROM_PROJECT=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	Main([]string{"hook", "claudecode", "--event", "PreToolUse"}, Options{Stdin: bytes.NewReader(bash("rm -rf /")), Stdout: &out, Stderr: io.Discard})
	if d, _ := decisionOf(t, out.String()); d != "deny" {
		t.Errorf("a project config.yaml disabled a built-in rule: %s", d)
	}
	if os.Getenv("HG_FROM_PROJECT") != "" {
		t.Error("the project's .env was applied")
	}
	Main([]string{"hook", "claudecode", "--event", "prompt.submit"}, Options{Stdin: bytes.NewReader(promptReq("HG_PRIVATE_PROMPT", "composer")), Stdout: io.Discard, Stderr: io.Discard})
	entries, _ := os.ReadDir(proj)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{".env", "config.yaml"}) {
		t.Errorf("h-guard wrote into the project directory: %v", names)
	}
}

// TestWatchdogAggregatesCommits：看门狗按 guard.Run 的规则累计提交——同样严时取后一次更完整的结论，
// 较宽提交的降级原因也保留；提交后 Check 改动自己的切片不影响已记下的内容（评审 R3-04）。
func TestWatchdogAggregatesCommits(t *testing.T) {
	e := newEnv(t)
	var out bytes.Buffer
	ad, _ := harness.Lookup("claudecode")
	ev, err := ad.Parse(bash("rm -rf ~"))
	if err != nil {
		t.Fatal(err)
	}
	h := &hookRun{o: Options{Stdout: &out, Getenv: func(string) string { return "" }}, adapter: ad, event: "PreToolUse",
		start: time.Now(), logs: &hglog.Writer{Dir: e.cache}}
	h.setEvent(ev)
	h.commit("action", guard.Verdict{Decision: guard.DecisionAsk, Fallbacks: []string{"judge_unavailable"}})
	first := guard.Verdict{Decision: guard.DecisionDeny, Findings: []guard.Finding{{Rule: "first"}}, Reasons: []guard.Reason{{Code: i18n.KeyActionBlocked}}}
	h.commit("action", first)
	first.Findings[0].Rule = "changed after commit"
	h.commit("action", guard.Verdict{Decision: guard.DecisionDeny, Findings: []guard.Finding{{Rule: "first"}, {Rule: "second"}},
		Reasons: []guard.Reason{{Code: i18n.KeyActionBlocked}}, Fallbacks: []string{"later_fallback"}})
	h.expire()
	v := h.best.Verdict
	if d, _ := decisionOf(t, out.String()); d != "deny" || len(v.Findings) != 2 || v.Findings[0].Rule != "first" {
		t.Errorf("decision %s, findings %+v", d, v.Findings)
	}
	for _, f := range []string{"judge_unavailable", "later_fallback", action.FallbackBudget} {
		if !slices.Contains(v.Fallbacks, f) {
			t.Errorf("fallbacks %v lack %s", v.Fallbacks, f)
		}
	}
	if !eventually(func() bool { return strings.Contains(e.files("health"), "local_budget_exceeded") }) {
		t.Error("missing budget health record")
	}
}

// brokenName 的 Name 总是 panic（扩展 Check 的故障注入；内置 action 的 Name 是常量）。
type brokenName struct{ guard.Check }

func (brokenName) Name() string { panic("name") }

// TestNamePanicUsesTheActionFailureFallback：用生产组装（hookRun.newEngine），Name panic 的动作检查按动作事件的
// 故障兜底请求确认，带 internal_error；已提交的 deny 保持 deny（评审 R4-03）。
func TestNamePanicUsesTheActionFailureFallback(t *testing.T) {
	e := newEnv(t)
	o := Options{Stderr: io.Discard, ConfigDir: e.configDir, CacheDir: e.cache, Getenv: func(string) string { return "" }, Now: time.Now}
	s, err := load(o, "")
	if err != nil {
		t.Fatal(err)
	}
	ad, _ := harness.Lookup("claudecode")
	for cmd, want := range map[string]string{"echo ok": "ask", "rm -rf ~": "deny"} {
		var out bytes.Buffer
		o.Stdout = &out
		ev, err := ad.Parse(bash(cmd))
		if err != nil {
			t.Fatal(err)
		}
		h := &hookRun{o: o, adapter: ad, event: "PreToolUse", start: time.Now(), logs: &hglog.Writer{Dir: e.cache}}
		h.setEvent(ev)
		eng := h.newEngine(s)
		eng.Checks[0] = brokenName{eng.Checks[0]}
		res := eng.Evaluate(context.Background(), ev, ad.CapsFor(ev))
		h.write(ev, res.Outcome)
		if d, _ := decisionOf(t, out.String()); d != want || !res.Runs[0].Panicked ||
			!slices.Contains(res.Outcome.Verdict.Fallbacks, engine.FallbackInternal) {
			t.Errorf("%q: rendered %s, want %s; outcome %+v", cmd, d, want, res.Outcome.Verdict)
		}
	}
}

// TestHookRunRecordsCommitsThroughTheProductionPath：真实的 hook 流程（run）用的 Engine 接上了提交记录，
// 防止只有测试接上、生产入口没接（评审 N02）。
func TestHookRunRecordsCommitsThroughTheProductionPath(t *testing.T) {
	e := newEnv(t)
	var out bytes.Buffer
	o := Options{Stdin: bytes.NewReader(bash("rm -rf ~")), Stdout: &out, Stderr: io.Discard, ConfigDir: e.configDir,
		CacheDir: e.cache, Getenv: func(string) string { return "" }, Now: time.Now}
	ad, _ := harness.Lookup("claudecode")
	h := &hookRun{o: o, adapter: ad, event: "PreToolUse", start: time.Now(), logs: &hglog.Writer{Dir: e.cache}}
	h.run(context.Background(), "")
	h.mu.Lock()
	committed := h.committed.With(guard.Verdict{Decision: guard.DecisionPass})
	h.mu.Unlock()
	if committed.Decision != guard.DecisionDeny {
		t.Fatalf("committed = %+v", committed)
	}
	if d, _ := decisionOf(t, out.String()); d != "deny" {
		t.Errorf("decision = %s", d)
	}
}

func TestBudgets(t *testing.T) {
	for _, tt := range []struct{ timeout, deadline, watchdog time.Duration }{
		{20 * time.Second, 19 * time.Second, 19500 * time.Millisecond},
		{2 * time.Second, time.Second, 1500 * time.Millisecond},
		{time.Second, 500 * time.Millisecond, 750 * time.Millisecond},
	} {
		if d, w := budgets(tt.timeout); d != tt.deadline || w != tt.watchdog {
			t.Errorf("budgets(%v) = %v, %v", tt.timeout, d, w)
		}
	}
}

func TestInvalidConfig(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\naction: {tier: 9}\n")
	out, _, _ := e.run(bash("ls"), "hook", "claudecode", "--event", "PreToolUse")
	if d, reason := decisionOf(t, out); d != "ask" || !strings.Contains(reason, "configuration is invalid (config.yaml: action.tier)") {
		t.Errorf("decision %s, reason %q", d, reason)
	}
	out, _, _ = e.run(promptReq("hello", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if r, err := extproto.ParseReply([]byte(out)); err != nil || r.Action != extproto.ActionPass {
		t.Errorf("prompt with an invalid config: %q, %v", out, err)
	}
	if h := e.files("health"); strings.Count(h, `"code":"config_invalid"`) != 2 {
		t.Errorf("health = %s", h)
	}
}

func TestOversizeInput(t *testing.T) {
	e := newEnv(t)
	big := bytes.Repeat([]byte("x"), MaxInput+1)
	out, _, _ := e.run(big, "hook", "claudecode", "--event", "PreToolUse")
	if d, reason := decisionOf(t, out); d != "ask" || !strings.Contains(reason, "too large") || !strings.Contains(reason, "Narrow") {
		t.Errorf("PreToolUse: %s %q", d, reason)
	}
	out, _, _ = e.run(big, "hook", "claudecode", "--event", "tool.result")
	if r, err := extproto.ParseReply([]byte(out)); err != nil || r.Action != extproto.ActionPass {
		t.Errorf("tool.result: %q, %v", out, err)
	}
	if h := e.files("health"); strings.Count(h, "input_too_large") != 2 {
		t.Errorf("health = %s", h)
	}
}

// TestRecoverBeforeParseAsks：事件解析之前就 panic（如 adapter 自身的 bug）时，PreToolUse 仍按 --event 请求确认，
// 不能什么都不输出而被 harness 放行（spec §10.1，评审 M1 终审）。
func TestRecoverBeforeParseAsks(t *testing.T) {
	var out bytes.Buffer
	cache := t.TempDir()
	h := &hookRun{o: Options{Stdout: &out, Getenv: func(string) string { return "" }, CacheDir: cache}, event: "PreToolUse",
		logs: &hglog.Writer{Dir: cache}}
	h.adapter, _ = harness.Lookup("claudecode")
	func() {
		defer h.recover()
		panic("parse")
	}()
	if d, _ := decisionOf(t, out.String()); d != "ask" {
		t.Errorf("panic before the event was parsed: %q, want ask", out.String())
	}
}

func TestRecoverKeepsTheStricterOutcome(t *testing.T) {
	var out bytes.Buffer
	cache := t.TempDir()
	h := &hookRun{o: Options{Stdout: &out, Getenv: func(string) string { return "" }, CacheDir: cache}, event: "PreToolUse"}
	h.adapter, _ = harness.Lookup("claudecode")
	h.logs = &hglog.Writer{Dir: cache}
	ev := guard.Event{Kind: guard.EventAction, Harness: "claudecode", Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "x", Shell: guard.ShellPOSIX}}}}
	h.ev = &ev
	func() {
		defer h.recover()
		panic("boom")
	}()
	if d, _ := decisionOf(t, out.String()); d != "ask" {
		t.Errorf("panic before any outcome = %s", d)
	}
	health, _ := os.ReadDir(filepath.Join(cache, "health"))
	if len(health) != 1 {
		t.Fatalf("health files = %d", len(health))
	}
	data, _ := os.ReadFile(filepath.Join(cache, "health", health[0].Name()))
	if !strings.Contains(string(data), `"where":"github.com/cyberchen1995/h-guard/internal/app.TestRecoverKeepsTheStricterOutcome`) ||
		strings.Contains(string(data), "boom") {
		t.Errorf("health = %s", data)
	}
	out.Reset()
	h.written = false // 第二种情形：Check 已提交 deny、尚未输出时 panic
	h.commit("action", guard.Verdict{Decision: guard.DecisionDeny, Reasons: []guard.Reason{{Code: i18n.KeyActionBlocked}},
		Fallbacks: []string{"regex_timeout"}})
	func() {
		defer h.recover()
		panic("again")
	}()
	if d, _ := decisionOf(t, out.String()); d != "deny" {
		t.Errorf("a deny reached before the panic must stay, got %s", d)
	}
	if v := h.best.Verdict; !slices.Contains(v.Fallbacks, "regex_timeout") || !slices.Contains(v.Fallbacks, engine.FallbackInternal) {
		t.Errorf("fallbacks = %v, want the committed ones and internal_error", v.Fallbacks)
	}
}

func TestCheckCommand(t *testing.T) {
	e := newEnv(t)
	out, _, code := e.run(nil, "check", "rm -rf /")
	if code != 0 || !strings.Contains(out, "decision: deny") || !strings.Contains(out, "finding: catastrophic (local)") {
		t.Errorf("check = %q (exit %d)", out, code)
	}
	out, _, _ = e.run(nil, "check", "--shell", "posix", "git push", "--request", "push it")
	if !strings.Contains(out, "decision: pass") || !strings.Contains(out, "judge_disabled_hits") {
		t.Errorf("check git push = %q", out)
	}
	if _, _, code := e.run(nil, "check"); code != 2 {
		t.Errorf("check without a command exit = %d", code)
	}
}

func TestCheckWithJudgePrintsWhatIsSent(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		io.WriteString(w, `{"answers":{"publish":{"type":"noul","noul":0.95},"explicitly_requested":{"type":"noul","noul":0.9},
		"blast_radius":{"type":"score","probabilities":{"0":0,"1":0,"2":1,"3":0}}}}`)
	}))
	defer srv.Close()
	e := newEnv(t)
	e.config("version: 1\nbackends: {jev: {type: typesafe, profile: jev, base_url: '" + srv.URL + "', api_key_env: HG_TEST_KEY}}\n")
	t.Setenv("HG_TEST_KEY", "test-key-not-a-secret")
	out, stderr, code := e.run(nil, "check", "git push origin main", "--request", "push to origin", "--judge")
	if code != 0 || gotAuth != "Bearer test-key-not-a-secret" {
		t.Fatalf("exit %d, auth %q", code, gotAuth)
	}
	if !strings.Contains(stderr, "sending to jev ("+srv.URL+"/v1/systemone)") || !strings.Contains(stderr, `"command": "git push origin main"`) ||
		strings.Contains(stderr, "test-key-not-a-secret") {
		t.Errorf("stderr = %s", stderr)
	}
	if !strings.Contains(out, "decision: pass") {
		t.Errorf("an explicit request must authorize: %s", out)
	}
}

func TestVersion(t *testing.T) {
	if out, _, code := newEnv(t).run(nil, "version"); code != 0 || !strings.HasPrefix(out, "h-guard ") {
		t.Errorf("version = %q", out)
	}
}

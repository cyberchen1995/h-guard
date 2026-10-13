package action_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// fakeBackend 按题返回固定答案；panicOn 非空时对含该命令的 state panic。
type fakeBackend struct {
	calls   atomic.Int32
	answers map[string]judge.Answer
	err     error
	panicOn string
	states  []map[string]any
}

func (f *fakeBackend) Name() string            { return "fake" }
func (f *fakeBackend) Caps() judge.BackendCaps { return judge.BackendCaps{Batch: true} }
func (f *fakeBackend) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	f.calls.Add(1)
	f.states = append(f.states, state)
	if f.panicOn != "" && strings.Contains(state["call"].(map[string]any)["command"].(string), f.panicOn) {
		panic("boom")
	}
	if f.err != nil {
		return judge.Response{}, f.err
	}
	return judge.Response{Answers: f.answers}, nil
}

// low 是「模型认为都不是」的答案：各规则 0，未要求，影响范围 0。
func low() map[string]judge.Answer {
	a := map[string]judge.Answer{action.SignalRequested: {P: judge.Prob(0)}, action.SignalRadius: {Dist: []float64{1, 0, 0, 0}}}
	for _, id := range []string{"guard_tampering", "recursive_delete", "destructive_git", "branch_ops", "publish", "verify_bypass"} {
		a[id] = judge.Answer{P: judge.Prob(0)}
	}
	return a
}

func with(a map[string]judge.Answer, kv ...any) map[string]judge.Answer {
	for i := 0; i+1 < len(kv); i += 2 {
		switch v := kv[i+1].(type) {
		case float64:
			a[kv[i].(string)] = judge.Answer{P: judge.Prob(v)}
		case []float64:
			a[kv[i].(string)] = judge.Answer{Dist: v}
		}
	}
	return a
}

func newCheck(t *testing.T, judgeOn bool, j action.Judge) *action.Check {
	t.Helper()
	cfg := config.Defaults()
	cfg.Judge.Enabled = judgeOn
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	return &action.Check{Rules: set, Config: cfg, Catalog: cat, Locale: "en", Judge: j}
}

func event(requests []guard.Request, cmds ...string) guard.Event {
	ev := guard.Event{Kind: guard.EventAction, Harness: "claudecode", Tool: "Bash", Cwd: "/w", Requests: requests}
	for _, c := range cmds {
		ev.Actions = append(ev.Actions, guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: c, Shell: guard.ShellPOSIX}})
	}
	return ev
}

func user(text string) guard.Request { return guard.Request{Text: text, Source: guard.SourceUser} }

func run(t *testing.T, c *action.Check, ev guard.Event) guard.Verdict {
	t.Helper()
	v, err := guard.Run(context.Background(), c, ev)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func codes(v guard.Verdict) []string {
	var out []string
	for _, r := range v.Reasons {
		out = append(out, r.Code)
	}
	return out
}

func TestJudgeOff(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, "git push origin main")); v.Decision != guard.DecisionPass || v.Signals["judge_disabled_hits"] == nil {
		t.Errorf("git push with the judge off = %+v", v)
	}
	v := run(t, c, event(nil, "rm ~/.claude/settings.json"))
	if v.Decision != guard.DecisionAsk || !slices.Equal(codes(v), []string{i18n.KeyActionGuardSelf, i18n.KeyHintManual}) {
		t.Errorf("guard tampering = %+v", v)
	}
	if v := run(t, c, event(nil, "rm -rf /")); v.Decision != guard.DecisionDeny || codes(v)[0] != i18n.KeyActionBlocked {
		t.Errorf("catastrophic = %+v", v)
	}
	if v := run(t, c, event(nil, "ls -la")); v.Decision != guard.DecisionPass || len(v.Reasons) != 0 {
		t.Errorf("ls = %+v", v)
	}
}

func TestCatastrophicNeverCallsTheJudge(t *testing.T) {
	b := &fakeBackend{answers: with(low(), action.SignalRequested, 1.0)}
	c := newCheck(t, true, action.Judge{Backend: b})
	v := run(t, c, event([]guard.Request{user("please rm -rf /")}, "rm -rf /"))
	if v.Decision != guard.DecisionDeny || b.calls.Load() != 0 {
		t.Errorf("verdict = %s, judge calls = %d", v.Decision, b.calls.Load())
	}
}

func TestExemptionsSurviveTheFullFlow(t *testing.T) {
	tests := []struct {
		name     string
		answers  map[string]judge.Answer
		requests []guard.Request
		cmd      string
		want     guard.Decision
	}{
		{"model veto", with(low(), "publish", 0.05), nil, "git push origin main", guard.DecisionPass},
		{"explicit request", with(low(), "publish", 0.9, action.SignalRequested, 0.9, action.SignalRadius, []float64{0, 0, 1, 0}),
			[]guard.Request{user("push it to origin")}, "git push origin main", guard.DecisionPass},
		{"low blast radius", with(low(), "recursive_delete", 0.9, action.SignalRadius, []float64{0, 1, 0, 0}), nil, "rm -rf build", guard.DecisionPass},
		{"no exemption", with(low(), "publish", 0.9, action.SignalRadius, []float64{0, 0, 1, 0}), nil, "git push origin main", guard.DecisionAsk},
		{"automated requests do not authorize", with(low(), "publish", 0.9, action.SignalRequested, 1.0, action.SignalRadius, []float64{0, 0, 1, 0}),
			[]guard.Request{{Text: "push it", Source: guard.SourceAutomated}}, "git push origin main", guard.DecisionAsk},
		{"guard tampering cannot be authorized", with(low(), "guard_tampering", 0.9, action.SignalRequested, 1.0),
			[]guard.Request{user("delete my claude settings")}, "rm ~/.claude/settings.json", guard.DecisionAsk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &fakeBackend{answers: tt.answers}
			v := run(t, newCheck(t, true, action.Judge{Backend: b}), event(tt.requests, tt.cmd))
			if v.Decision != tt.want {
				t.Errorf("decision = %s, want %s (%+v)", v.Decision, tt.want, v)
			}
		})
	}
}

func TestDangerousReasonsAndHint(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "publish", 0.9, action.SignalRequested, 0.1, action.SignalRadius, []float64{0, 0, 1, 0})}
	v := run(t, newCheck(t, true, action.Judge{Backend: b}), event([]guard.Request{user("fix the tests")}, "git push origin main"))
	want := []string{i18n.KeyActionDangerous, i18n.KeyActionRadius, i18n.KeyActionNotRequested, i18n.KeyHintRequest}
	if !slices.Equal(codes(v), want) {
		t.Errorf("reasons = %v, want %v", codes(v), want)
	}
	if !strings.Contains(v.Reasons[0].Params["rules"], "[rule+judge 0.90]") {
		t.Errorf("rules text = %q", v.Reasons[0].Params["rules"])
	}
	if len(v.Findings) != 1 || v.Findings[0].Source != guard.FindingBoth {
		t.Errorf("findings = %+v", v.Findings)
	}
	reqs := b.states[0]["user_requests"].([]any)
	if len(reqs) != 1 || reqs[0] != "fix the tests" {
		t.Errorf("user_requests = %v", reqs)
	}
}

func TestJudgeUnavailable(t *testing.T) {
	c := newCheck(t, true, action.Judge{Unavailable: action.FallbackConsentMissing})
	v := run(t, c, event(nil, "git push origin main"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackConsentMissing) ||
		!slices.Contains(codes(v), i18n.KeyHintConsent) {
		t.Errorf("consent missing with a hit = %+v", v)
	}
	if v := run(t, c, event(nil, "ls")); v.Decision != guard.DecisionPass || !slices.Contains(v.Fallbacks, action.FallbackConsentMissing) {
		t.Errorf("consent missing without hits = %+v", v)
	}
	b := &fakeBackend{err: &judge.Error{Kind: judge.Timeout}}
	v = run(t, newCheck(t, true, action.Judge{Backend: b}), event(nil, "git push"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackJudgeTimeout) ||
		!slices.Contains(codes(v), i18n.KeyHintJudgeUnavailable) {
		t.Errorf("timeout = %+v", v)
	}
	for _, r := range v.Reasons {
		if r.Code == i18n.KeyHintRequest {
			t.Error("an unavailable judge must not suggest restating the request")
		}
	}
}

func TestTruncatedEvidence(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "recursive_delete", 0.01, action.SignalRequested, 1.0)}
	c := newCheck(t, true, action.Judge{Backend: b})
	c.Config.Policy.MaxCommandChars = 40
	cmd := "git status && " + strings.Repeat("echo ok && ", 10) + "rm -rf src && git status"
	v := run(t, c, event([]guard.Request{user("run git status")}, cmd))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackTruncated) || !slices.Contains(codes(v), i18n.KeyHintSplit) {
		t.Errorf("truncated = %+v", v)
	}
}

func TestMultipleActionsTakeTheStrictest(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, "ls", "rm -rf /", "git status")); v.Decision != guard.DecisionDeny {
		t.Errorf("decision = %s", v.Decision)
	}
}

func TestCommittedActionSurvivesALaterPanic(t *testing.T) {
	b := &fakeBackend{answers: with(low(), "publish", 0.9, action.SignalRadius, []float64{0, 0, 1, 0}), panicOn: "second"}
	c := newCheck(t, true, action.Judge{Backend: b})
	v, err := guard.Run(context.Background(), c, event(nil, "git push origin main", "echo second"))
	var pe *guard.PanicError
	if !errors.As(err, &pe) || v.Decision != guard.DecisionAsk {
		t.Errorf("verdict = %s, err = %v", v.Decision, err)
	}
}

// TestDenySurvivesBudgetExhaustion：灾难性形态命中之后预算耗尽，结论仍为 deny 且保留命中，
// 并且 deny 在后续匹配之前就已提交（评审 M1-02）。
func TestDenySurvivesBudgetExhaustion(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	dir := t.TempDir()
	for name, pattern := range map[string]string{"zzslow": "(a+)+$", "zzz": "nevermatch"} {
		body := "schema: 1\nid: " + name + "\naction: ask\non: [exec]\nreason: {en: slow}\nmatch:\n  exec:\n    any: ['" + pattern + "']\n"
		if err := os.WriteFile(filepath.Join(dir, name+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	if c.Rules, err = rules.Load(dir); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var commits []guard.Verdict
	v, err := c.Evaluate(ctx, event(nil, "rm -rf ~; echo "+strings.Repeat("a", 40)+"!"), func(cv guard.Verdict) { commits = append(commits, cv) })
	if err != nil || v.Decision != guard.DecisionDeny || !slices.Contains(v.Fallbacks, action.FallbackBudget) {
		t.Fatalf("verdict = %+v, err = %v", v, err)
	}
	if !slices.ContainsFunc(v.Findings, func(f guard.Finding) bool { return f.Rule == "catastrophic" }) {
		t.Errorf("findings = %+v, want catastrophic", v.Findings)
	}
	if len(commits) == 0 || commits[0].Decision != guard.DecisionDeny {
		t.Errorf("the deny must be committed before the slow rules run: %+v", commits)
	}
}

func TestBudgetExhaustionWithoutDenyAsks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, _ := guard.Run(ctx, newCheck(t, false, action.Judge{}), event(nil, "ls"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackBudget) {
		t.Errorf("verdict = %+v", v)
	}
}

// TestRegexTimeoutDoesNotWeakenADefiniteDeny：某个模式超时不能让另一处的确定命中降为请求确认；只有超时命中时
// 请求确认并说明正则超时，不能说成「修改护栏本身」（评审 M1 终审）。
func TestRegexTimeoutDoesNotWeakenADefiniteDeny(t *testing.T) {
	slow := "rmdir" + strings.Repeat(" -r", 20000) // 让灾难性规则的一个模式超时
	c := newCheck(t, false, action.Judge{})
	if v := run(t, c, event(nil, slow+"; echo $(rm -rf /)")); v.Decision != guard.DecisionDeny {
		t.Errorf("a definite catastrophic match after a timeout: %s, want deny", v.Decision)
	}
	v := run(t, c, event(nil, slow))
	codes := map[string]bool{}
	for _, r := range v.Reasons {
		codes[r.Code] = true
	}
	if v.Decision != guard.DecisionAsk || codes[i18n.KeyActionGuardSelf] || !codes[i18n.KeyActionRegexTimeout] {
		t.Errorf("a timed-out match alone: %s, reasons %v", v.Decision, v.Reasons)
	}
}

// TestShellContextDecides：同一个危险命令在不同的 shell 上下文里结论不同——真正执行时阻止，作为数据时放行
// （评审 N01；命令只交给检测器，不执行）。
func TestShellContextDecides(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	tests := []struct {
		name, cmd string
		want      guard.Decision
	}{
		{"heredoc paren inside substitution", "echo \"$(cat <<'EOF'\n)\nEOF\nrm -rf ~\n)\"", guard.DecisionDeny},
		{"comment paren inside substitution", "echo \"$(echo x # )\nrm -rf ~\n)\"", guard.DecisionDeny},
		{"nested quotes control", "echo \"$(echo \"$(printf ')')\"; rm -rf ~)\"", guard.DecisionDeny},
		{"space in quoted delimiter", "cat <<' EOF'\nsafe\n EOF\nrm -rf ~", guard.DecisionDeny},
		{"indented delimiter line is data", "cat <<'EOF'\n EOF\nrm -rf ~\nEOF", guard.DecisionPass},
		{"split prefix word", "su\\\ndo rm -rf ~", guard.DecisionDeny},
		{"split command word", "rm -r\\\nf ~", guard.DecisionDeny},
		{"split heredoc delimiter", "cat <<E\\\nOF\nsafe\nEOF\nrm -rf ~", guard.DecisionDeny},
		{"quoted heredoc keeps the backslash", "cat <<'EOF'\nx\\\nEOF\nrm -rf ~", guard.DecisionDeny},
		{"unquoted heredoc joins lines", "cat <<EOF\nx\\\nEOF\nrm -rf ~\nEOF", guard.DecisionPass},
		{"continuation inside single quotes is text", "echo 'su\\\ndo rm -rf ~'", guard.DecisionPass},
		{"continuation inside quoted heredoc is text", "cat > f <<'EOF'\nsu\\\ndo rm -rf ~\nEOF", guard.DecisionPass},
		{"comment backslash does not continue", "echo hi # note \\\nrm -rf ~", guard.DecisionDeny},
		// 续行先于词法单元的识别（评审 R3-02）
		{"split substitution in double quotes", "echo \"$\\\n(rm -rf ~)\"", guard.DecisionDeny},
		{"split substitution in expandable heredoc", "cat <<EOF\n$\\\n(rm -rf ~)\nEOF", guard.DecisionDeny},
		{"split assignment prefix", "F\\\nOO=1 rm -rf ~", guard.DecisionDeny},
		{"split interpreter name", "bas\\\nh <<'EOF'\nrm -rf ~\nEOF", guard.DecisionDeny},
		// 被续行拆开的 heredoc 运算符：正文照常按执行或数据处理（评审 R4-01）
		{"split heredoc operator, expandable body", "cat <\\\n<EOF\n$(rm -rf ~)\nEOF", guard.DecisionDeny},
		{"split heredoc operator, interpreter body", "bash <\\\n<'EOF'\nrm -rf ~\nEOF", guard.DecisionDeny},
		// 参数默认值里的进程替换会执行；引号里的是字面内容（评审 R5-01）
		{"process substitution in parameter default", "echo ${x:-<(rm -rf ~)}", guard.DecisionDeny},
		{"output process substitution in parameter default", "echo ${x:->(rm -rf ~)}", guard.DecisionDeny},
		{"process substitution mid-word in parameter default", "echo ${x:-a<(rm -rf ~)}", guard.DecisionDeny},
		{"split process substitution in parameter default", "echo ${x:-<\\\n(rm -rf ~)}", guard.DecisionDeny},
		{"single-quoted process substitution in parameter default", "echo ${x:-'<(rm -rf ~)'}", guard.DecisionPass},
		{"double-quoted process substitution in parameter default", "echo ${x:-\">(rm -rf ~)\"}", guard.DecisionPass},
		{"parameter default in double quotes", "echo \"${x:-<(rm -rf ~)}\"", guard.DecisionPass},
		// 命令替换再多，后面的内容也要检查（评审 M1 终审）
		{"after many substitutions", "echo" + strings.Repeat(" $(true)", 70) + " $(rm -rf /)", guard.DecisionDeny},
	}
	for _, tt := range tests {
		if v := run(t, c, event(nil, tt.cmd)); v.Decision != tt.want {
			t.Errorf("%s: %s, want %s", tt.name, v.Decision, tt.want)
		}
	}
	// 引号里的进程替换是字面内容：模型开启时可以因普通全文规则请求确认，但不能当作灾难性执行（评审 R5-01）
	for _, cmd := range []string{"echo ${x:-'<(rm -rf ~)'}", "echo ${x:-\">(rm -rf ~)\"}", "echo \"${x:-<(rm -rf ~)}\""} {
		if v := run(t, newCheck(t, true, action.Judge{}), event(nil, cmd)); v.Decision == guard.DecisionDeny {
			t.Errorf("%q: literal text treated as catastrophic execution", cmd)
		}
	}
	// 模型开启但不可用时普通正则命中请求确认：嵌套上下文里的字面反斜杠换行不能拼出命令（评审 R3-03）
	unavailable := newCheck(t, true, action.Judge{})
	for _, cmd := range []string{
		"echo \"$(printf '%s' 'r\\\nm -rf build')\"",
		"echo hi # r\\\nm -rf build",
		"echo \"$(cat <<'EOF'\nr\\\nm -rf build\nEOF\n)\"",
		"cat <\\\n<'EOF'\nrm -rf build\nEOF",               // 拆开的运算符，正文是字面数据（评审 R4-01）
		"echo ${x:-\"$(printf '%s' 'r\\\nm -rf build')\"}", // 参数展开里的嵌套引号（评审 R4-02）
	} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionPass {
			t.Errorf("%q: %s, want pass", cmd, v.Decision)
		}
	}
	for _, cmd := range []string{"r\\\nm -rf build", "echo ${x:-$(r\\\nm -rf build)}"} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionAsk {
			t.Errorf("%q: a real continuation must still match: %s", cmd, v.Decision)
		}
	}
	for _, cmd := range []string{"cat <\\\n<EOF\n$(rm -rf ~)\nEOF", "bash <\\\n<'EOF'\nrm -rf ~\nEOF",
		"echo ${x:-<(rm -rf ~)}", "echo ${x:->(rm -rf ~)}"} {
		if v := run(t, unavailable, event(nil, cmd)); v.Decision != guard.DecisionDeny {
			t.Errorf("%q with the judge enabled: %s, want deny", cmd, v.Decision)
		}
	}
}

func TestProbe(t *testing.T) {
	v := run(t, newCheck(t, false, action.Judge{}), event(nil, "  h-guard-probe "))
	if v.Decision != guard.DecisionAsk || codes(v)[0] != i18n.KeyActionProbe {
		t.Errorf("probe = %+v", v)
	}
}

func TestAppliesOnlyToExec(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	file := guard.Event{Kind: guard.EventAction, Harness: "h", Actions: []guard.Action{{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "x"}}}}
	if c.Applies(file) || c.Applies(guard.Event{Kind: guard.EventPrompt}) || !c.Applies(event(nil, "ls")) {
		t.Error("Applies must be true only for events with exec actions")
	}
}

func TestDisabledRuleNoLongerMatches(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	if _, err := c.Rules.Apply(rules.Overrides{"catastrophic": false}); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, event(nil, "rm -rf /")); v.Decision == guard.DecisionDeny {
		t.Error("a disabled hard rule must not match")
	}
}

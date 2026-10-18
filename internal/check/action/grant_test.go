package action_test

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/grant"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// TestGrantFlow：接入单次授权时，可以授权的请求确认记下待批准的操作，前进路径换成 h-guard allow；批准之后同一事件
// 放行一次（命中照常记录，信号带编号），再来一次又请求确认。一次工具调用里的全部动作作为一个整体授权。
func TestGrantFlow(t *testing.T) {
	st := &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	c := newCheck(t, false, action.Judge{})
	c.Grants = st
	ev := event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh", "ls")
	v := run(t, c, ev)
	if v.Decision != guard.DecisionAsk || v.Reasons[0].Code != i18n.KeyHintGrant {
		t.Fatalf("first = %+v", v)
	}
	id := v.Reasons[0].Params["id"]
	if id != action.OpOf(ev).ID() || v.Reasons[0].Params["minutes"] != "10" {
		t.Errorf("grant params = %v", v.Reasons[0].Params)
	}
	if p, err := st.Lookup(id); err != nil || len(p.Op.Actions) != 2 || p.Rules[0] != "obfuscated_exec" {
		t.Errorf("pending = %+v, %v", p, err)
	}
	if _, err := approveID(st, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	// 只有其中一个动作的事件对不上
	if v := run(t, c, event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh")); v.Decision != guard.DecisionAsk {
		t.Errorf("partial event = %s", v.Decision)
	}
	v = run(t, c, ev)
	if v.Decision != guard.DecisionPass || v.Signals[action.SignalGrant] != id || len(v.Findings) != 1 {
		t.Errorf("granted = %+v", v)
	}
	if v := run(t, c, ev); v.Decision != guard.DecisionAsk {
		t.Errorf("after use = %s", v.Decision)
	}
}

// TestGrantNeverReleasesDenyOrHardRules：批准过也不放行 deny 与硬规则：灾难性命令照常 deny（且照常提交），
// 护栏自我保护照常请求确认，也不提供 h-guard allow。
func TestGrantNeverReleasesDenyOrHardRules(t *testing.T) {
	st := &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	c := newCheck(t, false, action.Judge{})
	c.Grants = st
	for _, cmd := range []string{"rm -rf /", "rm ~/.claude/settings.json", "echo x | base64 -d | sh; rm ~/.claude/settings.json"} {
		ev := event(nil, cmd)
		// 伪造一条已批准的授权：Offer 之后直接批准
		id, _ := st.Offer(action.OpOf(ev), nil)
		if _, err := approveID(st, id, time.Minute); err != nil {
			t.Fatal(err)
		}
		v := run(t, c, ev)
		if v.Decision == guard.DecisionPass || codes(v)[0] == i18n.KeyHintGrant {
			t.Errorf("%s = %+v", cmd, v)
		}
		if !st.Has(action.OpOf(ev)) {
			t.Errorf("%s used the approval", cmd)
		}
	}
}

// TestExplainNamesOperationImpactAndAdvice：打断的原因依次写明为什么（规则）、操作与目标、后果与更稳妥的做法；
// 命令里的凭据形状遮蔽，过长的命令截断。
func TestExplainNamesOperationImpactAndAdvice(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	v := run(t, c, event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh # token sk-abcdefghijklmnop1234 "+strings.Repeat("x", 300)))
	var op, impact, advice string
	for _, r := range v.Reasons {
		switch r.Code {
		case i18n.KeyActionOperation:
			op = c.Catalog.Text("en", r.Code, r.Params)
		case i18n.KeyActionImpact:
			impact = r.Params["impact"]
		case i18n.KeyActionAdvice:
			advice = r.Params["advice"]
		}
	}
	if !strings.HasPrefix(op, "Operation: `echo cm0gLXJmIGJ1aWxk") || !strings.Contains(op, "` in /w.") ||
		strings.Contains(op, "sk-abcdefghijklmnop1234") || !strings.Contains(op, "…") {
		t.Errorf("operation = %q", op)
	}
	if impact == "" || advice == "" {
		t.Errorf("impact %q, advice %q", impact, advice)
	}
	zh := c.Catalog.Text("zh-CN", i18n.KeyActionOperation, map[string]string{"command": "git reset --hard", "cwd": "/w"})
	if zh != "操作：在 /w 中运行 `git reset --hard`。" {
		t.Errorf("zh-CN = %q", zh)
	}
}

// TestEveryInterruptionIsExplained 是拦截说明的验收：每条内置规则的每个命中示例，在它会打断的条件下（模型开启、
// 回答危险、用户没有要求过），原因都写明操作与目标、后果、更稳妥的做法；Codex 这类不能确认的 harness 上，
// 可以授权的（不是 deny、不是硬规则）都给出 h-guard allow，其余都不给。
func TestEveryInterruptionIsExplained(t *testing.T) {
	set := newCheck(t, false, action.Judge{}).Rules
	n := 0
	defer func() {
		if n < 50 {
			t.Errorf("only %d examples checked", n)
		}
	}()
	for _, r := range set.All() {
		for _, ex := range r.Examples.Hit {
			if ex.Command == "" {
				continue // 文件动作的示例由 TestFileActionsOnProtectedPaths、TestSensitiveRead 覆盖
			}
			n++
			shell := ex.Shell
			if shell == "" {
				shell = guard.ShellPOSIX
			}
			answers := with(low(), action.SignalRadius, []float64{0, 0, 0, 1})
			for id := range answers {
				if id != action.SignalRequested && id != action.SignalRadius {
					answers[id] = judge.Answer{P: judge.Prob(0.95)}
				}
			}
			c := newCheck(t, true, action.Judge{Backend: &fakeBackend{answers: answers}})
			c.Grants = &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
			ev := guard.Event{Kind: guard.EventAction, Harness: "codex", Tool: "Bash", Cwd: "/w",
				Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: ex.Command, Shell: shell}}}}
			v := run(t, c, ev)
			if v.Decision == guard.DecisionPass {
				t.Errorf("%s: %q does not interrupt", r.ID, ex.Command)
				continue
			}
			got := codes(v)
			for _, want := range []string{i18n.KeyActionOperation, i18n.KeyActionImpact, i18n.KeyActionAdvice} {
				if !slices.Contains(got, want) {
					t.Errorf("%s: %q lacks %s (%v)", r.ID, ex.Command, want, got)
				}
			}
			locked := false
			for _, f := range v.Findings {
				locked = locked || set.Get(f.Rule).Locked
			}
			if offered := got[0] == i18n.KeyHintGrant; offered != (v.Decision == guard.DecisionAsk && !locked) {
				t.Errorf("%s: %q %s, locked hit %v, grant offered %v", r.ID, ex.Command, v.Decision, locked, offered)
			}
		}
	}
}

// TestGrantUsedEvenWhenNotNeeded：有授权的重试即使本来就放行（如模型这次的回答不同），授权也用掉，
// 不能留到之后再放行一次同样的操作。
func TestGrantUsedEvenWhenNotNeeded(t *testing.T) {
	st := &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	c := newCheck(t, false, action.Judge{})
	c.Grants = st
	ev := event(nil, "ls -la")
	id, _ := st.Offer(action.OpOf(ev), nil)
	if _, err := approveID(st, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, ev); v.Decision != guard.DecisionPass {
		t.Fatalf("ls = %s", v.Decision)
	}
	if st.Has(action.OpOf(ev)) {
		t.Error("the approval survived a retry that passed on its own")
	}
}

// TestExplainRedactsBeforeClipping：凭据跨过截断位置时照样遮蔽（先遮蔽再截断）。
func TestExplainRedactsBeforeClipping(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	cmd := "echo cm0gLXJmIGJ1aWxk | base64 -d | sh # " + strings.Repeat("y", 150) + " https://user:hunter2hunter2hunter2hunter2@example.com/repo"
	for _, r := range run(t, c, event(nil, cmd)).Reasons {
		if r.Code == i18n.KeyActionOperation && strings.Contains(r.Params["command"], "hunter2") {
			t.Errorf("command = %q", r.Params["command"])
		}
	}
}

// TestEveryActionIsExplained：一次工具调用里几个同样严的动作（补丁改了几个受保护的文件），每个都写明。
func TestEveryActionIsExplained(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	ev := event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh", "echo bHMgLWxh | base64 -d | bash")
	var ops []string
	for _, r := range run(t, c, ev).Reasons {
		if r.Code == i18n.KeyActionOperation {
			ops = append(ops, r.Params["command"])
		}
	}
	if len(ops) != 2 {
		t.Errorf("operations explained: %v", ops)
	}
}

// TestOpBindsTheTool：同样的命令由不同的工具执行是不同的操作，授权对不上。
func TestOpBindsTheTool(t *testing.T) {
	a := event(nil, "ls")
	b := a
	b.Tool = "write_stdin"
	if action.OpOf(a).ID() == action.OpOf(b).ID() {
		t.Error("tool is not part of the operation")
	}
}

// TestBudgetExhaustionStillNamesTheOperation：本地检查来不及做完时，请求确认的原因同样写明操作。
func TestBudgetExhaustionStillNamesTheOperation(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, _ := guard.Run(ctx, c, event(nil, "git reset --hard"))
	if v.Decision != guard.DecisionAsk || !slices.Contains(codes(v), i18n.KeyActionOperation) {
		t.Errorf("verdict = %+v", v)
	}
}

// TestNoGrantWhenTheCallWritesFiles：调用里有文件动作时不提供授权：事件只有路径，批准绑不住写进去的内容，
// 也绑不住读的时候路径指向哪里。
func TestNoGrantWhenTheCallWritesFiles(t *testing.T) {
	c := newCheck(t, false, action.Judge{})
	c.Grants = &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	ev := event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh")
	ev.Actions = append(ev.Actions, guard.Action{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: "notes.md"}})
	if v := run(t, c, ev); v.Decision != guard.DecisionAsk || slices.Contains(codes(v), i18n.KeyHintGrant) {
		t.Errorf("with a file write = %+v", v)
	}
	// 读文件同样不授权：路径可能在批准之后换成指向别处的符号链接
	ev.Actions[1].Kind = guard.ActionFileRead
	if v := run(t, c, ev); slices.Contains(codes(v), i18n.KeyHintGrant) {
		t.Errorf("with a file read = %+v", v)
	}
}

// TestGrantKeepsSignals：用掉授权放行时保留判断层的信号，决策日志查得到放行的是怎样的操作。
func TestGrantKeepsSignals(t *testing.T) {
	st := &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	c := newCheck(t, false, action.Judge{})
	c.Grants = st
	ev := event(nil, "echo cm0gLXJmIGJ1aWxk | base64 -d | sh")
	id, _ := st.Offer(action.OpOf(ev), nil)
	if _, err := approveID(st, id, time.Minute); err != nil {
		t.Fatal(err)
	}
	if v := run(t, c, ev); v.Decision != guard.DecisionPass || v.Signals["judge"] != "off" || v.Signals[action.SignalGrant] != id {
		t.Errorf("signals = %v", v.Signals)
	}
}

// TestFileBudgetExhaustionNamesTheFile：文件检查来不及做完时同样写明是哪个文件操作。
func TestFileBudgetExhaustionNamesTheFile(t *testing.T) {
	c := fileCheck(t, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v, _ := guard.Run(ctx, c, fileEvent(guard.ActionFileWrite, "~/.claude/settings.json", ""))
	found := false
	for _, r := range v.Reasons {
		found = found || (r.Code == i18n.KeyActionOperation && strings.Contains(r.Params["command"], "~/.claude/settings.json"))
	}
	if v.Decision != guard.DecisionAsk || !found {
		t.Errorf("verdict = %+v", v)
	}
}

// approveID 按编号查出待批准记录再批准它，与 h-guard allow 的做法一致。
func approveID(s *grant.Store, id string, ttl time.Duration) (grant.Grant, error) {
	p, err := s.Lookup(id)
	if err != nil {
		return grant.Grant{}, err
	}
	return s.Approve(p, ttl)
}

// TestNoGrantAfterARegexTimeout：某个规则的正则超时时本地检查没做完，不提供授权。
func TestNoGrantAfterARegexTimeout(t *testing.T) {
	st := &grant.Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: time.Now}
	c := newCheck(t, false, action.Judge{})
	c.Grants = st
	v := run(t, c, event(nil, "rmdir"+strings.Repeat(" -r", 20000)))
	if v.Decision != guard.DecisionAsk || !slices.Contains(v.Fallbacks, action.FallbackRegexTimeout) {
		t.Fatalf("verdict = %s %v", v.Decision, v.Fallbacks)
	}
	for _, r := range v.Reasons {
		if r.Code == i18n.KeyHintGrant {
			t.Errorf("grant offered after a regex timeout: %+v", r)
		}
	}
}

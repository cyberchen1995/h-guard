package rules_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func builtinSet(t *testing.T) *rules.Set {
	t.Helper()
	s, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func hits(t *testing.T, s *rules.Set, cmd string) map[string]bool {
	t.Helper()
	e, err := command.Expand(context.Background(), cmd, guard.ShellPOSIX)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range s.All() {
		res, err := r.MatchExec(context.Background(), e)
		if err != nil {
			t.Fatal(err)
		}
		if res.Hit {
			out[r.ID] = true
		}
	}
	return out
}

func TestBuiltinRules(t *testing.T) {
	s := builtinSet(t)
	want := map[string]struct {
		action        guard.Decision
		locked, judge bool
	}{
		"catastrophic":     {guard.DecisionDeny, true, false},
		"fork_bomb":        {guard.DecisionDeny, true, false},
		"guard_tampering":  {guard.DecisionAsk, true, false},
		"recursive_delete": {guard.DecisionAsk, false, true},
		"destructive_git":  {guard.DecisionAsk, false, true},
		"branch_ops":       {guard.DecisionAsk, false, true},
		"publish":          {guard.DecisionAsk, false, true},
		"verify_bypass":    {guard.DecisionAsk, false, true},
	}
	if len(s.All()) != len(want) {
		t.Fatalf("got %d rules, want %d", len(s.All()), len(want))
	}
	for id, w := range want {
		r := s.Get(id)
		if r == nil || r.Action != w.action || r.Locked != w.locked || r.RequiresJudge != w.judge || !r.Enabled() {
			t.Errorf("%s = %+v", id, r)
			continue
		}
		if _, ok := r.JudgeQuestion(); ok != (id != "catastrophic" && id != "fork_bomb") {
			t.Errorf("%s: has question = %v", id, ok)
		}
	}
	if s.Get("guard_tampering").Bypassable() || !s.Get("publish").Bypassable() {
		t.Error("only guard_tampering is not bypassable")
	}
	if s.Get("recursive_delete").RadiusFloor != 1.25 {
		t.Error("recursive_delete radius_floor must be 1.25")
	}
}

func TestBuiltinExamples(t *testing.T) {
	for _, r := range builtinSet(t).All() {
		if len(r.Examples.Hit) == 0 || len(r.Examples.Miss) == 0 {
			t.Errorf("%s has no hit or miss examples", r.ID)
		}
		if err := r.CheckExamples(context.Background()); err != nil {
			t.Error(err)
		}
	}
}

func TestCaseInsensitiveLikePython(t *testing.T) {
	s := builtinSet(t)
	if !hits(t, s, "GIT PUSH origin main")["publish"] {
		t.Error("rules must be case-insensitive")
	}
	// branch_ops 用 (?-i:-D) 区分 -D（强制删除）与 -d（安全删除）
	if !hits(t, s, "git branch -D x")["branch_ops"] || hits(t, s, "git branch -d x")["branch_ops"] {
		t.Error("(?-i:…) must keep -D case-sensitive")
	}
}

func TestMentionsAreNotCatastrophic(t *testing.T) {
	s := builtinSet(t)
	for _, cmd := range []string{
		`echo "别用 rm -rf / 这种命令"`,
		`grep -rn "rm -rf /" docs/`,
		`printf "%s\n" "rm -rf /" >> notes.md`,
		`echo "dd if=/dev/zero of=/dev/disk2 会抹掉整块盘"`,
		`rg --fixed-strings "sudo rm -rf ~"`,
	} {
		if hits(t, s, cmd)["catastrophic"] {
			t.Errorf("%q matched catastrophic", cmd)
		}
	}
	for _, cmd := range []string{"cd /tmp; rm -rf /", "make build || rm -rf /", "env FOO=1 rm -rf /", "nohup rm -rf /",
		`echo "$(rm -rf /)"`, "sudo -u root rm -rf /"} {
		if !hits(t, s, cmd)["catastrophic"] {
			t.Errorf("%q did not match catastrophic", cmd)
		}
	}
}

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const userPublish = `schema: 1
id: publish
action: ask
on: [exec]
reason: {en: custom publish}
match:
  exec:
    any: ['\bship-it\b']
`

func TestUserRulesOverrideByID(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "publish.yaml", userPublish)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Get("publish")
	if r.Builtin || r.ReasonText("en") != "custom publish" {
		t.Errorf("publish = %+v", r)
	}
	h := hits(t, s, "ship-it now")
	if !h["publish"] || hits(t, s, "git push")["publish"] {
		t.Error("the user rule must replace the built-in one entirely")
	}
	if _, err := rules.Load(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("a missing user dir must be skipped: %v", err)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := map[string]string{
		"override locked":   strings.Replace(userPublish, "id: publish", "id: catastrophic", 1),
		"user locked":       strings.Replace(userPublish, "on: [exec]", "on: [exec]\nlocked: true", 1),
		"bad schema":        strings.Replace(userPublish, "schema: 1", "schema: 2", 1),
		"unknown field":     userPublish + "colour: red\n",
		"bad regex":         strings.Replace(userPublish, `'\bship-it\b'`, `'(unclosed'`, 1),
		"bad action":        strings.Replace(userPublish, "action: ask", "action: warn", 1),
		"file rule":         strings.Replace(userPublish, "on: [exec]", "on: [file_read]", 1),
		"no reason":         strings.Replace(userPublish, "reason: {en: custom publish}", "reason: {zh-CN: x}", 1),
		"judge no question": strings.Replace(userPublish, "on: [exec]", "on: [exec]\nrequires_judge: true", 1),
		"no patterns":       strings.Replace(userPublish, `any: ['\bship-it\b']`, "any: []", 1),
		"second document":   userPublish + "---\nschema: 1\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRule(t, dir, "r.yaml", body)
			_, err := rules.Load(dir)
			var re *rules.Error
			switch {
			case err == nil:
				t.Errorf("Load accepted:\n%s", body)
			case !strings.Contains(err.Error(), "r.yaml"):
				t.Errorf("error does not name the file: %v", err)
			case !errors.As(err, &re) || !strings.HasPrefix(re.Brief(), "r.yaml"):
				t.Errorf("err = %#v, want *rules.Error naming r.yaml", err)
			}
		})
	}
	dir := t.TempDir()
	writeRule(t, dir, "a.yaml", userPublish)
	writeRule(t, dir, "b.yaml", userPublish)
	if _, err := rules.Load(dir); err == nil {
		t.Error("duplicate user rule ids must be rejected")
	}
}

func TestApplyOverrides(t *testing.T) {
	s := builtinSet(t)
	warnings, err := s.Apply(rules.Overrides{"publish": false, "catastrophic": false})
	if err != nil {
		t.Fatal(err)
	}
	if s.Get("publish").Enabled() || s.Get("catastrophic").Enabled() || !s.Get("branch_ops").Enabled() {
		t.Error("overrides not applied")
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "catastrophic") {
		t.Errorf("warnings = %q", warnings)
	}
	var re *rules.Error
	if _, err := builtinSet(t).Apply(rules.Overrides{"nope": false}); !errors.As(err, &re) || re.Brief() != "rules rules.nope" {
		t.Errorf("overriding an unknown rule: err = %v", err)
	}
}

func TestStateOf(t *testing.T) {
	s := builtinSet(t)
	tests := []struct {
		id          string
		tier        int
		judge       bool
		effective   bool
		inactiveWhy string
	}{
		{"publish", 1, false, false, rules.InactiveJudgeDisabled},
		{"publish", 1, true, true, ""},
		{"guard_tampering", 1, false, true, ""},
		{"catastrophic", 1, false, true, ""},
	}
	for _, tt := range tests {
		st := rules.StateOf(s.Get(tt.id), tt.tier, tt.judge)
		if st.Effective != tt.effective || st.Inactive != tt.inactiveWhy {
			t.Errorf("%s tier=%d judge=%v: %+v", tt.id, tt.tier, tt.judge, st)
		}
	}
	s.Apply(rules.Overrides{"catastrophic": false})
	if st := rules.StateOf(s.Get("catastrophic"), 1, true); st.Effective || st.Inactive != rules.InactiveDisabled {
		t.Errorf("disabled hard rule: %+v", st)
	}
	if !rules.TierCovers(1, guard.ActionExec) || rules.TierCovers(1, guard.ActionFileRead) || !rules.TierCovers(2, guard.ActionFileRead) ||
		rules.TierCovers(2, guard.ActionToolCall) || !rules.TierCovers(3, guard.ActionToolCall) {
		t.Error("TierCovers does not follow spec §4")
	}
}

// TestDeadlineIsCheckedBeforeEveryMatch：截止时间到了之后不再开始新的正则匹配（评审 M1-07）。
func TestDeadlineIsCheckedBeforeEveryMatch(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "slow.yaml", `schema: 1
id: slow
action: ask
on: [exec]
reason: {en: slow}
match:
  exec:
    any: ['^(a+)+$']
    command_position: true
`)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := command.Expand(context.Background(), strings.Repeat(strings.Repeat("a", 40)+"!;", 8), guard.ShellPOSIX)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := s.Get("slow").MatchExec(ctx, e)
	if err == nil || !res.TimedOut || time.Since(start) > 2*rules.MatchTimeout+100*time.Millisecond {
		t.Errorf("res = %+v, err = %v after %v", res, err, time.Since(start))
	}
}

// TestDefiniteMatchClearsEarlierTimeout：前面的模式超时之后，另一个模式确定命中时结论是确定命中，不带超时标记
// （否则 deny 级规则的确定命中会被降为请求确认，评审 M1 终审）。
func TestDefiniteMatchClearsEarlierTimeout(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "slow.yaml", `schema: 1
id: slow
action: deny
on: [exec]
reason: {en: slow}
match:
  exec:
    any: ['^(a+)+$', 'aaaa!']
`)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := command.Expand(context.Background(), strings.Repeat("a", 40)+"!", guard.ShellPOSIX)
	res, err := s.Get("slow").MatchExec(context.Background(), e)
	if err != nil || !res.Hit || res.TimedOut {
		t.Errorf("res = %+v, err = %v; want a definite hit", res, err)
	}
}

func TestRegexTimeoutCountsAsHit(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "slow.yaml", `schema: 1
id: slow
action: ask
on: [exec]
reason: {en: slow}
match:
  exec:
    any: ['^(a+)+$']
`)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := command.Expand(context.Background(), strings.Repeat("a", 40)+"!", guard.ShellPOSIX)
	res, err := s.Get("slow").MatchExec(context.Background(), e)
	if err != nil || !res.Hit || !res.TimedOut {
		t.Errorf("res = %+v, err = %v", res, err)
	}
}

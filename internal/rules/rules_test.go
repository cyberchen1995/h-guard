package rules_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
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
		"sensitive_read":   {guard.DecisionAsk, false, false},
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
		if _, ok := r.JudgeQuestion(); ok != (id != "catastrophic" && id != "fork_bomb" && id != "sensitive_read") {
			t.Errorf("%s: has question = %v", id, ok)
		}
	}
	if s.Get("guard_tampering").Bypassable() || !s.Get("publish").Bypassable() {
		t.Error("only guard_tampering is not bypassable")
	}
	for _, r := range s.All() {
		if r.Vetoable() != (r.ID != "guard_tampering") {
			t.Errorf("%s: vetoable = %v; only guard_tampering cannot be vetoed by the judge", r.ID, r.Vetoable())
		}
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

// TestVetoableIsIndependentOfBypassable：vetoable_by_judge 与 bypassable_by_request 各自独立，默认都为 true。
func TestVetoableIsIndependentOfBypassable(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "a.yaml", strings.Replace(userPublish, "id: publish", "id: no_veto\nvetoable_by_judge: false", 1))
	writeRule(t, dir, "b.yaml", strings.Replace(userPublish, "id: publish", "id: no_bypass\nbypassable_by_request: false", 1))
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r := s.Get("no_veto"); r.Vetoable() || !r.Bypassable() {
		t.Errorf("no_veto: vetoable %v, bypassable %v", r.Vetoable(), r.Bypassable())
	}
	if r := s.Get("no_bypass"); !r.Vetoable() || r.Bypassable() {
		t.Errorf("no_bypass: vetoable %v, bypassable %v", r.Vetoable(), r.Bypassable())
	}
}

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
		"file rule asks":    strings.Replace(userFileRule, "on: [file_read]", "on: [file_read]\nquestion: {kind: probability, instructions: {question: q}}", 1),
		"signal id":         strings.Replace(userPublish, "id: publish", "id: explicitly_requested", 1),
		"signal id radius":  strings.Replace(userPublish, "id: publish", "id: blast_radius", 1),
		"bad exclude":       strings.Replace(userFileRule, "exclude: ['**/secrets/README.md']", "exclude: ['README.md']", 1),
		"exclude, no paths": strings.Replace(userFileRule, "paths: ['**/secrets/**']", "paths: []", 1),
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

func TestGuardTamperingCoversFileActions(t *testing.T) {
	r := builtinSet(t).Get("guard_tampering")
	for _, k := range []guard.ActionKind{guard.ActionFileWrite, guard.ActionFileDelete, guard.ActionFileRename} {
		if !r.AppliesTo(k) {
			t.Errorf("guard_tampering does not apply to %s", k)
		}
	}
	if r.AppliesTo(guard.ActionFileRead) {
		t.Error("reading the guard's files is not tampering")
	}
	env := rules.ExampleEnv
	hit, complete := r.MatchFile(paths.Resolve("~/.codex/config.toml", env), env)
	miss, _ := r.MatchFile(paths.Resolve("README.md", env), env)
	if !hit || miss || !complete {
		t.Error("MatchFile does not follow the rule's paths")
	}
	if hit, _ := builtinSet(t).Get("publish").MatchFile(paths.Resolve("~/.codex/config.toml", env), env); hit {
		t.Error("an exec-only rule matched a path")
	}
	// 动词前要有词边界（M1 遗留的误拦）
	s := builtinSet(t)
	for _, cmd := range []string{"grep confirm ~/.claude/settings.json", "git log --format=%s -- ~/.codex/hooks.json",
		"docker run --rm -v ~/.codex/config.toml:/c.toml:ro img", "tool -rm ~/.claude/settings.json",
		"-rm ~/.claude/settings.json"} {
		if hits(t, s, cmd)["guard_tampering"] {
			t.Errorf("%q matched guard_tampering", cmd)
		}
	}
	// 单字母前缀的工具（Homebrew 的 gsed、grm 等 GNU 工具，scp、srm、xcp、rcp、ipython）与连字符连着的工具名
	// （uu-rm）同样是改动：M1 覆盖它们，词边界不能丢掉
	for _, cmd := range []string{"gsed -i 's/h-guard//' ~/.claude/settings.json", "grm ~/.claude/settings.json",
		"gcp /tmp/x ~/.codex/hooks.json", "gtee ~/.config/h-guard/config.yaml",
		"scp /tmp/evil.yaml ~/.config/h-guard/config.yaml", "srm ~/.config/h-guard/config.yaml",
		"xcp /tmp/x ~/.claude/settings.json", "rcp /tmp/x ~/.codex/hooks.json",
		`ipython -c "open('/home/u/.claude/settings.json','w').write('{}')"`, "uu-rm ~/.codex/config.toml"} {
		if !hits(t, s, cmd)["guard_tampering"] {
			t.Errorf("%q did not match guard_tampering", cmd)
		}
	}
}

// TestAgentCannotEnableABackend：agent 在 hook 下运行 h-guard backend enable（哪怕用 script 之类的伪终端绕过
// 终端检查）会替用户记下同意，必须请求确认；用户在自己终端里运行不经过 hook。查看与撤销同意不算。
func TestAgentCannotEnableABackend(t *testing.T) {
	s := builtinSet(t)
	for _, cmd := range []string{"h-guard backend enable local", `printf 'y\n' | script -q /dev/null h-guard backend enable local`,
		"/usr/local/bin/h-guard backend enable jev"} {
		if !hits(t, s, cmd)["guard_tampering"] {
			t.Errorf("%q did not match guard_tampering", cmd)
		}
	}
	for _, cmd := range []string{"h-guard backend list", "h-guard backend disable local", "h-guard status"} {
		if hits(t, s, cmd)["guard_tampering"] {
			t.Errorf("%q matched guard_tampering", cmd)
		}
	}
}

// TestHarmlessDdTargetsAreNotCatastrophic：只豁免去向固定、写入无害的设备。/dev/stdout、/dev/stderr、/dev/fd/N
// 可能已被 shell 重定向到块设备（评审 M2-04），与 M1 一样拒绝——包括同一段把标准输出重定向到普通文件的
// 写法（已知的保守误报）。dd 的输出重定向指向设备时同样拒绝。
func TestHarmlessDdTargetsAreNotCatastrophic(t *testing.T) {
	s := builtinSet(t)
	for _, cmd := range []string{"dd if=/dev/zero of=/dev/null count=1",
		`dd if=x "of=/dev/null"`, "dd if=x of=/dev/tty", "dd if=/dev/zero of=/dev/null bs=1 count=1 2>/dev/null",
		"dd if=/dev/zero of=/dev/null >./log 2>&1",
		// 注释与引号里的 > 不是重定向（评审 R2-04）
		"dd if=/dev/zero of=/dev/null bs=1M count=1 # example alternative: >/dev/sda",
		"dd if=/dev/zero of=/dev/null count=1 #>/dev/sda", `dd if=/dev/zero of=/dev/null status='x >/dev/sda'`,
		// 输入文件名里的字面 >（引号或转义）不是重定向（评审 R3-01）
		`dd if=">/dev/sda" count=0`, `dd if=\>/dev/sda count=0`,
		// bash 的 <> 打开的不是块设备（/dev/tcp 是网络连接）：<> 只对 dd 生效，exec 3<>… 照常放行
		"exec 3<>/dev/tcp/example.com/80",
		// 复合命令的结尾词带的重定向指向无害设备：照常放行
		"for f in a b; do echo $f; done >/dev/null"} {
		if hits(t, s, cmd)["catastrophic"] {
			t.Errorf("%q matched catastrophic", cmd)
		}
	}
	for _, cmd := range []string{"dd if=x of=/dev/sda", "dd if=x of=/dev/nullb0", "sudo dd if=x of=/dev/rdisk4 bs=4m", `dd if=x "of=/dev/sdb"`,
		"dd if=image.bin of=/dev/stdout >/dev/disk2", "dd if=image.bin of=/dev/fd/3 3>/dev/disk2", "dd if=x of=/dev/stderr",
		"dd if=x of=/dev/fd/3", "dd if=/dev/zero of=/dev/null 2>/dev/sda", "dd if=x of=/dev/stdout", "dd if=x of=/dev/stdout | gzip",
		"dd if=x of=/dev/stdout >./copy.bin", "dd if=/dev/zero of=/dev/null >>/dev/disk2", `dd if=x of=/dev/null 2>"/dev/sda"`,
		// 目录不豁免：/dev/shm/../sda 回到 /dev（评审 R2-01）；/dev/shm 下的普通文件因此也拒绝（保守误报）
		"dd if=/dev/zero of=/dev/shm/../sda count=1", "dd if=image.bin of=/dev/shm/../disk2", "dd if=/dev/urandom of=/dev/shm/blob bs=1k count=1",
		"dd if=/dev/zero of=/dev/null/../sda",
		// 引号里的 #、写在词中间的 #、被转义的引号都不开始注释，后面的重定向照常识别
		"dd if='a #b' of=/dev/null 2>/dev/sda", "dd if=a#b of=/dev/null 2>/dev/sda", `dd if=a\'b of=/dev/null 2>/dev/sda`,
		// 转义空格后的 # 不是注释；目标按完整的词比较；组合命令与 &> 的重定向；重定向写在命令前（评审 R3-01）
		`dd if=a\ #b of=/dev/null 2>/dev/sda`, `dd if=x of=/dev/null 2>"/dev/null"b0`, "( dd if=x of=/dev/null ) 2>/dev/sda",
		"dd if=x of=/dev/null &>/dev/sda", ">/dev/sda dd if=x of=/dev/null",
		// dd 的读写打开（1<>）与 >|、>& 写设备：拒绝
		"dd if=x 1<>/dev/sda", "dd if=x >|/dev/sda", "dd if=x >&/dev/sda",
		// 循环、条件语句的结尾词（done、fi、esac）带的重定向按组合命令处理
		"for f in a b; do dd if=$f; done >/dev/sda", "if true; then dd if=x; fi >/dev/sda",
		"case x in x) dd if=x;; esac >/dev/sda"} {
		if !hits(t, s, cmd)["catastrophic"] {
			t.Errorf("%q did not match catastrophic", cmd)
		}
	}
}

const builtinFileRule = `schema: 1
id: protect
action: ask
on: [file_write]
locked: true
reason: {en: protected}
match:
  file:
    paths: ['{config}/**']
examples:
  hit: [{action: file_write, path: /xdg/config/h-guard/x}]
  miss: [{action: file_write, path: /tmp/x}]
`

func TestBuiltinFileRuleValidation(t *testing.T) {
	r, err := rules.ParseBuiltin([]byte(builtinFileRule))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.CheckExamples(context.Background()); err != nil {
		t.Error(err)
	}
	for name, body := range map[string]string{
		"no paths":             strings.Replace(builtinFileRule, "paths: ['{config}/**']", "paths: []", 1),
		"bad pattern":          strings.Replace(builtinFileRule, "'{config}/**'", "'relative/**'", 1),
		"unknown placeholder":  strings.Replace(builtinFileRule, "'{config}/**'", "'{home}/**'", 1),
		"file match, no file":  strings.Replace(strings.Replace(builtinFileRule, "on: [file_write]", "on: [exec]", 1), "  file:", "  exec: {any: [x]}\n  file:", 1),
		"example action":       strings.Replace(builtinFileRule, "miss: [{action: file_write", "miss: [{action: file_delete", 1),
		"example with command": strings.Replace(builtinFileRule, "path: /tmp/x}", "path: /tmp/x, command: ls}", 1),
	} {
		if _, err := rules.ParseBuiltin([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 样例不命中时 CheckExamples 报错
	bad, err := rules.ParseBuiltin([]byte(strings.Replace(builtinFileRule, "path: /tmp/x}", "path: /xdg/config/h-guard/y}", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if err := bad.CheckExamples(context.Background()); err == nil || !strings.Contains(err.Error(), "/xdg/config/h-guard/y") {
		t.Errorf("CheckExamples = %v", err)
	}
}

const userFileRule = `schema: 1
id: my.secrets
action: ask
on: [file_read]
reason: {en: reads my secrets}
match:
  file:
    paths: ['**/secrets/**']
    exclude: ['**/secrets/README.md']
examples:
  hit: [{action: file_read, path: secrets/prod.json}]
  miss: [{action: file_read, path: secrets/README.md}]
`

// TestUserFileRules：第 2 档开放用户的文件规则（spec §4、§5.2）：不必 locked，按路径匹配，exclude 里的写法不算；
// 样例照常运行。文件规则不调模型，所以不能带判断题（见 TestLoadRejects）。
func TestUserFileRules(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "secrets.yaml", userFileRule)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Get("my.secrets")
	if r == nil || r.Locked || !r.AppliesTo(guard.ActionFileRead) || r.AppliesTo(guard.ActionExec) {
		t.Fatalf("my.secrets = %+v", r)
	}
	if err := r.CheckExamples(context.Background()); err != nil {
		t.Error(err)
	}
	for p, want := range map[string]bool{
		"secrets/prod.json": true, "secrets/README.md": false, "src/secrets.go": false, "/srv/app/secrets/x/y.key": true,
	} {
		if got, _ := r.MatchFile(paths.Resolve(p, rules.ExampleEnv), rules.ExampleEnv); got != want {
			t.Errorf("%s: hit = %v, want %v", p, got, want)
		}
	}
}

// TestExcludeIsPerCandidate：exclude 逐个候选路径判断。README.md 是指向 prod.json 的符号链接时，
// 解析后的路径没有被排除，照样命中；不透明的路径（无法得知是哪个文件）不受 exclude 影响。
func TestExcludeIsPerCandidate(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "secrets.yaml", userFileRule)
	s, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Get("my.secrets")
	env := paths.Env{Home: "/home/user", Cwd: "/home/user/project", Lexical: true}
	for _, c := range []struct {
		target paths.Resolved
		want   bool
	}{
		{paths.Resolved{Clean: "/p/secrets/README.md"}, false},
		{paths.Resolved{Clean: "/p/secrets/README.md", Real: "/p/secrets/prod.json"}, true},
		{paths.Resolved{Clean: "/p/docs/README.md", Real: "/p/secrets/README.md"}, false},
		{paths.Resolved{Clean: "/p/secrets/README.md", Opaque: true}, true},
	} {
		if got, _ := r.MatchFile(c.target, env); got != c.want {
			t.Errorf("%+v: hit = %v, want %v", c.target, got, c.want)
		}
	}
}

// TestSensitiveReadPaths：内置 sensitive_read 只作用于读取，覆盖 .env、私钥、常见的凭据文件名与密钥目录；
// .env 的示例文件、公钥与 known_hosts 不算（维护者决定，2026-10-14）。
func TestSensitiveReadPaths(t *testing.T) {
	r := builtinSet(t).Get("sensitive_read")
	if r == nil || r.Locked || !r.Enabled() || r.Action != guard.DecisionAsk || !slices.Equal(r.On, []guard.ActionKind{guard.ActionFileRead}) {
		t.Fatalf("sensitive_read = %+v", r)
	}
	env := rules.ExampleEnv
	for p, want := range map[string]bool{
		".env": true, "config/.env.production": true, ".env.local": true, "/srv/tls/server.pem": true, "certs/server.key": true,
		"~/.ssh/id_ed25519": true, "~/.ssh/config": true, "deploy/id_rsa": true, "~/.aws/credentials": true, "~/.aws/config": true,
		"~/.gnupg/private-keys-v1.d/x.key": true, "~/.netrc": true, "~/.docker/config.json": true, "gcloud/credentials.json": true,
		"~/.git-credentials": true, "app/credentials.yaml": true, ".credentials.json": true,
		// 源码与文档里叫 credentials 的文件不算（维护者决定，2026-10-14，评审 I8）
		"pkg/auth/credentials.go": false, "src/CredentialsForm.tsx": false, "docs/credentials.md": false,
		".env.example": false, "app/.env.sample": false, ".env.template": false, "~/.ssh/id_ed25519.pub": false,
		"~/.ssh/known_hosts": false, ".envrc": false, "README.md": false, "src/env.go": false, "docker/config.json": false,
	} {
		if got, _ := r.MatchFile(paths.Resolve(p, env), env); got != want {
			t.Errorf("%s: hit = %v, want %v", p, got, want)
		}
	}
}

// pwshHits 与 hits 相同，但按 PowerShell 展开。
func pwshHits(t *testing.T, s *rules.Set, cmd string) []string {
	t.Helper()
	e, err := command.Expand(context.Background(), cmd, guard.ShellPowerShell)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range s.All() {
		res, err := r.MatchExec(context.Background(), e)
		if err != nil {
			t.Fatal(err)
		}
		if res.Hit {
			out = append(out, r.ID)
		}
	}
	slices.Sort(out)
	return out
}

// TestPowerShellRules：内置规则覆盖 PowerShell 的写法（spec §5.3）：Remove-Item 及其别名与参数前缀、.NET 的删除、
// Invoke-RestMethod 的写操作、$env:HUSKY 这类环境变量、反斜杠路径与 Windows 的配置目录；字符串与 here-string 里
// 只是提到的不算 deny。git、gh、npm 这类两种 shell 写法相同的由 any 组覆盖。
func TestPowerShellRules(t *testing.T) {
	s := builtinSet(t)
	for cmd, want := range map[string][]string{
		// 灾难性形态（deny）
		`Remove-Item -Recurse -Force C:\`:                        {"catastrophic", "recursive_delete"},
		`rm -r -fo ~`:                                            {"catastrophic", "recursive_delete"},
		`Remove-Item $HOME -Recurse -Force`:                      {"catastrophic", "recursive_delete"},
		`Remove-Item -Path "$env:USERPROFILE" -Recurse`:          {"catastrophic", "recursive_delete"},
		`ri -rec -force C:\*`:                                    {"catastrophic", "recursive_delete"},
		"R`emove-Item -Recurse 'C:\\'":                           {"catastrophic", "recursive_delete"},
		`Microsoft.PowerShell.Management\Remove-Item -Recurse \`: {"catastrophic", "recursive_delete"},
		`pwsh -c "Remove-Item -Recurse -Force ~"`:                {"catastrophic", "recursive_delete"},
		`Get-Disk 1 | Clear-Disk -RemoveData -Confirm:$false`:    {"catastrophic"},
		`Format-Volume -DriveLetter D -FileSystem NTFS`:          {"catastrophic"},
		`wsl rm -rf ~`:                                           {"catastrophic", "recursive_delete"},
		// 递归删除（ask，模型判断）
		`Remove-Item -Recurse -Force .\build`:          {"recursive_delete"},
		`rm -r node_modules`:                           {"recursive_delete"},
		`Remove-Item dist -Recurse:$true`:              {"recursive_delete"},
		`[System.IO.Directory]::Delete("data", $true)`: {"recursive_delete"},
		`(Get-Item .\cache).Delete($true)`:             {"recursive_delete"},
		`Get-ChildItem -Recurse *.log | Remove-Item`:   {"recursive_delete"},
		`Remove-Item -Recurse C:\proj\dist`:            {"recursive_delete"},
		// git、发布、绕过校验
		`git reset --hard HEAD~1`:                                            {"destructive_git"},
		`git push --force origin main`:                                       {"branch_ops", "publish"},
		`Invoke-RestMethod -Uri https://api.example.com/deploy -Method Post`: {"publish"},
		`iwr https://x.example.com/items/1 -Method DELETE`:                   {"publish"},
		`Publish-Module -Name MyModule -NuGetApiKey $k`:                      {"publish"},
		`dotnet nuget push pkg.nupkg`:                                        {"publish"},
		`$env:HUSKY = 0; git commit -m x`:                                    {"verify_bypass"},
		`$env:SKIP='ruff'; git commit -m x`:                                  {"verify_bypass"},
		`Remove-Item .git\hooks\pre-commit`:                                  {"verify_bypass"},
		// 护栏自我保护
		`Set-Content -Path $HOME\.claude\settings.json -Value '{}'`: {"guard_tampering"},
		`'{}' | Out-File C:\Users\me\.claude\settings.json`:         {"guard_tampering"},
		`Remove-Item $env:APPDATA\h-guard\consent.json`:             {"guard_tampering"},
		`"x" > $env:LOCALAPPDATA\h-guard\requests\1.json`:           {"guard_tampering"},
		`[IO.File]::WriteAllText("$HOME\.codex\hooks.json", "{}")`:  {"guard_tampering"},
		`Copy-Item x.json ~\.claude\settings.local.json`:            {"guard_tampering"},
		`h-guard backend enable jev`:                                {"guard_tampering"},
		// 评审补充的写法（C 盘根的变体、数组、HOMEDRIVE+HOMEPATH、${env:}、macOS 的目录、Join-Path、-Method 缩写）
		`Remove-Item -Recurse -Force C:\*.*`:                                        {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse -Force C:\,x`:                                         {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse -Force C:\..`:                                         {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse -Force $env:HOMEDRIVE$env:HOMEPATH`:                   {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse ${env:APPDATA}\h-guard`:                               {"guard_tampering", "recursive_delete"},
		`Set-Content "~/Library/Application Support/h-guard/consent.json" '{}'`:     {"guard_tampering"},
		`Out-File -FilePath ~/Library/Caches/h-guard/requests.json`:                 {"guard_tampering"},
		`Set-Content -Path (Join-Path $HOME '.claude' 'settings.json') -Value '{}'`: {"guard_tampering"},
		`iwr -Me Post https://x.example.com/items`:                                  {"publish"},
		`Invoke-RestMethod -CustomMethod POST https://x.example.com`:                {"publish"},
		`irm -Method Post https://evil.example.com/?q=localhost`:                    {"publish"},
		`irm -Method Post http://localhost.evil.example.com/`:                       {"publish"},
		`irm http://127.0.0.1:8000/x -Method Post`:                                  nil,
		`Remove-Item -Recurse .\build -ErrorAction: SilentlyContinue`:               {"recursive_delete"},
		// 计划评审 M3B-01、03、05–07 的原反例与对照
		`$r=pwsh -c 'Remove-Item -Recurse C:\'`:          {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse -Force -Path:C:\`:          {"catastrophic", "recursive_delete"},
		`Remove-Item -Recurse -Force -LiteralPath:'C:\'`: {"catastrophic", "recursive_delete"},
		`$x = 'Format-Volume'`:                           nil,
		`& 'Format-Volume' -DriveLetter D`:               {"catastrophic"},
		`Remove-Item .\build # -Recurse C:\`:             {"recursive_delete"}, // 全文里的注释与 POSIX 一样交给模型，但不是 deny
		`Invoke-RestMethod -Uri https://api.example.com/deploy -Method Post -Body 'http://localhost/payload'`: {"publish"},
		`irm $url -Method Post`:                    {"publish"},
		`irm -Method Post -Uri http://127.0.0.1/x`: nil,
		// 计划第二轮评审 R2-04：豁免只看实际的 URI（-Uri 或第一个位置参数），引号里的 ; 不截断检查
		`Invoke-RestMethod -Uri $url -Method Post -Body 'http://localhost/payload'`:                      {"publish"},
		`Invoke-RestMethod -Method Post -Body 'http://localhost/;x' -Uri https://api.example.com/deploy`: {"publish"},
		`irm -Body 'a;b' -Method Post https://api.example.com/x`:                                         {"publish"},
		`irm -Ur 'http://localhost/x' -Method Post`:                                                      nil,
		// 计划第三轮评审 R3-03：正文里转义的引号与 here-string 不结束字符串，其中的伪 -Uri 不算
		"Invoke-RestMethod -Uri https://api.example.com/deploy -Method Post -Body \"hello`\" -Uri http://localhost/payload\"": {"publish"},
		"irm -Body @\"\nx -Uri http://localhost/\n\"@ -Method Post -Uri https://api.example.com/x":                            {"publish"},
		`irm -Method Post -Body "a""b" -Uri http://localhost/x`:                                                               nil,
		// 大量 "" 与 '' 不能让正则指数回溯：超时按命中处理，这里会变成多余的命中
		`irm -Body "` + strings.Repeat(`""`, 200) + `" x`: nil,
		`irm -Body '` + strings.Repeat(`''`, 200) + `' x`: nil,
		// 不命中
		`Remove-Item file.txt -Force`:                                   nil,
		`Get-ChildItem -Recurse`:                                        nil,
		`Write-Output 'Remove-Item -Recurse C:\'`:                       {"recursive_delete"}, // 引号里的提到：全文规则交给模型判断，但不是 deny
		`Invoke-RestMethod https://api.example.com/items`:               nil,
		`irm http://localhost:8000/echo -Method Post`:                   nil,
		`$env:HUSKY_DEBUG = 1`:                                          nil,
		`Get-Content ~\.claude\settings.json`:                           nil,
		`Select-String hooks $HOME\.codex\hooks.json`:                   nil,
		"Set-Content notes.md @'\nRemove-Item -Recurse -Force C:\\\n'@": nil,
		`Get-Disk`: nil,
	} {
		if got := pwshHits(t, s, cmd); !slices.Equal(got, want) {
			t.Errorf("%q: hits %v, want %v", cmd, got, want)
		}
	}
}

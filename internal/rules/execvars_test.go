package rules

import (
	"slices"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/dlclark/regexp2"
)

func mustMatch(t *testing.T, pattern string, env paths.Env, hit, miss []string) {
	t.Helper()
	re, err := compileTemplate(pattern, env)
	if err != nil {
		t.Fatalf("%q: %v", pattern, err)
	}
	for _, s := range hit {
		if ok, _ := re.MatchString(s); !ok {
			t.Errorf("%q (%v) does not match %q", pattern, env.Vars, s)
		}
	}
	for _, s := range miss {
		if ok, _ := re.MatchString(s); ok {
			t.Errorf("%q (%v) matches %q", pattern, env.Vars, s)
		}
	}
}

// TestExecPlaceholderExpansion：占位符展开为转义后的字面量，\ 与 / 都算分隔符，主目录之下另认 ~、$HOME 等写法。
func TestExecPlaceholderExpansion(t *testing.T) {
	env := paths.Env{Home: "/home/u", Vars: map[string]string{
		VarPiAgentDir: "/opt/p.i+(x)/agent/", VarDSHHome: "/home/u/my dsh", VarCodexHome: `C:\Users\Me\codex`,
	}}
	mustMatch(t, `^rm {pi_agent_dir}[/\\]+settings\.json$`, env,
		[]string{"rm /opt/p.i+(x)/agent/settings.json", `rm \opt\p.i+(x)\agent\settings.json`, "rm /OPT/p.i+(x)//agent/settings.json"},
		// 元字符按字面匹配：. 不匹配任意字符，+ 不是量词
		[]string{"rm /opt/pXi+(x)/agent/settings.json", "rm /opt/p.ii(x)/agent/settings.json", "rm /opt/p.i+(x)/agentX/settings.json"})
	mustMatch(t, `^rm {dsh_home}[/\\]+cordis\.patch\.yml$`, env,
		[]string{"rm /home/u/my dsh/cordis.patch.yml", `rm ~/my\ dsh/cordis.patch.yml`, "rm $HOME/my dsh/cordis.patch.yml",
			"rm ${HOME}/my dsh/cordis.patch.yml", `rm $env:USERPROFILE\my dsh\cordis.patch.yml`, `rm %USERPROFILE%\my dsh\cordis.patch.yml`},
		[]string{"rm /home/u/mydsh/cordis.patch.yml", "rm ~/other/cordis.patch.yml", "rm $HOMEDIR/my dsh/cordis.patch.yml"})
	mustMatch(t, `^rm {codex_home}[/\\]+hooks\.json$`, env,
		[]string{`rm C:\Users\Me\codex\hooks.json`, "rm c:/users/me/codex/hooks.json"},
		[]string{`rm D:\Users\Me\codex\hooks.json`})
	// 值就是主目录
	home := paths.Env{Home: "/home/u", Vars: map[string]string{VarDSHHome: "/home/u/"}}
	mustMatch(t, `^rm {dsh_home}[/\\]+x$`, home, []string{"rm ~/x", "rm /home/u/x"}, []string{"rm /home/x"})
	// 主目录之外的值不认 ~
	mustMatch(t, `^rm {pi_agent_dir}[/\\]+x$`, env, nil, []string{"rm ~/agent/x"})
}

// TestExecPlaceholderUnset：没有值的占位符换成永不匹配的 (?!)：那一处不匹配，同一条模式里有值的其他分支照常匹配。
func TestExecPlaceholderUnset(t *testing.T) {
	env := paths.Env{Home: "/home/u", Vars: map[string]string{VarDSHHome: "/srv/dsh"}}
	if got := expandExec(`{pi_agent_dir}/x`, env); got != neverMatch+"/x" {
		t.Errorf("unset placeholder expands to %q", got)
	}
	mustMatch(t, `{pi_agent_dir}`, env, nil, []string{"", "rm x", "/home/u"})
	mustMatch(t, `rm (?:{pi_agent_dir}|{dsh_home})[/\\]+x`, env, []string{"rm /srv/dsh/x"}, []string{"rm /x", "rm x"})
	mustMatch(t, `rm {pi_agent_dir}[/\\]+x`, paths.Env{}, nil, []string{"rm /x", "rm //x"})
}

// TestExecPlaceholderSyntax：转义的花括号、不认识的名字原样保留；规则加载时试编译含占位符的模式。
func TestExecPlaceholderSyntax(t *testing.T) {
	env := paths.Env{Vars: map[string]string{VarConfig: "/c"}}
	for p, want := range map[string]string{
		`\{config}`:       `\{config}`,
		`\\{config}`:      `\\(?i:[/\\]+c)`,
		`{nope}`:          `{nope}`,
		`a{2}{config}`:    `a{2}(?i:[/\\]+c)`,
		`{config}{cache}`: `(?i:[/\\]+c)` + neverMatch,
	} {
		if got := expandExec(p, env); got != want {
			t.Errorf("expandExec(%q) = %q, want %q", p, got, want)
		}
	}
	if got := execVars(`{config}/a|{cache}|\{dsh_home}|{config}`); !slices.Equal(got, []string{VarConfig, VarCache}) {
		t.Errorf("execVars = %v", got)
	}
	if _, err := compileExec(&ExecMatch{Any: []string{`rm {config}(`}}); err == nil {
		t.Error("a broken pattern with a placeholder was accepted")
	}
	// QuoteMeta 的转义 regexp2 都接受：任意值展开后都能编译
	for _, v := range []string{`/a.b*c?d+e(f)g[h]i{j}k|l^m$n\o`, "/", "rel/dir", `\\server\share`} {
		re := execLiteral(v, "/")
		if _, err := regexp2.Compile(re, regexp2.IgnoreCase); err != nil {
			t.Errorf("execLiteral(%q) = %q: %v", v, re, err)
		}
	}
}

// TestExecPlaceholderCache：同一环境只编译一次；环境变了重新展开。
func TestExecPlaceholderCache(t *testing.T) {
	c, err := compileExec(&ExecMatch{Any: []string{`^rm {pi_agent_dir}$`, `^static$`}})
	if err != nil {
		t.Fatal(err)
	}
	a := paths.Env{Vars: map[string]string{VarPiAgentDir: "/a"}}
	r1, r2 := c.resolve(a), c.resolve(a)
	if r1 != r2 || len(r1.any) != 2 {
		t.Fatalf("resolve = %p %p (%d patterns)", r1, r2, len(r1.any))
	}
	b := paths.Env{Vars: map[string]string{VarPiAgentDir: "/b"}}
	r3 := c.resolve(b)
	if r3 == r1 {
		t.Fatal("a changed environment reused the old patterns")
	}
	if ok, _ := r3.any[1].MatchString("rm /b"); !ok {
		t.Error("the re-expanded pattern does not match the new value")
	}
	static, err := compileExec(&ExecMatch{Any: []string{`^static$`}})
	if err != nil {
		t.Fatal(err)
	}
	if static.resolve(a) != &static.base {
		t.Error("patterns without placeholders are not the precompiled ones")
	}
}

// TestExecPlaceholderList：有多个值的占位符（paths.Env.Lists）匹配其中任一个值；没有值时那一处不匹配；值变了缓存跟着换。
func TestExecPlaceholderList(t *testing.T) {
	env := paths.Env{Home: "/home/u", Lists: map[string][]string{VarOpenClawIncludes: {"/etc/openclaw/plugins.json", "/home/u/.openclaw/a b.json5", ""}}}
	mustMatch(t, `^sed -i x {openclaw_includes}$`, env,
		[]string{"sed -i x /etc/openclaw/plugins.json", `sed -i x \etc\openclaw\plugins.json`, `sed -i x ~/.openclaw/a\ b.json5`},
		[]string{"sed -i x /etc/openclaw/plugins.jsonX", "sed -i x /etc/openclaw/other.json", "sed -i x "})
	mustMatch(t, `^rm {openclaw_includes}$`, paths.Env{Lists: map[string][]string{VarOpenClawIncludes: nil}}, nil, []string{"rm /etc/openclaw/plugins.json", "rm "})
	other := paths.Env{Home: "/home/u", Lists: map[string][]string{VarOpenClawIncludes: {"/srv/x.json"}}}
	if templateKey(env, []string{VarOpenClawIncludes}) == templateKey(other, []string{VarOpenClawIncludes}) {
		t.Errorf("the cache key ignores the list's values")
	}
}

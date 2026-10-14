package command_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// MARK 是无害的标记命令：测试只看它是否作为内层命令被提取出来。
const MARK = "touch /tmp/hg-mark"

func expand(t *testing.T, cmd string) command.Expansion {
	t.Helper()
	e, err := command.Expand(context.Background(), cmd, guard.ShellPOSIX)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// inner 返回深度大于 0 的单元文本。
func inner(e command.Expansion) []string {
	var out []string
	for _, u := range e.Units[1:] {
		out = append(out, strings.TrimSpace(u.Text))
	}
	return out
}

func TestHeredocData(t *testing.T) {
	tests := []struct {
		name, cmd string
		bodyKept  bool     // 正文是否留在原命令单元里
		inner     []string // 提取出的内层命令
	}{
		{"quoted data heredoc is literal", "cat > f <<'EOF'\n$(" + MARK + ")\nEOF", false, nil},
		{"double-quoted delimiter", "cat > f <<\"EOF\"\n`" + MARK + "`\nEOF", false, nil},
		{"backslash delimiter", "cat > f <<\\EOF\n$(" + MARK + ")\nEOF", false, nil},
		{"unquoted data heredoc expands", "cat > f <<EOF\nnote: $(" + MARK + ")\nEOF", false, []string{MARK}},
		{"quotes are literal in heredoc bodies", "cat > f <<EOF\nit's `" + MARK + "`\nEOF", false, []string{MARK}},
		{"dash delimiter", "cat > f <<-EOF\n\t" + MARK + "\n\tEOF", false, nil},
		// 交给解释器的正文：全文留在原命令单元里，另作为内层命令按段检查
		{"bash with quoted delimiter runs the body", "bash <<'EOF'\n" + MARK + "\nEOF", true, []string{MARK}},
		{"bash with unquoted delimiter runs the body", "bash <<EOF\n" + MARK + "\nEOF", true, []string{MARK}},
		{"piped into a shell runs the body", "cat <<'EOF' | bash\n" + MARK + "\nEOF", true, []string{MARK}},
		{"absolute interpreter path", "/bin/sh <<'EOF'\n" + MARK + "\nEOF", true, []string{MARK}},
		{"python heredoc runs the body", "python3 <<'PY'\nimport os\nPY", true, []string{"import os"}},
		{"mixed quoting in the delimiter is quoted", "cat > f <<E'OF'\n$(" + MARK + ")\nEOF", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := expand(t, tt.cmd)
			kept := strings.Contains(e.Units[0].Text, MARK) || strings.Contains(e.Units[0].Text, "import os")
			if kept != tt.bodyKept {
				t.Errorf("body kept = %v, want %v; unit = %q", kept, tt.bodyKept, e.Units[0].Text)
			}
			if got := inner(e); !slices.Equal(got, tt.inner) {
				t.Errorf("inner = %q, want %q", got, tt.inner)
			}
		})
	}
}

func TestHeredocKeepsSurroundingCommands(t *testing.T) {
	e := expand(t, "cat > a <<'A'\nfirst\nA\n"+MARK+"\ncat > b <<'B'\nsecond\nB")
	text := e.Units[0].Text
	if strings.Contains(text, "first") || strings.Contains(text, "second") || !strings.Contains(text, MARK) {
		t.Errorf("unit = %q", text)
	}
}

// TestHeredocRecognitionFollowsQuoting：引号或注释里的 <<、混合引号的定界符都不能让后面真正执行的命令
// 被当成 heredoc 数据丢掉（评审 M1-01）。
func TestHeredocRecognitionFollowsQuoting(t *testing.T) {
	for _, cmd := range []string{
		"printf '%s\\n' '<<EOF'\n" + MARK,
		"echo \"<<EOF\"\n" + MARK,
		"echo hi # see <<EOF\n" + MARK,
		"echo x <<E'OF'\nsafe\nEOF\n" + MARK,
		"cat <<A <<'B'\nfirst\nA\nsecond\nB\n" + MARK,
		"bash <<'EOF'\necho it's\nEOF\n" + MARK,
	} {
		e := expand(t, cmd)
		if got := e.Units[0].Positions(); !slices.Contains(got, MARK) {
			t.Errorf("%q: positions = %q, want %q among them", cmd, got, MARK)
		}
	}
	// 两个 heredoc 写在同一行：两段正文都是数据
	text := expand(t, "cat <<A <<'B'\nfirst\nA\nsecond\nB\n"+MARK).Units[0].Text
	if strings.Contains(text, "first") || strings.Contains(text, "second") {
		t.Errorf("both bodies must be stripped: %q", text)
	}
}

// TestHeredocClosingLineIsExact：普通 << 的结束行与定界符精确比较，<<- 只去前导制表符（评审 N01）。
func TestHeredocClosingLineIsExact(t *testing.T) {
	tests := []struct {
		name, cmd string
		markRuns  bool // MARK 在原命令单元中处于命令位置
	}{
		{"delimiter with a space", "cat <<' EOF'\nsafe\n EOF\n" + MARK, true},
		{"indented line is data", "cat <<'EOF'\n EOF\n" + MARK + "\nEOF", false},
		{"trailing space is data", "cat <<'EOF'\nEOF \n" + MARK + "\nEOF", false},
		{"dash strips tabs", "cat <<-'EOF'\n\tsafe\n\tEOF\n" + MARK, true},
		{"dash keeps spaces", "cat <<-'EOF'\n  EOF\n" + MARK + "\nEOF", false},
	}
	for _, tt := range tests {
		got := slices.Contains(expand(t, tt.cmd).Units[0].Positions(), MARK)
		if got != tt.markRuns {
			t.Errorf("%s: MARK in command position = %v, want %v", tt.name, got, tt.markRuns)
		}
	}
}

// TestLineContinuationFollowsContext：反斜杠换行在引号外、双引号内、不带引号的 heredoc 正文里是续行；
// 在单引号内、带引号定界符的 heredoc 正文与注释里不是（评审 N01）。
func TestLineContinuationFollowsContext(t *testing.T) {
	tests := []struct {
		name, cmd string
		markRuns  bool
	}{
		{"split prefix word", "su\\\ndo " + MARK, true},
		{"split command word", "tou\\\nch /tmp/hg-mark", true},
		{"split delimiter", "cat <<E\\\nOF\nsafe\nEOF\n" + MARK, true},
		{"quoted heredoc keeps the backslash", "cat <<'EOF'\nx\\\nEOF\n" + MARK, true},
		{"unquoted heredoc joins lines", "cat <<EOF\nx\\\nEOF\n" + MARK + "\nEOF", false},
		{"single quotes keep it", "echo 'su\\\ndo " + MARK + "'", false},
		{"comment does not continue", "echo hi # note \\\n" + MARK, true},
		// 续行先于词法单元的识别（评审 R3-02）
		{"split substitution in double quotes", "echo \"$\\\n(" + MARK + ")\"", true},
		{"split substitution in expandable heredoc", "cat <<EOF\n$\\\n(" + MARK + ")\nEOF", true},
		{"split assignment prefix", "F\\\nOO=1 " + MARK, true},
		{"split heredoc operator", "cat <\\\n<EOF\n" + MARK + "\nEOF", false},
		{"split heredoc operator, expandable body", "cat <\\\n<EOF\n$(" + MARK + ")\nEOF", true},
		{"split heredoc operator, interpreter body", "bash <\\\n<'EOF'\n" + MARK + "\nEOF", true},
		{"split interpreter name", "bas\\\nh <<'EOF'\n" + MARK + "\nEOF", true},
		{"split process substitution", "cat <\\\n(" + MARK + ")", true},
	}
	for _, tt := range tests {
		e := expand(t, tt.cmd)
		got := false
		for _, u := range e.Units {
			got = got || slices.Contains(u.Positions(), MARK)
		}
		if got != tt.markRuns {
			t.Errorf("%s: MARK in command position = %v, want %v (units %+v)", tt.name, got, tt.markRuns, e.Units)
		}
	}
	// 全文匹配另有去掉续行的版本
	if texts := expand(t, "tou\\\nch /tmp/hg-mark").Units[0].FullTexts(); len(texts) != 2 || texts[1] != MARK {
		t.Errorf("FullTexts = %q", texts)
	}
}

// TestFullTextsJoinOnlyRealContinuations：去掉续行的全文由词法分析生成，嵌套上下文里的字面反斜杠换行
// （命令替换里的单引号、注释、带引号定界符的 heredoc 正文）不会被拼起来（评审 R3-03）；真正的续行照常拼接。
func TestFullTextsJoinOnlyRealContinuations(t *testing.T) {
	split := "tou\\\nch /tmp/hg-mark"
	tests := []struct {
		name, cmd string
		joined    bool // 某个单元的全文含 MARK
	}{
		{"single quotes inside substitution", "echo \"$(printf '%s' '" + split + "')\"", false},
		{"comment inside substitution", "echo \"$(echo x # " + split + "\n)\"", false},
		{"quoted heredoc inside substitution", "echo \"$(cat <<'EOF'\n" + split + "\nEOF\n)\"", false},
		{"dollar-single quotes", "echo $'" + split + "'", false},
		{"comment", "echo hi # " + split, false},
		{"plain", split, true},
		{"inside double quotes", "echo \"" + split + "\"", true},
		{"inside substitution", "echo \"$(" + split + ")\"", true},
		{"inside backticks, even within quotes", "echo `printf '%s' '" + split + "'`", true},
		{"unquoted heredoc body", "cat <<EOF\n$(" + split + ")\nEOF", true},
		// 参数展开里的命令替换按同一套词法读取（评审 R4-02）
		{"nested quotes inside parameter expansion", "echo ${x:-\"$(printf '%s' '" + split + "')\"}", false},
		{"substitution inside parameter expansion", "echo ${x:-$(" + split + ")}", true},
	}
	// 参数展开里的 $'…' 按 ANSI-C 引号读取：\' 不结束引号，后面的 $(…) 是字面内容
	for _, u := range expand(t, "echo ${x:-$'a\\'$("+MARK+")'}").Units[1:] {
		t.Errorf("literal text inside $'…' was extracted as a command: %q", u.Text)
	}
	for _, tt := range tests {
		got := false
		for _, u := range expand(t, tt.cmd).Units {
			for _, text := range u.FullTexts() {
				got = got || strings.Contains(text, MARK)
			}
		}
		if got != tt.joined {
			t.Errorf("%s: MARK in a full text = %v, want %v", tt.name, got, tt.joined)
		}
	}
	// 运算符字符本身不是续行：<<< 不产生去掉续行的视图；运算符中间真有续行时才拼接
	if texts := expand(t, "cat <<<safe").Units[0].FullTexts(); len(texts) != 1 {
		t.Errorf("here-string: FullTexts = %q", texts)
	}
	if texts := expand(t, "cat <<\\\n<safe").Units[0].FullTexts(); len(texts) != 2 || texts[1] != "cat <<<safe" {
		t.Errorf("split here-string: FullTexts = %q", texts)
	}
}

// TestExpansionContextMatrix：所处位置 × 展开写法 × 是否被续行拆开，逐一核对哪些内容会被提取为内层命令
// （评审 R5-01 建议的成对用例）。预期取自 bash 实测（printf 标记，不执行危险命令）：命令替换在单引号与
// 带引号定界符的 heredoc 正文之外都会执行；进程替换只在引号之外执行（双引号、heredoc 正文里是字面内容）；
// 被续行拆开的写法与不拆开的相同。
func TestExpansionContextMatrix(t *testing.T) {
	contexts := []struct {
		name, tmpl  string // tmpl 中的 %s 换成展开写法
		subst, proc bool   // 命令替换、进程替换是否执行
	}{
		{"word", "echo %s", true, true},
		{"parameter default", "echo ${x:-%s}", true, true},
		{"parameter default, mid-word", "echo ${x:-a%s}", true, true},
		{"double quotes", `echo "%s"`, true, false},
		{"single quotes", "echo '%s'", false, false},
		{"parameter in double quotes", `echo "${x:-%s}"`, true, false},
		{"single quotes in parameter", "echo ${x:-'%s'}", false, false},
		{"double quotes in parameter", `echo ${x:-"%s"}`, true, false},
		{"command substitution", "echo $(echo %s)", true, true},
		{"unquoted heredoc", "cat <<EOF\n%s\nEOF", true, false},
		{"quoted heredoc", "cat <<'EOF'\n%s\nEOF", false, false},
	}
	expansions := []struct {
		name, text string // text 中的 X 换成 MARK
		proc       bool
	}{
		{"$()", "$(X)", false}, {"split $()", "$\\\n(X)", false}, {"backticks", "`X`", false},
		{"<()", "<(X)", true}, {"split <()", "<\\\n(X)", true},
		{">()", ">(X)", true}, {"split >()", ">\\\n(X)", true},
	}
	for _, c := range contexts {
		for _, x := range expansions {
			cmd := strings.ReplaceAll(c.tmpl, "%s", strings.ReplaceAll(x.text, "X", MARK))
			want := c.subst
			if x.proc {
				want = c.proc
			}
			got := false
			for _, u := range expand(t, cmd).Units[1:] {
				got = got || slices.Contains(u.Positions(), MARK)
			}
			if got != want {
				t.Errorf("%s / %s: extracted = %v, want %v (command %q)", c.name, x.name, got, want, cmd)
			}
		}
	}
}

// TestSubstitutionEndFollowsLexing：$(…) 的右括号按同一套词法规则找，heredoc 正文与注释里的 ) 不算（评审 N01）。
func TestSubstitutionEndFollowsLexing(t *testing.T) {
	for _, cmd := range []string{
		"echo \"$(cat <<'EOF'\n)\nEOF\n" + MARK + "\n)\"",
		"echo \"$(echo x # )\n" + MARK + "\n)\"",
		"echo \"$(echo \"$(printf ')')\"; " + MARK + ")\"",
		"echo $( (echo a) ; " + MARK + ")",
	} {
		e := expand(t, cmd)
		found := false
		for _, u := range e.Units[1:] {
			found = found || slices.Contains(u.Positions(), MARK)
		}
		if !found {
			t.Errorf("%q: MARK not found as an inner command: %+v", cmd, e.Units)
		}
	}
}

func TestUnterminatedHeredocStripsToEnd(t *testing.T) {
	if text := expand(t, "cat > f <<'EOF'\n"+MARK).Units[0].Text; strings.Contains(text, MARK) {
		t.Errorf("unit = %q", text)
	}
}

func TestCommandsWithoutHeredocAreUntouched(t *testing.T) {
	for _, cmd := range []string{"git status", "echo 'a << b'", "grep '<<' file.txt", "cat <<< 'here string'", "ls -la"} {
		if got := expand(t, cmd).Units[0].Text; got != cmd {
			t.Errorf("%q became %q", cmd, got)
		}
	}
}

func TestSubstitutions(t *testing.T) {
	tests := []struct {
		cmd   string
		inner []string
	}{
		{`echo "$(` + MARK + `)"`, []string{MARK}},
		{"echo \"`" + MARK + "`\"", []string{MARK}},
		{`echo $(` + MARK + `)`, []string{MARK}},
		{`echo '$(` + MARK + `)'`, nil},
		{`echo "$(echo "(" ; ` + MARK + `)"`, []string{`echo "(" ; ` + MARK}},
		{`echo \$(` + MARK + `)`, nil},
		{`echo "$(` + MARK, []string{MARK}}, // 未闭合时取到末尾
		{`diff <(` + MARK + `) x`, []string{MARK}},
		{`echo ${X:-$(` + MARK + `)}`, []string{MARK}},
	}
	for _, tt := range tests {
		if got := inner(expand(t, tt.cmd)); !slices.Equal(got, tt.inner) {
			t.Errorf("%q: inner = %q, want %q", tt.cmd, got, tt.inner)
		}
	}
}

func TestNestedShells(t *testing.T) {
	tests := []struct {
		cmd   string
		inner []string
	}{
		{`bash -c "` + MARK + `"`, []string{MARK}},
		{`sh -c '` + MARK + `'`, []string{MARK}},
		{`/usr/bin/bash -lc '` + MARK + `'`, []string{MARK}},
		{`sudo -u root bash -o pipefail -c '` + MARK + `'`, []string{MARK}},
		{`cd /x && zsh -c "` + MARK + `"`, []string{MARK}},
		{`bash script.sh`, nil},
		{`python3 -c "` + MARK + `"`, nil},
		{`echo "bash -c ` + MARK + `"`, nil},
	}
	for _, tt := range tests {
		if got := inner(expand(t, tt.cmd)); !slices.Equal(got, tt.inner) {
			t.Errorf("%q: inner = %q, want %q", tt.cmd, got, tt.inner)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	// 4 层嵌套：第 4 层不再展开，按原文作为一个单元
	cmd := `bash -c 'sh -c "echo \$(echo \$(` + MARK + `))"'`
	e := expand(t, cmd)
	maxDepth := 0
	for _, u := range e.Units {
		maxDepth = max(maxDepth, u.Depth)
	}
	if maxDepth > command.MaxDepth+1 {
		t.Errorf("max depth = %d", maxDepth)
	}
	found := false
	for _, u := range e.Units {
		found = found || strings.Contains(u.Text, MARK)
	}
	if !found {
		t.Error("the innermost command must still be matched as text")
	}
	deep := strings.Repeat("$(", 6) + MARK + strings.Repeat(")", 6)
	if e := expand(t, "echo "+deep); !e.Limited {
		t.Error("expansion beyond MaxDepth must set Limited")
	}
}

// TestNormalizedPositions：给 deny 级规则的规范化命令位置——词去掉引号与转义，命令词取路径最后一段，
// ${HOME} 写作 $HOME，词末的 / 去掉（单独的 / 保留），重定向的目标不算；前缀词照常剥离（评审 M1 终审）。
func TestNormalizedPositions(t *testing.T) {
	for cmd, want := range map[string][]string{
		`rm -rf "$HOME"`:              {"rm -rf $HOME"},
		`/bin/rm -rf '/'`:             {"rm -rf /"},
		`\rm -rf ${HOME}/`:            {"rm -rf $HOME"},
		`sudo timeout 5 rm -rf ~/`:    {"rm -rf ~"},
		`echo "rm -rf /"`:             {`echo "rm -rf /"`},
		`rm -rf / >/dev/null; ls "a"`: {"rm -rf /", "ls a"},
		`rm -rf "my dir"`:             {`rm -rf "my dir"`},
	} {
		if got := command.NormalizedPositions(cmd); !slices.Equal(got, want) {
			t.Errorf("NormalizedPositions(%q) = %q, want %q", cmd, got, want)
		}
	}
	// timeout 的时长参数与选项一起跳过，原文的命令位置同样受益
	for cmd, want := range map[string]string{"timeout 5 rm -rf build": "rm -rf build", "timeout -s KILL 5 git push": "git push"} {
		if got := command.CommandPositions(cmd); !slices.Equal(got, []string{want}) {
			t.Errorf("CommandPositions(%q) = %q, want %q", cmd, got, want)
		}
	}
}

// TestManySubstitutionsAreAllExpanded：单元数不设上限，很多个命令替换之后（含嵌套在里面的）的内容照常提取，
// 不会因数量多而被丢掉（评审 M1 终审）。耗时由截止时间约束。
func TestManySubstitutionsAreAllExpanded(t *testing.T) {
	cmd := strings.Repeat("echo $(true) ; ", 80) + "echo $(echo $(" + MARK + "))"
	e := expand(t, cmd)
	found := false
	for _, u := range e.Units {
		found = found || slices.Contains(u.Positions(), MARK)
	}
	if !found || e.Limited {
		t.Errorf("units = %d, limited = %v, MARK extracted = %v", len(e.Units), e.Limited, found)
	}
}

func TestCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := command.Expand(ctx, "ls", guard.ShellPOSIX); err == nil {
		t.Error("Expand ignored a canceled context")
	}
}

func TestSegments(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a && b; c | d", []string{"a", "b", "c", "d"}},
		{`git commit -m "a && b"`, []string{`git commit -m "a && b"`}},
		{"one\ntwo", []string{"one", "two"}},
		{`echo \" && ls`, []string{`echo \"`, "ls"}},
		{`echo '\'; ls`, []string{`echo '\'`, "ls"}}, // 单引号内的反斜杠是字面量
		{"(cd x && ls)", []string{"cd x", "ls"}},
		{"echo hi # a; b\nls", []string{"echo hi # a; b", "ls"}},
	}
	for _, tt := range tests {
		if got := command.Segments(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("Segments(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCommandPositions(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"sudo rm -rf x", []string{"rm -rf x"}},
		{"env FOO=1 BAR=2 rm x", []string{"rm x"}},
		{"nohup nice -n 5 rm x", []string{"rm x"}},
		{"sudo -u root rm x", []string{"rm x"}},
		{"/usr/bin/sudo -- rm x", []string{"rm x"}},
		{`echo "rm -rf x"`, []string{`echo "rm -rf x"`}},
		{"cd /tmp && rm x; ls", []string{"cd /tmp", "rm x", "ls"}},
		{"sudo\trm x", []string{"rm x"}},
		{"'sudo' rm x", []string{"rm x"}},
		{"if rm x; then ls; fi", []string{"rm x", "ls", "fi"}},
		{"{ rm x; }", []string{"rm x"}},
		{"! rm x", []string{"rm x"}},
	}
	for _, tt := range tests {
		if got := command.CommandPositions(tt.in); !slices.Equal(got, tt.want) {
			t.Errorf("CommandPositions(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestStripQuoted(t *testing.T) {
	tests := map[string]string{
		`echo ':(){ :|:& };:' >> f`: "echo  >> f",
		`a "b \" c" d`:              "a  d",
		`a \" b`:                    `a \" b`,
		`echo '\'; :(){ :|:& };:`:   "echo ; :(){ :|:& };:",
	}
	for in, want := range tests {
		if got := command.StripQuoted(in); got != want {
			t.Errorf("StripQuoted(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWords(t *testing.T) {
	got := command.Words(`a 'b c' "d \"e\" \n" f\ g '' E'OF'`)
	want := []string{"a", "b c", `d "e" \n`, "f g", "", "EOF"}
	if !slices.Equal(got, want) {
		t.Errorf("Words = %q, want %q", got, want)
	}
}

func FuzzExpand(f *testing.F) {
	for _, s := range []string{
		"cat > f <<'EOF'\nx\nEOF", "bash -c 'echo $(ls)'", "echo \"`a`\" $(b", "<<", "<<-'", "a;b&&c|d",
		"printf '%s\\n' '<<EOF'\nx", "echo x <<E'OF'\nsafe\nEOF\nx", "echo '\\'; x", "sudo\tx", "a <<A <<B\n1\nA\n2\nB",
		"echo \"$(cat <<'E'\n)\nE\nx\n)\"", "su\\\ndo x", "cat <<E\\\nOF\ns\nEOF\nx", "cat <<EOF\nx\\\nEOF\ny\nEOF",
		"echo \"$\\\n(x)\"", "a &\\\n& b", "cat <\\\n<E\nx\nE", "${x:-$\\\n(y)}", "`a\\\n'b`", "$\\\n",
		"cat <\\\n<E\n$(x)\nE", "${x:-\"$(a 'b\\\nc')\"}", "cat <<<x", "${x:-`a`", "${x:-$(a",
		"${x:-<(a)}", "${x:-a>(b", "${x:-<\\\n(c)}", "${x:-'<(d)'}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := command.Expand(context.Background(), s, guard.ShellPOSIX)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Units) == 0 {
			t.Fatalf("no units")
		}
		for _, u := range e.Units {
			_ = u.Positions()
			_ = u.NormalizedPositions()
			_ = u.Unquoted()
		}
	})
}

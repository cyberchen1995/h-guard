package command_test

import (
	"context"
	"reflect"
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
// 被当成 heredoc 数据丢掉。
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

// TestHeredocClosingLineIsExact：普通 << 的结束行与定界符精确比较，<<- 只去前导制表符。
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
// 在单引号内、带引号定界符的 heredoc 正文与注释里不是。
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
		// 续行先于词法单元的识别
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
// （命令替换里的单引号、注释、带引号定界符的 heredoc 正文）不会被拼起来；真正的续行照常拼接。
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
		// 参数展开里的命令替换按同一套词法读取
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
// （成对的用例）。预期取自 bash 实测（printf 标记，不执行危险命令）：命令替换在单引号与
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

// TestSubstitutionEndFollowsLexing：$(…) 的右括号按同一套词法规则找，heredoc 正文与注释里的 ) 不算。
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
// ${HOME} 写作 $HOME，词末的 / 去掉（单独的 / 保留），重定向的目标不算；前缀词照常剥离。
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
// 不会因数量多而被丢掉。耗时由截止时间约束。
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

// TestPipelines：管道按 | 相连的各段给出，; && 换行另起一条；词是取值（去引号），前缀词与重定向不算。
func TestPipelines(t *testing.T) {
	got := command.Pipelines(`echo 'a b' | sudo base64 -d 2>/dev/null | sh; ls -la && FOO=1 env bash -s`)
	want := [][][]string{{{"echo", "a b"}, {"base64", "-d"}, {"sh"}}, {{"ls", "-la"}}, {{"bash", "-s"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q", got)
	}
}

// TestReadsFiles：命令里有一段读文件内容的命令（cat、head、grep、jq、git show、Get-Content……）时，工具输出是
// 文件内容（outbound 第 2 档扫描它，维护者决定 2026-10-15）；跨 shell 的嵌套照样认。
func TestReadsFiles(t *testing.T) {
	for _, c := range []struct {
		cmd   string
		shell guard.Shell
	}{
		{"xargs -a .env echo", guard.ShellPOSIX},
		{"cat .env", guard.ShellPOSIX},
		{"head -n 20 config/prod.yaml", guard.ShellPOSIX},
		{"sudo tail -f /var/log/app.log", guard.ShellPOSIX},
		{"cd app && sed -n '1,40p' settings.py", guard.ShellPOSIX},
		{"rg -n API_KEY src", guard.ShellPOSIX},
		{"jq .token ~/.config/gh/hosts.json", guard.ShellPOSIX},
		{"git show HEAD:secrets.yaml", guard.ShellPOSIX},
		{"/bin/cat notes.txt | wc -l", guard.ShellPOSIX},
		{`bash -c "less README.md"`, guard.ShellPOSIX},
		{"Get-Content .env", guard.ShellPowerShell},
		{"gc C:\\app\\appsettings.json | Select-Object -First 5", guard.ShellPowerShell},
		{"Select-String -Path *.cs -Pattern password", guard.ShellPowerShell},
		{"type secrets.txt", guard.ShellPowerShell},
		// 经 xargs、find -exec 调用的读文件命令
		{"ls *.env | xargs cat", guard.ShellPOSIX},
		{"find . -name '*.pem' -exec cat {} \\;", guard.ShellPOSIX},
		// 带参数的选项与 --
		{"ls | xargs -I {} cat {}", guard.ShellPOSIX},
		{"ls | xargs -n 1 -P 4 cat", guard.ShellPOSIX},
		{"ls | xargs -I{} -- cat {}", guard.ShellPOSIX},
		{"ls | xargs --max-args 2 --delimiter=, cat", guard.ShellPOSIX},
		{"git -C /repo show HEAD:secrets.txt", guard.ShellPOSIX},
		{"git -c core.pager=cat --git-dir /r/.git --no-pager show HEAD:a", guard.ShellPOSIX},
		{"git --git-dir=/r/.git --work-tree /r cat-file -p HEAD:a", guard.ShellPOSIX},
		// 容器、远程主机里的读文件命令，压缩文件，git log -p
		{"docker exec web cat /app/.env", guard.ShellPOSIX},
		{"docker exec -it -u root -e A=1 web sh -c 'cat /app/.env'", guard.ShellPOSIX},
		{"podman exec db head -5 /etc/pgpass", guard.ShellPOSIX},
		{"docker compose exec api cat config/prod.yaml", guard.ShellPOSIX},
		{"kubectl exec pod-1 -n prod -- cat /etc/secret/token", guard.ShellPOSIX},
		{"kubectl exec -it deploy/api -c app -- sh -c 'cat /run/secrets/db'", guard.ShellPOSIX},
		{"ssh deploy@host cat .env", guard.ShellPOSIX},
		{"ssh -p 2222 -i ~/.ssh/k host 'cat /etc/app.conf'", guard.ShellPOSIX},
		{"zcat logs/app.log.gz | tail", guard.ShellPOSIX},
		{"xzcat dump.sql.xz", guard.ShellPOSIX},
		{"column -t .env", guard.ShellPOSIX},
		{"git log -p -- config/", guard.ShellPOSIX},
		{"cmd /c type .env", guard.ShellPowerShell},
		{"[IO.File]::ReadAllText('C:\\app\\.env')", guard.ShellPowerShell},
	} {
		if !command.ReadsFiles(c.cmd, c.shell) {
			t.Errorf("%s: not a file read", c.cmd)
		}
	}
	for _, c := range []struct {
		cmd   string
		shell guard.Shell
	}{
		{"npm test", guard.ShellPOSIX},
		{"ls -la", guard.ShellPOSIX},
		{"git status && git log --oneline", guard.ShellPOSIX},
		{"echo cat", guard.ShellPOSIX},
		{"git -C /repo status", guard.ShellPOSIX},
		{"docker exec web ls /app", guard.ShellPOSIX},
		{"kubectl exec pod-1 -- env", guard.ShellPOSIX},
		{"ssh host uptime", guard.ShellPOSIX},
		{"git log --oneline", guard.ShellPOSIX},
		{"ls | xargs -I cat echo cat", guard.ShellPOSIX},
		{"Get-ChildItem", guard.ShellPowerShell},
	} {
		if command.ReadsFiles(c.cmd, c.shell) {
			t.Errorf("%s: a file read", c.cmd)
		}
	}
}

// TestReadTargets：读文件命令的文件参数、输入重定向的目标与 PowerShell 的路径参数；模式参数与选项的值不算。
func TestReadTargets(t *testing.T) {
	for _, tc := range []struct {
		cmd   string
		shell guard.Shell
		want  []string
	}{
		{"cat .env", guard.ShellPOSIX, []string{".env"}},
		{"sudo cat ~/.aws/credentials | grep key", guard.ShellPOSIX, []string{"~/.aws/credentials"}},
		{"head -n 5 config/.env.prod", guard.ShellPOSIX, []string{"config/.env.prod"}},
		{"grep KEY .env", guard.ShellPOSIX, []string{".env"}},
		{"grep -e KEY -- .env", guard.ShellPOSIX, []string{".env"}},
		{"sed -n 1p ~/.ssh/id_rsa", guard.ShellPOSIX, []string{"~/.ssh/id_rsa"}},
		{"tr a b < .env", guard.ShellPOSIX, []string{".env"}},
		{"while read l; do echo $l; done < ~/.netrc", guard.ShellPOSIX, []string{"~/.netrc"}},
		{"bash -c 'base64 id_rsa'", guard.ShellPOSIX, []string{"id_rsa"}},
		{"cat <<EOF\nx\nEOF", guard.ShellPOSIX, nil},
		{"ls -la ~/.ssh", guard.ShellPOSIX, nil},
		{"echo .env", guard.ShellPOSIX, nil},
		{"Get-Content -Path .env -Raw", guard.ShellPowerShell, []string{".env"}},
		{"gc ~/.ssh/id_rsa -TotalCount 3", guard.ShellPowerShell, []string{"~/.ssh/id_rsa"}},
		{"Select-String -Pattern key -Path .env", guard.ShellPowerShell, []string{".env"}},
		{"[IO.File]::ReadAllText('C:\\Users\\me\\.aws\\credentials')", guard.ShellPowerShell, []string{"C:\\Users\\me\\.aws\\credentials"}},
		{"cmd /c type .env", guard.ShellPowerShell, []string{".env"}},
		{`Get-Content "C:\Users\Jane Doe\.ssh\config"`, guard.ShellPowerShell, []string{`C:\Users\Jane Doe\.ssh\config`}},
		{`Write-Output "[IO.File]::ReadAllText('.env')"`, guard.ShellPowerShell, nil},
		{`$k = [IO.File]::ReadAllText('.env')`, guard.ShellPowerShell, []string{".env"}},
		{`gc $HOME\.aws\credentials`, guard.ShellPowerShell, []string{`~/.aws\credentials`}},
		{`cat "$HOME/.ssh/config"`, guard.ShellPOSIX, []string{"~/.ssh/config"}},
		{"cat ${HOME}/.netrc", guard.ShellPOSIX, []string{"~/.netrc"}},
		{"grep -eTOKEN .env", guard.ShellPOSIX, []string{".env"}},
		{"grep -ie token .env", guard.ShellPOSIX, []string{".env"}},
		{"grep -i token .env", guard.ShellPOSIX, []string{".env"}},
		{"Get-Content -Path:.env", guard.ShellPowerShell, []string{".env"}},
		{"Get-Content -Encoding:utf8 .env", guard.ShellPowerShell, []string{".env"}},
		{"Select-String KEY .env", guard.ShellPowerShell, []string{".env"}},
		{"sls KEY", guard.ShellPowerShell, nil},
		{"cd ~/.ssh && cat config", guard.ShellPOSIX, []string{"config", "~/.ssh/config"}},
		{"cd /etc; cat /tmp/x", guard.ShellPOSIX, []string{"/tmp/x"}},
		{"Set-Location ~/.ssh; Get-Content config", guard.ShellPowerShell, []string{"config", "~/.ssh/config"}},
		{"Get-Content -Verbose .env", guard.ShellPowerShell, []string{".env"}},
		{"cd ~/.ssh && cat < config", guard.ShellPOSIX, []string{"config", "~/.ssh/config"}},
		{"column -t .env", guard.ShellPOSIX, []string{".env"}},
		{"Get-Content README.md,.env", guard.ShellPowerShell, []string{"README.md", ".env"}},
		{`Get-Content "a,b.txt"`, guard.ShellPowerShell, []string{"a,b.txt"}},
		{"Get-Item .env | Get-Content", guard.ShellPowerShell, []string{".env"}},
		{"Get-Item .env | Remove-Item", guard.ShellPowerShell, nil},
		{"grep -f .env README.md", guard.ShellPOSIX, []string{".env", "README.md"}},
		{"grep --file=.env README.md", guard.ShellPOSIX, []string{".env", "README.md"}},
		{"grep -if.env README.md", guard.ShellPOSIX, []string{".env", "README.md"}},
		{"cd ~/.ssh; (cd /tmp); cat config", guard.ShellPOSIX, []string{"config", "~/.ssh/config", "/tmp/config"}},
		{"Get-Content -Pa .env", guard.ShellPowerShell, []string{".env"}},
		{"Get-Content -Lit .env", guard.ShellPowerShell, []string{".env"}},
		{"cmd /d /c type .env", guard.ShellPowerShell, []string{".env"}},
		{"git diff --no-index README.md .env", guard.ShellPOSIX, []string{"README.md", ".env"}},
		{"git diff HEAD -- .env", guard.ShellPOSIX, nil},
		{"echo x | xargs cat .env", guard.ShellPOSIX, []string{".env"}},
		{"xargs -a .env echo", guard.ShellPOSIX, []string{".env"}},
		{"xargs --arg-file=.env echo", guard.ShellPOSIX, []string{".env"}},
		{"xargs -a 'secret dir/.env' echo", guard.ShellPOSIX, []string{"secret dir/.env"}},
		{"Get-Item .env; Get-Content", guard.ShellPowerShell, nil},
		{"Import-Csv -UseCulture .env", guard.ShellPowerShell, []string{".env"}},
		{`Microsoft.PowerShell.Management\Get-Content .env`, guard.ShellPowerShell, []string{".env"}},
		// 递归读取给出的目录；没有给出路径时读工作目录（rg 只在标准输入不是管道时）
		{"grep -r TOKEN .", guard.ShellPOSIX, []string{"."}},
		{"grep -rn TOKEN", guard.ShellPOSIX, []string{"."}},
		{"grep -n TOKEN", guard.ShellPOSIX, nil},
		{"rg TOKEN", guard.ShellPOSIX, []string{"."}},
		{"rg -r X TOKEN src", guard.ShellPOSIX, []string{"src"}},
		{"git log | rg TOKEN", guard.ShellPOSIX, nil},
		{"find . -name '*.go' | xargs grep -r TOKEN", guard.ShellPOSIX, nil},
		{"grep -r --include '*.go' TOKEN src", guard.ShellPOSIX, []string{"src"}},
		// cmd 的主目录变量与加了引号的 /c 内层命令
		{`cmd /c type %USERPROFILE%\.docker\config.json`, guard.ShellPowerShell, []string{`~/.docker\config.json`}},
		{`cmd /c type %HOMEDRIVE%%HOMEPATH%\.netrc`, guard.ShellPowerShell, []string{`~/.netrc`}},
		{`cmd /c "type .env"`, guard.ShellPowerShell, []string{".env"}},
		{`cmd /c 'type .env'`, guard.ShellPowerShell, []string{".env"}},
		{`cmd /c "echo hi & more < .env"`, guard.ShellPowerShell, []string{".env"}},
		{`cmd /c type "a b.txt"`, guard.ShellPowerShell, []string{"a b.txt"}},
		{`cmd /c "echo type .env"`, guard.ShellPowerShell, nil},
		// git diff --no-index：-- 之后的都是路径
		{"git diff --no-index -- -dir/.env README", guard.ShellPOSIX, []string{"-dir/.env", "README"}},
		// PowerShell 的数组表达式
		{"Get-Content @('.env')", guard.ShellPowerShell, []string{".env"}},
		{`Get-Content -Path @('README.md'; ".env") -Raw`, guard.ShellPowerShell, []string{"README.md", ".env"}},
		{"Get-Content ('a.txt', '.env')", guard.ShellPowerShell, []string{"a.txt", ".env"}},
		{`Get-Content @("$x")`, guard.ShellPowerShell, []string{`@("$x")`}},
		// xargs 只在命令位置上算
		{"echo xargs -a .env", guard.ShellPOSIX, nil},
		{"sudo -u root xargs -a .env echo", guard.ShellPOSIX, []string{".env"}},
		{"FOO=1 nice -n 5 xargs --arg-file=.env echo", guard.ShellPOSIX, []string{".env"}},
		// POSIX 的 $HOME 区分大小写，PowerShell 的不区分
		{`home=/tmp; cat "$home/.netrc"`, guard.ShellPOSIX, []string{"$home/.netrc"}},
		{`cat "$Home/.netrc"`, guard.ShellPOSIX, []string{"$Home/.netrc"}},
		{`gc $Home\.netrc`, guard.ShellPowerShell, []string{`~/.netrc`}},
		{`gc ${env:UserProfile}\.netrc`, guard.ShellPowerShell, []string{`~/.netrc`}},
	} {
		if got := command.ReadTargets(tc.cmd, tc.shell); !slices.Equal(got, tc.want) {
			t.Errorf("%q: %q, want %q", tc.cmd, got, tc.want)
		}
	}
}

// TestReadTargetList：每个文件参数另带通配符、花括号是否生效与递归读取的方式。
func TestReadTargetList(t *testing.T) {
	posix, pwsh := guard.ShellPOSIX, guard.ShellPowerShell
	for _, tc := range []struct {
		cmd   string
		shell guard.Shell
		want  []command.ReadTarget
	}{
		{"cat .env*", posix, []command.ReadTarget{{Path: ".env*", Shell: posix, Glob: true}}},
		{"cat '.env*'", posix, []command.ReadTarget{{Path: ".env*", Shell: posix}}},
		{`cat .env\*`, posix, []command.ReadTarget{{Path: ".env*", Shell: posix}}},
		{`cat ".env"*`, posix, []command.ReadTarget{{Path: ".env*", Shell: posix, Glob: true}}},
		{"cat .en{u..v}", posix, []command.ReadTarget{{Path: ".en{u..v}", Shell: posix, Brace: true}}},
		{"cat '.{env,example}'", posix, []command.ReadTarget{{Path: ".{env,example}", Shell: posix}}},
		{"cat ${HOME}/x", posix, []command.ReadTarget{{Path: "~/x", Shell: posix}}},
		{"cat '.env*' .env*", posix, []command.ReadTarget{{Path: ".env*", Shell: posix, Glob: true}}},
		{"Get-Content '.env*'", pwsh, []command.ReadTarget{{Path: ".env*", Shell: pwsh, Glob: true}}},
		{"Get-Content -LiteralPath '.{env,example}'", pwsh, []command.ReadTarget{{Path: ".{env,example}", Shell: pwsh}}},
		{"Get-Content -LiteralPath '.env*'", pwsh, []command.ReadTarget{{Path: ".env*", Shell: pwsh}}},
		{"Get-Content '.{env,example}'", pwsh, []command.ReadTarget{{Path: ".{env,example}", Shell: pwsh, Glob: true}}},
		{"grep -r TOKEN --include=*.go --exclude-dir .git src", posix, []command.ReadTarget{{Path: "src", Shell: posix,
			Walk: &command.Walk{Hidden: true, Include: []string{"*.go"}, ExcludeDir: []string{".git"}}}}},
		{"grep -Rl TOKEN", posix, []command.ReadTarget{{Path: ".", Shell: posix, Walk: &command.Walk{Hidden: true, Follow: true}}}},
		{"grep -d recurse TOKEN x", posix, []command.ReadTarget{{Path: "x", Shell: posix, Walk: &command.Walk{Hidden: true}}}},
		{"rg TOKEN src", posix, []command.ReadTarget{{Path: "src", Shell: posix, Walk: &command.Walk{}}}},
		{"rg -uu -L TOKEN", posix, []command.ReadTarget{{Path: ".", Shell: posix, Walk: &command.Walk{Hidden: true, Follow: true}}}},
		{"rg --hidden -g '!*.md' -g '*.go' -g 'a/*.go' TOKEN", posix, []command.ReadTarget{{Path: ".", Shell: posix,
			Walk: &command.Walk{Hidden: true, Include: []string{"*.go"}, Exclude: []string{"*.md"}}}}},
		{"ack -n TOKEN x", posix, []command.ReadTarget{{Path: "x", Shell: posix}}},
	} {
		got := command.ReadTargetList(tc.cmd, tc.shell)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q:\n got  %s\n want %s", tc.cmd, fmtTargets(got), fmtTargets(tc.want))
		}
	}
}

func fmtTargets(ts []command.ReadTarget) string {
	var b strings.Builder
	for _, t := range ts {
		b.WriteString(t.Path + " " + string(t.Shell))
		if t.Glob {
			b.WriteString(" glob")
		}
		if t.Brace {
			b.WriteString(" brace")
		}
		if t.Walk != nil {
			b.WriteString(" walk=" + strings.Join(append(append(append([]string{}, t.Walk.Include...), "|"), t.Walk.Exclude...), ","))
			if t.Walk.Hidden {
				b.WriteString(" hidden")
			}
			if t.Walk.Follow {
				b.WriteString(" follow")
			}
		}
		b.WriteString("; ")
	}
	return b.String()
}

package command

import (
	"path"
	"regexp"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// HeredocPlaceholder 代替数据 heredoc 的正文（与 Python 版一致）。
const HeredocPlaceholder = "\n<h-guard:heredoc-data>\n"

// 会把 heredoc 正文当代码执行的程序沿用 Python 版的列表，分成两组：posixInterpreters 的正文按 POSIX 检查，
// pwshInterpreters（pwsh、powershell）的按 PowerShell 检查。
var posixInterpreters = regexp.MustCompile(`(?:^|[\s;&|(])(?:/\S*/)?(?:bash|sh|zsh|dash|ksh|ash|fish|` +
	`python[0-9.]*|python3?|node|deno|ruby|perl|php|psql|mysql|sqlite3?)\b`)

var pwshInterpreters = regexp.MustCompile(`(?:^|[\s;&|(])(?:/\S*/)?(?:pwsh|powershell)(?:\.exe)?\b`)

// executedHeredoc 返回 heredoc 正文交给的解释器按哪些 shell 检查：这一行在运算符之前（从上一个 ; & 或换行算起）
// 或定界符之后（到行尾，含管道）出现解释器（沿用 Python 版 strip_heredoc_data 的判断）。按去掉续行后的
// 文本判断（ba\ 换行 sh <<'EOF' 也是交给 bash）。出现 pwsh、powershell 时按 PowerShell，出现别的解释器时按
// POSIX，两者都出现时两种都查（bash <<EOF | tee pwsh.log 的正文仍按 POSIX 检查）。没有解释器时为空。
func executedHeredoc(lx lexed, h heredoc) []guard.Shell {
	from := 0
	for _, t := range lx.tokens {
		if t.start >= h.op.start {
			break
		}
		if t.kind == tokSep && (t.op == "\n" || strings.ContainsAny(t.op, ";&")) {
			from = t.end
		}
	}
	lineEnd := h.bodyStart - 1
	if lineEnd < h.delim.end {
		lineEnd = h.delim.end
	}
	before, after := lx.join(from, h.op.start), lx.join(h.delim.end, lineEnd)
	var out []guard.Shell
	if pwshInterpreters.MatchString(before) || pwshInterpreters.MatchString(after) {
		out = append(out, guard.ShellPowerShell)
	}
	if posixInterpreters.MatchString(before) || posixInterpreters.MatchString(after) {
		out = append(out, guard.ShellPOSIX)
	}
	return out
}

// stripHeredocs 处理 heredoc：
//   - 正文送给解释器的（bash <<'EOF'、cat <<EOF | bash）原样保留，并作为内层命令返回（executed），
//     不论定界符是否带引号；
//   - 定界符带引号的数据 heredoc（'EOF'、"EOF"、\EOF、E'OF'）是字面量，正文换成占位符；
//   - 定界符不带引号的数据 heredoc 会展开 $(…) 与反引号：正文换成占位符，并放入 expandable 供提取命令替换。
//
// expandable 与 executed 中的正文已去掉续行（不带引号定界符的正文在读入时就去掉，$\ 换行 ( 仍是命令替换）。
//
// heredoc 的识别以词法分析为准：引号或注释里的 << 不是 heredoc，here-string（<<<）也不是。
func stripHeredocs(cmd string) (out string, expandable []string, executed []nested) {
	if !strings.Contains(cmd, "<") { // 不能只找 <<：运算符可以被续行拆开（<\ 换行 <EOF）
		return cmd, nil, nil
	}
	lx := lex(cmd)
	if len(lx.heredocs) == 0 {
		return cmd, nil, nil
	}
	var b strings.Builder
	last := 0
	for _, h := range lx.heredocs {
		body := lx.join(h.bodyStart, h.bodyEnd)
		if shells := executedHeredoc(lx, h); len(shells) > 0 {
			for _, shell := range shells {
				executed = append(executed, nested{text: body, shell: shell})
			}
			continue
		}
		b.WriteString(cmd[last:h.bodyStart])
		b.WriteString(HeredocPlaceholder)
		last = h.bodyEnd
		if !h.delim.quoted {
			expandable = append(expandable, body)
		}
	}
	b.WriteString(cmd[last:])
	return b.String(), expandable, executed
}

// Segments 按不在引号内的 ; & | && || ( ) 与换行切段，丢掉空段（Python 版 command_segments，
// 但以词法分析为准：单引号内的反斜杠是字面量，heredoc 正文不算命令段）。返回各段去掉首尾空白的原文。
func Segments(cmd string) []string {
	lx := lex(cmd)
	var out []string
	for _, seg := range lx.segments() {
		out = append(out, strings.TrimSpace(cmd[seg.start:seg.end]))
	}
	return out
}

// prefixWords 是放在命令前面、不改变「执行哪个命令」的词与保留字；值为该词需要参数的选项。
var prefixWords = map[string][]string{
	"sudo":    {"-u", "-g", "-C", "-D", "-p", "-r", "-t", "-U", "-T", "--user", "--group", "--chdir"},
	"doas":    {"-u", "-C"},
	"env":     {"-u", "-C", "--unset", "--chdir"},
	"command": nil,
	"nohup":   nil,
	"time":    {"-f", "-o"},
	"nice":    {"-n", "--adjustment"},
	"timeout": {"-s", "-k", "--signal", "--kill-after"},
	"ionice":  {"-c", "-n", "-p", "--class", "--classdata"},
	"exec":    {"-a"},
	"builtin": nil,
	// xargs 运行它后面的命令（输入为空时 GNU xargs 也运行一次）
	"xargs": {"-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--max-chars", "--delimiter",
		"--arg-file", "--replace", "--max-lines", "--eof"},
	"busybox": nil,
	// 在新会话、改了缓冲方式或包上伪终端后运行它后面的命令
	"setsid": {"-w", "--wait"}, "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"}, "unbuffer": nil,
	// 保留字：if rm …、do rm …、{ rm …; }、! rm …
	"!": nil, "{": nil, "}": nil, "if": nil, "then": nil, "else": nil, "elif": nil, "do": nil, "while": nil, "until": nil,
}

// prefixPositional 是前缀词在选项之后、命令之前的位置参数个数（timeout 5 rm …）。
var prefixPositional = map[string]int{"timeout": 1}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// commandStart 返回段中的词与命令词的下标：跳过前缀词及其选项、位置参数，赋值与保留字。重定向的目标、
// heredoc 的定界符与重定向前的文件描述符号（2>）不算词。没有命令词时下标等于词数。
func commandStart(lx lexed, seg segment) ([]token, int) {
	var words []token
	target := false
	for _, t := range seg.tokens {
		switch {
		case t.kind == tokRedir || t.kind == tokHeredoc:
			if n := len(words); n > 0 && words[n-1].end == t.start && isDigits(words[n-1].value) {
				words = words[:n-1] // 2>file 的 2
			}
			target = true
		case t.kind == tokWord && target:
			target = false
		case t.kind == tokWord:
			words = append(words, t)
		}
	}
	var argOpts []string
	positional := 0
	k := 0
	for k < len(words) {
		w := words[k]
		base := strings.ToLower(path.Base(w.value))
		if opts, ok := prefixWords[base]; ok && w.value != "" {
			argOpts, positional = opts, prefixPositional[base]
			k++
			continue
		}
		if assignment.MatchString(lx.join(w.start, w.end)) {
			k++
			continue
		}
		if strings.HasPrefix(w.value, "-") && k+1 < len(words) {
			k++
			if contains(argOpts, w.value) && k+1 < len(words) {
				k++
			}
			continue
		}
		if positional > 0 && k+1 < len(words) {
			positional--
			k++
			continue
		}
		break
	}
	return words, k
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// CommandPositions 返回每一段中真正处于「要被执行」位置的部分：去掉 sudo、env、FOO=1、保留字这类前缀
// 及前缀词的选项（Python 版 command_position_text）。`echo "别用 rm -rf /"` 剥完仍以 echo 开头，
// 锚在段首的正则不会命中。词按 shell 规则切分（空格、制表符都算），前缀词按去引号后的值比较，
// 赋值前缀按去掉续行后的原文判断（F\ 换行 OO=1 也是赋值）；返回的文本去掉续行。
//
// 与 Python 版的差异（只收紧）：前缀词需要参数的选项连同参数一起跳过（sudo -u root rm …），timeout 的时长也跳过，
// 段首的选项词总是跳过，保留字也剥掉，括号也分段，重定向的目标不当作命令词（>log rm …）。
func CommandPositions(cmd string) []string {
	lx := lex(cmd)
	var out []string
	for _, seg := range lx.segments() {
		words, k := commandStart(lx, seg)
		if k < len(words) {
			if s := strings.TrimSpace(lx.join(words[k].start, seg.end)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// Pipelines 返回 POSIX 命令里的各条管道：每条是用 | 或 |& 依次相连的各段，每段是命令位置起的词的取值（去掉引号
// 与转义，不做展开；跳过 sudo、env 这类前缀词与变量赋值；重定向与它的目标不算）。给需要「上一段的输出交给下一段」
// 这种结构的检测用（detect/encoded）。
func Pipelines(cmd string) [][][]string {
	lx := lex(cmd)
	var out [][][]string
	var pipe [][]string
	cur := segment{start: -1}
	flush := func(end int, op string) {
		if len(cur.tokens) > 0 {
			cur.end = end
			words, k := commandStart(lx, cur)
			var vals []string
			for _, w := range words[k:] {
				vals = append(vals, w.value)
			}
			if len(vals) > 0 {
				pipe = append(pipe, vals)
			}
		}
		cur = segment{start: -1}
		if op != "|" && op != "|&" && len(pipe) > 0 {
			out = append(out, pipe)
			pipe = nil
		}
	}
	for _, t := range lx.tokens {
		if t.kind == tokSep {
			flush(t.start, t.op)
			continue
		}
		if cur.start < 0 {
			cur.start = t.start
		}
		cur.tokens = append(cur.tokens, t)
	}
	flush(len(lx.src), "")
	return out
}

// NormalizedPositions 返回各段命令位置的规范写法，给 deny 级规则在原文之外再匹配一次：词按 shell 规则取值
// （去掉引号与转义，不做展开），命令词取路径的最后一段（/bin/rm → rm），${HOME} 写作 $HOME，词末的 / 去掉
// （单独的 / 保留），以单个空格连接；重定向的目标不算。含空白的词保留原文写法，不拼出新的词。
// 于是 rm -rf "$HOME"、/bin/rm -rf '/'、\rm -rf ${HOME}/ 与 rm -rf $HOME、rm -rf / 一样匹配。
func NormalizedPositions(cmd string) []string {
	lx := lex(cmd)
	var out []string
	for _, seg := range lx.segments() {
		words, k := commandStart(lx, seg)
		if k >= len(words) {
			continue
		}
		parts := make([]string, 0, len(words)-k)
		for i, w := range words[k:] {
			v := w.value
			switch {
			case strings.ContainsAny(v, " \t\n"):
				v = lx.join(w.start, w.end)
			default:
				if i == 0 && v != "" {
					v = path.Base(v)
				}
				v = strings.ReplaceAll(v, "${HOME}", "$HOME")
				if len(v) > 1 {
					if v = strings.TrimRight(v, "/"); v == "" {
						v = "/"
					}
				}
			}
			parts = append(parts, v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// StripQuoted 抹掉引号里的内容（Python 版 strip_quoted），给自带分隔符、无法切段的形态用（fork bomb）。
// 引号之外的字符、运算符与空白原样保留；heredoc 正文不在其中（交给解释器的正文另作为内层命令检查）。
func StripQuoted(cmd string) string {
	lx := lex(cmd)
	var b strings.Builder
	last := 0
	gap := func(end int) {
		for _, h := range lx.heredocs {
			if h.bodyStart >= last && h.bodyStart < end {
				b.WriteString(lx.join(last, h.bodyStart))
				last = h.closeEnd
			}
		}
		if last < end {
			b.WriteString(lx.join(last, end)) // 词与词之间的续行（注释里的反斜杠不是续行）
		}
	}
	for _, t := range lx.tokens {
		gap(t.start)
		if t.kind == tokWord {
			b.WriteString(t.bare)
		} else {
			b.WriteString(cmd[t.start:t.end])
		}
		last = t.end
	}
	gap(len(cmd))
	return b.String()
}

// Words 按 POSIX 规则把一段命令切成词并去掉引号，不做任何展开；运算符与 heredoc 正文不算词。
func Words(s string) []string {
	var words []string
	for _, t := range lex(s).tokens {
		if t.kind == tokWord {
			words = append(words, t.value)
		}
	}
	return words
}

// codeSubstitutions 返回命令中不在单引号内的命令替换（$(…)、反引号、<(…)、>(…)）的内容。
func codeSubstitutions(cmd string) []string {
	var out []string
	for _, t := range lex(cmd).tokens {
		out = append(out, t.subs...)
	}
	return out
}

// substitutions 提取不带引号定界符的 heredoc 正文（已去掉续行）中的 $(…) 与反引号命令替换。正文里的引号
// 不起作用；$(…) 的右括号仍按词法分析寻找。未闭合的替换取到末尾。
func substitutions(body string) []string {
	var out []string
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\':
			i++
		case c == '$' && i+1 < len(body) && body[i+1] == '(':
			end, _ := matchParen(body, i+1)
			if end < 0 {
				return append(out, body[i+2:])
			}
			out = append(out, body[i+2:end])
			i = end
		case c == '`':
			end := closingBacktick(body, i+1)
			if end < 0 {
				return append(out, body[i+1:])
			}
			out = append(out, strings.ReplaceAll(body[i+1:end], "\\`", "`"))
			i = end
		}
	}
	return out
}

var shells = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "ash": true}

// nestedScripts 取出嵌套调用的脚本：bash -c '…'、sh -lc "…"、eval 的参数、交给 shell 的 here-string
// （bash <<< '…'）与管道里 echo、printf 交给 shell 的文本（echo '…' | sh）按 POSIX 检查，
// pwsh、powershell 的 -Command、-EncodedCommand 与按位置给出的命令按 PowerShell 检查（见 pwshScripts）。
func nestedScripts(cmd string) []nested {
	var out []nested
	for _, pos := range CommandPositions(cmd) {
		words := Words(pos)
		if len(words) < 2 {
			continue
		}
		switch name := strings.TrimSuffix(strings.ToLower(path.Base(words[0])), ".exe"); {
		case name == "eval":
			out = append(out, nested{text: strings.Join(words[1:], " "), shell: guard.ShellPOSIX})
		case shells[name]:
			for _, s := range shellScripts(words[1:]) {
				out = append(out, nested{text: s, shell: guard.ShellPOSIX})
			}
			for _, s := range hereStrings(pos) {
				out = append(out, nested{text: s, shell: guard.ShellPOSIX})
			}
		case name == "pwsh" || name == "powershell":
			scripts, enc := pwshScripts(words[1:])
			for _, s := range scripts {
				out = append(out, nested{text: s, shell: guard.ShellPowerShell, encoded: enc})
			}
		}
	}
	for _, s := range pipedScripts(cmd) {
		out = append(out, nested{text: s, shell: guard.ShellPOSIX})
	}
	return out
}

// hereStrings 返回一段命令里 here-string（<<< 后的词，去掉引号）的取值。
func hereStrings(pos string) []string {
	var out []string
	toks := lex(pos).tokens
	for i := 0; i+1 < len(toks); i++ {
		if toks[i].kind == tokRedir && toks[i].op == "<<<" && toks[i+1].kind == tokWord {
			out = append(out, toks[i+1].value)
		}
	}
	return out
}

// pipedScripts 返回管道里 echo、printf 交给 shell 的文本（echo 'rm -rf /' | sh）：下一段是不带脚本参数的
// shell（sh、bash -s，不是 bash -c … 或 bash file.sh）。echo 的选项（-n、-e）不算文本。
func pipedScripts(cmd string) []string {
	var out []string
	for _, pipe := range Pipelines(cmd) {
		for i := 1; i < len(pipe); i++ {
			src, dst := pipe[i-1], pipe[i]
			if !shells[strings.ToLower(path.Base(dst[0]))] || !readsStdin(dst[1:]) {
				continue
			}
			args := src[1:]
			switch path.Base(src[0]) {
			case "echo":
				for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "neE") == "" {
					args = args[1:]
				}
			case "printf":
			default:
				continue
			}
			if len(args) > 0 {
				out = append(out, strings.Join(args, " "))
			}
		}
	}
	return out
}

// readsStdin 报告 shell 的参数是否让它从标准输入读脚本：只有选项（-x、-s、-o 名字），没有 -c 与脚本文件。
func readsStdin(args []string) bool {
	for j := 0; j < len(args); j++ {
		w := args[j]
		switch {
		case w == "-o" || w == "+o":
			j++
		case w == "-s" || w == "--":
			return true
		case len(w) > 1 && (w[0] == '-' || w[0] == '+'):
			if w[0] == '-' && !strings.HasPrefix(w, "--") && strings.ContainsRune(w[1:], 'c') {
				return false
			}
		default:
			return false
		}
	}
	return true
}

var (
	// ifsWord 是 $IFS、${IFS} 及其取子串的写法（${IFS:0:1}）：不加引号时展开成空白，rm${IFS}-rf${IFS}/ 即 rm -rf /
	ifsWord = regexp.MustCompile(`\$IFS\b|\$\{IFS(?:[:#%][^}]*)?\}`)
	// braceList 是独立成词、不加引号的花括号列表：{rm,-rf,/} 展开成 rm -rf /
	braceList = regexp.MustCompile(`(^|[\s;&|()])\{([^{}\s,'"]*(?:,[^{}\s,'"]*)+)\}`)
)

// rewritten 返回把 $IFS 换成空格、把花括号列表展开后的命令；没有这两种写法时返回空串。只多检查一种读法：
// 引号里的同样写法也会被替换，替换后至多多出命中，不会少。
func rewritten(cmd string) string {
	out := ifsWord.ReplaceAllString(cmd, " ")
	for {
		next := braceList.ReplaceAllStringFunc(out, func(m string) string {
			sub := braceList.FindStringSubmatch(m)
			return sub[1] + strings.Join(strings.Split(sub[2], ","), " ")
		})
		if next == out {
			break
		}
		out = next
	}
	if out == cmd {
		return ""
	}
	return out
}

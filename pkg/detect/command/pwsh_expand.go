package command

import (
	"encoding/base64"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// pwshNormalize 把 PowerShell 当作 - 与引号的 Unicode 字符换成 ASCII 写法。
func pwshNormalize(s string) string { return pwshUnicode.Replace(s) }

var pwshUnicode = strings.NewReplacer(
	"\u2013", "-", "\u2014", "-", "\u2015", "-",
	"\u2018", "'", "\u2019", "'", "\u201a", "'", "\u201b", "'",
	"\u201c", `"`, "\u201d", `"`, "\u201e", `"`,
)

// nested 是一段要按某个 shell 再检查一遍的内层命令。
type nested struct {
	text  string
	shell guard.Shell
	// block 为真表示同一脚本里的代码（PowerShell 的脚本块、括号与子表达式），不是交给解释器的嵌套调用：
	// 不消耗展开深度，只受 maxBlocks 约束（与 POSIX 的 if、{ } 不占深度一致）
	block bool
	// encoded 为真表示正文由 -EncodedCommand 解码而来（Unit.Encoded）
	encoded bool
}

// pwshExpand 处理一个 PowerShell 单元（spec §5.3）：返回剥离数据 here-string 后的全文，以及要再检查的内层命令：
//   - 子表达式 $(…)（含双引号字符串与 @"…"@ 里的）、括号、脚本块里的代码；
//   - 交给解释器的字符串：同一管道里后面有 iex（Invoke-Expression）、pwsh、powershell 时按 PowerShell，
//     有 bash、sh 等或 wsl 时按 POSIX（中间隔着 Out-String 这类透传命令也算）；iex 的字符串参数（含 iex(…)），
//     [scriptblock]::Create(…) 与 InvokeScript(…) 的字符串参数。它们的正文保留在全文里，另作为内层命令检查；
//   - 嵌套调用：pwsh、powershell 的 -Command、-EncodedCommand 与按位置给出的命令；Start-Process 启动它们时
//     -ArgumentList 里的命令；bash -c 等与 wsl 交给 Linux 执行的命令（按 POSIX 检查）。
//
// 作为数据的 here-string（@'…'@，以及没有交给解释器的 @"…"@）正文换成占位符，其中的 $(…) 照样提取；
// 交给 python 等别的解释器的不剥离（全文规则看得到），但不按 shell 命令检查。
func pwshExpand(text string) (string, []nested) {
	lx := pwshLex(text)
	segs := lx.segmentsWithOps()
	executed := map[int]guard.Shell{} // 交给解释器执行的字符串词（按起点）与所用的 shell
	kept := map[int]bool{}            // 交给别的解释器的字符串词：不当数据剥离
	for i := 0; i < len(segs); {
		j := i // 管道 segs[i..j]
		for j+1 < len(segs) && segs[j].op == "|" {
			j++
		}
		for p := i + 1; p <= j; p++ {
			shell, runs, reads := lx.pipeInterpreter(segs[p].pwSegment)
			for q := i; q < p; q++ {
				for _, w := range segs[q].tokens {
					if w.kind != tokWord || !isStringWord(lx.src[w.start:w.end]) {
						continue
					}
					if _, done := executed[w.start]; runs && !done {
						executed[w.start] = shell
					}
					kept[w.start] = kept[w.start] || reads
				}
			}
		}
		i = j + 1
	}
	var inner []nested
	for _, seg := range segs {
		name, args, ok := lx.command(seg.pwSegment)
		if !ok {
			continue
		}
		switch {
		case name == "iex" || name == "invoke-expression":
			for _, w := range args {
				if isStringWord(lx.src[w.start:w.end]) {
					executed[w.start] = guard.ShellPowerShell
				}
			}
		case name == "pwsh" || name == "powershell":
			scripts, enc := pwshScripts(values(args))
			for _, s := range scripts {
				inner = append(inner, nested{text: s, shell: guard.ShellPowerShell, encoded: enc})
			}
		case shells[name]:
			for _, s := range shellScripts(values(args)) {
				inner = append(inner, nested{text: s, shell: guard.ShellPOSIX})
			}
		case name == "wsl":
			if s := wslCommand(values(args)); s != "" {
				inner = append(inner, nested{text: s, shell: guard.ShellPOSIX})
			}
		case name == "start-process" || name == "saps" || name == "start":
			inner = append(inner, startProcess(lx, args)...)
		}
	}
	var b strings.Builder
	last := 0
	for _, t := range lx.tokens {
		if t.kind != tokWord {
			continue
		}
		raw := lx.src[t.start:t.end]
		if shell, ok := executed[t.start]; ok {
			inner = append(inner, nested{text: t.value, shell: shell})
		}
		for _, s := range t.subs {
			inner = append(inner, nested{text: s, shell: guard.ShellPowerShell, block: true})
		}
		for _, body := range t.codeArgs {
			for _, s := range stringLiterals(body) {
				inner = append(inner, nested{text: s, shell: guard.ShellPowerShell})
			}
		}
		if n := hereStart(raw, 0); n > 0 && !kept[t.start] {
			if _, ok := executed[t.start]; !ok {
				// 数据 here-string：正文换成占位符（结束行保留）
				// 结束行按词法的规则找（正文为空时结束行紧跟开头那一行）；未闭合时保留最后一行
				bodyEnd := len(raw)
				if k := strings.Index(raw[n-1:], "\n"+raw[1:2]+"@"); k >= 0 {
					bodyEnd = n - 1 + k
				} else if k := strings.LastIndex(raw, "\n"); k >= n {
					bodyEnd = k
				}
				b.WriteString(text[last : t.start+n])
				b.WriteString(HeredocPlaceholder)
				last = t.start + bodyEnd
			}
		}
	}
	b.WriteString(text[last:])
	return b.String(), inner
}

// command 返回段中实际命令的规范名字（见 commandName）与它的参数。赋值紧贴命令时（$r=pwsh …）名字取 = 之后的
// 部分，与命令位置一致（计划评审 M3B-01）。没有命令词时 ok 为假。
func (lx pwLexed) command(seg pwSegment) (name string, args []pwToken, ok bool) {
	words, k, at := lx.commandStart(seg)
	if k >= len(words) {
		return "", nil, false
	}
	v := words[k].value
	if at > words[k].start {
		v = pwshLex(lx.join(at, words[k].end)).firstValue()
	}
	return commandName(v), words[k+1:], true
}

// pipeInterpreter 报告管道里的一段是否把送来的文本当代码执行：iex、pwsh、powershell 按 PowerShell；bash、sh 等，
// 以及没有给出命令（或命令是 shell 而没有 -c）的 wsl 按 POSIX。python、node 等别的解释器只报告 reads：
// 送去的 here-string 不当数据剥离。
func (lx pwLexed) pipeInterpreter(seg pwSegment) (shell guard.Shell, runs, reads bool) {
	name, args, ok := lx.command(seg)
	if !ok {
		return "", false, false
	}
	switch {
	case pwInterpreter(name):
		return guard.ShellPowerShell, true, true
	case shells[name]:
		return guard.ShellPOSIX, true, true
	case name == "wsl":
		cmd := Words(wslCommand(values(args)))
		if len(cmd) == 0 || (shells[strings.ToLower(path.Base(cmd[0]))] && len(shellScripts(cmd[1:])) == 0) {
			return guard.ShellPOSIX, true, true
		}
	case otherInterpreters.MatchString(name):
		return "", false, true
	}
	return "", false, false
}

// otherInterpreters 是 POSIX 侧解释器列表（interpreters）里不是 shell 的那些：python、node 等。
var otherInterpreters = regexp.MustCompile(`^(?:fish|python[0-9.]*|node|deno|ruby|perl|php|psql|mysql|sqlite3?)$`)

// stringLiterals 返回代码 code 里的字符串字面量（单引号、双引号与 here-string）的值。
func stringLiterals(code string) []string {
	lx := pwshLex(code)
	var out []string
	for _, t := range lx.tokens {
		if t.kind == tokWord && isStringWord(code[t.start:t.end]) {
			out = append(out, t.value)
		}
	}
	return out
}

// startProcessSwitches 是 Start-Process 不带值的选项（小写，去掉开头的 -）；其余选项都带值。
var startProcessSwitches = map[string]bool{"nonewwindow": true, "nnw": true, "passthru": true, "wait": true,
	"usenewenvironment": true, "loaduserprofile": true, "lup": true}

// startProcess 返回 Start-Process 启动 pwsh、powershell、bash 等或 wsl 时 -ArgumentList 里的命令：
// 程序是 -FilePath（或第一个位置参数），参数是 -ArgumentList（或第二个位置参数），逗号分隔的各项以空格连接，
// 与 Start-Process 拼出的命令行相同。
func startProcess(lx pwLexed, args []pwToken) []nested {
	var file, list string
	positional := 0
	for i := 0; i < len(args); i++ {
		v := args[i].value
		// 只有不带引号的 -x 是 Start-Process 的参数名；带引号的（"-c …"）是位置参数（参数列表）
		if raw := lx.src[args[i].start:args[i].end]; strings.HasPrefix(raw, "-") && len(v) > 1 {
			name := strings.ToLower(strings.TrimPrefix(v, "-"))
			if startProcessSwitches[name] || i+1 >= len(args) {
				continue
			}
			i++
			switch {
			case strings.HasPrefix("filepath", name) && len(name) >= 2, name == "path", name == "pspath":
				file = args[i].value
			case strings.HasPrefix("argumentlist", name) && len(name) >= 2, name == "args", name == "al":
				list, i = arraySpan(lx, args, i)
			}
			continue
		}
		switch positional {
		case 0:
			file = v
		case 1:
			list, i = arraySpan(lx, args, i)
		}
		positional++
	}
	if file == "" || list == "" {
		return nil
	}
	// 显式的数组 @(…) 与括号：里面同样是逗号分隔的字面量（计划第二轮评审 R2-02）
	if t := strings.TrimSpace(list); (strings.HasPrefix(t, "@(") || strings.HasPrefix(t, "(")) && strings.HasSuffix(t, ")") {
		list = t[strings.IndexByte(t, '(')+1 : len(t)-1]
	}
	var cmdline []string
	for _, item := range listItems(list) {
		cmdline = append(cmdline, pwshLex(item).firstValue())
	}
	argv := values(wordsOf(pwshLex(strings.Join(cmdline, " "))))
	var out []nested
	switch name := commandName(file); {
	case name == "pwsh" || name == "powershell":
		scripts, enc := pwshScripts(argv)
		for _, s := range scripts {
			out = append(out, nested{text: s, shell: guard.ShellPowerShell, encoded: enc})
		}
	case shells[name]:
		for _, s := range shellScripts(argv) {
			out = append(out, nested{text: s, shell: guard.ShellPOSIX})
		}
	case name == "wsl":
		if s := wslCommand(argv); s != "" {
			out = append(out, nested{text: s, shell: guard.ShellPOSIX})
		}
	}
	return out
}

// arraySpan 返回从 args[i] 起的数组字面量的原文与它最后一个词的下标：逗号两边可以有空白（'-c', 'x'），
// 数组因此跨几个词（计划评审 M3B-02）。
func arraySpan(lx pwLexed, args []pwToken, i int) (string, int) {
	j := i
	for j+1 < len(args) && (strings.HasSuffix(lx.src[args[j].start:args[j].end], ",") || strings.HasPrefix(lx.src[args[j+1].start:args[j+1].end], ",")) {
		j++
	}
	return lx.src[args[i].start:args[j].end], j
}

// wordsOf 返回词法单元里的词。
func wordsOf(lx pwLexed) []pwToken {
	var out []pwToken
	for _, t := range lx.tokens {
		if t.kind == tokWord {
			out = append(out, t)
		}
	}
	return out
}

// listItems 按引号与括号之外的逗号切开数组字面量的原文（'-c','x' → '-c' 与 'x'）。
func listItems(raw string) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c == '`':
			i++
		case c == '\'':
			_, end := readSingle(raw, i)
			i = end - 1
		case c == '"':
			l := &pwLexer{src: raw}
			_, _, end := l.readDouble(i)
			i = end - 1
		case c == '(' || c == '{':
			depth++
		case (c == ')' || c == '}') && depth > 0:
			depth--
		case c == ',' && depth == 0:
			out = append(out, raw[last:i])
			last = i + 1
		}
	}
	return append(out, raw[last:])
}

// pwSegmentOp 是一段与它后面的分段运算符（没有时为空）。
type pwSegmentOp struct {
	pwSegment
	op string
}

// segmentsWithOps 与 segments 相同，另记下每段之后的分段运算符。
func (lx pwLexed) segmentsWithOps() []pwSegmentOp {
	var out []pwSegmentOp
	cur := pwSegmentOp{pwSegment: pwSegment{start: -1}}
	for _, t := range lx.tokens {
		if t.kind == tokSep {
			if len(cur.tokens) > 0 {
				cur.end, cur.op = t.start, t.op
				out = append(out, cur)
			}
			cur = pwSegmentOp{pwSegment: pwSegment{start: -1}}
			continue
		}
		if cur.start < 0 {
			cur.start = t.start
		}
		cur.tokens = append(cur.tokens, t)
	}
	if len(cur.tokens) > 0 {
		cur.end = len(lx.src)
		out = append(out, cur)
	}
	return out
}

// commandName 返回命令词的规范名字：取到第一个 ( 之前（iex(…)），再取路径或模块限定名的最后一段，小写，
// 去掉 .exe。
func commandName(v string) string {
	if j := strings.IndexByte(v, '('); j > 0 {
		v = v[:j]
	}
	if j := strings.LastIndexAny(v, `\/`); j >= 0 {
		v = v[j+1:]
	}
	return strings.TrimSuffix(strings.ToLower(v), ".exe")
}

// pwInterpreter 报告名字为 name 的命令是否把管道送来的字符串当代码执行。
func pwInterpreter(name string) bool {
	return name == "iex" || name == "invoke-expression" || name == "pwsh" || name == "powershell"
}

// isStringWord 报告词的原文是否是一个字符串字面量（单引号、双引号或 here-string）。
func isStringWord(raw string) bool {
	return strings.HasPrefix(raw, "'") || strings.HasPrefix(raw, `"`) || hereStart(raw, 0) > 0
}

func values(ws []pwToken) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.value
	}
	return out
}

// pwshValueOptions 是 pwsh、powershell 带值的选项（小写，去掉开头的 - 或 /）：值不是命令。
var pwshValueOptions = map[string]bool{
	"ex": true, "ep": true, "executionpolicy": true, "w": true, "windowstyle": true, "wd": true, "workingdirectory": true,
	"config": true, "configurationname": true, "o": true, "of": true, "outputformat": true, "if": true, "in": true,
	"inputformat": true, "v": true, "version": true, "psconsolefile": true, "custompipename": true, "settings": true,
	"settingsfile": true,
}

// pwshScripts 返回 pwsh、powershell 参数里会被执行的命令：-Command（及其前缀写法 -c、-co…）之后的全部参数，
// -EncodedCommand（-e、-ec、-en…）的解码结果，没有选项时按位置给出的参数（powershell.exe 把它当命令，
// pwsh 当脚本文件：一律按命令检查，只会更严）。-File 的脚本不检查。选项可以用 -、-- 或 / 开头。
//
// encoded 报告返回的命令是否由 -EncodedCommand 解码而来（规则 obfuscated_exec 据此识别，与解码共用一处判断）。
func pwshScripts(args []string) (scripts []string, encoded bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "/") {
			return []string{strings.Join(args[i:], " ")}, false
		}
		name := strings.ToLower(strings.TrimLeft(a, "-/"))
		switch {
		case name == "":
			continue // - 从标准输入读命令
		case strings.HasPrefix("command", name):
			if i+1 < len(args) {
				return []string{strings.Join(args[i+1:], " ")}, false
			}
			return nil, false
		case name == "e" || name == "ec" || (len(name) >= 2 && strings.HasPrefix("encodedcommand", name)):
			if i+1 < len(args) {
				if s, ok := decodeCommand(args[i+1]); ok {
					return []string{s}, true
				}
			}
			return nil, false
		case name == "f" || (len(name) >= 2 && strings.HasPrefix("file", name)):
			return nil, false
		case pwshValueOptions[name]:
			i++
		}
	}
	return nil, false
}

// decodeCommand 解码 -EncodedCommand 的参数：Base64（可以不带填充）的 UTF-16LE。与 .NET 一样忽略空白、
// 奇数个字节时最后一个字节换成 U+FFFD（评审 C1：.NET 照常执行这两种写法）；仍解不出的 PowerShell 也拒绝执行。
func decodeCommand(s string) (string, bool) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return "", false
		}
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	out := string(utf16.Decode(u))
	if len(b)%2 != 0 {
		out += "\uFFFD"
	}
	return out, true
}

// shellScripts 返回 bash -c '…'、sh -lc "…" 这类参数里的脚本（与 nestedScripts 的规则相同）。
func shellScripts(args []string) []string {
	hasC := false
	for j := 0; j < len(args); j++ {
		w := args[j]
		if w == "-o" || w == "+o" {
			j++
			continue
		}
		if len(w) > 1 && (w[0] == '-' || w[0] == '+') {
			if w[0] == '-' && !strings.HasPrefix(w, "--") && strings.ContainsRune(w[1:], 'c') {
				hasC = true
			}
			continue
		}
		if hasC {
			return []string{w}
		}
		break
	}
	return nil
}

// wslValueOptions 是 wsl 带值的选项。
var wslValueOptions = map[string]bool{"-d": true, "--distribution": true, "-u": true, "--user": true, "--cd": true,
	"--shell-type": true, "--distribution-id": true}

// wslCommand 返回 wsl 交给 Linux 执行的命令：跳过选项（-d、-u 等带值）、-e/--exec 与 --，其余参数以空格连接。
// 只有选项（如 wsl --list）时为空。
func wslCommand(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--" || a == "-e" || a == "--exec":
			return strings.Join(args[i+1:], " ")
		case a == "~": // wsl ~：在 Linux 的主目录里启动，之后才是命令
		case wslValueOptions[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			return strings.Join(args[i:], " ")
		}
	}
	return ""
}

package command

import (
	"regexp"
	"slices"
	"strings"
)

// PowerShell 的词法分析（spec §5.3）。切段、命令位置、去引号与内层命令的提取共用这一套规则：
//   - 语句按 ; 换行 | && || 切段，命令后面的 & 是后台运算符，也切段；段首的 & 与 . 是调用运算符；
//   - 单引号字符串按字面（'' 是一个单引号）；双引号字符串里反引号转义下一个字符，"" 是一个双引号，
//     $(…) 是子表达式；@'…'@、@"…"@ 是 here-string（开头的 @' 后到行尾、结束的 '@ 在行首）；
//   - 反引号在引号之外转义下一个字符，反引号紧跟换行是续行；
//   - 词首的 # 开始注释，<# … #> 是块注释；
//   - (…)、$(…)、@(…)、{…}、@{…} 里是代码，不切外层的段，其中的分隔符、引号与注释按同一套规则读取；
//     未配对的 ) 与 } 按分段处理。
//
// 未闭合的引号、here-string、括号与注释延伸到末尾：宁可把后面的内容当数据，也不凭空切出命令。
// PowerShell 还把 Unicode 破折号（– — ―）当作 -、把中文引号（‘ ’ ‚ ‛ 与 “ ” „）当作引号，可以与 ASCII 引号混用：
// 展开前先换成 ASCII 写法（pwshNormalize），否则混用时后面的命令会被当成字符串（评审 C2、C3）。
// 停止解析符 --% 之后到换行或 | 的内容按字面交给程序，其中的引号不起作用（评审 I4）。

// pwToken 是 PowerShell 的词法单元，start、end 为原文中的字节区间。
type pwToken struct {
	kind       tokKind // tokWord、tokSep 或 tokRedir
	start, end int
	op         string   // 运算符
	value      string   // 词：去掉引号与反引号转义后的值；括号、脚本块与子表达式保留原文
	bare       string   // 词：引号之外的原文（反引号转义保留原样），供 Unquoted 使用
	subs       []string // 词：其中 (…)、$(…)、@(…)、{…}、@{…} 与双引号字符串里 $(…) 的代码
	comma      bool     // 词：以未转义的逗号结尾（数组未完，下一行接着读）
}

// pwLexed 是一段 PowerShell 命令的词法分析结果。conts 是代码里的续行（反引号加换行，或反引号加 \r\n）：
// 起点与长度。
type pwLexed struct {
	src    string
	tokens []pwToken
	conts  [][2]int
}

// join 返回 src[a:b] 去掉其中续行后的文本。
func (lx pwLexed) join(a, b int) string {
	var sb strings.Builder
	last := a
	for _, c := range lx.conts {
		if c[0] >= a && c[0]+c[1] <= b && c[0] >= last {
			sb.WriteString(lx.src[last:c[0]])
			last = c[0] + c[1]
		}
	}
	sb.WriteString(lx.src[last:b])
	return sb.String()
}

type pwLexer struct {
	src string
	lx  pwLexed
}

func pwshLex(s string) pwLexed {
	l := &pwLexer{src: s, lx: pwLexed{src: s}}
	l.run()
	slices.SortFunc(l.lx.conts, func(a, b [2]int) int { return a[0] - b[0] })
	l.lx.conts = slices.Compact(l.lx.conts)
	return l.lx
}

func isPwBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v' }

// contLen 返回 i 处续行的长度（反引号加 \n 为 2，加 \r\n 为 3），不是续行时为 0。
func (l *pwLexer) contLen(i int) int {
	s := l.src
	if i+1 < len(s) && s[i] == '`' {
		if s[i+1] == '\n' {
			return 2
		}
		if s[i+1] == '\r' && i+2 < len(s) && s[i+2] == '\n' {
			return 3
		}
	}
	return 0
}

// afterComma 报告最后一个词是否以未转义的逗号结尾（数组未完）。转义的逗号（`,）是字面字符，换行照常结束命令
// （计划第三轮评审 R3-01）。
func (l *pwLexer) afterComma() bool {
	n := len(l.lx.tokens)
	return n > 0 && l.lx.tokens[n-1].kind == tokWord && l.lx.tokens[n-1].comma
}

// afterAssignment 报告当前这一段到目前为止是不是一个赋值的左边：$x = 或 $x=（段里只有这些词）。
// 命令参数里的 =、$x= 不算，后面的 & 仍是后台运算符（计划第三轮评审 R3-02）。
func (l *pwLexer) afterAssignment() bool {
	var words []string
	for i := len(l.lx.tokens) - 1; i >= 0 && l.lx.tokens[i].kind != tokSep; i-- {
		t := l.lx.tokens[i]
		if t.kind != tokWord {
			return false
		}
		words = append([]string{l.src[t.start:t.end]}, words...)
	}
	switch len(words) {
	case 1:
		return strings.HasPrefix(words[0], "$") && strings.HasSuffix(words[0], "=") && pwAssign.MatchString(words[0])
	case 2:
		return strings.HasPrefix(words[0], "$") && pwAssignOp(words[1])
	}
	return false
}

func (l *pwLexer) sep(op string, i, n int) {
	l.lx.tokens = append(l.lx.tokens, pwToken{kind: tokSep, start: i, end: i + n, op: op})
}

func (l *pwLexer) run() {
	s := l.src
	segStart := true // 段首：& 与 . 是调用运算符
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isPwBlank(c):
			i++
		case l.contLen(i) > 0:
			n := l.contLen(i)
			l.lx.conts = append(l.lx.conts, [2]int{i, n})
			i += n
		case c == '\n' && l.afterComma():
			i++ // 行尾的逗号：数组在下一行继续，换行不切段（计划第二轮评审 R2-02）
		case c == '\n' || c == ';':
			l.sep(string(c), i, 1)
			i++
			segStart = true
		case c == '#':
			i = lineEnd(s, i)
		case c == '<' && i+1 < len(s) && s[i+1] == '#':
			i = blockCommentEnd(s, i)
		case c == '|' || (c == '&' && i+1 < len(s) && s[i+1] == '&'):
			n := 1
			if i+1 < len(s) && s[i+1] == c {
				n = 2
			}
			l.sep(s[i:i+n], i, n)
			i += n
			segStart = true
		case c == '&' && l.afterAssignment():
			// 赋值右边的调用运算符（$r = & 'tool'），不是后台运算符（计划第二轮评审 R2-03）
			l.lx.tokens = append(l.lx.tokens, pwToken{kind: tokWord, start: i, end: i + 1, value: "&", bare: "&"})
			i++
		case c == '&' && !segStart:
			l.sep("&", i, 1) // 后台运算符
			i++
			segStart = true
		case c == '&':
			// 段首的调用运算符：作为值为 & 的词，命令位置跳过它
			l.lx.tokens = append(l.lx.tokens, pwToken{kind: tokWord, start: i, end: i + 1, value: "&", bare: "&"})
			i++
			segStart = false
		case c == ')' || c == '}':
			l.sep(string(c), i, 1) // 未配对的右括号
			i++
			segStart = true
		case l.redirLen(i) > 0:
			n := l.redirLen(i)
			l.lx.tokens = append(l.lx.tokens, pwToken{kind: tokRedir, start: i, end: i + n, op: s[i : i+n]})
			i += n
		default:
			t := l.readWord(i)
			if s[t.start:t.end] == "--%" {
				// 停止解析：到换行或 | 为止按字面，引号不起作用
				end := t.end
				for end < len(s) && s[end] != '\n' && s[end] != '|' {
					end++
				}
				t.end = end
				t.value, t.bare = s[t.start:end], s[t.start:end]
			}
			l.lx.tokens = append(l.lx.tokens, t)
			i = t.end
			segStart = false
		}
	}
}

// redirLen 返回 i 处重定向运算符的长度（> >> 2> 2>> *> 2>&1 <），不是重定向时为 0。
func (l *pwLexer) redirLen(i int) int {
	s := l.src
	j := i
	if j+1 < len(s) && (isDigit(s[j]) || s[j] == '*') && s[j+1] == '>' {
		j++
	}
	switch {
	case j < len(s) && s[j] == '>':
		j++
		if j < len(s) && s[j] == '>' {
			j++
		}
		if j+1 < len(s) && s[j] == '&' && isDigit(s[j+1]) {
			j += 2
		}
		return j - i
	case j == i && s[j] == '<':
		return 1
	}
	return 0
}

func isDigit(c byte) bool  { return '0' <= c && c <= '9' }
func isLetter(c byte) bool { return 'a' <= c|0x20 && c|0x20 <= 'z' }

func lineEnd(s string, i int) int {
	if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(s)
}

func blockCommentEnd(s string, i int) int {
	if j := strings.Index(s[i+2:], "#>"); j >= 0 {
		return i + 2 + j + 2
	}
	return len(s)
}

// wordEnd 报告 c 是否结束引号之外的词。
func wordEnd(c byte) bool {
	return isPwBlank(c) || strings.IndexByte("\n;|&)}<>", c) >= 0
}

// readWord 读一个词：引号、here-string、括号、脚本块与子表达式连在词里。
func (l *pwLexer) readWord(start int) pwToken {
	s := l.src
	t := pwToken{kind: tokWord, start: start}
	var val, bare strings.Builder
	commaEnd := -1 // 最后一个未转义的逗号之后的位置
	i := start
	for i < len(s) {
		c := s[i]
		switch {
		case wordEnd(c) && !(c == '<' && i == start):
			t.end = i
			t.value, t.bare, t.comma = val.String(), bare.String(), commaEnd == t.end
			return t
		case c == '`':
			if l.contLen(i) > 0 {
				t.end = i
				t.value, t.bare, t.comma = val.String(), bare.String(), commaEnd == t.end
				return t
			}
			if i+1 < len(s) {
				val.WriteByte(s[i+1])
				bare.WriteString(s[i : i+2])
				i += 2
			} else {
				bare.WriteByte(c)
				i++
			}
		case c == '\'':
			body, end := readSingle(s, i)
			val.WriteString(body)
			i = end
		case c == '"':
			body, subs, end := l.readDouble(i)
			val.WriteString(body)
			t.subs = append(t.subs, subs...)
			i = end
		case c == '@' && hereStart(s, i) > 0: // $x=@' 这类不在词首的 here-string 同样识别（评审 C4）
			body, subs, end := l.readHere(i)
			val.WriteString(body)
			t.subs = append(t.subs, subs...)
			i = end
		case c == '$' && i+1 < len(s) && s[i+1] == '{':
			// ${name}：变量名按字面，到 } 为止
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				end = len(s) - i - 1
			}
			val.WriteString(s[i : i+end+1])
			bare.WriteString(s[i : i+end+1])
			i += end + 1
		case c == '(' || c == '{' || ((c == '$' || c == '@') && i+1 < len(s) && (s[i+1] == '(' || (c == '@' && s[i+1] == '{'))):
			open := i
			if c == '$' || c == '@' {
				open++
			}
			closer := byte(')')
			if s[open] == '{' {
				closer = '}'
			}
			end := l.skipCode(open+1, closer)
			t.subs = append(t.subs, s[open+1:end])
			if end < len(s) {
				end++
			}
			val.WriteString(s[i:end])
			bare.WriteString(s[i:end])
			i = end
		default:
			val.WriteByte(c)
			bare.WriteByte(c)
			i++
			if c == ',' {
				commaEnd = i
			}
		}
	}
	t.end = len(s)
	t.value, t.bare, t.comma = val.String(), bare.String(), commaEnd == t.end
	return t
}

// readSingle 读 i 处的单引号字符串，返回内容与字符串之后的位置。” 是一个单引号；未闭合时到末尾。
func readSingle(s string, i int) (string, int) {
	var b strings.Builder
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\'' {
			if j+1 < len(s) && s[j+1] == '\'' {
				b.WriteByte('\'')
				j++
				continue
			}
			return b.String(), j + 1
		}
		b.WriteByte(s[j])
	}
	return b.String(), len(s)
}

// pwEscapes 是双引号字符串里反引号转义的特殊字符；其余字符转义为它本身。
var pwEscapes = map[byte]byte{'0': 0, 'a': '\a', 'b': '\b', 'e': 0x1b, 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}

// readDouble 读 i 处的双引号字符串：返回内容（转义已处理，$(…) 保留原文）、其中 $(…) 的代码与之后的位置。
func (l *pwLexer) readDouble(i int) (string, []string, int) {
	s := l.src
	var b strings.Builder
	var subs []string
	j := i + 1
	for j < len(s) {
		switch c := s[j]; {
		case c == '`' && j+1 < len(s):
			if e, ok := pwEscapes[s[j+1]]; ok {
				b.WriteByte(e)
			} else {
				b.WriteByte(s[j+1])
			}
			j += 2
		case c == '"':
			if j+1 < len(s) && s[j+1] == '"' {
				b.WriteByte('"')
				j += 2
				continue
			}
			return b.String(), subs, j + 1
		case c == '$' && j+1 < len(s) && s[j+1] == '(':
			end := l.skipCode(j+2, ')')
			subs = append(subs, s[j+2:end])
			if end < len(s) {
				end++
			}
			b.WriteString(s[j:end])
			j = end
		default:
			b.WriteByte(c)
			j++
		}
	}
	return b.String(), subs, len(s)
}

// hereStart 返回 i 处 here-string 开头（@' 或 @" 加可选空白与换行）的长度；不是时为 0。
func hereStart(s string, i int) int {
	if i+1 >= len(s) || s[i] != '@' || (s[i+1] != '\'' && s[i+1] != '"') {
		return 0
	}
	j := i + 2
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r') {
		j++
	}
	if j < len(s) && s[j] == '\n' {
		return j + 1 - i
	}
	return 0
}

// readHere 读 i 处的 here-string：返回正文、@"…"@ 正文里 $(…) 的代码与之后的位置。结束行以 '@（或 "@）开头；
// 未闭合时到末尾。
func (l *pwLexer) readHere(i int) (string, []string, int) {
	s := l.src
	quote := s[i+1]
	bodyStart := i + hereStart(s, i)
	closer := "\n" + string(quote) + "@"
	end, bodyEnd := len(s), len(s)
	if k := strings.Index(s[bodyStart-1:], closer); k >= 0 {
		bodyEnd = bodyStart - 1 + k
		end = bodyEnd + len(closer)
	}
	if bodyEnd < bodyStart {
		bodyEnd = bodyStart
	}
	body := strings.TrimSuffix(s[bodyStart:bodyEnd], "\r")
	var subs []string
	if quote == '"' {
		for j := bodyStart; j < bodyEnd; j++ {
			switch {
			case s[j] == '`':
				j++
			case s[j] == '$' && j+1 < bodyEnd && s[j+1] == '(':
				e := l.skipCode(j+2, ')')
				if e > bodyEnd {
					e = bodyEnd
				}
				subs = append(subs, s[j+2:e])
				j = e
			}
		}
	}
	return body, subs, end
}

// skipCode 从 i 起读代码，返回与之配对的 closer（) 或 }）的位置；没有时返回原文长度。引号、here-string、
// 注释与嵌套的括号按同一套规则跳过，续行照常记下。
func (l *pwLexer) skipCode(i int, closer byte) int {
	s := l.src
	tokenStart := true
	for i < len(s) {
		c := s[i]
		switch {
		case l.contLen(i) > 0:
			n := l.contLen(i)
			l.lx.conts = append(l.lx.conts, [2]int{i, n})
			i += n
			tokenStart = true
			continue
		case c == '`':
			i += 2
		case c == closer:
			return i
		case c == '\'':
			_, i = readSingle(s, i)
		case c == '"':
			_, _, i = l.readDouble(i)
		case c == '@' && hereStart(s, i) > 0:
			_, _, i = l.readHere(i)
		case c == '#' && tokenStart:
			i = lineEnd(s, i)
		case c == '<' && i+1 < len(s) && s[i+1] == '#':
			i = blockCommentEnd(s, i)
		case c == '(' || c == '{':
			inner := byte(')')
			if c == '{' {
				inner = '}'
			}
			i = l.skipCode(i+1, inner)
			if i < len(s) {
				i++
			}
		default:
			i++
		}
		if i <= len(s) && i > 0 {
			tokenStart = isPwBlank(s[i-1]) || strings.IndexByte("\n;|&({", s[i-1]) >= 0
		}
	}
	return len(s)
}

// pwSegment 是按分段运算符切开的一段。
type pwSegment struct {
	tokens     []pwToken
	start, end int
}

func (lx pwLexed) segments() []pwSegment {
	var out []pwSegment
	cur := pwSegment{start: -1}
	flush := func(end int) {
		if len(cur.tokens) > 0 {
			cur.end = end
			out = append(out, cur)
		}
		cur = pwSegment{start: -1}
	}
	for _, t := range lx.tokens {
		if t.kind == tokSep {
			flush(t.start)
			continue
		}
		if cur.start < 0 {
			cur.start = t.start
		}
		cur.tokens = append(cur.tokens, t)
	}
	flush(len(lx.src))
	return out
}

// pwAssign 匹配词开头的赋值（$x =、$env:A += 等）。
var pwAssign = regexp.MustCompile(`^\$[\w:{}?.\[\]]+\s*(?:[-+*/%]|\?\?)?=`)

// commandStart 返回段中的词（不含重定向的目标）、命令词的下标与命令开始的位置：跳过段首的调用运算符 & 与 .，
// 以及开头的赋值（$x = cmd、$x=cmd）。没有命令词时下标等于词数。
func (lx pwLexed) commandStart(seg pwSegment) (words []pwToken, k, at int) {
	target := false
	for _, t := range seg.tokens {
		switch {
		case t.kind == tokRedir:
			target = !strings.Contains(t.op, "&") // 2>&1 没有目标
		case t.kind == tokWord && target:
			target = false
		case t.kind == tokWord:
			words = append(words, t)
		}
	}
	for k < len(words) && (words[k].value == "&" || words[k].value == ".") && words[k].end-words[k].start == 1 {
		k++
	}
	if k < len(words) {
		w := words[k]
		raw := lx.join(w.start, w.end)
		if m := pwAssign.FindString(raw); m != "" && strings.HasPrefix(w.value, "$") {
			if len(m) < len(raw) {
				// $r=git：命令从 = 之后开始，就在这个词里
				return words, k, w.start + len(m)
			}
			k++
		} else if strings.HasPrefix(w.value, "$") && k+1 < len(words) && pwAssignOp(words[k+1].value) {
			k += 2
		}
		// 赋值右边的调用运算符同样跳过（$r = & 'tool'、$r = . pwsh，计划第二轮评审 R2-03）
		for k < len(words) && (words[k].value == "&" || words[k].value == ".") && words[k].end-words[k].start == 1 {
			k++
		}
	}
	if k < len(words) {
		return words, k, words[k].start
	}
	return words, k, seg.end
}

func pwAssignOp(v string) bool {
	switch v {
	case "=", "+=", "-=", "*=", "/=", "%=", "??=":
		return true
	}
	return false
}

// pwshPositions 返回各段命令位置的文本（去掉续行与转义反引号）。注释不在其中：注释里的参数不是实际参数
// （计划评审 M3B-06）。
func pwshPositions(lx pwLexed) []string {
	var out []string
	for _, seg := range lx.segments() {
		if _, _, at := lx.commandStart(seg); at < seg.end {
			if s := strings.TrimSpace(lx.segmentText(seg, at)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// segmentText 返回段中从 at 起的词法单元的原文（去掉续行与转义反引号），单元之间保留原来的空白、去掉注释。
func (lx pwLexed) segmentText(seg pwSegment, at int) string {
	var b strings.Builder
	prev := -1
	for _, t := range seg.tokens {
		if t.end <= at {
			continue
		}
		start := max(t.start, at)
		if prev >= 0 {
			b.WriteString(stripComments(lx.join(prev, start)))
		}
		b.WriteString(lx.join(start, t.end))
		prev = t.end
	}
	return b.String()
}

// stripComments 去掉词法单元之间的注释（那里的 # 与 <# 都开始注释），换行保留。
func stripComments(gap string) string {
	var b strings.Builder
	for i := 0; i < len(gap); {
		switch {
		case strings.HasPrefix(gap[i:], "<#"):
			i = blockCommentEnd(gap, i)
		case gap[i] == '#':
			i = lineEnd(gap, i)
		default:
			b.WriteByte(gap[i])
			i++
		}
	}
	return b.String()
}

// pwshNormalized 返回各段命令位置的规范写法（见 TestPowerShellNormalizedPositions）：词取去掉引号与转义后的值，
// 命令词取路径或模块限定名的最后一段，${env:X}、${HOME} 写作 $env:X、$HOME，词末的 \ 与 / 去掉
// （盘符根与单独的分隔符保留），以单个空格连接。含空白的词保留原文写法。
func pwshNormalized(lx pwLexed) []string {
	var out []string
	for _, seg := range lx.segments() {
		words, k, at := lx.commandStart(seg)
		if at >= seg.end {
			continue
		}
		// 命令位置上的字符串是表达式（$x = 'Format-Volume'），不是调用；经 & 或 . 调用时才是命令
		// （计划评审 M3B-05）
		called := k > 0 && words[k-1].end-words[k-1].start == 1 && (words[k-1].value == "&" || words[k-1].value == ".")
		if rest := lx.src[at:]; !called && (strings.HasPrefix(rest, "'") || strings.HasPrefix(rest, `"`) || hereStart(rest, 0) > 0) {
			continue
		}
		var parts []string
		for i := k; i < len(words); i++ {
			w := words[i]
			v := w.value
			if i == k && at > w.start {
				v = pwshLex(lx.join(at, w.end)).firstValue()
			}
			switch {
			case strings.ContainsAny(v, " \t\n"):
				v = lx.join(w.start, w.end)
			default:
				if i == k {
					if j := strings.LastIndexAny(v, `\/`); j >= 0 && j+1 < len(v) {
						v = v[j+1:]
					}
				}
				v = trimSeparators(pwVarBraces.ReplaceAllString(v, "$$$1"))
			}
			parts = append(parts, v)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

// trimSeparators 去掉词末的 \ 与 /，单独的分隔符与盘符根（C:\）保留。
func trimSeparators(v string) string {
	t := strings.TrimRight(v, `\/`)
	switch {
	case t == v:
		return v
	case t == "":
		return v[:1]
	case len(t) == 2 && t[1] == ':' && isLetter(t[0]):
		return v[:3]
	}
	return t
}

// pwVarBraces 匹配 ${env:X}、${HOME} 这类带花括号的变量名。
var pwVarBraces = regexp.MustCompile(`\$\{((?:env:)?\w+)\}`)

// firstValue 返回第一个词的值。
func (lx pwLexed) firstValue() string {
	for _, t := range lx.tokens {
		if t.kind == tokWord {
			return t.value
		}
	}
	return ""
}

// pwshUnquoted 返回抹掉引号内容后的文本：引号之外的字符、运算符与空白原样保留。
func pwshUnquoted(lx pwLexed) string {
	var b strings.Builder
	last := 0
	for _, t := range lx.tokens {
		b.WriteString(lx.join(last, t.start))
		if t.kind == tokWord {
			b.WriteString(t.bare)
		} else {
			b.WriteString(lx.src[t.start:t.end])
		}
		last = t.end
	}
	b.WriteString(lx.join(last, len(lx.src)))
	return b.String()
}

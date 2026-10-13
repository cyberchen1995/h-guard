package command

import (
	"slices"
	"strings"
)

// tokKind 是 POSIX shell 词法单元的类型。
type tokKind uint8

const (
	tokWord    tokKind = iota // 词（可含引号、转义与命令替换）
	tokSep                    // 分段：; & | && || ;; |& ( ) 与换行
	tokRedir                  // 重定向与 here-string：< > >> <& >& <> >| <<<，分词但不分段
	tokHeredoc                // << 或 <<-
)

// token 是一个词法单元。start、end 为原文中的字节区间。
type token struct {
	kind       tokKind
	start, end int
	op         string   // 运算符（非词时；中间的续行已去掉）
	value      string   // 词：去掉引号、转义与续行后的值（命令替换保留原文）
	bare       string   // 词：引号之外的字符（转义保留原样），供 StripQuoted 使用
	quoted     bool     // 词：含引号或反斜杠转义
	subs       []string // 词：其中不在单引号内的命令替换 $(…)、`…`、<(…)、>(…) 的内容
}

// heredoc 是一个 heredoc：运算符、定界符与正文、结束行的区间。
type heredoc struct {
	op, delim            token
	bodyStart, bodyEnd   int // 正文（不含结束行）
	closeStart, closeEnd int // 结束行（不含换行）；未闭合时都等于原文长度
	closed               bool
}

// lexed 是一段命令的词法分析结果。heredoc 正文与结束行不产生词法单元。
//
// conts 是词法分析确认的续行（反斜杠加换行）中反斜杠的下标，升序：shell 在读入时就去掉它们，
// 所以 $\ 换行 ( 是命令替换、F\ 换行 OO=1 是赋值。去掉续行的视图（join）都由它生成，
// 不另写只认引号的扫描器（评审 R3-02、R3-03）。
type lexed struct {
	src      string
	tokens   []token
	heredocs []heredoc
	conts    []int
}

// join 返回 src[a:b] 去掉其中续行后的文本（分析过程中也可调用：只用已经记下的续行）。
func (lx lexed) join(a, b int) string {
	var in []int
	for _, p := range lx.conts {
		if a <= p && p+2 <= b {
			in = append(in, p)
		}
	}
	slices.Sort(in)
	var sb strings.Builder
	last := a
	for _, p := range slices.Compact(in) {
		sb.WriteString(lx.src[last:p])
		last = p + 2
	}
	sb.WriteString(lx.src[last:b])
	return sb.String()
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v' }

func isOpChar(c byte) bool { return strings.IndexByte(";&|()<>", c) >= 0 }

// isCont 报告 s[i:] 是否以反斜杠换行开头。
func isCont(s string, i int) bool { return i+1 < len(s) && s[i] == '\\' && s[i+1] == '\n' }

// skipConts 跳过从 i 开始的连续续行，返回其后的位置。
func skipConts(s string, i int) int {
	for isCont(s, i) {
		i += 2
	}
	return i
}

// at 返回 s[i]，越界时返回 0。
func at(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// lex 按 POSIX shell 的引用规则切分 s：单引号内一切按字面；双引号内反斜杠只转义 $ ` " \ 与换行；
// 引号外反斜杠转义下一个字符；词首的 # 开始注释。heredoc 的正文在所在行结束后读取，定界符按引号去除后的值
// 匹配，定界符的任何部分带引号或反斜杠时正文为字面量。
//
// 续行（反斜杠加换行）与 shell 一样先于词法单元的识别：在引号外、双引号内、${…} 与反引号内、不带引号定界符的
// heredoc 正文里去掉（$\ 换行 ( 仍是命令替换，&\ 换行 & 仍是 &&）；在单引号、$'…'、注释与带引号定界符的
// heredoc 正文里是字面内容。去掉的位置记在 conts 里。
// 未闭合的引号、命令替换一直延伸到末尾：宁可把后面的内容当作引号内的数据，也不凭空切出命令。
func lex(s string) lexed {
	l := lexer{lx: lexed{src: s}, wantDelim: -1}
	l.run(0)
	return l.finish()
}

// matchParen 返回与 s[open] == '(' 配对的右括号下标，以及括号内的续行：括号内按同一套词法规则读取，
// 引号、注释与 heredoc 正文中的 ) 都不算；没有配对时返回 -1。用于 $(…)、<(…)、>(…)。
func matchParen(s string, open int) (int, []int) {
	l := lexer{lx: lexed{src: s}, wantDelim: -1, subshell: true, stop: -1}
	l.run(open + 1)
	return l.stop, l.lx.conts
}

// lexer 是增量的词法分析状态。subshell 为真时在深度为 0 的 ) 处停止（stop 记下它的下标）。
type lexer struct {
	lx        lexed
	pending   []int // 本行出现、正文尚未读取的 heredoc
	wantDelim int   // 刚读到 <<，下一个词是定界符；值为 heredoc 序号
	subshell  bool
	depth     int
	stop      int
}

// cont 记下 i 处的续行。
func (l *lexer) cont(i int) { l.lx.conts = append(l.lx.conts, i) }

// contsBetween 记下 [a, b) 中运算符的字符之间、$ 与 ( 之间跳过的续行。这段里除续行外只有运算符字符，
// 没有别的反斜杠，所以遇到的反斜杠换行都是续行（运算符字符本身不能记成续行）。
func (l *lexer) contsBetween(a, b int) {
	for i := a; i < b; i++ {
		if isCont(l.lx.src, i) {
			l.cont(i)
			i++
		}
	}
}

// contsIn 记下 [a, b) 中全部未转义的反斜杠换行：用于在读入时整段去掉续行的上下文（反引号内、
// 不带引号定界符的 heredoc 正文），其中的引号不起作用。
func (l *lexer) contsIn(a, b int) {
	s := l.lx.src
	for i := a; i < b; i++ {
		if s[i] == '\\' {
			if i+1 < b && s[i+1] == '\n' {
				l.cont(i)
			}
			i++
		}
	}
}

// matchParen 是带续行记录的 matchParen。
func (l *lexer) matchParen(open int) int {
	end, conts := matchParen(l.lx.src, open)
	l.lx.conts = append(l.lx.conts, conts...)
	return end
}

// procSubst 报告 s[i] 是否是进程替换 <(…)、>(…) 的开头，返回 ( 的下标。
func procSubst(s string, i int) (int, bool) {
	if c := at(s, i); c != '<' && c != '>' {
		return 0, false
	}
	j := skipConts(s, i+1)
	return j, at(s, j) == '('
}

func (l *lexer) run(i int) {
	s := l.lx.src
	for i < len(s) {
		c := s[i]
		_, isProc := procSubst(s, i)
		switch {
		case isBlank(c):
			i++
		case isCont(s, i):
			l.cont(i)
			i += 2
		case c == '\n':
			l.lx.tokens = append(l.lx.tokens, token{kind: tokSep, start: i, end: i + 1, op: "\n"})
			i++
			l.wantDelim = -1
			for k, h := range l.pending {
				if k > 0 && i < len(s) && s[i] == '\n' { // 同一行的下一个 heredoc 从上一个结束行之后开始
					i++
				}
				i = l.readBody(h, i)
			}
			l.pending = l.pending[:0]
		case c == '#':
			if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(s)
			}
		case isProc:
			t := l.readWord(i)
			l.lx.tokens = append(l.lx.tokens, t)
			i = t.end
		case isOpChar(c):
			t := l.readOp(i)
			if l.subshell && t.op == "(" {
				l.depth++
			}
			if l.subshell && t.op == ")" {
				if l.depth == 0 {
					l.stop = t.start
					return
				}
				l.depth--
			}
			l.lx.tokens = append(l.lx.tokens, t)
			i = t.end
			l.wantDelim = -1
			if t.kind == tokHeredoc {
				l.lx.heredocs = append(l.lx.heredocs, heredoc{op: t})
				l.wantDelim = len(l.lx.heredocs) - 1
			}
		default:
			t := l.readWord(i)
			l.lx.tokens = append(l.lx.tokens, t)
			i = t.end
			if l.wantDelim >= 0 {
				l.lx.heredocs[l.wantDelim].delim = t
				l.pending = append(l.pending, l.wantDelim)
				l.wantDelim = -1
			}
		}
	}
}

// finish 丢掉只有运算符、没有定界符或没有正文的 <<，并把续行位置排序去重。
func (l *lexer) finish() lexed {
	kept := l.lx.heredocs[:0]
	for _, h := range l.lx.heredocs {
		if h.delim.end > 0 && (h.closed || h.bodyStart > 0) {
			kept = append(kept, h)
		}
	}
	l.lx.heredocs = kept
	slices.Sort(l.lx.conts)
	l.lx.conts = slices.Compact(l.lx.conts)
	return l.lx
}

// readBody 从 i 开始读取第 n 个 heredoc 的正文，返回结束行末尾的位置（指向结束行后的换行）。
// 结束行与定界符精确比较；<<- 只去掉每行的前导制表符。定界符不带引号时，正文里的反斜杠换行是续行
// （读入时就去掉，正文里的引号不起作用）：续行拼成的逻辑行整体与定界符比较（与 shell 一致，
// x\ 换行 EOF 不是结束行）。
func (l *lexer) readBody(n, i int) int {
	s := l.lx.src
	h := &l.lx.heredocs[n]
	h.bodyStart = i
	dash := h.op.op == "<<-"
	var logical strings.Builder
	lineStart := i
	for off := i; off <= len(s); {
		nl := strings.IndexByte(s[off:], '\n')
		line := s[off:]
		if nl >= 0 {
			line = s[off : off+nl]
		}
		part := line
		if dash {
			part = strings.TrimLeft(part, "\t")
		}
		if !h.delim.quoted && nl >= 0 && endsWithContinuation(part) {
			logical.WriteString(part[:len(part)-1])
			l.cont(off + len(line) - 1)
		} else {
			logical.WriteString(part)
			if logical.String() == h.delim.value {
				h.bodyEnd, h.closeStart, h.closeEnd, h.closed = lineStart, lineStart, off+len(line), true
				return off + len(line)
			}
			logical.Reset()
			lineStart = off + len(line) + 1
		}
		if nl < 0 {
			break
		}
		off += nl + 1
	}
	h.bodyEnd, h.closeStart, h.closeEnd = len(s), len(s), len(s)
	return len(s)
}

// endsWithContinuation 报告一行是否以未转义的反斜杠结尾（奇数个反斜杠）。
func endsWithContinuation(line string) bool {
	n := 0
	for k := len(line) - 1; k >= 0 && line[k] == '\\'; k-- {
		n++
	}
	return n%2 == 1
}

var ops = []string{"<<<", "<<-", "&&", "||", ";;", "|&", "<<", ">>", "<&", ">&", "<>", ">|", ";", "&", "|", "(", ")", "<", ">"}

// readOp 读取从 i 开始的运算符。运算符的字符之间可以有续行（&\ 换行 & 即 &&，<\ 换行 < 即 heredoc）。
func (l *lexer) readOp(i int) token {
	s := l.lx.src
	var pos []int // 运算符各字符的下标
	var chars []byte
	for j := i; len(pos) < 3 && j < len(s); {
		if len(pos) > 0 && isCont(s, j) {
			j += 2
			continue
		}
		pos, chars = append(pos, j), append(chars, s[j])
		j++
	}
	for _, op := range ops {
		if strings.HasPrefix(string(chars), op) {
			end := pos[len(op)-1] + 1
			l.contsBetween(i+1, end) // 运算符字符之间只有续行
			t := token{start: i, end: end, op: op, kind: tokSep}
			switch op {
			case "<<", "<<-":
				t.kind = tokHeredoc
			case "<<<", ">>", "<&", ">&", "<>", ">|", "<", ">":
				t.kind = tokRedir
			}
			return t
		}
	}
	return token{kind: tokSep, start: i, end: i + 1, op: s[i : i+1]}
}

// readWord 读取从 i 开始的一个词，直到引号之外的空白、换行或运算符。
func (l *lexer) readWord(i int) token {
	s := l.lx.src
	t := token{kind: tokWord, start: i}
	var val, bare strings.Builder
	// paren 读取 s[open] == '(' 开始的替换，返回右括号的下标（未闭合时为末尾）
	paren := func(open int) int {
		end := l.matchParen(open)
		if end < 0 {
			t.subs = append(t.subs, s[min(open+1, len(s)):])
			return len(s) - 1
		}
		t.subs = append(t.subs, s[open+1:end])
		return end
	}
	for i < len(s) {
		c := s[i]
		j := skipConts(s, i+1) // $、<、> 之后跳过续行再看下一个字符
		switch {
		case isBlank(c) || c == '\n':
			goto done
		case (c == '<' || c == '>') && at(s, j) == '(' && i == t.start:
			l.contsBetween(i+1, j)
			end := paren(j)
			val.WriteString(s[i : end+1])
			bare.WriteString(s[i : end+1])
			i = end + 1
		case isOpChar(c):
			goto done
		case isCont(s, i):
			l.cont(i) // 续行：反斜杠与换行都去掉，词继续
			i += 2
		case c == '\\':
			t.quoted = true
			if i+1 < len(s) {
				val.WriteByte(s[i+1])
				bare.WriteString(s[i : i+2])
				i += 2
			} else {
				val.WriteByte(c)
				bare.WriteByte(c)
				i++
			}
		case c == '\'':
			t.quoted = true
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				val.WriteString(s[i+1:])
				i = len(s)
			} else {
				val.WriteString(s[i+1 : i+1+end])
				i += end + 2
			}
		case c == '$' && at(s, j) == '\'':
			l.contsBetween(i+1, j)
			t.quoted = true
			k := j + 1
			for k < len(s) && s[k] != '\'' {
				if s[k] == '\\' {
					k++
				}
				k++
			}
			val.WriteString(s[j+1 : min(k, len(s))])
			i = min(k+1, len(s))
		case c == '"':
			t.quoted = true
			i = l.readDouble(i+1, &val, &t)
		case c == '$' && at(s, j) == '(':
			l.contsBetween(i+1, j)
			end := paren(j)
			val.WriteString(s[i : end+1])
			bare.WriteString(s[i : end+1])
			i = end + 1
		case c == '`':
			end := l.backtick(i, &t)
			val.WriteString(s[i : end+1])
			bare.WriteString(s[i : end+1])
			i = end + 1
		case c == '$' && at(s, j) == '{':
			l.contsBetween(i+1, j)
			end := l.closingBrace(j, &t)
			if end < 0 {
				end = len(s) - 1
			}
			val.WriteString(s[i : end+1])
			bare.WriteString(s[i : end+1])
			i = end + 1
		default:
			val.WriteByte(c)
			bare.WriteByte(c)
			i++
		}
	}
done:
	t.end = i
	t.value, t.bare = val.String(), bare.String()
	return t
}

// readDouble 读取双引号内的内容（从 i 开始，不含开引号），返回闭引号之后的位置。
func (l *lexer) readDouble(i int, val *strings.Builder, t *token) int {
	s := l.lx.src
	for i < len(s) {
		c := s[i]
		switch {
		case c == '"':
			return i + 1
		case isCont(s, i):
			l.cont(i)
			i += 2
		case c == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\", s[i+1]) >= 0:
			val.WriteByte(s[i+1])
			i += 2
		case c == '$' && at(s, skipConts(s, i+1)) == '(':
			j := skipConts(s, i+1)
			l.contsBetween(i+1, j)
			end := l.matchParen(j)
			if end < 0 {
				t.subs = append(t.subs, s[j+1:])
				val.WriteString(s[i:])
				return len(s)
			}
			t.subs = append(t.subs, s[j+1:end])
			val.WriteString(s[i : end+1])
			i = end + 1
		case c == '`':
			end := l.backtick(i, t)
			val.WriteString(s[i : end+1])
			i = end + 1
		default:
			val.WriteByte(c)
			i++
		}
	}
	return len(s)
}

// backtick 读取 s[open] == '`' 开始的命令替换，返回闭合反引号的下标（未闭合时为末尾）。反引号内的续行
// 在读入时就去掉（其中的引号不起作用），内层命令取去掉续行、还原 \` 之后的内容。
func (l *lexer) backtick(open int, t *token) int {
	s := l.lx.src
	end := closingBacktick(s, open+1)
	if end < 0 {
		end = len(s)
	}
	l.contsIn(open+1, end)
	t.subs = append(t.subs, strings.ReplaceAll(l.lx.join(open+1, end), "\\`", "`"))
	return min(end, len(s)-1)
}

// closingBrace 返回与 s[open] == '{' 配对的右花括号下标，考虑引号与转义；没有时返回 -1（其后全部算在里面）。
// 单引号之外的续行记入 conts。其中的命令替换 $(…) 与反引号（双引号内也是）、引号外的进程替换 <(…)、>(…)
// （默认值里任何位置都会执行，评审 R5-01）交给同一套词法分析读取，内容记入 t.subs：里面的引号、注释与续行
// 按各自的上下文处理，不由这里的单层引号状态解释（评审 R4-02）。引号内的 <(…)、>(…) 是字面内容。
func (l *lexer) closingBrace(open int, t *token) int {
	s := l.lx.src
	depth := 0
	var quote byte
	for i := open; i < len(s); i++ {
		c := s[i]
		j := skipConts(s, i+1)
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case isCont(s, i):
			l.cont(i)
			i++
		case c == '\\':
			i++
		case c == '$' && at(s, j) == '(', quote == 0 && (c == '<' || c == '>') && at(s, j) == '(':
			l.contsBetween(i+1, j)
			end := l.matchParen(j)
			if end < 0 {
				t.subs = append(t.subs, s[j+1:])
				return -1
			}
			t.subs = append(t.subs, s[j+1:end])
			i = end
		case quote == 0 && c == '$' && at(s, j) == '\'':
			// $'…'：与 readWord 一致，反斜杠转义下一个字符（\' 不结束引号），其中一切按字面
			l.contsBetween(i+1, j)
			k := j + 1
			for k < len(s) && s[k] != '\'' {
				if s[k] == '\\' {
					k++
				}
				k++
			}
			i = k
		case c == '`':
			i = l.backtick(i, t) // 未闭合时为末尾，循环随之结束
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func closingBacktick(s string, from int) int {
	for i := from; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '`':
			return i
		}
	}
	return -1
}

// segment 是按分段运算符切开的一段：词法单元与原文区间 [start, end)。
// heredoc 正文与结束行在换行之后，不属于任何一段。
type segment struct {
	tokens     []token
	start, end int
}

// segments 返回各段，丢掉没有词法单元的空段。
func (lx lexed) segments() []segment {
	var out []segment
	var cur segment
	cur.start = -1
	flush := func(end int) {
		if len(cur.tokens) > 0 {
			cur.end = end
			out = append(out, cur)
		}
		cur = segment{start: -1}
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

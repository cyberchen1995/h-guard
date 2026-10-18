package codex

import (
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/applypatch"
)

// errUnparsed 表示 apply_patch 的内容读不懂：不能当作「没有动作」，调用方按 harness.TargetUnparsedError 请求确认。
var errUnparsed = applypatch.ErrUnparsed

const (
	beginPatch = applypatch.BeginPatch
	endPatch   = applypatch.EndPatch
)

// patchActions 把 apply_patch 的补丁转成动作（见 applypatch.Actions）。
func patchActions(patch string) ([]guard.Action, error) { return applypatch.Actions(patch) }

// applyPatchWord 认出命令里的 apply_patch（Codex 也接受 applypatch），在去掉引号与反斜杠之后的文本上匹配，
// a'p'ply_patch、app\ly_patch 这类写法同样算。
var applyPatchWord = regexp.MustCompile(`(^|[^A-Za-z0-9_])apply_?patch([^A-Za-z0-9_]|$)`)

// embeddedPatches 读出命令文本里的补丁（经 shell 调用的 apply_patch）。补丁正文对 shell 是数据，命令规则看不到其中
// 的路径，所以这里是文件动作唯一的来源。
//
// 命令提到 apply_patch 时，只接受能静态读懂的写法（shellPatch）：一次调用，补丁来自 heredoc 或单引号参数，可选的
// cd <字面路径> && 前缀（相对路径按它解析），可选的 bash -lc 包装。其余写法——补丁来自文件、管道或变量，补丁里的
// 路径会被 shell 展开，有别的命令——一律返回 errUnparsed：调用方请求确认，不能被别处的一份字面补丁抵消。没有提到 apply_patch 的补丁（如写进文件）读得出就照样加上文件动作，只会更严；读不出就当作数据。
// 带着补丁的命令里有展开时，不能断定补丁没有交给 apply_patch（工具名可以由变量拼出），也不知道它在哪个目录生效，
// 同样返回 errUnparsed。
func embeddedPatches(cmd string) ([]guard.Action, error) {
	// 是否提到 apply_patch 看两处，任一处认出即可：按 shell 词法读出的词（$'…' 按 ANSI-C 解码），
	// 以及去掉反斜杠续行、引号与反斜杠之后的整段文本（词法读不完整时的兜底）
	words, dynamic, lexed := commandWords(cmd)
	if !applyPatchWord.MatchString(strings.NewReplacer("\\\n", "", `'`, "", `"`, "", `\`, "").Replace(cmd)) &&
		!slices.ContainsFunc(words, applyPatchWord.MatchString) {
		if strings.Contains(cmd, beginPatch) && (dynamic || !lexed) {
			return nil, errUnparsed
		}
		return dataPatches(cmd)
	}
	dir, patch, ok := shellPatch(cmd, 0)
	if !ok {
		return nil, errUnparsed
	}
	acts, err := patchActions(patch)
	if err != nil {
		return nil, err
	}
	if dir != "" {
		for i := range acts {
			acts[i].File.Path = under(dir, acts[i].File.Path)
			if acts[i].File.To != "" {
				acts[i].File.To = under(dir, acts[i].File.To)
			}
		}
	}
	return acts, nil
}

// dataPatches 读出没有交给 apply_patch 的补丁（如写进文件）里的文件动作。读不出的补丁（缺结尾、格式不对，如用
// printf 写成一行的）返回 errUnparsed：工具名可以经 sed、xargs 之类拼出而不带任何展开，看不出这份补丁是否被
// 执行，就不能当作数据丢掉。
func dataPatches(cmd string) ([]guard.Action, error) {
	var out []guard.Action
	for rest := cmd; ; {
		i := strings.Index(rest, beginPatch)
		if i < 0 {
			return out, nil
		}
		j := strings.Index(rest[i:], endPatch)
		if j < 0 {
			return nil, errUnparsed
		}
		acts, err := patchActions(rest[i : i+j+len(endPatch)])
		if err != nil {
			return nil, errUnparsed
		}
		out = append(out, acts...)
		rest = rest[i+j+len(endPatch):]
	}
}

// under 把相对路径放到 dir 下；绝对路径（/、~、盘符、\\ 开头）不变。
func under(dir, p string) string {
	if !relative(p) {
		return p
	}
	return strings.TrimRight(dir, `/\`) + "/" + p
}

// shellPatch 按 POSIX shell 的规则读一条 apply_patch 调用，返回 cd 的目录（没有时为空）与补丁原文。认得的写法：
//
//	[bash|sh|zsh -c|-lc '<内层>']     内层同样按本函数读（只一层）
//	[cd <字面路径> &&] apply_patch|applypatch <<[-]DELIM … DELIM
//	[cd <字面路径> &&] apply_patch|applypatch '<补丁>'
//
// 词按 shell 的引号规则去掉引号（反斜杠续行先去掉）；词里有 $、反引号、通配符或花括号（会被展开）时读不懂。
// cd 的目录见 cdDir。
// 不带引号的 heredoc 正文里有 $、反引号或反斜杠时读不懂。调用之后除了空白不能再有别的内容。
func shellPatch(s string, depth int) (dir, patch string, ok bool) {
	s = strings.TrimSpace(s)
	w, rest, ok := readWord(s)
	if !ok {
		return "", "", false
	}
	if depth == 0 && (w == "bash" || w == "sh" || w == "zsh" || strings.HasSuffix(w, "/bash") || strings.HasSuffix(w, "/sh") || strings.HasSuffix(w, "/zsh")) {
		flag, rest, ok := readWord(strings.TrimLeft(rest, " \t"))
		if !ok || (flag != "-c" && flag != "-lc" && flag != "-cl") {
			return "", "", false
		}
		inner, rest, ok := readWord(strings.TrimLeft(rest, " \t"))
		if !ok || strings.TrimSpace(rest) != "" {
			return "", "", false
		}
		return shellPatch(inner, 1)
	}
	if w == "cd" {
		src := strings.TrimLeft(rest, " \t")
		d, r, ok := readWord(src)
		if ok {
			d, ok = cdDir(src[:len(src)-len(r)], d)
		}
		r = strings.TrimLeft(r, " \t")
		if !ok || !strings.HasPrefix(r, "&&") {
			return "", "", false
		}
		dir = d
		if w, rest, ok = readWord(strings.TrimLeft(r[2:], " \t\n")); !ok {
			return "", "", false
		}
	}
	if w != "apply_patch" && w != "applypatch" {
		return "", "", false
	}
	rest = strings.TrimLeft(rest, " \t")
	if strings.HasPrefix(rest, "<<") {
		patch, ok = readHeredoc(rest[2:])
		return dir, patch, ok
	}
	if !strings.HasPrefix(rest, "'") {
		return "", "", false
	}
	patch, rest, ok = readWord(rest)
	return dir, patch, ok && strings.TrimSpace(rest) == ""
}

// cdDir 判断 cd 的目录：src 是词的原文，d 是去掉引号之后的结果。按 shell 的运行时语义：
//   - cd - 与选项由运行时决定或改变 cd 的行为，读不懂；
//   - 词以不带引号的 ~ 开头、tilde 前缀（到第一个不带引号的 / 为止）里没有任何引用时才展开为 Home。前缀里有引用
//     （包括一对空引号，如 ~ 之后紧跟两个单引号，或 ~"/"），或 ~ 本身来自引号或转义时，是 cwd 下名为 ~ 的目录，
//     解析为 ./~…；~user、~+、~- 由运行时决定，读不懂。反斜杠续行在识别词之前就被 shell 去掉，
//     不是引用；
//   - 不以 /、~、.、.. 开头的相对目录受 CDPATH 影响，读不懂。
func cdDir(src, d string) (string, bool) {
	for strings.HasPrefix(src, "\\\n") {
		src = src[2:]
	}
	switch {
	case d == "" || strings.HasPrefix(d, "-"):
		return "", false
	case strings.HasPrefix(src, "~"):
		home := true
	prefix:
		for i := 1; i < len(src); i++ {
			switch {
			case strings.HasPrefix(src[i:], "\\\n"):
				i++
			case src[i] == '/':
				break prefix
			case strings.IndexByte(`'"\`, src[i]) >= 0:
				return "./" + d, true
			default:
				home = false
			}
		}
		if !home {
			return "", false
		}
		return d, true
	case strings.HasPrefix(d, "~"):
		return "./" + d, true
	case relative(d) && d != "." && d != ".." && !strings.HasPrefix(d, "./") && !strings.HasPrefix(d, "../"):
		return "", false
	}
	return d, true
}

// readWord 从 s 开头读一个 shell 词：单引号里按字面，双引号里只认 \\ \" \$ \` 转义，引号外的反斜杠转义下一个字符。
// 词在空白或运算符（; & | < > ( ) 换行）处结束。会被展开的写法（引号外或双引号里的 $、反引号，引号外的通配符与
// 花括号）返回 ok 为假。开头的 ~ 照原样保留（是否展开由调用方按原文判断，见 cdDir）。
func readWord(s string) (word, rest string, ok bool) {
	var b strings.Builder
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return "", "", false
			}
			b.WriteString(s[i+1 : i+1+j])
			i += j + 2
		case c == '"':
			i++
			for {
				if i >= len(s) {
					return "", "", false
				}
				if s[i] == '"' {
					i++
					break
				}
				if s[i] == '$' || s[i] == '`' {
					return "", "", false
				}
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\\\"$`\n", s[i+1]) >= 0 {
					if s[i+1] != '\n' {
						b.WriteByte(s[i+1])
					}
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
		case c == '\\':
			if i+1 >= len(s) {
				return "", "", false
			}
			if s[i+1] != '\n' {
				b.WriteByte(s[i+1])
			}
			i += 2
		case strings.IndexByte(" \t\n;&|<>()", c) >= 0:
			if i == 0 {
				return "", s, false
			}
			return b.String(), s[i:], true
		case strings.IndexByte("$`*?[]{}", c) >= 0:
			return "", "", false
		default:
			b.WriteByte(c)
			i++
		}
	}
	if i == 0 {
		return "", "", false
	}
	return b.String(), "", true
}

// commandWords 按 shell 的词法读出命令里的词，只用来判断命令是否提到 apply_patch：单引号、双引号、
// 反斜杠按 shell 的规则去掉，$'…' 按 ANSI-C 转义解码（a$'pply_patch' 与 $'\x61pply_patch' 都是 apply_patch），
// $"…" 同双引号；heredoc 正文不是词，跳过。不做任何求值：展开（引号外或双引号里的 $ 与反引号，不带引号的 heredoc
// 正文里的 $ 与反引号）原样留在词里，并由 dynamic 报告。引号或 heredoc 不完整时 ok 为假。
func commandWords(s string) (words []string, dynamic, ok bool) {
	type heredoc struct {
		delim         string
		strip, quoted bool
	}
	var (
		b       strings.Builder
		inWord  bool
		pending []heredoc
	)
	flush := func() {
		if inWord {
			words = append(words, b.String())
			b.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return words, dynamic, false
			}
			if s[i+1] != '\n' {
				b.WriteByte(s[i+1])
				inWord = true
			}
			i += 2
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return words, dynamic, false
			}
			b.WriteString(s[i+1 : i+1+j])
			inWord = true
			i += j + 2
		case c == '$' && strings.HasPrefix(s[i+1:], "'"):
			dec, n, ok := ansiC(s[i+2:])
			if !ok {
				return words, dynamic, false
			}
			b.WriteString(dec)
			inWord = true
			i += 2 + n
		case c == '"' || c == '$' && strings.HasPrefix(s[i+1:], `"`):
			if c == '$' {
				i++
			}
			inWord = true
			for i++; ; {
				if i >= len(s) {
					return words, dynamic, false
				}
				if s[i] == '"' {
					i++
					break
				}
				if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\\\"$`\n", s[i+1]) >= 0 {
					if s[i+1] != '\n' {
						b.WriteByte(s[i+1])
					}
					i += 2
					continue
				}
				if s[i] == '$' || s[i] == '`' {
					dynamic = true
				}
				b.WriteByte(s[i])
				i++
			}
		case c == '$' || c == '`':
			dynamic = true
			b.WriteByte(c)
			inWord = true
			i++
		case c == '\n':
			flush()
			i++
			for _, h := range pending {
				for {
					if i >= len(s) {
						return words, dynamic, false
					}
					end := strings.IndexByte(s[i:], '\n')
					if end < 0 {
						end = len(s) - i
					}
					line := s[i : i+end]
					i += end + 1
					if h.strip {
						line = strings.TrimLeft(line, "\t")
					}
					if line == h.delim {
						break
					}
					if !h.quoted && strings.ContainsAny(line, "$`") {
						dynamic = true
					}
				}
			}
			pending = nil
		case strings.HasPrefix(s[i:], "<<") && !strings.HasPrefix(s[i:], "<<<"):
			flush()
			i += 2
			h := heredoc{strip: strings.HasPrefix(s[i:], "-")}
			if h.strip {
				i++
			}
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			delim, rest, ok := readWord(s[i:])
			if !ok {
				return words, dynamic, false
			}
			h.delim, h.quoted = delim, strings.ContainsAny(s[i:len(s)-len(rest)], `'"\`)
			pending = append(pending, h)
			i = len(s) - len(rest)
		case strings.IndexByte(" \t;&|()<>", c) >= 0:
			flush()
			i++
		default:
			b.WriteByte(c)
			inWord = true
			i++
		}
	}
	flush()
	return words, dynamic, len(pending) == 0
}

// ansiC 解码 $'…' 的内容（s 从开引号之后开始），返回解码结果与读过的字节数（含结束的单引号）。与 bash 相同，解码出
// 零字节（\0、\x00、\u0000、\c@ 等）时截断这一段：零字节与之后到结束引号的内容都不要，引号之后的部分照常拼接。
func ansiC(s string) (string, int, bool) {
	var b strings.Builder
	cut := false
	emit := func(p string) {
		if cut {
			return
		}
		if k := strings.IndexByte(p, 0); k >= 0 {
			p, cut = p[:k], true
		}
		b.WriteString(p)
	}
	for i := 0; i < len(s); {
		c := s[i]
		if c == '\'' {
			return b.String(), i + 1, true
		}
		if c != '\\' || i+1 >= len(s) {
			emit(s[i : i+1])
			i++
			continue
		}
		e := s[i+1]
		i += 2
		if k := strings.IndexByte("abeEfnrtv", e); k >= 0 {
			emit("\a\b\x1b\x1b\f\n\r\t\v"[k : k+1])
			continue
		}
		switch e {
		case '\\', '\'', '"', '?':
			emit(string(e))
		case 'c':
			if i < len(s) {
				emit(string(s[i] & 0x1f))
				i++
			}
		case 'x', 'u', 'U':
			max := map[byte]int{'x': 2, 'u': 4, 'U': 8}[e]
			v, n := 0, 0
			for ; n < max && i+n < len(s) && strings.IndexByte("0123456789abcdefABCDEF", s[i+n]) >= 0; n++ {
				v = v*16 + hexVal(s[i+n])
			}
			switch {
			case n == 0:
				emit("\\" + string(e))
			case e == 'x':
				emit(string([]byte{byte(v)}))
			default:
				emit(string(rune(v)))
			}
			i += n
		default:
			if e < '0' || e > '7' {
				emit("\\" + string(e))
				continue
			}
			v, n := int(e-'0'), 0
			for ; n < 2 && i+n < len(s) && s[i+n] >= '0' && s[i+n] <= '7'; n++ {
				v = v*8 + int(s[i+n]-'0')
			}
			emit(string([]byte{byte(v)}))
			i += n
		}
	}
	return "", 0, false
}

func hexVal(c byte) int {
	switch {
	case c >= 'a':
		return int(c-'a') + 10
	case c >= 'A':
		return int(c-'A') + 10
	}
	return int(c - '0')
}

// readHeredoc 读 << 之后的部分：[-]、定界符（带引号时正文按字面）、换行、正文与结束行；结束行之后只能有空白。
// 不带引号的定界符：正文里有 $、反引号或反斜杠（展开或续行）就读不懂——展开出来的值可以含换行与新的操作头，
// 不只路径行要紧。
func readHeredoc(s string) (string, bool) {
	strip := strings.HasPrefix(s, "-")
	if strip {
		s = s[1:]
	}
	s = strings.TrimLeft(s, " \t")
	nl := strings.IndexByte(s, '\n')
	if nl < 0 {
		return "", false
	}
	head := strings.TrimRight(s[:nl], " \t")
	quoted := strings.ContainsAny(head, `'"\`)
	delim, rest, ok := readWord(head)
	if !ok || delim == "" || strings.TrimSpace(rest) != "" {
		return "", false
	}
	lines := strings.Split(s[nl+1:], "\n")
	for i, line := range lines {
		if strip {
			line = strings.TrimLeft(line, "\t")
		}
		if line != delim {
			continue
		}
		for _, after := range lines[i+1:] {
			if strings.TrimSpace(after) != "" {
				return "", false
			}
		}
		body := lines[:i]
		if strip {
			body = slices.Clone(body)
			for k := range body {
				body[k] = strings.TrimLeft(body[k], "\t")
			}
		}
		if !quoted {
			for _, l := range body {
				if strings.ContainsAny(l, "$`\\") {
					return "", false
				}
			}
		}
		return strings.Join(body, "\n"), true
	}
	return "", false
}

// relative 报告路径是否相对于 cwd（不以 /、~、盘符或 \\ 开头）。
func relative(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, `\\`) {
		return false
	}
	return !(len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

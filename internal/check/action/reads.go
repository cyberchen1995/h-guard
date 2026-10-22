package action

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// maxGlobMatches 是一个通配符参数最多检查的文件数，也是一个递归读取的目录最多检查的文件数。
const maxGlobMatches = 1024

// maxWalkEntries 是递归展开（** 与 grep -r 等）最多查看的目录项数（文件与目录都算）。
const maxWalkEntries = 4 * maxGlobMatches

// readProblem 是命令读取的文件没有全部检查的原因：展开超过上限（dir 为空），或有目录读不了（dir 是那个目录）。
type readProblem struct {
	pattern string // 命令里的参数
	dir     string
}

// verdict 是没有全部检查时的结论：请求确认（失败即确认）。
func (p *readProblem) verdict() guard.Verdict {
	if p.dir != "" {
		return guard.Verdict{
			Decision: guard.DecisionAsk,
			Reasons: []guard.Reason{
				{Code: i18n.KeyActionReadUnreadable, Params: map[string]string{"pattern": p.pattern, "dir": p.dir}},
				{Code: i18n.KeyHintManual},
			},
		}
	}
	return globTooMany(p.pattern)
}

// globTooMany 是通配符参数匹配的文件太多、没有逐个检查时的结论：请求确认。
func globTooMany(pattern string) guard.Verdict {
	return guard.Verdict{
		Decision: guard.DecisionAsk,
		Reasons: []guard.Reason{
			{Code: i18n.KeyActionGlobTooMany, Params: map[string]string{"pattern": pattern, "limit": strconv.Itoa(maxGlobMatches)}},
			{Code: i18n.KeyHintManual},
		},
	}
}

// expandReads 把命令读取的文件展开成要逐个检查的路径。shell 展开发生在命令运行时，这里按磁盘现状展开：
//   - 花括号（{a,b}、{x..y}）只在 POSIX shell 里、且在引号之外时展开；
//   - 通配符参数换成它匹配到的文件（cat .env* 读到的是 .env），带通配符的原文不是一个文件，不检查；
//     引号里的通配符与 PowerShell 的 -LiteralPath 按字面，就是一个文件。* 与 ? 不匹配开头的点，与 shell 一致；
//     dotglob 为 true 时（命令里开了 shopt -s dotglob 等）也匹配，PowerShell 的通配符总是按匹配处理（只收紧）。
//     globstar 为 true 时 ** 跨目录匹配，有上限地递归展开；
//   - 递归读取的目录（grep -r、rg）换成其中会读到的文件，有上限。
//
// problem 不为空表示有内容没有全部检查（展开超过上限、目录读不了、时限用完），调用方据此请求确认。
func (c *Check) expandReads(ctx context.Context, targets []command.ReadTarget, cwd string, dotglob, globstar bool) (out []string, problem *readProblem) {
	fail := func(p *readProblem) {
		if problem == nil {
			problem = p
		}
	}
	abs := func(p string) string {
		if rest, ok := strings.CutPrefix(p, "~/"); ok && c.Paths.Home != "" {
			return filepath.Join(c.Paths.Home, rest)
		}
		if p == "~" && c.Paths.Home != "" {
			return c.Paths.Home
		}
		if !filepath.IsAbs(p) && cwd != "" {
			return filepath.Join(cwd, p)
		}
		return p
	}
	for _, t := range targets {
		words := []string{t.Path}
		if t.Brace {
			var complete bool
			words, complete = expandBraces(t.Path) // cat .{env,example}：先展开花括号，再展开通配符
			if !complete {
				fail(&readProblem{pattern: t.Path}) // 展开出的词超过上限：其余的没有检查
			}
		}
		for _, w := range words {
			var files []string
			switch {
			case !t.Glob || !strings.ContainsAny(w, "*?["):
				out = append(out, w)
				if t.Walk == nil || c.Paths.Lexical {
					continue
				}
				files = []string{abs(w)}
			case c.Paths.Lexical:
				continue // 只按文本判断时不读磁盘
			default:
				matches, bad, err := globRead(ctx, abs(w), dotglob || t.Shell == guard.ShellPowerShell, globstar && t.Shell != guard.ShellPowerShell)
				if err != nil {
					out = append(out, w) // 不是合法的通配符（引号里的 [）：shell 按字面读这个文件
					continue
				}
				if bad != nil {
					bad.pattern = w
					fail(bad)
				}
				out = append(out, matches...)
				files = matches
			}
			if t.Walk == nil {
				continue
			}
			for _, root := range files {
				found, bad := walkRead(ctx, root, t.Walk)
				if bad != nil {
					bad.pattern = w
					fail(bad)
				}
				out = append(out, found...)
			}
		}
	}
	return out, problem
}

// globRead 展开一个通配符（绝对路径或相对于进程的工作目录）。与 filepath.Glob 不同，读不了的目录（权限不够等）
// 不当作没有匹配：其中可能有要检查的文件，bad 写明这个目录。匹配超过 maxGlobMatches 时 bad 不为空且 dir 为空。
// globstar 为 true 时整段是 ** 的部分匹配零层或多层目录（不进入以点开头的目录，除非 dot；不跟随符号链接）。
func globRead(ctx context.Context, pattern string, dot, globstar bool) (matches []string, bad *readProblem, err error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, nil, err
	}
	pattern = filepath.Clean(pattern)
	if globstar {
		segs := strings.Split(filepath.ToSlash(pattern), "/")
		for i, s := range segs {
			if s != "**" {
				continue
			}
			// ** 之前的部分先按普通通配符展开，再从每个结果往下找
			base := strings.Join(segs[:i], "/")
			switch {
			case i == 0:
				base = "." // 相对路径（没有工作目录时）
			case base == "":
				base = "/"
			case strings.HasSuffix(base, ":"):
				base += "/" // C:/**
			}
			bases := []string{filepath.FromSlash(base)}
			if hasMeta(base) {
				if bases, bad, err = globRead(ctx, filepath.FromSlash(base), dot, false); err != nil || bad != nil {
					return nil, bad, err
				}
			}
			for _, b := range bases {
				found, bad := starWalk(ctx, b, segs[i:], dot)
				matches = append(matches, found...)
				if bad != nil {
					return matches, bad, nil
				}
				if len(matches) > maxGlobMatches {
					return matches[:maxGlobMatches], &readProblem{}, nil
				}
			}
			return matches, nil, nil
		}
	}
	matches, bad = globPaths(pattern)
	kept := matches[:0]
	segs := strings.Split(filepath.ToSlash(pattern), "/")
	for _, m := range matches {
		if dot || !hiddenByGlob(segs, strings.Split(filepath.ToSlash(m), "/")) {
			kept = append(kept, m)
		}
	}
	if len(kept) > maxGlobMatches {
		return kept[:maxGlobMatches], &readProblem{}, nil
	}
	return kept, bad, nil
}

// globPaths 与 filepath.Glob 的展开相同（pattern 已确认合法），另报告读不了的目录。
func globPaths(pattern string) ([]string, *readProblem) {
	if !hasMeta(pattern) {
		if _, err := os.Lstat(pattern); err != nil {
			return nil, unreadable(err, filepath.Dir(pattern))
		}
		return []string{pattern}, nil
	}
	dir, file := filepath.Split(pattern)
	vol := len(filepath.VolumeName(pattern))
	dir = cleanGlobPath(dir, vol)
	if !hasMeta(dir[vol:]) {
		return globDir(dir, file, nil)
	}
	if dir == pattern { // 防止无限递归（与 filepath.Glob 相同）
		return nil, nil
	}
	dirs, bad := globPaths(dir)
	if bad != nil {
		return nil, bad
	}
	var matches []string
	for _, d := range dirs {
		if matches, bad = globDir(d, file, matches); bad != nil {
			return matches, bad
		}
	}
	return matches, nil
}

// globDir 把目录 dir 里名字匹配 pattern 的项接在 matches 后面；dir 读不了时报告它。
func globDir(dir, pattern string, matches []string) ([]string, *readProblem) {
	fi, err := os.Stat(dir)
	if err != nil {
		return matches, unreadable(err, dir)
	}
	if !fi.IsDir() {
		return matches, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return matches, unreadable(err, dir)
	}
	for _, e := range entries {
		if ok, _ := filepath.Match(pattern, e.Name()); ok {
			matches = append(matches, filepath.Join(dir, e.Name()))
		}
	}
	return matches, nil
}

// unreadable 是读目录出错时的问题：不存在（或不是目录）的路径里没有文件，不算；其余错误（权限不够等）算。
func unreadable(err error, dir string) *readProblem {
	if errors.Is(err, fs.ErrNotExist) || isNotDir(err) {
		return nil
	}
	return &readProblem{dir: dir}
}

// isNotDir 报告错误是不是路径中间的一段不是目录（/etc/passwd/x）。
func isNotDir(err error) bool {
	var pe *fs.PathError
	return errors.As(err, &pe) && strings.Contains(strings.ToLower(pe.Err.Error()), "not a directory")
}

// cleanGlobPath 去掉目录末尾的分隔符（与 filepath.Glob 相同）。
func cleanGlobPath(path string, vol int) string {
	switch {
	case path == "":
		return "."
	case len(path) == vol+1 && os.IsPathSeparator(path[len(path)-1]):
		return path // /、\、C:\
	case vol == len(path) && vol == 2:
		return path + "." // C:
	}
	return path[:len(path)-1]
}

// hasMeta 报告路径里有没有通配符（与 filepath.Match 一致：Windows 以外 \ 是转义）。
func hasMeta(path string) bool {
	magic := `*?[`
	if runtime.GOOS != "windows" {
		magic = `*?[\`
	}
	return strings.ContainsAny(path, magic)
}

// starWalk 在 base 下找相对路径匹配 segs（以 ** 开头，各段以 / 分隔）的项，有上限地遍历：查看的目录项超过
// maxWalkEntries、读不了的目录与时限用完都报告问题。只进入还可能匹配的目录。
func starWalk(ctx context.Context, base string, segs []string, dot bool) (matches []string, bad *readProblem) {
	if segsMatch(segs, nil, dot, false) {
		matches = append(matches, base) // ** 匹配零层：base 本身（a/** 含 a）
	}
	seen := 0
	var walk func(dir string, rel []string) bool
	walk = func(dir string, rel []string) bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			bad = unreadable(err, dir)
			return bad == nil
		}
		for _, e := range entries {
			if seen++; seen > maxWalkEntries || ctx.Err() != nil {
				bad = &readProblem{}
				return false
			}
			p, r := filepath.Join(dir, e.Name()), append(rel[:len(rel):len(rel)], e.Name())
			if segsMatch(segs, r, dot, false) {
				matches = append(matches, p)
			}
			// 不跟随符号链接（bash 4.3 起与 zsh 的 ** 都不跟随）
			if e.IsDir() && segsMatch(segs, r, dot, true) && !walk(p, r) {
				return false
			}
		}
		return true
	}
	walk(base, nil)
	return matches, bad
}

// segsMatch 报告相对路径 name（各段）是否匹配 pat（各段，整段的 ** 匹配零层或多层）。prefix 为真时只问
// name 之下还有没有可能匹配（决定要不要进入这个目录）。不以点开头的通配符段与 ** 不匹配以点开头的名字，除非 dot。
func segsMatch(pat, name []string, dot, prefix bool) bool {
	if len(name) == 0 {
		return prefix || len(pat) == 0 || (len(pat) == 1 && pat[0] == "**")
	}
	if len(pat) == 0 {
		return false
	}
	hidden := !dot && strings.HasPrefix(name[0], ".")
	if pat[0] == "**" {
		if segsMatch(pat[1:], name, dot, prefix) {
			return true
		}
		return !hidden && segsMatch(pat, name[1:], dot, prefix)
	}
	if ok, _ := filepath.Match(pat[0], name[0]); !ok {
		return false
	}
	if hidden && hasMeta(pat[0]) && !strings.HasPrefix(pat[0], ".") {
		return false
	}
	return segsMatch(pat[1:], name[1:], dot, prefix)
}

// walkRead 是递归读取（grep -r、rg）从 root 读到的文件。root 不是目录时为空（文件本身已经检查）；命令行上给出的
// root 是符号链接时照样进入。查看的目录项超过 maxWalkEntries、文件超过 maxGlobMatches、有目录读不了、
// 时限用完时报告问题（其余文件没有检查）。
func walkRead(ctx context.Context, root string, w *command.Walk) (files []string, bad *readProblem) {
	fi, err := os.Stat(root)
	if err != nil {
		return nil, unreadable(err, root)
	}
	if !fi.IsDir() {
		return nil, nil
	}
	seen := 0
	var walk func(dir string) bool
	walk = func(dir string) bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			bad = unreadable(err, dir)
			return bad == nil
		}
		for _, e := range entries {
			name := e.Name()
			if !w.Hidden && strings.HasPrefix(name, ".") {
				continue
			}
			if seen++; seen > maxWalkEntries || ctx.Err() != nil {
				bad = &readProblem{}
				return false
			}
			p := filepath.Join(dir, name)
			isDir := e.IsDir()
			if e.Type()&fs.ModeSymlink != 0 {
				if !w.Follow {
					continue // 不跟随时目录里的符号链接跳过（grep -r、rg 都是这样）
				}
				fi, err := os.Stat(p)
				if err != nil {
					continue // 断开的链接：读不到内容
				}
				isDir = fi.IsDir() // 跟随时的环路由查看的目录项上限截断
			}
			if isDir {
				if !matchAny(w.ExcludeDir, name) && !walk(p) {
					return false
				}
				continue
			}
			if (len(w.Include) > 0 && !matchAny(w.Include, name)) || matchAny(w.Exclude, name) {
				continue
			}
			if files = append(files, p); len(files) > maxGlobMatches {
				bad = &readProblem{}
				return false
			}
		}
		return true
	}
	walk(root)
	return files, bad
}

// matchAny 报告文件名是否匹配 globs 中的任一个（不合法的模式不匹配）。
func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}
	return false
}

// readRulesActive 报告当前档位下有没有检查读文件的规则：没有时不必展开命令读取的文件。
func (c *Check) readRulesActive() bool {
	for _, r := range c.Rules.All() {
		if r.Enabled() && r.AppliesTo(guard.ActionFileRead) && (r.Locked || rules.TierCovers(c.Config.Action.Tier, guard.ActionFileRead)) {
			return true
		}
	}
	return false
}

// maxBraceWords 是一个参数的花括号最多展开出的词数。
const maxBraceWords = maxGlobMatches

// braceSeq 是花括号的序列写法：{x..y} 或 {x..y..incr}，x、y 同为整数或同为单个字母。
var braceSeq = regexp.MustCompile(`^(?:(-?\d+)\.\.(-?\d+)|([A-Za-z])\.\.([A-Za-z]))(?:\.\.(-?\d+))?$`)

// expandBraces 展开 bash 的花括号：{a,b}（可嵌套、可多组）与序列 {x..y[..incr]}（.en{u..v} 含 .env）；
// 没有花括号时就是 t 本身，原文也保留。展开出的词超过 maxBraceWords 时停下，complete 为 false。
func expandBraces(t string) (out []string, complete bool) {
	out = []string{t}
	for i := 0; i < len(out); i++ {
		if len(out) >= maxBraceWords {
			return out, false
		}
		w := out[i]
		for from := 0; ; {
			k := strings.IndexByte(w[from:], '{')
			if k < 0 {
				break
			}
			open := from + k
			from = open + 1
			if open > 0 && w[open-1] == '$' {
				continue // ${name} 是参数展开
			}
			// 找到与 open 配对的 }，记下顶层的逗号
			depth, commas, end := 0, []int{}, -1
			for j := open; j < len(w) && end < 0; j++ {
				switch w[j] {
				case '{':
					depth++
				case '}':
					if depth--; depth == 0 {
						end = j
					}
				case ',':
					if depth == 1 {
						commas = append(commas, j)
					}
				}
			}
			if end < 0 {
				break
			}
			var alts []string
			if len(commas) > 0 {
				bounds := append(append([]int{open}, commas...), end)
				for k := 0; k+1 < len(bounds); k++ {
					alts = append(alts, w[bounds[k]+1:bounds[k+1]])
				}
			} else if seq, ok := braceSequence(w[open+1:end], maxBraceWords-len(out)); !ok {
				return out, false // 序列展开出的词超过上限
			} else {
				alts = seq
			}
			if alts == nil {
				continue // 不是花括号展开（{x}）：看后面的
			}
			for _, a := range alts {
				out = append(out, w[:open]+a+w[end+1:])
			}
			break
		}
	}
	return out, true
}

// braceSequence 展开序列 x..y[..incr]（bash 的写法：整数有前导零时补齐位数，字母按字符编码依次取）；
// 不是序列时 seq 为空、ok 为真；展开出的词超过 limit 时 ok 为假。
func braceSequence(s string, limit int) (seq []string, ok bool) {
	m := braceSeq.FindStringSubmatch(s)
	if m == nil {
		return nil, true
	}
	step := int64(1)
	if m[5] != "" {
		n, err := strconv.ParseInt(m[5], 10, 64)
		if err != nil {
			return nil, false
		}
		if n < 0 {
			n = -n
		}
		if n != 0 {
			step = n
		}
	}
	var from, to int64
	width := 0
	if m[1] != "" {
		a, err1 := strconv.ParseInt(m[1], 10, 64)
		b, err2 := strconv.ParseInt(m[2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, false
		}
		from, to = a, b
		if zeroPadded(m[1]) || zeroPadded(m[2]) {
			width = max(len(m[1]), len(m[2]))
		}
	} else {
		from, to = int64(m[3][0]), int64(m[4][0])
	}
	span := to - from
	if span < 0 {
		span = -span
	}
	if span/step+1 > int64(limit) {
		return nil, false
	}
	dir := int64(1)
	if to < from {
		dir = -1
	}
	for v := from; (dir > 0 && v <= to) || (dir < 0 && v >= to); v += dir * step {
		if m[1] == "" {
			seq = append(seq, string(rune(v)))
			continue
		}
		n := strconv.FormatInt(v, 10)
		if width > 0 {
			neg := strings.HasPrefix(n, "-")
			n = strings.TrimPrefix(n, "-")
			pad := width - len(n)
			if neg {
				pad--
			}
			if pad > 0 {
				n = strings.Repeat("0", pad) + n
			}
			if neg {
				n = "-" + n
			}
		}
		seq = append(seq, n)
	}
	return seq, true
}

// zeroPadded 报告整数写法是否有前导零（01、-01）。
func zeroPadded(s string) bool {
	s = strings.TrimPrefix(s, "-")
	return len(s) > 1 && s[0] == '0'
}

// dotglobOn 认出命令里让通配符匹配点文件的设置：bash 的 shopt -s dotglob、GLOBIGNORE，zsh 的 setopt globdots。
var dotglobOn = regexp.MustCompile(`\bshopt\s+(?:-\w+\s+)*-s\b[^\n;&|]*\bdotglob\b|\bGLOBIGNORE=|\bsetopt\b[^\n;&|]*\bglob_?dots\b`)

// globstarOn 认出让 ** 递归匹配的设置：bash 的 shopt -s globstar。
var globstarOn = regexp.MustCompile(`\bshopt\s+(?:-\w+\s+)*-s\b[^\n;&|]*\bglobstar\b`)

// hiddenByGlob 报告匹配结果 m 是否经由一段不以点开头的通配符匹配了以点开头的名字：shell 不这样展开（*/* 不进 .ssh）。
func hiddenByGlob(pat, m []string) bool {
	if len(pat) != len(m) {
		return false
	}
	for i, p := range pat {
		if strings.ContainsAny(p, "*?[") && !strings.HasPrefix(p, ".") && strings.HasPrefix(m[i], ".") {
			return true
		}
	}
	return false
}

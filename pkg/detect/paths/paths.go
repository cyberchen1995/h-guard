// Package paths 解析文件动作的目标路径并按路径模式匹配（spec §5.5）。它是 h-guard 中路径解析的唯一来源：
// 规则包的 match.file.paths、护栏自我保护都经过这里。
//
// 解析：展开 ~，相对路径基于 cwd，规范化；再对已存在的最长前缀解析符号链接、拼上不存在的部分
// （写入目标可能还不存在；指向不存在文件的符号链接解析为链接目标，因为写入它会创建目标）。
// 原始路径与解析后的路径都参与匹配，任一命中即命中。解析失败（权限、循环链接）时只用规范化后的原始路径。
//
// 有些写法 realpath 不改写，却与另一个位置是同一个文件（Env.RootAliases、Env.Opaque，按平台取默认值）：
//   - 指向根目录的别名前缀（macOS 的 firmlink /System/Volumes/Data）：前缀之下的路径去掉前缀后另作候选；
//   - 无法映射到规范位置的前缀（macOS 的 volfs /.vol 按 inode 打开文件，Linux 的 /proc）：其下的目标标为 Opaque，
//     有模式的 Matcher 一律按命中处理（fail-closed，可能就是受保护的文件）。
//
// 按字面匹配（Lexical，规则样例）时两者都不处理。
//
// Windows（Env.Windows，spec §5.5 第 4 步）：\\?\、\\.\ 前缀先去掉（卷 GUID、GLOBALROOT 等无法映射到盘符的前缀
// 标为不透明）；每段末尾的点与空格、冒号之后的数据流名去掉后的写法另作候选；短文件名（8.3）换成长文件名后另作
// 候选；本机的管理共享（\\localhost\C$\…）换回盘符路径另作候选；盘符相对路径（C:foo）不透明；以单个分隔符
// 开头的路径（\Users\x）在 cwd 所在卷的根下；目录联接与
// 符号链接一样解析。\ 与 / 都是分隔符，比较时一律换成 /。
//
// 模式：`**/` 匹配零或多级目录，末尾的 `/**` 匹配目录本身及其下全部内容，其余 `**` 匹配任意字符，
// `*`、`?` 不跨目录；以 `~/` 开头的按主目录展开，以 `{name}` 开头的按 Env.Vars 展开。模式开头的
// 固定部分同样解析符号链接，所以受保护文件本身是符号链接时，改它的目标也命中。
package paths

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"
)

// Env 是解析路径与展开模式所需的环境。
type Env struct {
	Home     string            // 用户主目录；为空时不展开 ~，以 ~/ 开头的模式不匹配
	Cwd      string            // 相对路径的基准；为空时相对路径无法解析
	Vars     map[string]string // 模式开头 {name} 的值；没有值的模式不匹配
	FoldCase bool              // 不区分大小写比较
	Lexical  bool              // 不访问文件系统、不解析符号链接（规则样例用）
	// RootAliases 是指向根目录的别名前缀（绝对路径，用 / 分隔）；nil 时用 RootAliasesDefault，空切片表示没有
	RootAliases []string
	// Opaque 是无法映射到规范位置的前缀（绝对路径，用 / 分隔）；nil 时用 OpaqueDefault，空切片表示没有
	Opaque []string
	// Windows 按 Windows 的规则解析与比较（见包注释）；调用方一般设为 WindowsDefault。在其他平台上设为真时
	// 只有不访问文件系统的部分（前缀、末尾的点与空格、数据流、分隔符）有意义，供测试使用
	Windows bool
}

// FoldCaseDefault 报告当前平台的默认文件系统是否不区分大小写（macOS、Windows 是，Linux 否）。
var FoldCaseDefault = runtime.GOOS == "darwin" || runtime.GOOS == "windows"

// RootAliasesDefault 是当前平台指向根目录的别名前缀：macOS 的 firmlink /System/Volumes/Data（数据卷的挂载点，
// /System/Volumes/Data$HOME 与 $HOME 是同一个目录，realpath 不改写它），其他平台没有。
var RootAliasesDefault = map[string][]string{"darwin": {"/System/Volumes/Data"}}[runtime.GOOS]

// OpaqueDefault 是当前平台无法映射到规范位置的前缀：macOS 的 volfs /.vol（/.vol/<dev>/<ino> 按 inode 打开文件），
// Linux 的 /proc（/proc/<pid>/root、/proc/<pid>/cwd 等经由别的进程的视图打开文件），其他平台没有。
var OpaqueDefault = map[string][]string{"darwin": {"/.vol"}, "linux": {"/proc"}}[runtime.GOOS]

// 解析失败的原因。
var (
	ErrRelative = errors.New("relative path without a working directory")
	ErrNoHome   = errors.New("~ without a home directory")
	ErrLoop     = errors.New("too many levels of symbolic links")
)

// maxHops 是解析一个路径时最多跟随的符号链接数（与 Linux 的 MAXSYMLINKS 相同）。
const maxHops = 40

// Resolved 是一个路径的解析结果。
type Resolved struct {
	Clean string // 展开 ~、基于 cwd、规范化后的路径（不访问文件系统）
	Real  string // 再解析符号链接后的路径；解析失败或 Lexical 时为空
	Err   error  // 解析失败的原因；为 nil 时 Clean 是绝对路径
	// Aliases 是 Clean、Real 去掉根目录别名前缀（Env.RootAliases）后的写法，与两者都不同；Lexical 时为空
	Aliases []string
	// Opaque 报告 Clean、Real 或 Aliases 之一在 Env.Opaque 的前缀之下：无法得知它是哪个文件，
	// 有模式的 Matcher 一律按命中处理（见 Matcher.Match）。Lexical 时为 false
	Opaque bool
}

// Candidates 返回参与匹配的路径：Clean，与它不同的 Real，以及 Aliases。
func (r Resolved) Candidates() []string {
	out := []string{r.Clean}
	if r.Real != "" && r.Real != r.Clean {
		out = append(out, r.Real)
	}
	return append(out, r.Aliases...)
}

// Resolve 解析 path（spec §5.5 第 1、2、5 步）。Real 由未规范化的绝对路径解析：`alias/../x` 中 alias 是
// 符号链接时，.. 从链接目标回退（与操作系统打开文件时一致），提前 Clean 会把它错算成 `x`（评审 M2-02）。
func Resolve(path string, env Env) Resolved {
	var r Resolved
	var opaque bool
	if env.Windows {
		path, opaque = stripWindowsPrefix(path)
		if abs, rooted, ok := rootRelative(path, env.Cwd); rooted {
			if ok {
				path = abs
			} else {
				opaque = true // 不知道是哪个卷
			}
		}
	}
	raw, err := expandHome(path, env.Home)
	if err == nil && !filepath.IsAbs(raw) {
		if env.Cwd == "" || !filepath.IsAbs(env.Cwd) {
			err = ErrRelative
		} else {
			raw = env.Cwd + string(filepath.Separator) + raw // 不用 Join：Join 会 Clean
		}
	}
	r.Clean = filepath.Clean(raw)
	if err != nil {
		r.Err = err
		return r
	}
	if env.Lexical {
		return r
	}
	r.Real, r.Err = realpath(raw)
	r.Aliases, r.Opaque = rootForms(r, env)
	if env.Windows {
		r.Opaque = r.Opaque || opaque
		for _, c := range r.Candidates() {
			// 解析出的路径（如联接的目标）同样可能带卷 GUID 等前缀（评审 I7）
			stripped, op := stripWindowsPrefix(c)
			r.Opaque = r.Opaque || op
			for _, alt := range append([]string{stripped, longName(c)}, windowsForms(stripped, localHosts())...) {
				if alt != "" && !slices.Contains(r.Candidates(), alt) {
					r.Aliases = append(r.Aliases, alt)
				}
			}
		}
	}
	return r
}

// rootForms 按 env 的根目录别名与不透明前缀（nil 时取平台默认值）处理 Clean 与 Real：返回去掉别名前缀后的
// 写法（反复去掉，直到不再以别名前缀开头；不含 Clean、Real 本身），以及其中是否有路径在不透明前缀之下。
func rootForms(r Resolved, env Env) (aliases []string, opaque bool) {
	roots, opq := env.RootAliases, env.Opaque
	if roots == nil {
		roots = RootAliasesDefault
	}
	if opq == nil {
		opq = OpaqueDefault
	}
	seen := []string{r.Clean, r.Real}
	pending := []string{r.Clean, r.Real}
	for len(pending) > 0 {
		c := filepath.ToSlash(pending[0])
		pending = pending[1:]
		if c == "" {
			continue
		}
		for _, p := range opq {
			if _, ok := cutDir(c, p, env.FoldCase); ok {
				opaque = true
			}
		}
		for _, p := range roots {
			rest, ok := cutDir(c, p, env.FoldCase)
			if !ok || rest == c {
				continue
			}
			if alt := filepath.FromSlash(rest); !slices.Contains(seen, alt) {
				seen = append(seen, alt)
				aliases = append(aliases, alt)
				pending = append(pending, alt)
			}
		}
	}
	return aliases, opaque
}

// cutDir 报告用 / 分隔的绝对路径 p 是否等于目录 dir 或在其下（fold 时不区分大小写），并返回去掉 dir 后的
// 绝对路径（p 等于 dir 时为 /）。dir 末尾的 / 不计；dir 为 / 时一切绝对路径都在其下。
func cutDir(p, dir string, fold bool) (rest string, ok bool) {
	dir = strings.TrimRight(dir, "/")
	i := 0
	if fold {
		// 按字符比较：大小写不同的字符编码长度可能不同（如 ſ 与 s），不能按字节切分前缀
		for _, d := range dir {
			c, n := utf8.DecodeRuneInString(p[i:])
			if n == 0 || !strings.EqualFold(string(c), string(d)) {
				return "", false
			}
			i += n
		}
	} else if strings.HasPrefix(p, dir) {
		i = len(dir)
	} else {
		return "", false
	}
	switch rest = p[i:]; {
	case rest == "":
		return "/", true
	case rest[0] == '/':
		return rest, true
	}
	return "", false
}

// expandHome 展开开头的 ~ 与 ~/（~user 不展开）。不做规范化（见 Resolve）。
func expandHome(p, home string) (string, error) {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, "~"+string(filepath.Separator)) {
		return p, nil
	}
	if home == "" {
		return p, ErrNoHome
	}
	return home + p[1:], nil
}

// realpath 逐级解析绝对路径 abs 中的符号链接；从第一个不存在的部分起按字面拼接。
// 链接目标里的 .. 按已解析的真实位置回退。
func realpath(abs string) (string, error) {
	vol := filepath.VolumeName(abs)
	sep := string(filepath.Separator)
	pending := split(abs[len(vol):])
	cur := vol + sep
	hops := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return filepath.Join(append([]string{next}, pending...)...), nil
		}
		if err != nil {
			return "", err
		}
		target, isLink, err := readLink(next, fi)
		if err != nil {
			return "", err
		}
		if !isLink {
			cur = next
			continue
		}
		if hops++; hops > maxHops {
			return "", ErrLoop
		}
		if filepath.IsAbs(target) {
			tv := filepath.VolumeName(target)
			cur, target = tv+sep, target[len(tv):]
		}
		pending = append(split(target), pending...)
	}
	return cur, nil
}

func split(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == filepath.Separator })
}

var placeholder = regexp.MustCompile(`^\{([a-z][a-z0-9_]*)\}(?:/|$)`)

// Placeholder 返回模式开头 {name} 中的 name。
func Placeholder(pattern string) (string, bool) {
	m := placeholder.FindStringSubmatch(pattern)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ValidPattern 校验模式的写法：以 /、~/、**/ 或 {name} 开头，不含 . 与 .. 段。
func ValidPattern(pattern string) error {
	_, isVar := Placeholder(pattern)
	switch {
	case pattern == "":
		return errors.New("empty pattern")
	case !isVar && strings.HasPrefix(pattern, "{"):
		return errors.New("a placeholder is {name} in lower case, followed by / or the end")
	case !isVar && !strings.HasPrefix(pattern, "/") && !strings.HasPrefix(pattern, "~/") && !strings.HasPrefix(pattern, "**/"):
		return errors.New("a pattern starts with /, ~/, **/ or {name}")
	case strings.ContainsRune(pattern, 0):
		return errors.New("NUL in pattern")
	}
	for _, seg := range strings.Split(pattern, "/")[1:] {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%q segments are not allowed", seg)
		}
	}
	return nil
}

// Matcher 是按某个 Env 展开并编译好的一组模式。
type Matcher struct {
	res        []*regexp.Regexp
	windows    bool // 候选路径里的 \ 也是分隔符（Env.Windows）
	incomplete bool // 有受保护的目录读不全（超过 maxEntries 项或读取出错），其中符号链接的别名可能缺失
}

// Complete 报告别名是否收集完整。不完整时调用方应带上降级标记，而不是把「没找到别名」当作检查完整。
func (m *Matcher) Complete() bool { return !m.incomplete }

// Compile 按 env 展开并编译模式（模式须已通过 ValidPattern）。缺少 ~ 或占位符值的模式跳过。
// 不是 Lexical 时，另按文件系统上的别名（见 aliases）各编译一份。
func Compile(patterns []string, env Env) (*Matcher, error) {
	m := &Matcher{windows: env.Windows}
	for _, p := range patterns {
		if err := ValidPattern(p); err != nil {
			return nil, fmt.Errorf("pattern %q: %w", p, err)
		}
		expanded, ok := expandPattern(p, env)
		if !ok {
			continue
		}
		srcs := []string{translate(expanded)}
		if !env.Lexical {
			alt, complete := aliases(expanded, env)
			srcs = append(srcs, alt...)
			m.incomplete = m.incomplete || !complete
		}
		for _, s := range srcs {
			// 路径里的目录名可以含换行符，`.` 必须能匹配它（s 标志），否则 `**/`、`/**` 会漏掉这类路径（fail-open）。
			flags := "(?s)"
			if env.FoldCase {
				flags = "(?is)"
			}
			re, err := regexp.Compile(flags + "^" + s + "$")
			if err != nil {
				return nil, fmt.Errorf("pattern %q: %w", p, err)
			}
			m.res = append(m.res, re)
		}
	}
	return m, nil
}

// maxEntries 是为找出目录里的符号链接最多读取的目录项数。受保护的目录由 h-guard 自己管理，正常只有几项；
// 超过上限时别名收集不完整，Matcher.Complete 报告出来（评审 R2-02），不悄悄当作没有别名。
const maxEntries = 4096

// aliases 返回展开后的模式 p 在文件系统上的别名（正则，不含锚点），让「改符号链接的目标」同样命中
// （评审 M2-03）：
//   - 开头的固定部分解析符号链接后的写法：受保护的文件或目录本身是符号链接（dotfiles 仓库）；
//   - 固定部分之后的第一段是通配符时，固定部分这一层目录里名字匹配该段的符号链接，其目标以及目标之下的
//     全部内容：如配置目录里链接到别处的 config.yaml。只看这一层，更深的链接要在模式里写出所在目录；
//   - 以 **/ 开头、其余部分不含通配符的模式（项目级的 hook 配置）：在 cwd 及其各级上级目录各实例化一份，
//     解析出不同真实路径的，该真实路径也受保护。
//
// complete 为 false 表示有目录读不全（超过 maxEntries 项，或因权限等原因读取失败；目录不存在不算）。
// 正在使用的文件应在规则里写出固定路径，不依赖目录扫描。
func aliases(p string, env Env) (out []string, complete bool) {
	if rest, ok := strings.CutPrefix(p, "**/"); ok {
		if strings.ContainsAny(rest, "*?") || !filepath.IsAbs(env.Cwd) {
			return nil, true
		}
		for dir := filepath.Clean(env.Cwd); ; dir = filepath.Dir(dir) {
			inst := filepath.Join(dir, filepath.FromSlash(rest))
			if rp, err := realpath(inst); err == nil && rp != inst {
				out = append(out, regexp.QuoteMeta(filepath.ToSlash(rp)))
			}
			if filepath.Dir(dir) == dir {
				return out, true
			}
		}
	}
	prefix, rest := literalPrefix(p)
	if prefix == "" {
		return nil, true
	}
	rp, err := realpath(filepath.FromSlash(prefix))
	if err != nil {
		return nil, false
	}
	if alt := filepath.ToSlash(rp); alt != prefix {
		out = append(out, regexp.QuoteMeta(alt)+translate(rest))
	}
	if rest == "" {
		return out, true
	}
	seg, _, _ := strings.Cut(rest[1:], "/")
	entries, complete := readDir(rp)
	for _, e := range entries {
		if e.Type()&fs.ModeSymlink == 0 {
			continue
		}
		name := e.Name()
		if env.FoldCase {
			seg, name = strings.ToLower(seg), strings.ToLower(name)
		}
		if ok, _ := pathpkg.Match(seg, name); seg != "**" && !ok {
			continue
		}
		if target, err := realpath(filepath.Join(rp, e.Name())); err == nil {
			out = append(out, regexp.QuoteMeta(filepath.ToSlash(target))+"(?:/.*)?")
		}
	}
	return out, complete
}

// readDir 读取 dir 的前 maxEntries 项。complete 为 false 表示还有更多项或读取出错；目录不存在算完整（没有可扫的）。
func readDir(dir string) (entries []fs.DirEntry, complete bool) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, errors.Is(err, fs.ErrNotExist)
	}
	defer f.Close()
	entries, err = f.ReadDir(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return entries, false
	}
	if len(entries) > maxEntries {
		return entries[:maxEntries], false
	}
	return entries, true
}

// Match 报告 r 的任一候选路径是否命中任一模式。r 是 Opaque 时，只要有模式就算命中（fail-closed）：
// 无法得知它是哪个文件。所有模式都因缺少 ~ 或占位符的值而跳过时不命中。
func (m *Matcher) Match(r Resolved) bool {
	if r.Opaque && len(m.res) > 0 {
		return true
	}
	for _, c := range r.Candidates() {
		c = slash(c, m.windows)
		for _, re := range m.res {
			if re.MatchString(c) {
				return true
			}
		}
	}
	return false
}

// expandPattern 展开开头的 ~ 或 {name}，结果用 / 分隔。
func expandPattern(p string, env Env) (string, bool) {
	if name, ok := Placeholder(p); ok {
		v := env.Vars[name]
		if v == "" {
			return "", false
		}
		return strings.TrimSuffix(slash(filepath.Clean(v), env.Windows), "/") + p[len(name)+2:], true
	}
	if strings.HasPrefix(p, "~/") {
		if env.Home == "" {
			return "", false
		}
		return strings.TrimSuffix(slash(filepath.Clean(env.Home), env.Windows), "/") + p[1:], true
	}
	return p, true
}

// literalPrefix 把模式拆成不含通配符的开头若干段与其余部分（其余部分以 / 开头或为空）。
func literalPrefix(p string) (prefix, rest string) {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.ContainsAny(s, "*?") {
			return strings.Join(segs[:i], "/"), "/" + strings.Join(segs[i:], "/")
		}
	}
	return p, ""
}

// translate 把 glob 换成正则（不含锚点）。
func translate(glob string) string {
	var b strings.Builder
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case glob[i:] == "/**":
			b.WriteString("(?:/.*)?")
			i += 3
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		case glob[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			_, n := utf8.DecodeRuneInString(glob[i:])
			b.WriteString(regexp.QuoteMeta(glob[i : i+n]))
			i += n
		}
	}
	return b.String()
}

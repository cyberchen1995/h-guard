package rules

import (
	pathpkg "path"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/dlclark/regexp2"
)

// exec 模式的占位符：与路径模式相同的 {name}（见 placeholders），可以写在模式的任意位置（字符类里除外），
// 前面的反斜杠个数为奇数时（\{config}）是字面的花括号，不是占位符；不认识的名字原样保留（regexp2 里不是量词的
// {…} 按字面匹配）。
//
// 展开：值是一个目录或文件（paths.Env.Vars），换成匹配它的字面量（regexp.QuoteMeta 转义，regexp2 接受这些转义），
// 外面包一层 (?i:…)：
//   - \ 与 / 都当作分隔符，每处分隔符匹配 [/\\]+（命令里两种写法都有，Windows 上 PowerShell 也接受 /）；
//   - 空格前可以有一个反斜杠（POSIX 的 Application\ Support）；
//   - 值在主目录之下时，主目录的部分另可写成 ~、$HOME、${HOME}、$env:HOME、$env:USERPROFILE、%USERPROFILE%
//     （路径模式解析目标时会展开 ~，命令文本不会，这几种写法在这里补上）。
//
// 值是相对路径时，按 env.Cwd（事件的工作目录）解析后的绝对路径与原样的相对路径（须从参数开头起）都认；没有 Cwd 时
// 只按原样匹配。值是根目录时展开为不占字符的「这里开始一个路径」，模式里紧跟的分隔符照常匹配那个 /。
//
// 占位符也可以写在后向断言里：regexp2 的后向断言不要求定长。
//
// 值为空（环境变量没有设置、没有 --config）时，占位符换成永不匹配的 (?!)：用到它的那一处不匹配，不会变成匹配一切，
// 规则照常加载；与路径模式里「没有值的模式不匹配」一致。占位符写在可选的位置（(?:{x})?）时，那一处退化为不写它。
var execPlaceholder = regexp.MustCompile(`(\\*)\{([a-z_]+)\}`)

// neverMatch 是未设置的占位符展开成的正则。
const neverMatch = `(?!)`

// homeForms 是主目录在命令里的其他写法（不区分大小写）。
const homeForms = `~|\$\{?home\}?|\$\{?env:(?:home|userprofile)\}?|%userprofile%`

// execVars 返回模式 p 用到的占位符（按出现顺序，去重）。
func execVars(p string) []string {
	var out []string
	for _, m := range execPlaceholder.FindAllStringSubmatch(p, -1) {
		if len(m[1])%2 == 0 && placeholders[m[2]] && !slices.Contains(out, m[2]) {
			out = append(out, m[2])
		}
	}
	return out
}

// expandExec 按 env 展开模式 p 里的占位符。
func expandExec(p string, env paths.Env) string {
	return execPlaceholder.ReplaceAllStringFunc(p, func(s string) string {
		m := execPlaceholder.FindStringSubmatch(s)
		if len(m[1])%2 != 0 || !placeholders[m[2]] {
			return s
		}
		v := env.Vars[m[2]]
		abs := absDir(v, env.Cwd)
		if abs == v {
			return m[1] + execLiteral(v, env.Home)
		}
		// 相对的值：命令里既可能写解析后的绝对路径，也可能照原样写相对路径（shell 按同一个 cwd 解析）
		return m[1] + "(?:" + execLiteral(abs, env.Home) + "|" + pathStart + execLiteral(v, env.Home) + ")"
	})
}

// pathStart 要求路径从一个参数的开头起：前面是行首、空白、引号、= 或 shell 的分隔符。相对路径与根目录展开时用它，
// 否则相对路径 agent 会匹配 /x/agent 的后半截，根目录会匹配任何一个 /。
const pathStart = "(?<![^\\s'\"`=(<>|;&])"

// execLiteral 是匹配目录 v 的正则（见 execPlaceholder 的说明）；v 为空时永不匹配。
func execLiteral(v, home string) string {
	if v == "" {
		return neverMatch
	}
	n := normDir(v)
	if n == "/" {
		// 根目录展开为「这里开始一个路径、后面跟着分隔符」，不占字符：模式里紧跟的 [/\\]+ 照常匹配那个 /，
		// 不会要求两个分隔符
		return pathStart + `(?=[/\\])`
	}
	lit := literalSegments(n)
	if h := normDir(home); h != "" {
		switch {
		case strings.EqualFold(n, h):
			lit = "(?:" + lit + "|" + homeForms + ")"
		case len(n) > len(h) && strings.EqualFold(n[:len(h)+1], h+"/"):
			lit = "(?:" + literalSegments(h) + "|" + homeForms + ")" + literalSegments(n[len(h):])
		}
	}
	return "(?i:" + lit + ")"
}

// absDir 把相对路径 v 接到 cwd 下（cwd 为空时原样返回）。以 / 或 \ 开头、带盘符的路径不是相对路径。
func absDir(v, cwd string) string {
	if v == "" || cwd == "" || strings.HasPrefix(v, "/") || strings.HasPrefix(v, `\`) || driveLetter.MatchString(v) {
		return v
	}
	return strings.ReplaceAll(cwd, `\`, "/") + "/" + v
}

var driveLetter = regexp.MustCompile(`^[A-Za-z]:`)

// normDir 把 \ 换成 /，规范化并去掉末尾的 /；根目录保留为 /，不能变成空（空的字面量匹配任何位置）。
func normDir(v string) string {
	if v == "" {
		return ""
	}
	n := pathpkg.Clean(strings.ReplaceAll(v, `\`, "/"))
	if n == "/" {
		return n
	}
	return strings.TrimSuffix(n, "/")
}

// literalSegments 把 / 分隔的路径换成正则：各段转义，分隔符匹配 [/\\]+，空格前可有反斜杠。
func literalSegments(n string) string {
	segs := strings.Split(n, "/")
	for i, s := range segs {
		segs[i] = strings.ReplaceAll(regexp.QuoteMeta(s), " ", `\\? `)
	}
	return strings.Join(segs, `[/\\]+`)
}

// execGroup 是一组 exec 模式，按规则里的顺序：不含占位符的在加载时编译（re），含占位符的匹配时按环境展开编译
// （tpl，结果缓存）。顺序要保留：每次匹配都有超时，预算也按顺序耗尽，先写的模式先得出结论。
type execGroup []execPattern

type execPattern struct {
	re  *regexp2.Regexp
	tpl string
}

// static 是不含占位符时的全部模式。
func (g execGroup) static() []*regexp2.Regexp {
	out := make([]*regexp2.Regexp, 0, len(g))
	for _, p := range g {
		out = append(out, p.re)
	}
	return out
}

// resolvedExec 是按某个环境展开后的全部模式。
type resolvedExec struct {
	key                              string
	any, posix, powershell, redirect []*regexp2.Regexp
	broken                           bool // 有模式展开后编译失败：按命中处理（只收紧）
}

// templateKey 是缓存的键：主目录、工作目录（相对的值按它解析）与各占位符的值。
func templateKey(env paths.Env, names []string) string {
	var b strings.Builder
	b.WriteString(env.Home + "\x00" + env.Cwd)
	for _, n := range names {
		b.WriteString("\x00" + env.Vars[n])
	}
	return b.String()
}

// compileTemplate 展开并编译一条含占位符的模式。
func compileTemplate(p string, env paths.Env) (*regexp2.Regexp, error) {
	re, err := regexp2.Compile(expandExec(p, env), regexp2.IgnoreCase)
	if err != nil {
		return nil, err
	}
	re.MatchTimeout = MatchTimeout
	return re, nil
}

// resolve 返回按 env 展开后的模式。没有含占位符的模式时直接用加载时编译的结果；否则按环境缓存最近一次的展开，
// 同一进程里环境不变，每条规则只编译一次。
func (c *compiledExec) resolve(env paths.Env) *resolvedExec {
	if len(c.vars) == 0 {
		return &c.base
	}
	key := templateKey(env, c.vars)
	if r := c.cache.Load(); r != nil && r.key == key {
		return r
	}
	r := &resolvedExec{key: key}
	for _, g := range []struct {
		src *execGroup
		dst *[]*regexp2.Regexp
	}{{&c.any, &r.any}, {&c.posix, &r.posix}, {&c.powershell, &r.powershell}, {&c.redirects, &r.redirect}} {
		for _, p := range *g.src {
			if p.tpl == "" {
				*g.dst = append(*g.dst, p.re)
				continue
			}
			re, err := compileTemplate(p.tpl, env)
			if err != nil {
				r.broken = true
				continue
			}
			*g.dst = append(*g.dst, re)
		}
	}
	c.cache.Store(r)
	return r
}

// probeEnv 是加载时试编译含占位符的模式所用的环境：每个占位符都有值，值里有空格与正则元字符，且在主目录之下。
var probeEnv = func() paths.Env {
	env := paths.Env{Home: "/probe home", Vars: map[string]string{}}
	for name := range placeholders {
		env.Vars[name] = `/probe home/a.b+(c)[d]{e}|f\g`
	}
	return env
}()

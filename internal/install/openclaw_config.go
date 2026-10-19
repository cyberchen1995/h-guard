package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// OpenClawEffective 是 OpenClaw 实际生效的配置：openclaw.json 与它用 $include 引入的文件合并之后的结果。install、
// install --remove、status 与规则的占位符都从这里读，只读不写。
type OpenClawEffective struct {
	Path     string         // 配置文件（OpenClawConfig）
	Exists   bool           // 配置文件存在
	Merged   map[string]any // 合并后的配置；Err 不为空时可能缺少读不到的部分
	Includes []string       // $include 引入的文件（逐层，不含配置文件本身）
	Include  bool           // 配置里有 $include
	Err      error          // 配置或引入的文件读不到、不是 JSON5、引入成环、太深或超出引入的根目录；这时 Merged 不可信
	// Unresolved 是 h-guard 不能确定 OpenClaw 会怎样展开的值（如 ${VAR} 的值可能来自 .env 文件或登录 shell），
	// 每项是值在配置里的位置（如 plugins.deny[0]）
	Unresolved []string
}

// unresolvedUnder 报告 prefix（如 plugins）下有没有不能确定的值。
func (e OpenClawEffective) unresolvedUnder(prefix string) bool {
	for _, u := range e.Unresolved {
		if u == prefix || strings.HasPrefix(u, prefix+".") || strings.HasPrefix(u, prefix+"[") {
			return true
		}
	}
	return false
}

// openclawIncludeDepth 是 $include 嵌套的上限（与 OpenClaw 一样 10 层）。
const openclawIncludeDepth = 10

// openclawMaxIncludeBytes 是单个引入文件的大小上限（与 OpenClaw 一样 2 MB）。
const openclawMaxIncludeBytes = 2 << 20

// LoadOpenClawConfig 读出 OpenClaw 实际生效的配置，合并方式与 OpenClaw 一样（docs/gateway/config-secrets-env.md）：
// 对象里的 $include 是一个文件时用它的内容代替这个对象，是文件列表时按顺序深度合并（对象逐键合并，数组接在后面，
// 其余后面的覆盖前面的），同一对象里的其他键在引入之后同样合并；引入的文件里还可以再引入，最多 10 层；相对路径按
// 引入它的文件所在目录解析，解析后（以及解析符号链接后）必须在配置文件所在目录或 OPENCLAW_INCLUDE_ROOTS 列出的
// 目录之内（src/config/includes.ts）。合并之后展开字符串里的 ${VAR}（见 substituteEnv）。文件按 JSON5 解析。
// 配置文件不存在时 Merged 为空对象、Err 为空。
func LoadOpenClawConfig(t Target) OpenClawEffective {
	e := OpenClawEffective{Path: OpenClawConfig(t), Merged: map[string]any{}}
	b, err := os.ReadFile(e.Path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			e.Err = err
		}
		return e
	}
	e.Exists = true
	root, err := parseJSON5(b)
	if err != nil {
		e.Err = fmt.Errorf("%s: %w", e.Path, err)
		return e
	}
	l := &includeLoader{e: &e, roots: includeRoots(t, e.Path)}
	merged, err := l.resolve(root, e.Path, 0, []string{e.Path})
	if err != nil {
		e.Err = err
	}
	if m, ok := merged.(map[string]any); ok {
		e.Merged = m
	} else if e.Err == nil {
		e.Err = fmt.Errorf("%s: %w", e.Path, errNotObject)
	}
	substituteEnv(t, &e)
	return e
}

type includeLoader struct {
	e     *OpenClawEffective
	roots []includeRoot
}

// includeRoot 是允许引入文件的目录：写法上的路径与解析符号链接后的路径。
type includeRoot struct{ dir, real string }

// includeRoots 返回允许引入文件的目录：配置文件所在的目录，与 OPENCLAW_INCLUDE_ROOTS 列出的目录（按路径分隔符分开，
// 开头的 ~ 展开到 OpenClaw 的主目录）。
func includeRoots(t Target, config string) []includeRoot {
	dirs := []string{filepath.Dir(config)}
	for _, d := range filepath.SplitList(t.Getenv("OPENCLAW_INCLUDE_ROOTS")) {
		if d = strings.TrimSpace(d); d != "" {
			dirs = append(dirs, openclawPath(t, d))
		}
	}
	var roots []includeRoot
	for _, d := range dirs {
		d = filepath.Clean(d)
		real := d
		if r, err := filepath.EvalSymlinks(d); err == nil {
			real = r
		}
		roots = append(roots, includeRoot{dir: d, real: real})
	}
	return roots
}

// inside 报告 p 是不是在 dir 之内（或就是 dir）。
func inside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// within 按 OpenClaw 的规则检查引入的文件是否在允许的目录里：写法上的路径要在某个目录之内，文件存在时解析符号链接后
// 的路径也要在某个目录（解析后）之内。
func (l *includeLoader) within(p string) error {
	lexical := slices.ContainsFunc(l.roots, func(r includeRoot) bool { return inside(r.dir, p) })
	if !lexical {
		return fmt.Errorf("the include path escapes the config directory (%s) and OPENCLAW_INCLUDE_ROOTS", l.roots[0].dir)
	}
	real, err := filepath.EvalSymlinks(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // 读文件时报告
	}
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(l.roots, func(r includeRoot) bool { return inside(r.real, real) }) {
		return fmt.Errorf("the include path resolves through a symlink to %s, outside the config directory and OPENCLAW_INCLUDE_ROOTS", real)
	}
	return nil
}

// resolve 展开 v 里的 $include；file 是 v 所在的文件，chain 是正在展开的文件（用来发现成环）。出错时尽量返回
// 已经展开的部分，同时返回第一个错误。
func (l *includeLoader) resolve(v any, file string, depth int, chain []string) (any, error) {
	switch x := v.(type) {
	case []any:
		var first error
		out := make([]any, len(x))
		for i, item := range x {
			r, err := l.resolve(item, file, depth, chain)
			out[i] = r
			first = cmpOr(first, err)
		}
		return out, first
	case map[string]any:
		var first error
		inc, has := x["$include"]
		var base any = map[string]any{}
		if has {
			l.e.Include = true
			var files []string
			switch iv := inc.(type) {
			case string:
				files = []string{iv}
			case []any:
				for _, f := range iv {
					s, ok := f.(string)
					if !ok {
						return x, fmt.Errorf("%s: $include lists something that is not a path", file)
					}
					files = append(files, s)
				}
			default:
				return x, fmt.Errorf("%s: $include is neither a path nor a list of paths", file)
			}
			for i, f := range files {
				r, err := l.load(f, file, depth, chain)
				first = cmpOr(first, err)
				if len(files) == 1 {
					base = r
				} else if i == 0 {
					base = r
				} else {
					base = deepMerge(base, r)
				}
			}
		}
		rest := map[string]any{}
		// 按键排序展开，引入文件的顺序与第一个错误都是确定的
		for _, k := range slices.Sorted(maps.Keys(x)) {
			item := x[k]
			if k == "$include" {
				continue
			}
			r, err := l.resolve(item, file, depth, chain)
			rest[k] = r
			first = cmpOr(first, err)
		}
		if !has {
			return rest, first
		}
		if len(rest) == 0 {
			return base, first
		}
		return deepMerge(base, rest), first
	}
	return v, nil
}

// load 读一个引入的文件并展开它里面的 $include。
func (l *includeLoader) load(ref, from string, depth int, chain []string) (any, error) {
	if depth+1 > openclawIncludeDepth {
		return map[string]any{}, fmt.Errorf("%s: $include is nested more than %d levels deep", from, openclawIncludeDepth)
	}
	p := ref
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(from), p)
	}
	p = filepath.Clean(p)
	if strings.ContainsRune(ref, 0) || len(ref) >= 4096 || len(p) >= 4096 {
		return map[string]any{}, fmt.Errorf("%s: $include path is too long or contains a NUL byte", from)
	}
	if err := l.within(p); err != nil {
		return map[string]any{}, fmt.Errorf("%s: $include %s: %w", from, ref, err)
	}
	if slices.Contains(chain, p) {
		return map[string]any{}, fmt.Errorf("%s: $include of %s is circular", from, p)
	}
	if !slices.Contains(l.e.Includes, p) {
		l.e.Includes = append(l.e.Includes, p)
	}
	info, err := os.Stat(p)
	if err == nil && info.Size() > openclawMaxIncludeBytes {
		err = fmt.Errorf("larger than %d bytes", openclawMaxIncludeBytes)
	}
	var b []byte
	if err == nil {
		b, err = os.ReadFile(p)
	}
	if err != nil {
		return map[string]any{}, fmt.Errorf("%s: $include %s: %w", from, ref, err)
	}
	v, err := parseJSON5(b)
	if err != nil {
		return map[string]any{}, fmt.Errorf("%s: %w", p, err)
	}
	return l.resolve(v, p, depth+1, append(slices.Clip(chain), p))
}

// deepMerge 把 b 合并进 a（OpenClaw 的 mergeDeep，arrays: "concat"）：两边都是对象时逐键合并，都是数组时 b 接在 a
// 后面，其余情况 b 覆盖 a。
func deepMerge(a, b any) any {
	if aa, ok := a.([]any); ok {
		if ba, ok := b.([]any); ok {
			return append(slices.Clone(aa), ba...)
		}
	}
	am, ok1 := a.(map[string]any)
	bm, ok2 := b.(map[string]any)
	if !ok1 || !ok2 {
		return b
	}
	out := make(map[string]any, len(am)+len(bm))
	for k, v := range am {
		out[k] = v
	}
	for k, v := range bm {
		if old, ok := out[k]; ok {
			out[k] = deepMerge(old, v)
		} else {
			out[k] = v
		}
	}
	return out
}

func cmpOr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// decode 把合并后的配置按 JSON 读进 dst。
func (e OpenClawEffective) decode(dst any) error {
	b, err := toJSON(e.Merged)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// envRefRe 是字符串里的 ${VAR} 与 ${VAR:-fallback}（只认大写的名字），以及转义写法 $${...}。
var envRefRe = regexp.MustCompile(`\$?\$\{([A-Z_][A-Z0-9_]*)(?::-([^${}]*))?\}`)

// substituteEnv 按 OpenClaw 的规则展开合并后配置里字符串的 ${VAR}（docs/gateway/config-secrets-env.md）：值取自进程的
// 环境变量，没有或为空时用 :- 后的默认值，再没有时用配置里 env.vars 的值；都没有时原样保留（OpenClaw 同样保留并
// 警告）。$${VAR} 是字面的 ${VAR}。OpenClaw 还会从当前目录与状态目录的 .env 文件、以及（env.shellEnv.enabled 时）
// 登录 shell 补上缺少的变量，这些 h-guard 不读：有这些来源时，缺少的变量记进 Unresolved。注意这里用的是运行 h-guard
// 的进程的环境，Gateway 的环境可能不同。
func substituteEnv(t Target, e *OpenClawEffective) {
	envVars := map[string]string{}
	shellEnv := false
	if env, ok := e.Merged["env"].(map[string]any); ok {
		if vars, ok := env["vars"].(map[string]any); ok {
			for k, v := range vars {
				if s, ok := v.(string); ok {
					envVars[k] = s
				}
			}
		}
		if sh, ok := env["shellEnv"].(map[string]any); ok {
			shellEnv, _ = sh["enabled"].(bool)
		}
	}
	otherSources := shellEnv || exists(filepath.Join(OpenClawStateDir(t), ".env"))
	if cwd, err := os.Getwd(); err == nil && exists(filepath.Join(cwd, ".env")) {
		otherSources = true
	}
	var walk func(v any, path string) any
	walk = func(v any, path string) any {
		switch x := v.(type) {
		case string:
			return envRefRe.ReplaceAllStringFunc(x, func(m string) string {
				if strings.HasPrefix(m, "$$") {
					return m[1:]
				}
				sub := envRefRe.FindStringSubmatch(m)
				name, hasFallback := sub[1], strings.Contains(m, ":-")
				if val := t.Getenv(name); val != "" {
					return val
				}
				if hasFallback {
					return sub[2]
				}
				if val, ok := envVars[name]; ok && val != "" {
					return val
				}
				if otherSources {
					e.Unresolved = append(e.Unresolved, path)
				}
				return m
			})
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(x)) {
				p := k
				if path != "" {
					p = path + "." + k
				}
				x[k] = walk(x[k], p)
			}
			return x
		case []any:
			for i := range x {
				x[i] = walk(x[i], fmt.Sprintf("%s[%d]", path, i))
			}
			return x
		}
		return v
	}
	e.Merged, _ = walk(e.Merged, "").(map[string]any)
}

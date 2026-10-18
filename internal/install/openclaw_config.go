package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// OpenClawEffective 是 OpenClaw 实际生效的配置：openclaw.json 与它用 $include 引入的文件合并之后的结果。install、
// install --remove、status 与规则的占位符都从这里读，只读不写。
type OpenClawEffective struct {
	Path     string         // 配置文件（OpenClawConfig）
	Exists   bool           // 配置文件存在
	Merged   map[string]any // 合并后的配置；Err 不为空时可能缺少读不到的部分
	Includes []string       // $include 引入的文件（逐层，不含配置文件本身）
	Include  bool           // 配置里有 $include
	Err      error          // 配置或引入的文件读不到、不是 JSON5、引入成环或太深；这时 Merged 不可信
}

// openclawIncludeDepth 是 $include 嵌套的上限（与 OpenClaw 一样 10 层）。
const openclawIncludeDepth = 10

// openclawMaxIncludeBytes 是单个引入文件的大小上限（与 OpenClaw 一样 2 MB）。
const openclawMaxIncludeBytes = 2 << 20

// LoadOpenClawConfig 读出 OpenClaw 实际生效的配置，合并方式与 OpenClaw 一样（docs/gateway/config-secrets-env.md）：
// 对象里的 $include 是一个文件时用它的内容代替这个对象，是文件列表时按顺序深度合并（后面的覆盖前面的），同一对象
// 里的其他键在引入之后合并、覆盖引入的值；引入的文件里还可以再引入，最多 10 层；相对路径按引入它的文件所在目录
// 解析。文件按 JSON5 解析。配置文件不存在时 Merged 为空对象、Err 为空。
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
	l := &includeLoader{e: &e}
	merged, err := l.resolve(root, e.Path, 0, []string{e.Path})
	if err != nil {
		e.Err = err
	}
	if m, ok := merged.(map[string]any); ok {
		e.Merged = m
	} else if e.Err == nil {
		e.Err = fmt.Errorf("%s: %w", e.Path, errNotObject)
	}
	return e
}

type includeLoader struct{ e *OpenClawEffective }

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

// deepMerge 把 b 合并进 a：两边都是对象时逐键合并，其余情况 b 覆盖 a。
func deepMerge(a, b any) any {
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

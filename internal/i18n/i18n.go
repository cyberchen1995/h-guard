// Package i18n 生成本地化文本（spec §11）：消息目录内嵌在二进制里（locales 包），
// 语言按「配置 locale → LC_ALL → LANG → en」选择，缺失的键回落到 en。
package i18n

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/cyberchen1995/h-guard/locales"
	"go.yaml.in/yaml/v3"
)

// DefaultLocale 是默认语言，也是缺键时的回落语言。
const DefaultLocale = "en"

// Catalog 是全部语言的消息目录：语言 → 键 → 模板。
type Catalog struct {
	msgs map[string]map[string]string
}

// Load 读取内嵌的全部消息目录。
func Load() (*Catalog, error) {
	files, err := fs.Glob(locales.FS, "*.yaml")
	if err != nil {
		return nil, err
	}
	c := &Catalog{msgs: map[string]map[string]string{}}
	for _, name := range files {
		b, err := locales.FS.ReadFile(name)
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := yaml.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("i18n: %s: %w", name, err)
		}
		c.msgs[strings.TrimSuffix(name, ".yaml")] = m
	}
	if _, ok := c.msgs[DefaultLocale]; !ok {
		return nil, fmt.Errorf("i18n: missing %s catalog", DefaultLocale)
	}
	return c, nil
}

// Text 返回 key 在 locale 中的文本，把模板里的 {name} 换成 params[name]。locale 没有该键时用 en；
// en 也没有时返回 key 本身，保证不会输出空原因。
func (c *Catalog) Text(locale, key string, params map[string]string) string {
	tpl, ok := c.msgs[locale][key]
	if !ok {
		tpl, ok = c.msgs[DefaultLocale][key]
	}
	if !ok {
		return key
	}
	for name, value := range params {
		tpl = strings.ReplaceAll(tpl, "{"+name+"}", value)
	}
	return tpl
}

// Has 报告是否内置了 locale 的消息目录。
func (c *Catalog) Has(locale string) bool {
	_, ok := c.msgs[locale]
	return ok
}

// SelectLocale 按「配置 → LC_ALL → LANG → en」选择语言（spec §11）。配置了不支持的语言时继续看
// 环境变量；第一个非空的环境变量决定结果，它指定的语言不受支持（含 C、POSIX）时用 en。
func SelectLocale(configured string, getenv func(string) string) string {
	if loc, ok := normalize(configured); ok {
		return loc
	}
	if getenv == nil {
		return DefaultLocale
	}
	for _, name := range []string{"LC_ALL", "LANG"} {
		if v := getenv(name); v != "" {
			if loc, ok := normalize(v); ok {
				return loc
			}
			return DefaultLocale
		}
	}
	return DefaultLocale
}

// normalize 把 zh_CN.UTF-8、zh-Hans、en_US 这类写法映射到内置语言。
func normalize(v string) (string, bool) {
	v = strings.ToLower(v)
	if i := strings.IndexAny(v, ".@"); i >= 0 {
		v = v[:i]
	}
	v = strings.ReplaceAll(v, "_", "-")
	switch {
	case v == "en" || strings.HasPrefix(v, "en-"):
		return "en", true
	case v == "zh" || v == "zh-cn" || v == "zh-sg" || strings.HasPrefix(v, "zh-hans"):
		return "zh-CN", true
	}
	return "", false
}

// Pick 从多语言映射中取 locale 的文本：没有时取 en，再没有时取任意一个（按键排序后的第一个）。
// 规则包的 reason 用它（spec §11）。
func Pick(m map[string]string, locale string) string {
	if v, ok := m[locale]; ok {
		return v
	}
	if v, ok := m[DefaultLocale]; ok {
		return v
	}
	best := ""
	for k := range m {
		if best == "" || k < best {
			best = k
		}
	}
	return m[best]
}

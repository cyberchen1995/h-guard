// Package schematest 是 schema/ 下 JSON Schema 的测试辅助：一个只认少数关键字的最小校验器，以及按 yaml 标签
// 核对 schema 与 Go 结构体字段是否一致的检查。只给测试使用，生产代码不导入它。
//
// 支持的关键字：$schema、$id、$defs、$ref（只引用本文件的 #/$defs/…）、title、description、type、properties、
// additionalProperties、required、enum、const、items、minimum、maximum、exclusiveMinimum、minItems、default。
// schema 里出现其他关键字时报告 unsupported keyword <名字>，免得 schema 依赖校验器不检查的约束。
package schematest

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// keywords 是校验器认识的关键字。
var keywords = []string{
	"$schema", "$id", "$defs", "$ref", "title", "description", "type", "properties", "additionalProperties",
	"required", "enum", "const", "items", "minimum", "maximum", "exclusiveMinimum", "minItems", "default",
}

// Load 读出 path 处的 JSON Schema。
func Load(t testing.TB, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return m
}

// Validate 用 schema 校验 doc（JSON 或 yaml 库解码出的 any），返回每处违反的路径与原因；没有违反时为空。
// schema 里有不支持的关键字或引用时，只报告这些问题，不校验文档。
func Validate(schema map[string]any, doc any) []string {
	var errs []string
	checkKeywords(schema, schema, &errs)
	if len(errs) > 0 {
		return errs
	}
	v := validator{root: schema}
	v.validate(schema, doc, "$")
	return v.errs
}

// checkKeywords 遍历整个 schema（不只文档走到的部分），找出不支持的关键字与无法解析的 $ref。
func checkKeywords(root map[string]any, s map[string]any, errs *[]string) {
	for _, k := range sortedKeys(s) {
		if !slices.Contains(keywords, k) {
			*errs = append(*errs, "unsupported keyword "+k)
			continue
		}
		switch k {
		case "$defs", "properties":
			sub, _ := s[k].(map[string]any)
			for _, name := range sortedKeys(sub) {
				if m, ok := sub[name].(map[string]any); ok {
					checkKeywords(root, m, errs)
				}
			}
		case "items", "additionalProperties":
			if m, ok := s[k].(map[string]any); ok {
				checkKeywords(root, m, errs)
			}
		case "$ref":
			if _, err := lookupRef(root, s[k]); err != nil {
				*errs = append(*errs, err.Error())
			}
		}
	}
}

// lookupRef 解析 #/$defs/<名字> 形式的引用。
func lookupRef(root map[string]any, ref any) (map[string]any, error) {
	r, _ := ref.(string)
	name, ok := strings.CutPrefix(r, "#/$defs/")
	if !ok {
		return nil, fmt.Errorf("unsupported $ref %q (only #/$defs/<name>)", r)
	}
	defs, _ := root["$defs"].(map[string]any)
	m, ok := defs[name].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unresolved $ref %q", r)
	}
	return m, nil
}

type validator struct {
	root map[string]any
	errs []string
}

func (v *validator) fail(path, format string, args ...any) {
	v.errs = append(v.errs, path+": "+fmt.Sprintf(format, args...))
}

func (v *validator) validate(s map[string]any, doc any, path string) {
	if ref, ok := s["$ref"]; ok {
		target, err := lookupRef(v.root, ref)
		if err != nil {
			v.fail(path, "%v", err)
			return
		}
		v.validate(target, doc, path)
	}
	if t, ok := s["type"]; ok && !matchesType(t, doc) {
		v.fail(path, "want %v, got %s", t, typeName(doc))
		return // 类型不对时其余约束没有意义
	}
	if c, ok := s["const"]; ok && !equal(c, doc) {
		v.fail(path, "got %v, want %v", doc, c)
	}
	if e, ok := s["enum"].([]any); ok && !slices.ContainsFunc(e, func(x any) bool { return equal(x, doc) }) {
		v.fail(path, "got %v, want one of %v", doc, e)
	}
	if n, ok := number(doc); ok {
		if m, ok := number(s["minimum"]); ok && n < m {
			v.fail(path, "%v is below the minimum %v", doc, m)
		}
		if m, ok := number(s["maximum"]); ok && n > m {
			v.fail(path, "%v is above the maximum %v", doc, m)
		}
		if m, ok := number(s["exclusiveMinimum"]); ok && n <= m {
			v.fail(path, "%v is not above %v", doc, m)
		}
	}
	if list, ok := doc.([]any); ok {
		if m, ok := number(s["minItems"]); ok && float64(len(list)) < m {
			v.fail(path, "fewer than %v items", m)
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, x := range list {
				v.validate(items, x, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	if obj, ok := object(doc); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if name, _ := r.(string); !hasKey(obj, name) {
					v.fail(path+"."+name, "missing")
				}
			}
		}
		for _, k := range sortedKeys(obj) {
			p := path + "." + k
			if ps, ok := props[k].(map[string]any); ok {
				v.validate(ps, obj[k], p)
				continue
			}
			switch ap := s["additionalProperties"].(type) {
			case bool:
				if !ap {
					v.fail(p, "unknown property")
				}
			case map[string]any:
				v.validate(ap, obj[k], p)
			}
		}
	}
}

func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

// object 把文档里的映射统一成 map[string]any：yaml 库遇到非字符串的键（如不带引号的 true）时解码成 map[any]any。
func object(doc any) (map[string]any, bool) {
	switch m := doc.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, x := range m {
			out[fmt.Sprint(k)] = x
		}
		return out, true
	}
	return nil, false
}

// number 把 JSON（float64）与 yaml 库（int、int64、uint64、float64）的数字统一成 float64。
func number(x any) (float64, bool) {
	switch n := x.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

func matchesType(t any, doc any) bool {
	if list, ok := t.([]any); ok {
		return slices.ContainsFunc(list, func(x any) bool { return matchesType(x, doc) })
	}
	switch t {
	case "string":
		_, ok := doc.(string)
		return ok
	case "boolean":
		_, ok := doc.(bool)
		return ok
	case "number":
		_, ok := number(doc)
		return ok
	case "integer":
		n, ok := number(doc)
		return ok && n == math.Trunc(n) && !math.IsInf(n, 0)
	case "object":
		_, ok := object(doc)
		return ok
	case "array":
		_, ok := doc.([]any)
		return ok
	case "null":
		return doc == nil
	}
	return false
}

func typeName(doc any) string {
	switch {
	case doc == nil:
		return "null"
	case matchesType("integer", doc):
		return "integer"
	}
	for _, t := range []string{"string", "boolean", "number", "object", "array"} {
		if matchesType(t, doc) {
			return t
		}
	}
	return fmt.Sprintf("%T", doc)
}

// equal 比较 enum、const 的取值与文档：数字不区分来源的类型，其余按值比较。
func equal(a, b any) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	if _, ok := number(b); ok {
		return false
	}
	return reflect.DeepEqual(a, b)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// CompareStruct 从 typ 出发按 yaml 标签递归核对：每个结构体对应的 schema 是 additionalProperties 为 false 的
// object，properties 的键集合等于结构体的 yaml 字段名集合，各字段的 type 与 Go 类型相符。指针取元素类型，
// map 对应 additionalProperties，切片对应 items；跳过 yaml:"-" 与未导出字段；没有标签的导出字段按 yaml 库的
// 默认名（字段名小写）。partial 里的类型只核对列出的字段（如自定义解码、其余字段另行校验的后端配置），
// 它的 additionalProperties 不作要求。
func CompareStruct(t testing.TB, schema map[string]any, typ reflect.Type, partial map[reflect.Type][]string) {
	t.Helper()
	c := comparer{t: t, root: schema, partial: partial}
	c.compare(schema, typ, "$")
}

type comparer struct {
	t       testing.TB
	root    map[string]any
	partial map[reflect.Type][]string
}

func (c *comparer) resolve(s map[string]any, path string) (map[string]any, bool) {
	for range 16 {
		ref, ok := s["$ref"]
		if !ok {
			return s, true
		}
		target, err := lookupRef(c.root, ref)
		if err != nil {
			c.t.Errorf("%s: %v", path, err)
			return nil, false
		}
		s = target
	}
	c.t.Errorf("%s: $ref chain too long", path)
	return nil, false
}

// jsonType 是 Go 类型对应的 JSON Schema type。
func jsonType(typ reflect.Type) string {
	switch typ.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "integer"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Map, reflect.Struct:
		return "object"
	case reflect.Slice, reflect.Array:
		return "array"
	}
	return ""
}

func (c *comparer) compare(raw map[string]any, typ reflect.Type, path string) {
	s, ok := c.resolve(raw, path)
	if !ok {
		return
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	want := jsonType(typ)
	if got, ok := s["type"]; ok {
		if got != want {
			c.t.Errorf("%s: schema type %v, Go type %s wants %q", path, got, typ, want)
			return
		}
	} else if _, isConst := s["const"]; !isConst {
		if _, isEnum := s["enum"]; !isEnum {
			c.t.Errorf("%s: schema has no type (Go type %s)", path, typ)
		}
	}
	switch typ.Kind() {
	case reflect.Map:
		ap, ok := s["additionalProperties"].(map[string]any)
		if !ok {
			c.t.Errorf("%s: a map needs additionalProperties with the value schema", path)
			return
		}
		c.compare(ap, typ.Elem(), path+".<key>")
	case reflect.Slice, reflect.Array:
		items, ok := s["items"].(map[string]any)
		if !ok {
			c.t.Errorf("%s: a list needs items", path)
			return
		}
		c.compare(items, typ.Elem(), path+"[]")
	case reflect.Struct:
		c.compareStruct(s, typ, path)
	}
}

func (c *comparer) compareStruct(s map[string]any, typ reflect.Type, path string) {
	props, _ := s["properties"].(map[string]any)
	fields := yamlFields(typ)
	only, isPartial := c.partial[typ]
	if isPartial {
		for _, name := range only {
			if _, ok := fields[name]; !ok {
				c.t.Errorf("%s: %s has no field %q", path, typ, name)
			}
		}
		kept := make(map[string]reflect.Type, len(only))
		for _, name := range only {
			kept[name] = fields[name]
		}
		fields = kept
	} else if s["additionalProperties"] != false {
		c.t.Errorf("%s: an object for %s needs additionalProperties: false", path, typ)
	}
	names, keys := sortedKeys(fields), sortedKeys(props)
	if !slices.Equal(names, keys) {
		c.t.Errorf("%s: schema properties %v, %s fields %v", path, keys, typ, names)
		return
	}
	for _, name := range names {
		if fields[name] == nil {
			continue
		}
		sub, ok := props[name].(map[string]any)
		if !ok {
			c.t.Errorf("%s.%s: not a schema", path, name)
			continue
		}
		c.compare(sub, fields[name], path+"."+name)
	}
}

// yamlFields 返回结构体的 yaml 字段名与类型，规则同 yaml 库：yaml:"-" 与未导出字段跳过，没有标签时用小写字段名。
func yamlFields(typ reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for f := range typ.Fields() {
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		out[name] = f.Type
	}
	return out
}

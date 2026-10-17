package schematest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/internal/schematest"
)

// mustJSON 把 schema 的 JSON 文本解析成校验器使用的形状。
func mustJSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// mustYAML 按 yaml 库的方式把文档解码成 any（整数是 int，不是 float64）。
func mustYAML(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestValidate：每个支持的关键字各一个通过、一个不通过的文档；违反处的报告带路径。
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name, schema string
		ok, bad      string // YAML 文档
		want         string // bad 的报告里应出现的片段
	}{
		{"type string", `{"type":"string"}`, `abc`, `1`, "want string"},
		{"type integer", `{"type":"integer"}`, `3`, `3.5`, "want integer"},
		{"type number", `{"type":"number"}`, `3`, `"x"`, "want number"},
		{"type boolean", `{"type":"boolean"}`, `true`, `"yes"`, "want boolean"},
		{"type object", `{"type":"object"}`, `{a: 1}`, `[1]`, "want object"},
		{"type array", `{"type":"array"}`, `[1]`, `{a: 1}`, "want array"},
		{"additionalProperties false", `{"type":"object","properties":{"a":{}},"additionalProperties":false}`,
			`{a: 1}`, `{a: 1, foo: 1}`, "$.foo: unknown property"},
		{"additionalProperties schema", `{"type":"object","additionalProperties":{"type":"integer"}}`,
			`{a: 1, b: 2}`, `{a: 1, b: x}`, "$.b: want integer"},
		{"required", `{"type":"object","required":["version"]}`, `{version: 1}`, `{other: 1}`, "$.version: missing"},
		{"enum", `{"enum":["pass","ask","deny"]}`, `ask`, `allow`, "want one of"},
		{"const", `{"const":1}`, `1`, `2`, "want 1"},
		{"items", `{"type":"array","items":{"type":"string"}}`, `[a, b]`, `[a, 1]`, "$[1]: want string"},
		{"minimum", `{"type":"integer","minimum":1}`, `1`, `0`, "below the minimum"},
		{"maximum", `{"type":"number","maximum":3}`, `3`, `3.5`, "above the maximum"},
		{"exclusiveMinimum", `{"type":"number","exclusiveMinimum":0}`, `0.1`, `0`, "not above"},
		{"minItems", `{"type":"array","minItems":1}`, `[a]`, `[]`, "fewer than 1 items"},
		{"$ref", `{"$defs":{"tier":{"type":"integer","maximum":3}},"type":"object","properties":{"tier":{"$ref":"#/$defs/tier"}}}`,
			`{tier: 2}`, `{tier: 4}`, "$.tier: 4 is above the maximum"},
		{"annotations", `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"x","title":"t","description":"d","default":1,"type":"integer"}`,
			`1`, `x`, "want integer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := mustJSON(t, tc.schema)
			if errs := schematest.Validate(s, mustYAML(t, tc.ok)); len(errs) > 0 {
				t.Errorf("valid document rejected: %v", errs)
			}
			errs := schematest.Validate(s, mustYAML(t, tc.bad))
			if !slices.ContainsFunc(errs, func(e string) bool { return strings.Contains(e, tc.want) }) {
				t.Errorf("invalid document: got %v, want a report containing %q", errs, tc.want)
			}
		})
	}
}

// TestValidateNumbers：yaml 库解码出的 int、int64、uint64 与 JSON 的整数值 float64 都算整数；
// enum 与 const 比较时数字不区分来源。
func TestValidateNumbers(t *testing.T) {
	s := mustJSON(t, `{"type":"integer","enum":[1,2]}`)
	for _, v := range []any{1, int64(2), uint64(1), float64(2)} {
		if errs := schematest.Validate(s, v); len(errs) > 0 {
			t.Errorf("%T %v: %v", v, v, errs)
		}
	}
	if errs := schematest.Validate(s, 3); len(errs) == 0 {
		t.Error("3 should not be in the enum")
	}
}

// TestValidateUnsupportedKeyword：认识的关键字之外的一律报错，哪怕文档没有走到那里。
func TestValidateUnsupportedKeyword(t *testing.T) {
	for _, tc := range []struct{ schema, keyword string }{
		{`{"oneOf":[{"type":"string"},{"type":"integer"}]}`, "oneOf"},
		{`{"type":"object","properties":{"a":{"pattern":"^x"}}}`, "pattern"},
		{`{"$defs":{"x":{"if":{}}}}`, "if"},
	} {
		errs := schematest.Validate(mustJSON(t, tc.schema), "x")
		if !slices.Contains(errs, "unsupported keyword "+tc.keyword) {
			t.Errorf("%s: got %v", tc.schema, errs)
		}
	}
	// $ref 只能引用本文件的 #/$defs/…
	errs := schematest.Validate(mustJSON(t, `{"$ref":"other.json#/x"}`), "x")
	if len(errs) == 0 {
		t.Error("an external $ref should be rejected")
	}
}

type inner struct {
	Name string `yaml:"name"`
}

type sample struct {
	Version int              `yaml:"version"`
	Plain   string           // 没有标签：yaml 库默认用小写字段名
	Ptr     *inner           `yaml:"ptr"`
	Map     map[string]inner `yaml:"map"`
	List    []inner          `yaml:"list"`
	Skip    string           `yaml:"-"`
	hidden  string
	Partial partial `yaml:"partial"`
}

type partial struct {
	Type    string
	Profile string
	other   string
}

// TestCompareStruct：字段名集合按 yaml 标签递归核对；少写、多写的字段都报出来。
func TestCompareStruct(t *testing.T) {
	_ = sample{}.hidden
	_ = partial{}.other
	good := `{
	  "type": "object", "additionalProperties": false,
	  "$defs": {"inner": {"type": "object", "additionalProperties": false, "properties": {"name": {"type": "string"}}}},
	  "properties": {
	    "version": {"type": "integer"},
	    "plain": {"type": "string"},
	    "ptr": {"$ref": "#/$defs/inner"},
	    "map": {"type": "object", "additionalProperties": {"$ref": "#/$defs/inner"}},
	    "list": {"type": "array", "items": {"$ref": "#/$defs/inner"}},
	    "partial": {"type": "object", "additionalProperties": true, "properties": {"type": {"type": "string"}, "profile": {"type": "string"}}}
	  }}`
	parts := map[reflect.Type][]string{reflect.TypeFor[partial](): {"type", "profile"}}
	schematest.CompareStruct(t, mustJSON(t, good), reflect.TypeFor[sample](), parts)

	for _, tc := range []struct{ name, from, to string }{
		{"missing field", `"plain": {"type": "string"},`, ``},
		{"extra field", `"plain": {"type": "string"},`, `"plain": {"type": "string"}, "extra": {"type": "string"},`},
		{"nested", `"properties": {"name": {"type": "string"}}`, `"properties": {"nom": {"type": "string"}}`},
		{"wrong type", `"version": {"type": "integer"}`, `"version": {"type": "string"}`},
		{"open object", `"inner": {"type": "object", "additionalProperties": false,`, `"inner": {"type": "object",`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := strings.Replace(good, tc.from, tc.to, 1)
			if bad == good {
				t.Fatal("replacement did not apply")
			}
			ft := &fakeT{}
			schematest.CompareStruct(ft, mustJSON(t, bad), reflect.TypeFor[sample](), parts)
			if !ft.failed {
				t.Error("mismatch not reported")
			}
		})
	}
}

// fakeT 记录 CompareStruct 是否报告了失败。
type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Errorf(string, ...any) { f.failed = true }
func (f *fakeT) Fatalf(string, ...any) { f.failed = true }

// TestLoad：读出 JSON 文件。
func TestLoad(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(`{"type":"string"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s := schematest.Load(t, p); s["type"] != "string" {
		t.Errorf("got %v", s)
	}
}

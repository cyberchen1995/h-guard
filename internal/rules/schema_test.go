package rules_test

import (
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/internal/schematest"
	builtin "github.com/cyberchen1995/h-guard/rules"
)

const (
	actionSchema   = "../../schema/rule-action.schema.json"
	outboundSchema = "../../schema/rule-outbound.schema.json"
	schemaBase     = "https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/"
)

// TestRuleSchemasMatchStruct：两种规则的 schema 每一层的属性与 Rule、OutboundRule 的 yaml 字段一一对应；
// outbound 的 match.detector 取值等于可用的检测器。
func TestRuleSchemasMatchStruct(t *testing.T) {
	for _, tc := range []struct {
		path, file string
		typ        reflect.Type
	}{
		{actionSchema, "rule-action.schema.json", reflect.TypeFor[rules.Rule]()},
		{outboundSchema, "rule-outbound.schema.json", reflect.TypeFor[rules.OutboundRule]()},
	} {
		s := schematest.Load(t, tc.path)
		if s["$id"] != schemaBase+tc.file || s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: $id = %v, $schema = %v", tc.file, s["$id"], s["$schema"])
		}
		schematest.CompareStruct(t, s, tc.typ, nil)
	}
	s := schematest.Load(t, outboundSchema)
	match := s["properties"].(map[string]any)["match"].(map[string]any)
	if ref, ok := match["$ref"].(string); ok {
		match = s["$defs"].(map[string]any)[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any)
	}
	var got []string
	for _, v := range match["properties"].(map[string]any)["detector"].(map[string]any)["enum"].([]any) {
		got = append(got, v.(string))
	}
	if want := rules.Detectors(); !slices.Equal(got, want) {
		t.Errorf("match.detector enum = %v, want %v", got, want)
	}
}

// TestRuleSchemasAcceptBuiltin：内置规则包的每条规则都通过各自的 schema；规则写错的地方被拦下。
func TestRuleSchemasAcceptBuiltin(t *testing.T) {
	for _, tc := range []struct{ dir, schema string }{{"action", actionSchema}, {"outbound", outboundSchema}} {
		s := schematest.Load(t, tc.schema)
		files, err := fs.Glob(builtin.FS, tc.dir+"/*.yaml")
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v (%d files)", tc.dir, err, len(files))
		}
		for _, f := range files {
			data, err := fs.ReadFile(builtin.FS, f)
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatal(err)
			}
			if errs := schematest.Validate(s, doc); len(errs) > 0 {
				t.Errorf("%s: %v", f, errs)
			}
		}
	}
	for _, tc := range []struct{ schema, doc string }{
		{actionSchema, "schema: 1\nid: x\naction: warn\non: [exec]\nreason: {en: r}\nmatch: {exec: {any: [x]}}\n"},
		{actionSchema, "schema: 1\nid: x\naction: ask\non: [tool_call]\nreason: {en: r}\nmatch: {exec: {any: [x]}}\n"},
		{actionSchema, "schema: 1\nid: x\naction: ask\non: [exec]\nreason: {zh-CN: r}\nmatch: {exec: {any: [x]}}\n"},
		{actionSchema, "schema: 1\nid: x\naction: ask\non: [exec]\nreason: {en: r}\nmatch: {exec: {any: [x]}}\nradius_floor: 4\n"},
		{actionSchema, "schema: 1\nid: x\naction: ask\non: [exec]\nreason: {en: r}\nmatch: {exec: {any: [x]}}\ncategory: c\n"},
		{outboundSchema, "schema: 1\nid: x\ncategory: c\non: [exec]\nmatch: {regex: [x]}\n"},
		{outboundSchema, "schema: 1\nid: x\ncategory: c\non: [prompt]\nmatch: {detector: nope}\n"},
		{outboundSchema, "schema: 1\nid: x\ncategory: c\non: [prompt]\nmatch: {regex: [x]}\naction: deny\n"},
	} {
		var doc any
		if err := yaml.Unmarshal([]byte(tc.doc), &doc); err != nil {
			t.Fatal(err)
		}
		if errs := schematest.Validate(schematest.Load(t, tc.schema), doc); len(errs) == 0 {
			t.Errorf("%s accepted:\n%s", tc.schema, tc.doc)
		}
	}
}

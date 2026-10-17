package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/internal/schematest"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic" // 四个内置后端：type 的 enum 要与它们一致
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/openai"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

const configSchema = "../../schema/config.schema.json"

// TestConfigSchemaMatchesStruct：schema 每一层的属性与 Config 的 yaml 字段一一对应；后端只核对 type 与
// profile（其余字段由各后端类型校验），type 的取值等于已注册的后端类型。
func TestConfigSchemaMatchesStruct(t *testing.T) {
	s := schematest.Load(t, configSchema)
	want := "https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/config.schema.json"
	if s["$id"] != want || s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$id = %v, $schema = %v", s["$id"], s["$schema"])
	}
	schematest.CompareStruct(t, s, reflect.TypeFor[Config](), map[reflect.Type][]string{
		reflect.TypeFor[BackendConfig](): {"type", "profile"},
	})
	backend := resolve(t, s, s["properties"].(map[string]any)["backends"].(map[string]any)["additionalProperties"])
	if backend["additionalProperties"] != true || !slices.Equal(stringsOf(backend["required"]), []string{"type"}) {
		t.Errorf("backends.<name> should require type and allow the backend's own fields: %v", backend)
	}
	typ := backend["properties"].(map[string]any)["type"].(map[string]any)
	if got := stringsOf(typ["enum"]); !slices.Equal(got, judge.Types()) {
		t.Errorf("backends.<name>.type enum = %v, want %v", got, judge.Types())
	}
	if d, _ := backend["description"].(string); !strings.Contains(d, "docs/guide/configuration.md") {
		t.Errorf("backends.<name> description should point to the guide: %q", d)
	}
}

// TestConfigSchemaAcceptsDefaults：内置默认配置通过 schema（config init 的模板在 internal/app 里核对）。
func TestConfigSchemaAcceptsDefaults(t *testing.T) {
	s := schematest.Load(t, configSchema)
	var doc any
	if err := yaml.Unmarshal(defaultYAML, &doc); err != nil {
		t.Fatal(err)
	}
	if errs := schematest.Validate(s, doc); len(errs) > 0 {
		t.Errorf("default.yaml: %v", errs)
	}
}

// TestConfigSchemaRejectsUnknown：未知字段、类型不对、缺 version 的文档都不通过，取值越界的也不通过。
func TestConfigSchemaRejectsUnknown(t *testing.T) {
	s := schematest.Load(t, configSchema)
	for _, doc := range []string{
		"version: 1\nfoo: 1\n",
		"version: 1\njudge: {enabled: \"yes\"}\n",
		"locale: en\n",
		"version: 2\n",
		"version: 1\naction: {tier: 4}\n",
		"version: 1\npolicy: {on_unavailable: allow}\n",
		"version: 1\nbackends: {x: {model: m}}\n",
		"version: 1\nbackends: {x: {type: nope}}\n",
		"version: 1\noutbound: {categories: {pii: {action: ask}}}\n",
		"version: 1\nprofiles: {p: {thresholds: {hit: 1.5, veto: 0, requested: 0}}}\n",
		"version: 1\nrules: {publish: {}}\n",
	} {
		var v any
		if err := yaml.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatal(err)
		}
		if errs := schematest.Validate(s, v); len(errs) == 0 {
			t.Errorf("accepted:\n%s", doc)
		}
	}
	// 后端自己的字段由后端类型校验，schema 不拦
	var v any
	_ = yaml.Unmarshal([]byte("version: 1\nbackends: {x: {type: openai, base_url: \"http://localhost:1/v1\", model: m}}\n"), &v)
	if errs := schematest.Validate(s, v); len(errs) > 0 {
		t.Errorf("backend options rejected: %v", errs)
	}
}

func resolve(t *testing.T, root map[string]any, node any) map[string]any {
	t.Helper()
	m, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("not a schema: %v", node)
	}
	if ref, ok := m["$ref"].(string); ok {
		name, found := strings.CutPrefix(ref, "#/$defs/")
		if !found {
			t.Fatalf("unexpected $ref %q", ref)
		}
		return resolve(t, root, root["$defs"].(map[string]any)[name])
	}
	return m
}

func stringsOf(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

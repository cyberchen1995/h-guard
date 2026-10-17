package install

import (
	"encoding/json"
	"testing"
)

// TestObjectKeepsOrderAndValues：改写 harness 的 JSON 配置时保留键的顺序与其余内容，只动指定的键。
func TestObjectKeepsOrderAndValues(t *testing.T) {
	in := `{"model": "opus", "env": {"B": "2", "A": "1"}, "hooks": {"Stop": []}, "n": 1.50}`
	o, err := parseObject([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	env, err := o.object("env")
	if err != nil {
		t.Fatal(err)
	}
	env.set("CLAUDE_CODE_PLUGIN_DIRS", "/p")
	if err := o.setObject("env", env); err != nil {
		t.Fatal(err)
	}
	o.set("added", true)
	got := string(o.marshal())
	want := "{\n  \"model\": \"opus\",\n  \"env\": {\n    \"B\": \"2\",\n    \"A\": \"1\",\n    \"CLAUDE_CODE_PLUGIN_DIRS\": \"/p\"\n  },\n  \"hooks\": {\n    \"Stop\": []\n  },\n  \"n\": 1.50,\n  \"added\": true\n}\n"
	if got != want {
		t.Errorf("marshal =\n%s\nwant\n%s", got, want)
	}
	o.delete("hooks")
	if _, ok := o.get("hooks"); ok || !json.Valid(o.marshal()) {
		t.Errorf("delete: %s", o.marshal())
	}
	if _, err := o.object("model"); err == nil {
		t.Error("a string value read as an object")
	}
	missing, err := o.object("nothing")
	if err != nil || len(missing.keys) != 0 {
		t.Errorf("missing key: %+v, %v", missing, err)
	}
}

func TestParseObjectRejects(t *testing.T) {
	for _, in := range []string{"", "[]", "{", `{"a":1} x`, `{"a":1,"a":2}`, "// c\n{}"} {
		if _, err := parseObject([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if o, err := parseObject([]byte(" \n")); err == nil {
		t.Errorf("blank accepted: %+v", o)
	}
}

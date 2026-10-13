package i18n

import (
	"strings"
	"testing"
)

func mustLoad(t *testing.T) *Catalog {
	t.Helper()
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEveryKeyHasEnglishText(t *testing.T) {
	c := mustLoad(t)
	for _, k := range AllKeys {
		if _, ok := c.msgs[DefaultLocale][k]; !ok {
			t.Errorf("en lacks %q", k)
		}
	}
}

func TestEveryLocaleKeyIsKnown(t *testing.T) {
	c := mustLoad(t)
	known := map[string]bool{}
	for _, k := range AllKeys {
		known[k] = true
	}
	for loc, msgs := range c.msgs {
		for k := range msgs {
			if !known[k] {
				t.Errorf("%s has unknown key %q", loc, k)
			}
		}
	}
}

func TestTextFallsBackToEnglishAndFillsParams(t *testing.T) {
	c := mustLoad(t)
	c.msgs["zh-CN"] = map[string]string{} // 模拟 zh-CN 缺键
	got := c.Text("zh-CN", KeyActionBlocked, map[string]string{"rules": "rm -rf /"})
	if got != "Blocked: rm -rf /." {
		t.Errorf("fallback text = %q", got)
	}
	if got := c.Text("zh-CN", "no.such.key", nil); got != "no.such.key" {
		t.Errorf("missing key text = %q", got)
	}
}

func TestChineseText(t *testing.T) {
	c := mustLoad(t)
	got := c.Text("zh-CN", KeyActionRadius, map[string]string{"radius": "2.0"})
	if got != "影响范围 2.0/3。" {
		t.Errorf("zh-CN text = %q", got)
	}
	if !strings.Contains(c.Text("zh-CN", KeyHintRequest, nil), "下一条消息") {
		t.Error("zh-CN hint not localized")
	}
}

func TestSelectLocale(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	tests := []struct {
		configured string
		env        map[string]string
		want       string
	}{
		{"zh-CN", map[string]string{"LANG": "en_US.UTF-8"}, "zh-CN"},
		{"", map[string]string{"LC_ALL": "zh_CN.UTF-8", "LANG": "en_US.UTF-8"}, "zh-CN"},
		{"", map[string]string{"LANG": "zh_CN.GB2312"}, "zh-CN"},
		{"", map[string]string{"LANG": "fr_FR.UTF-8"}, "en"},
		{"", map[string]string{"LANG": "C"}, "en"},
		{"", nil, "en"},
		{"fr", nil, "en"},
	}
	for _, tt := range tests {
		if got := SelectLocale(tt.configured, env(tt.env)); got != tt.want {
			t.Errorf("SelectLocale(%q, %v) = %q, want %q", tt.configured, tt.env, got, tt.want)
		}
	}
}

func TestPick(t *testing.T) {
	m := map[string]string{"en": "Publishes", "zh-CN": "发布"}
	if Pick(m, "zh-CN") != "发布" || Pick(m, "fr") != "Publishes" {
		t.Errorf("Pick = %q / %q", Pick(m, "zh-CN"), Pick(m, "fr"))
	}
	if Pick(map[string]string{"zh-CN": "仅中文"}, "en") != "仅中文" {
		t.Error("Pick must fall back to any text when en is missing")
	}
	if Pick(nil, "en") != "" {
		t.Error("Pick(nil) must be empty")
	}
}

// TestParamValuesAreNotExpanded：参数值里的 {…} 原样保留，结果与参数的替换顺序无关（M1 遗留问题）。
func TestParamValuesAreNotExpanded(t *testing.T) {
	c := mustLoad(t)
	want := "The judge is unavailable ({rules}), so the matching rules ask for confirmation: a {code} b."
	for i := 0; i < 50; i++ {
		got := c.Text("en", KeyActionJudgeUnavailable, map[string]string{"code": "{rules}", "rules": "a {code} b"})
		if got != want {
			t.Fatalf("Text = %q, want %q", got, want)
		}
	}
	if got := c.Text("en", KeyHintConsent, nil); !strings.Contains(got, "{backend}") {
		t.Errorf("a missing param must stay visible: %q", got)
	}
}

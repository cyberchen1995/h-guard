package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultsAreValid(t *testing.T) {
	c := Defaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Judge.Enabled || c.Judge.Backend != "jev" || c.Action.Tier != 2 || c.Outbound.Tier != 1 {
		t.Errorf("defaults = %+v", c)
	}
	th := c.Thresholds()
	if th.Hit != 0.5 || th.Veto != 0.2 || th.Requested != 0.7 || th.RadiusFloor["recursive_delete"] != 1.25 {
		t.Errorf("jev thresholds = %+v", th)
	}
	if c.Policy.RequestWindow != 3 || c.Policy.MaxCommandChars != 8000 || c.Policy.MaxRequestChars != 2000 ||
		c.Policy.OnUnavailable != "pass" || c.Policy.WhenAskUnsupported != "deny" {
		t.Errorf("policy = %+v", c.Policy)
	}
}

func TestLoadMergesInOrder(t *testing.T) {
	dir := t.TempDir()
	user := write(t, dir, "config.yaml", "version: 1\nlocale: zh-CN\naction: {tier: 1}\npolicy: {request_window: 5}\n")
	extra := write(t, dir, "extra.yaml", "version: 1\naction: {tier: 3}\n")
	c, err := Load(user, extra)
	if err != nil {
		t.Fatal(err)
	}
	if c.Locale != "zh-CN" || c.Action.Tier != 3 || c.Policy.RequestWindow != 5 || c.Policy.MaxCommandChars != 8000 {
		t.Errorf("merged = %+v", c)
	}
}

func TestLoadSkipsMissingAndEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	empty := write(t, dir, "empty.yaml", "")
	c, err := Load(filepath.Join(dir, "missing.yaml"), empty)
	if err != nil {
		t.Fatal(err)
	}
	if c.Action.Tier != 2 {
		t.Errorf("tier = %d", c.Action.Tier)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := map[string]string{
		"unknown field":        "version: 1\njudge: {enabled: true, colour: red}\n",
		"type mismatch":        "version: 1\naction: {tier: high}\n",
		"wrong version":        "version: 2\n",
		"missing version":      "action: {tier: 1}\n",
		"tier out of range":    "version: 1\naction: {tier: 4}\n",
		"unknown backend":      "version: 1\njudge: {backend: nope}\n",
		"unknown backend type": "version: 1\nbackends: {x: {type: carrier-pigeon}}\njudge: {backend: x}\n",
		"bad threshold":        "version: 1\nprofiles: {jev: {thresholds: {hit: 1.5, veto: 0.2, requested: 0.7}}}\n",
		"bad on_unavailable":   "version: 1\npolicy: {on_unavailable: maybe}\n",
		"bad ask fallback":     "version: 1\npolicy: {when_ask_unsupported: ask}\n",
		"bad window":           "version: 1\npolicy: {request_window: 0}\n",
		"bad shell":            "version: 1\nharnesses: {codex: {shell: cmd}}\n",
		"bad rule id":          "version: 1\nrules: {'Bad Id': {enabled: false}}\n",
		"plaintext key":        "version: 1\nbackends: {jev: {type: typesafe, profile: jev, api_key: sk-abc}}\n",
		"backend type missing": "version: 1\nbackends: {jev: {model: x}}\n",
		"unknown profile":      "version: 1\nbackends: {jev: {type: typesafe, profile: nope}}\n",
		"bad backend option":   "version: 1\nbackends: {jev: {type: typesafe, base_url: 'ftp://x'}}\n",
		"rule without enabled": "version: 1\nrules: {publish: {}}\n",
		"incomplete profile":   "version: 1\nprofiles: {jev: {thresholds: {hit: 0.5}}}\n",
		"empty profile":        "version: 1\nprofiles: {jev: {}}\n",
		"second document":      "version: 1\n---\nversion: 1\njudge: {enabled: true}\n",
		"trailing garbage doc": "version: 1\n---\n: : :\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			p := write(t, t.TempDir(), "c.yaml", body)
			if _, err := Load(p); err == nil {
				t.Errorf("Load accepted:\n%s", body)
			}
		})
	}
}

func TestErrorsNamePathAndField(t *testing.T) {
	p := write(t, t.TempDir(), "c.yaml", "version: 1\naction: {tier: 9}\n")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "action.tier") || !strings.Contains(err.Error(), "c.yaml") {
		t.Errorf("err = %v", err)
	}
}

func TestErrorsDoNotEchoValues(t *testing.T) {
	const canary = "HGCanaryValue987654"
	for _, body := range []string{
		"version: 1\nbackends: {jev: {type: typesafe, profile: jev, base_url: 'https://user:" + canary + "@example.invalid'}}\n",
		"version: 1\npolicy: {on_unavailable: " + canary + "}\n",
		"version: 1\naction: {tier: " + canary + "}\n",
		"version: 1\nbackends: {jev: {type: " + canary + "}}\n",
		"version: 1\njudge: {backend: " + canary + "}\n",
	} {
		p := write(t, t.TempDir(), "config.yaml", body)
		_, err := Load(p)
		var ce *Error
		if !errors.As(err, &ce) {
			t.Fatalf("%s: err = %v, want *Error", body, err)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(ce.Brief(), canary) {
			t.Errorf("error echoes the configured value:\n%v\n%s", err, ce.Brief())
		}
		if !strings.HasPrefix(ce.Brief(), "config.yaml: ") {
			t.Errorf("Brief = %q", ce.Brief())
		}
	}
}

func TestExplicitZeroThresholdIsKept(t *testing.T) {
	p := write(t, t.TempDir(), "c.yaml", "version: 1\nprofiles: {jev: {thresholds: {hit: 0.5, veto: 0, requested: 0.9}}}\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if th := c.Thresholds(); th.Veto != 0 || th.Requested != 0.9 || len(th.RadiusFloor) != 0 {
		t.Errorf("thresholds = %+v", th)
	}
}

func TestBackendEntriesReplaceWhole(t *testing.T) {
	// 后端定义整条替换：用户重写 jev 而不写 profile 时，不继承内置的 profile
	p := write(t, t.TempDir(), "c.yaml", "version: 1\nbackends: {jev: {type: typesafe, model: jev-2}}\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Backends["jev"]; b.Type != "typesafe" || b.Profile != "" {
		t.Errorf("jev = %+v", b)
	}
	if th := c.Thresholds(); th.Hit != ConservativeThresholds.Hit {
		t.Errorf("a backend without a profile must use conservative thresholds, got %+v", th)
	}
}

func TestRuleEnabledOverride(t *testing.T) {
	p := write(t, t.TempDir(), "c.yaml", "version: 1\nrules: {publish: {enabled: false}}\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if on, set := c.RuleEnabled("publish"); on || !set {
		t.Errorf("publish = %v, %v", on, set)
	}
	if _, set := c.RuleEnabled("branch_ops"); set {
		t.Error("branch_ops must not be set")
	}
}

func TestShellFor(t *testing.T) {
	c := Defaults()
	if c.ShellFor("codex") != "posix" {
		t.Errorf("default shell = %s", c.ShellFor("codex"))
	}
	c.Harnesses = map[string]Harness{"codex": {Shell: "powershell"}}
	if c.ShellFor("codex") != "powershell" {
		t.Errorf("configured shell = %s", c.ShellFor("codex"))
	}
}

func TestNewBackend(t *testing.T) {
	b, err := Defaults().NewBackend("jev")
	if err != nil || b.Name() != "jev" {
		t.Fatalf("NewBackend = %v, %v", b, err)
	}
	if _, err := Defaults().NewBackend("nope"); err == nil {
		t.Error("NewBackend accepted an unknown name")
	}
}

func TestApplyDotEnv(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".env", "# comment\nHG_TEST_A=from-file\nexport HG_TEST_B='quoted value'\nHG_TEST_C=file\nnot a pair\n")
	t.Setenv("HG_TEST_C", "from-env")
	for _, k := range []string{"HG_TEST_A", "HG_TEST_B"} {
		t.Setenv(k, "") // 注册清理
		os.Unsetenv(k)
	}
	if err := ApplyDotEnv(dir); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("HG_TEST_A") != "from-file" || os.Getenv("HG_TEST_B") != "quoted value" {
		t.Errorf("A=%q B=%q", os.Getenv("HG_TEST_A"), os.Getenv("HG_TEST_B"))
	}
	if os.Getenv("HG_TEST_C") != "from-env" {
		t.Error("the environment must win over .env")
	}
	if err := ApplyDotEnv(filepath.Join(dir, "missing")); err != nil {
		t.Errorf("missing .env: %v", err)
	}
}

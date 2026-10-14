package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

// described 是说得出自己模型与概率获取方式的后端。
type described struct{ info judge.Info }

func (described) Name() string            { return "d" }
func (described) Caps() judge.BackendCaps { return judge.BackendCaps{} }
func (described) Ask(context.Context, map[string]any, []judge.Question) (judge.Response, error) {
	return judge.Response{}, nil
}
func (d described) Describe() judge.Info { return d.info }

// undescribed 没有实现 judge.Describer。
type undescribed struct{ judge.Backend }

var (
	digestA = QuestionsDigest([]judge.Question{{ID: "a", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "A?"}}})
	jevInfo = judge.Info{Target: "https://api.typesafe.ai:443", Model: "jev-latest", Probability: "native"}
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
	p := c.Profiles["jev"].Thresholds
	if *p.Hit != 0.4 || *p.Veto != 0.1 || *p.Requested != 0.75 || p.RadiusFloor["recursive_delete"] != 1.25 {
		t.Errorf("jev profile = %+v", p)
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
		"version: 1\nbackends: {jev: {type: typesafe, profile: jev, base_url: 'https://example.invalid/v1?key=" + canary + "'}}\n",
		"version: 1\nbackends: {jev: {type: typesafe, profile: jev, api_key_env: 'sk-" + canary + "'}}\n",
		"version: 1\npolicy: {on_unavailable: " + canary + "}\n",
		"version: 1\naction: {tier: " + canary + "}\n",
		"version: 1\nbackends: {jev: {type: " + canary + "}}\n",
		"version: 1\njudge: {backend: " + canary + "}\n",
		"version: 1\nbackends: {claude: {type: anthropic, model: m, answer: " + canary + "}}\n",
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
	c.Profiles["jev"] = Profile{Thresholds: c.Profiles["jev"].Thresholds,
		Fingerprint: &Fingerprint{Model: jevInfo.Model, Probability: jevInfo.Probability, Questions: digestA}}
	if th, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA); !cal.Calibrated() || th.Veto != 0 || th.Requested != 0.9 || len(th.RadiusFloor) != 0 {
		t.Errorf("thresholds = %+v (%+v)", th, cal)
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
	if th, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA); th.Hit != ConservativeThresholds.Hit || cal.Reason != UncalibratedNoProfile {
		t.Errorf("a backend without a profile must use conservative thresholds, got %+v (%+v)", th, cal)
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

// TestExecKindsFromYAML：exec 后端的 kinds 经配置文件解码后校验。空列表（与省略不同）、未知取值、重复都是
// 配置错误，说明不回显取值；省略时两种题型都能回答。
func TestExecKindsFromYAML(t *testing.T) {
	const canary = "HGCanaryKind987654"
	const prefix = "version: 1\nbackends: {local: {type: exec, command: /opt/judge/run"
	for name, kinds := range map[string]string{
		"empty list": "[]",
		"unknown":    "[probability, " + canary + "]",
		"duplicate":  "[scale, scale]",
	} {
		p := write(t, t.TempDir(), "c.yaml", prefix+", kinds: "+kinds+"}}\n")
		_, err := Load(p)
		// 要求 exec 自己的说明：kinds 不是已知字段时 Load 同样报错，但不是因为这一项的取值
		if err == nil || !strings.Contains(err.Error(), "backends.local: exec: kinds") || strings.Contains(err.Error(), canary) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for opt, want := range map[string][]judge.Kind{
		"":                              {judge.KindProbability, judge.KindScale},
		", kinds: [probability]":        {judge.KindProbability},
		", kinds: [scale, probability]": {judge.KindScale, judge.KindProbability},
	} {
		c, err := Load(write(t, t.TempDir(), "c.yaml", prefix+opt+"}}\n"))
		if err != nil {
			t.Fatalf("%q: %v", opt, err)
		}
		b, err := c.NewBackend("local")
		if err != nil {
			t.Fatalf("%q: %v", opt, err)
		}
		if got := b.Caps().Kinds; !slices.Equal(got, want) {
			t.Errorf("%q: kinds = %v, want %v", opt, got, want)
		}
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

// TestProfileNeedsAMatchingFingerprint：档案只在指纹与后端的模型、概率获取方式、题集一致时使用，
// 否则用保守默认值并说明原因（spec §8.3）。
func TestProfileNeedsAMatchingFingerprint(t *testing.T) {
	c := Defaults()
	jev := c.Profiles["jev"]
	jev.Fingerprint = nil // 内置档案自 M2 验收起带指纹；先看没有指纹的情形
	c.Profiles["jev"] = jev
	if th, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA); cal.Reason != UncalibratedNoFingerprint || cal.Profile != "jev" ||
		th.Hit != ConservativeThresholds.Hit || th.Requested != ConservativeThresholds.Requested {
		t.Errorf("jev without a fingerprint: %+v (%+v)", th, cal)
	}
	jev.Fingerprint = &Fingerprint{Model: "jev-latest", Probability: "native", Questions: digestA}
	c.Profiles["jev"] = jev
	th, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA)
	if !cal.Calibrated() || th.Hit != 0.4 || th.Veto != 0.1 || th.Requested != 0.75 || th.RadiusFloor["recursive_delete"] != 1.25 {
		t.Errorf("matching fingerprint: %+v (%+v)", th, cal)
	}
	th.RadiusFloor["recursive_delete"] = 0
	if *c.Profiles["jev"].Thresholds.Hit != 0.4 || c.Profiles["jev"].Thresholds.RadiusFloor["recursive_delete"] != 1.25 {
		t.Error("ThresholdsFor must return a copy")
	}
	otherModel, otherProb := jevInfo, jevInfo
	otherModel.Model, otherProb.Probability = "jev-2", "verbalized"
	digestB := QuestionsDigest([]judge.Question{{ID: "a", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "A, reworded?"}}})
	for want, call := range map[string]func() (Thresholds, Calibration){
		UncalibratedModel:       func() (Thresholds, Calibration) { return c.ThresholdsFor("jev", described{otherModel}, digestA) },
		UncalibratedProbability: func() (Thresholds, Calibration) { return c.ThresholdsFor("jev", described{otherProb}, digestA) },
		UncalibratedQuestions:   func() (Thresholds, Calibration) { return c.ThresholdsFor("jev", described{jevInfo}, digestB) },
		UncalibratedUndescribed: func() (Thresholds, Calibration) { return c.ThresholdsFor("jev", undescribed{}, digestA) },
	} {
		if th, cal := call(); cal.Reason != want || cal.Calibrated() || th.Hit != ConservativeThresholds.Hit || len(th.RadiusFloor) != 0 {
			t.Errorf("%s: %+v (%+v)", want, th, cal)
		}
	}
}

func TestQuestionsDigest(t *testing.T) {
	a := judge.Question{ID: "a", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "A?"}}
	b := judge.Question{ID: "b", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "B?"}, Levels: []string{"x", "y"}}
	if QuestionsDigest([]judge.Question{a, b}) != QuestionsDigest([]judge.Question{b, a}) {
		t.Error("the digest must not depend on question order")
	}
	b2 := b
	b2.Levels = []string{"x", "z"}
	if QuestionsDigest([]judge.Question{a, b}) == QuestionsDigest([]judge.Question{a, b2}) || QuestionsDigest([]judge.Question{a}) == QuestionsDigest([]judge.Question{a, b}) {
		t.Error("the digest must change with the levels or the set")
	}
	if !strings.HasPrefix(digestA, "sha256:") || len(digestA) != len("sha256:")+64 {
		t.Errorf("digest = %q", digestA)
	}
}

func TestFingerprintValidation(t *testing.T) {
	for name, fp := range map[string]string{
		"no model":   "{probability: native, questions: " + digestA + "}",
		"bad digest": "{model: m, probability: native, questions: abc}",
		"unknown":    "{model: m, probability: native, questions: " + digestA + ", extra: 1}",
	} {
		p := write(t, t.TempDir(), "c.yaml", "version: 1\nprofiles: {jev: {thresholds: {hit: 0.5, veto: 0.2, requested: 0.7}, fingerprint: "+fp+"}}\n")
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := write(t, t.TempDir(), "c.yaml", "version: 1\nprofiles: {jev: {thresholds: {hit: 0.5, veto: 0.2, requested: 0.7}, fingerprint: {model: m, probability: native, questions: "+digestA+"}}}\n")
	if _, err := Load(p); err != nil {
		t.Errorf("valid fingerprint rejected: %v", err)
	}
}

// TestAnthropicAnswerFromYAML：anthropic 的 answer 从配置读入（取答方式体现在 Caps().Mechanism 与校准用的
// Info.Probability 上）；未知取值是配置错误，说明不回显取值。
func TestAnthropicAnswerFromYAML(t *testing.T) {
	const prefix = "version: 1\nbackends: {claude: {type: anthropic, model: claude-sonnet-5-5"
	for answer, want := range map[string]struct {
		mechanism   judge.Mechanism
		probability string
	}{
		"":                     {judge.MechanismForcedTool, "verbalized"},
		", answer: structured": {judge.MechanismJSONSchema, "verbalized-structured"},
		", answer: auto_tool":  {judge.MechanismAutoTool, "verbalized-auto-tool"},
	} {
		c, err := Load(write(t, t.TempDir(), "c.yaml", prefix+answer+"}}\n"))
		if err != nil {
			t.Fatalf("%q: %v", answer, err)
		}
		b, err := c.NewBackend("claude")
		if err != nil {
			t.Fatal(err)
		}
		d, ok := b.(judge.Describer)
		if !ok || b.Caps().Mechanism != want.mechanism || d.Describe().Probability != want.probability {
			t.Errorf("%q: backend = %v, want mechanism %q and probability %q", answer, b, want.mechanism, want.probability)
		}
	}
	const canary = "HGCanaryAnswer864209"
	_, err := Load(write(t, t.TempDir(), "c.yaml", prefix+", answer: "+canary+"}}\n"))
	if err == nil || !strings.Contains(err.Error(), "backends.claude: anthropic: answer") || strings.Contains(err.Error(), canary) {
		t.Errorf("err = %v", err)
	}
}

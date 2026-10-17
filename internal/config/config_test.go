package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	"github.com/cyberchen1995/h-guard/pkg/judge/openai"
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

// TestDefaultsIncludeTheRecommendedBackends：内置后端是稳定的名字（jev、claude-haiku、claude-sonnet、
// gemma4-local），名字合法、构造得出、说得出模型与概率获取方式；默认仍然不开启模型，后端仍是 jev。
// 增减内置后端要在这里有意识地改。
func TestDefaultsIncludeTheRecommendedBackends(t *testing.T) {
	c := Defaults()
	if c.Judge.Enabled || c.Judge.Backend != "jev" {
		t.Errorf("judge = %+v, want disabled with backend jev", c.Judge)
	}
	want := []struct{ name, typ, profile, target, model, probability string }{
		{"claude-haiku", "anthropic", "claude-haiku", "https://api.anthropic.com:443", "claude-haiku-5-5", "verbalized"},
		{"claude-sonnet", "anthropic", "claude-sonnet", "https://api.anthropic.com:443", "claude-sonnet-5-5", "verbalized-structured-effort-low"},
		{"gemma4-local", "openai", "gemma4-local", "http://localhost:11434", "gemma4:12b-mlx", "logprobs-reasoning-effort-none"},
		{"jev", "typesafe", "jev", "https://api.typesafe.ai:443", "jev-latest", "native"},
	}
	var got []string
	for name := range c.Backends {
		got = append(got, name)
	}
	slices.Sort(got)
	var names []string
	for _, w := range want {
		names = append(names, w.name)
	}
	if !slices.Equal(got, names) {
		t.Fatalf("built-in backends = %v, want %v", got, names)
	}
	for _, w := range want {
		if !guard.ValidName(w.name) {
			t.Errorf("%s is not a valid name", w.name)
		}
		bc := c.Backends[w.name]
		if bc.Type != w.typ || bc.Profile != w.profile {
			t.Errorf("%s: type %q profile %q, want %q %q", w.name, bc.Type, bc.Profile, w.typ, w.profile)
		}
		b, err := c.NewBackend(w.name)
		if err != nil {
			t.Errorf("%s: %v", w.name, err)
			continue
		}
		d, ok := b.(judge.Describer)
		if !ok {
			t.Errorf("%s does not describe itself", w.name)
			continue
		}
		if info := d.Describe(); info.Target != w.target || info.Model != w.model || info.Probability != w.probability {
			t.Errorf("%s describes itself as %+v, want %s %s %s", w.name, info, w.target, w.model, w.probability)
		}
	}
	// claude-sonnet 的思考占用 max_tokens，所以结构化输出（强制工具调用在该模型上返回 400）与较低的 effort、
	// 较大的 max_tokens 一起出厂；claude-haiku 保持默认（answer tool）
	var sonnet, haiku anthropic.Options
	if err := c.Backends["claude-sonnet"].Decode(&sonnet); err != nil {
		t.Fatal(err)
	}
	if sonnet.Model != "claude-sonnet-5-5" || sonnet.Answer != "structured" || sonnet.Effort != "low" || sonnet.MaxTokens != 4096 {
		t.Errorf("claude-sonnet options = %+v", sonnet)
	}
	if err := c.Backends["claude-haiku"].Decode(&haiku); err != nil {
		t.Fatal(err)
	}
	if haiku.Model != "claude-haiku-5-5" || haiku.Answer != "" || haiku.Effort != "" || haiku.MaxTokens != 0 {
		t.Errorf("claude-haiku options = %+v", haiku)
	}
	// gemma4-local：本地 Ollama，读 logprobs，关掉思考让第一个 token 就是答案；本地模型慢，超时放宽到 30 秒
	var gemma openai.Options
	if err := c.Backends["gemma4-local"].Decode(&gemma); err != nil {
		t.Fatal(err)
	}
	if gemma.Model != "gemma4:12b-mlx" || gemma.BaseURL != "http://localhost:11434/v1" || gemma.Probability != "logprobs" ||
		gemma.ReasoningEffort != "none" || gemma.TimeoutMS != 30000 || gemma.APIKeyEnv != "" {
		t.Errorf("gemma4-local options = %+v", gemma)
	}
}

// TestGemma4LocalProfile：本地模型的内置档案是 sweep 的建议（拟合 113 条语料）：与保守默认值相比，
// 只有 recursive_delete 的影响范围下限不同。指纹的 probability 带 reasoning_effort 后缀（它进入指纹）；
// 请求与校准时逐字节相同，所以建议值仍然适用。
func TestGemma4LocalProfile(t *testing.T) {
	c := Defaults()
	p, ok := c.Profiles["gemma4-local"]
	if !ok {
		t.Fatal("no gemma4-local profile")
	}
	th := p.Thresholds
	if *th.Hit != ConservativeThresholds.Hit || *th.Veto != ConservativeThresholds.Veto || *th.Requested != ConservativeThresholds.Requested {
		t.Errorf("thresholds %+v differ from the conservative defaults %+v", th, ConservativeThresholds)
	}
	if *th.Hit != 0.3 || *th.Veto != 0.05 || *th.Requested != 0.9 || len(th.RadiusFloor) != 1 || th.RadiusFloor["recursive_delete"] != 1 {
		t.Errorf("thresholds = %+v", th)
	}
	fp := p.Fingerprint
	if fp == nil || fp.Model != "gemma4:12b-mlx" || fp.Probability != "logprobs-reasoning-effort-none" ||
		fp.Questions != "sha256:cdd8dab0be5e906b5d5f0fda6c5c60412214db02637af427adcc8e7a9415a5ab" {
		t.Errorf("fingerprint = %+v", fp)
	}
	b := c.Backends["gemma4-local"]
	if b.Type != "openai" || b.Profile != "gemma4-local" {
		t.Errorf("backend = %+v", b)
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
		"version: 1\nbackends: {claude: {type: anthropic, model: m, effort: " + canary + "}}\n",
		"version: 1\nbackends: {local: {type: openai, model: m, temperature: " + canary + "}}\n",
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
// 否则用保守默认值并说明原因。
func TestProfileNeedsAMatchingFingerprint(t *testing.T) {
	c := Defaults()
	jev := c.Profiles["jev"]
	jev.Fingerprint = nil // 内置档案带指纹；先看没有指纹的情形
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

// TestOutboundThreshold：outbound 的阈值单独写在档案的 thresholds.outbound，指纹另记 outbound 题集的指纹
// （fingerprint.outbound_questions），不动 action 的题集指纹；任一不一致时用默认值并说明原因。
func TestOutboundThreshold(t *testing.T) {
	c := Defaults()
	digestB := QuestionsDigest([]judge.Question{{ID: "b", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "B?"}}})
	jev := c.Profiles["jev"]
	jev.Fingerprint = &Fingerprint{Model: "jev-latest", Probability: "native", Questions: digestA}
	c.Profiles["jev"] = jev
	// 档案在、只是没写 outbound 门槛：原因写明是没有 outbound 门槛，不是档案不存在
	if th, cal := c.OutboundThresholdFor("jev", described{jevInfo}, digestB); th != DefaultOutboundThreshold || cal.Reason != UncalibratedNoOutbound {
		t.Errorf("no outbound threshold: %v (%+v)", th, cal)
	}
	if _, cal := c.OutboundThresholdFor("missing", described{jevInfo}, digestB); cal.Reason != UncalibratedNoProfile {
		t.Errorf("no profile: %+v", cal)
	}
	v := 0.35
	jev.Thresholds.Outbound = &v
	c.Profiles["jev"] = jev
	if th, cal := c.OutboundThresholdFor("jev", described{jevInfo}, digestB); th != DefaultOutboundThreshold || cal.Reason != UncalibratedNoFingerprint {
		t.Errorf("no outbound fingerprint: %v (%+v)", th, cal)
	}
	jev.Fingerprint.OutboundQuestions = digestB
	if th, cal := c.OutboundThresholdFor("jev", described{jevInfo}, digestB); th != 0.35 || !cal.Calibrated() {
		t.Errorf("calibrated: %v (%+v)", th, cal)
	}
	// action 的阈值与指纹不受影响
	if _, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA); !cal.Calibrated() {
		t.Errorf("action: %+v", cal)
	}
	other := jevInfo
	other.Model = "jev-2"
	for want, got := range map[string]Calibration{
		UncalibratedQuestions:   func() Calibration { _, c := c.OutboundThresholdFor("jev", described{jevInfo}, digestA); return c }(),
		UncalibratedModel:       func() Calibration { _, c := c.OutboundThresholdFor("jev", described{other}, digestB); return c }(),
		UncalibratedUndescribed: func() Calibration { _, c := c.OutboundThresholdFor("jev", undescribed{}, digestB); return c }(),
	} {
		if got.Reason != want {
			t.Errorf("%s: %+v", want, got)
		}
	}
}

// TestOutboundProfileValidation：thresholds.outbound 在 0..1；fingerprint.outbound_questions 写了就要是 sha256 指纹；
// judge_chunk_chars 至少 500。
func TestOutboundProfileValidation(t *testing.T) {
	for name, body := range map[string]string{
		"threshold":   "profiles: {p: {thresholds: {hit: 0.3, veto: 0.05, requested: 0.9, outbound: 1.5}}}\n",
		"fingerprint": "profiles: {p: {thresholds: {hit: 0.3, veto: 0.05, requested: 0.9}, fingerprint: {model: m, probability: native, questions: " + digestA + ", outbound_questions: abc}}}\n",
		"chunk":       "outbound: {judge_chunk_chars: 100}\n",
	} {
		p := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(p, []byte("version: 1\n"+body), 0o600)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if d := Defaults(); d.Outbound.JudgeChunkChars != 4000 {
		t.Errorf("judge_chunk_chars default = %d", d.Outbound.JudgeChunkChars)
	}
}

// TestOutboundJudgeSwitch：outbound.judge 默认开启，可以单独关掉（只用 action 判断，不把提示词与工具输出发给后端）；
// 按字段叠加。
func TestOutboundJudgeSwitch(t *testing.T) {
	if !Defaults().OutboundJudge() {
		t.Error("outbound.judge should default to true")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("version: 1\noutbound: {judge: false}\n"), 0o600)
	c, err := Load(p)
	if err != nil || c.OutboundJudge() || c.Outbound.Tier != 1 {
		t.Errorf("judge: false: %+v %v", c.Outbound, err)
	}
}

// TestOutboundOnlyProfile：只校准了 outbound 的档案合法（action 的三个阈值都不写、指纹只写 outbound_questions），
// action 按未校准处理；只写了一部分 action 阈值仍是错误（eval --outbound --sweep 的建议能直接写进配置）。
func TestOutboundOnlyProfile(t *testing.T) {
	digestB := QuestionsDigest([]judge.Question{{ID: "b", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "B?"}}})
	p := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(p, []byte("version: 1\nbackends: {jev: {type: typesafe, model: jev-latest, profile: ob, api_key_env: TYPESAFE_API_KEY}}\nprofiles: {ob: {thresholds: {outbound: 0.4}, fingerprint: {model: jev-latest, probability: native, outbound_questions: '"+digestB+"'}}}\n"), 0o600)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if th, cal := c.OutboundThresholdFor("jev", described{jevInfo}, digestB); th != 0.4 || !cal.Calibrated() {
		t.Errorf("outbound: %v %+v", th, cal)
	}
	if _, cal := c.ThresholdsFor("jev", described{jevInfo}, digestA); cal.Reason != UncalibratedNoProfile {
		t.Errorf("action: %+v", cal)
	}
	os.WriteFile(p, []byte("version: 1\nprofiles: {ob: {thresholds: {hit: 0.3, outbound: 0.4}}}\n"), 0o600)
	if _, err := Load(p); err == nil {
		t.Error("partial action thresholds accepted")
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

// TestOptionalParametersFromYAML：anthropic 的 effort 与 openai 的 temperature 从配置读入；
// 取值非法是配置错误，说明带后端名，不回显取值。
func TestOptionalParametersFromYAML(t *testing.T) {
	load := func(t *testing.T, backend string) (judge.Backend, error) {
		t.Helper()
		c, err := Load(write(t, t.TempDir(), "c.yaml", "version: 1\nbackends: {b: "+backend+"}\n"))
		if err != nil {
			return nil, err
		}
		return c.NewBackend("b")
	}
	probability := func(b judge.Backend) string { return b.(judge.Describer).Describe().Probability }

	for backend, want := range map[string]string{
		"{type: anthropic, model: m}":                                  "verbalized",
		"{type: anthropic, model: m, effort: low}":                     "verbalized-effort-low",
		"{type: anthropic, model: m, answer: structured, effort: max}": "verbalized-structured-effort-max",
	} {
		b, err := load(t, backend)
		if err != nil {
			t.Fatalf("%s: %v", backend, err)
		}
		if got := probability(b); got != want {
			t.Errorf("%s: Probability = %q, want %q", backend, got, want)
		}
	}
	for _, backend := range []string{
		"{type: openai, model: m, temperature: 0}",
		"{type: openai, model: m, temperature: 0.5, probability: logprobs}",
		"{type: openai, model: m, temperature: 1}",
	} {
		if _, err := load(t, backend); err != nil {
			t.Errorf("%s: %v", backend, err)
		}
	}
	for backend, want := range map[string]string{
		"{type: anthropic, model: m, effort: Low}":    "backends.b: anthropic: effort",
		"{type: openai, model: m, temperature: -1}":   "backends.b: openai: temperature",
		"{type: openai, model: m, temperature: 2}":    "backends.b: openai: temperature",
		"{type: openai, model: m, temperature: .nan}": "backends.b: openai: temperature",
	} {
		_, err := load(t, backend)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want it to mention %q", backend, err, want)
		}
	}
}

// TestOutboundCategories：内置三个类别：credentials、private_key 默认启用、deny，pii 默认关闭；用户配置
// 按字段叠加——只写 ignore 不会把内置的 enabled、action 清掉；自定义类别没写的字段取默认（启用、deny）。
func TestOutboundCategories(t *testing.T) {
	d := Defaults()
	for name, want := range map[string]Category{
		"credentials": {Enabled: true, Action: guard.DecisionDeny},
		"private_key": {Enabled: true, Action: guard.DecisionDeny},
		"pii":         {Enabled: false, Action: guard.DecisionDeny},
	} {
		if got := d.Category(name); got.Enabled != want.Enabled || got.Action != want.Action {
			t.Errorf("default %s = %+v", name, got)
		}
	}
	dir := t.TempDir()
	user := write(t, dir, "config.yaml", "version: 1\noutbound:\n  categories:\n    pii: {ignore: ['Me@My-Company.com']}\n"+
		"    credentials: {action: warn}\n    acme-codename: {question: {question: 'Does the text name Project Falcon?'}}\n")
	extra := write(t, dir, "extra.yaml", "version: 1\noutbound: {categories: {pii: {enabled: true}}}\n")
	c, err := Load(user, extra)
	if err != nil {
		t.Fatal(err)
	}
	if pii := c.Category("pii"); !pii.Enabled || pii.Action != guard.DecisionDeny || !slices.Equal(pii.Ignore, []string{"Me@My-Company.com"}) {
		t.Errorf("pii = %+v", pii)
	}
	if cr := c.Category("credentials"); !cr.Enabled || cr.Action != guard.DecisionWarn {
		t.Errorf("credentials = %+v", cr)
	}
	acme := c.Category("acme-codename")
	if !acme.Enabled || acme.Action != guard.DecisionDeny || acme.Question == nil || acme.Question.Question == "" || !acme.Configured {
		t.Errorf("acme = %+v", acme)
	}
	// 没有配置的类别（只有规则引用它）：启用、deny
	if x := c.Category("from-a-rule"); !x.Enabled || x.Action != guard.DecisionDeny || x.Configured {
		t.Errorf("unconfigured = %+v", x)
	}
	// outbound 不能请求确认；名字、题目与忽略值都要合法；未知字段是错误
	for name, body := range map[string]string{
		"ask":           "version: 1\noutbound: {categories: {pii: {action: ask}}}\n",
		"bad name":      "version: 1\noutbound: {categories: {'Bad Name': {action: deny}}}\n",
		"empty ignore":  "version: 1\noutbound: {categories: {pii: {ignore: ['  ']}}}\n",
		"no question":   "version: 1\noutbound: {categories: {x: {question: {counts_as_yes: y}}}}\n",
		"unknown field": "version: 1\noutbound: {categories: {pii: {colour: red}}}\n",
	} {
		if _, err := Load(write(t, t.TempDir(), "c.yaml", body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

package migrate

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/rules"
)

// baseline 返回 Python 版出厂的 questions.json，供测试在它上面改。
func baseline(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(pythonDefault, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func convert(t *testing.T, m map[string]any) Result {
	t.Helper()
	b, _ := json.Marshal(m)
	r, err := Convert(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func notes(r Result) string { return strings.Join(r.Notes, "\n") }

func value(r Result, path string) (string, bool) {
	for _, v := range r.Config {
		if strings.Join(v.Path, ".") == path {
			return v.Value, true
		}
	}
	return "", false
}

// TestUnchangedIsNothing：出厂文件原样（含用户 config --init 复制的整份文件）不迁移任何东西：Go 版的内置规则与默认值
// 已经覆盖它们（且更严）。
func TestUnchangedIsNothing(t *testing.T) {
	r := convert(t, baseline(t))
	if len(r.Config) != 0 || len(r.Rules) != 0 || len(r.Notes) != 0 {
		t.Errorf("result = %+v", r)
	}
}

// TestRuleChanges：只迁移相对出厂文件的改动：新增的规则写成规则包；检测写法（正则、动作、命令位置、去引号）改过的
// 非锁定内置规则以同 id 覆盖（说明会失去 Go 版的 PowerShell 写法与收紧）；改过的锁定规则（灾难性形态、护栏自我保护）
// 不能覆盖，改用新 id；文件里没有的规则不停用，只说明（审查 C1）。
func TestRuleChanges(t *testing.T) {
	m := baseline(t)
	rs := m["rules"].(map[string]any)
	rs["my_deploy"] = map[string]any{"action": "ask", "reason": "部署到生产", "regex": []any{`\bmake\s+deploy\b`},
		"question": map[string]any{"type": "noul", "instructions": map[string]any{"question": "Would `call.command` deploy?",
			"counts_as_yes": "make deploy", "counts_as_no": "make test"}, "criteria": map[string]any{"true": "deploys", "false": "does not"}}}
	pub := rs["publish"].(map[string]any)
	pub["regex"] = append(pub["regex"].([]any), `\bmake\s+release\b`)
	delete(rs, "verify_bypass")
	cat := m["patterns_extra"].(map[string]any)["catastrophic"].(map[string]any)
	cat["regex"] = append(cat["regex"].([]any), `\bwipefs\b`)
	r := convert(t, m)
	if got := slices.Sorted(maps.Keys(r.Rules)); !slices.Equal(got, []string{"catastrophic_migrated.yaml", "my_deploy.yaml", "publish.yaml"}) {
		t.Fatalf("rule files = %v", got)
	}
	if len(r.Config) != 0 {
		t.Errorf("config = %+v", r.Config)
	}
	n := notes(r)
	for _, want := range []string{`publish: overrides the built-in rule`, `catastrophic is a locked built-in rule`,
		`verify_bypass is not in your questions.json`, "h-guard keeps it on", `my_deploy: the English reason`} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
	dir := t.TempDir()
	for name, b := range r.Rules {
		os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	set, err := rules.Load(dir)
	if err != nil {
		t.Fatalf("generated packs do not load: %v", err)
	}
	if r := set.Get("my_deploy"); r == nil || !r.RequiresJudge || r.Question == nil || r.Reason["zh-CN"] != "部署到生产" {
		t.Errorf("my_deploy = %+v", r)
	}
	if r := set.Get("catastrophic_migrated"); r == nil || r.Action != "deny" || !r.Match.Exec.CommandPosition {
		t.Errorf("catastrophic_migrated = %+v", r)
	}
}

// TestPolicyAndModel：policy 里有对应的字段写进配置；阈值属于按后端校准的档案，不迁移（说明用 eval --sweep）；
// 逐规则阈值、guarded_tools、signals 没有对应，说明后不迁移；新增的保护路径写成文件规则；model 写进 jev 后端。
func TestPolicyAndModel(t *testing.T) {
	m := baseline(t)
	p := m["policy"].(map[string]any)
	p["request_window"] = 5.0
	p["on_unavailable"] = "ask"
	p["hit_threshold"] = 0.6
	p["guarded_tools"] = []any{"Bash", "Shell"}
	p["protected_paths"] = append(p["protected_paths"].([]any), "~/.ssh/config")
	m["rules"].(map[string]any)["publish"].(map[string]any)["threshold"] = 0.8
	m["signals"].(map[string]any)["blast_radius"].(map[string]any)["instructions"] = "changed"
	m["model"] = "jev-2"
	r := convert(t, m)
	for path, want := range map[string]string{"policy.request_window": "5", "policy.on_unavailable": "ask",
		"backends.jev.model": "jev-2", "backends.jev.type": "typesafe"} {
		if v, _ := value(r, path); v != want {
			t.Errorf("%s = %q, want %q", path, v, want)
		}
	}
	if _, ok := value(r, "policy.hit_threshold"); ok {
		t.Error("thresholds were migrated")
	}
	n := notes(r)
	for _, want := range []string{"hit_threshold", "--sweep", "publish: threshold", "guarded_tools", "signals.blast_radius"} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
	if b := r.Rules["migrated_protected_paths.yaml"]; !strings.Contains(string(b), "~/.ssh/config") || strings.Contains(string(b), "~/.codex") {
		t.Errorf("protected paths pack =\n%s", b)
	}
	dir := t.TempDir()
	for name, b := range r.Rules {
		os.WriteFile(filepath.Join(dir, name), b, 0o600)
	}
	if _, err := rules.Load(dir); err != nil {
		t.Errorf("generated packs do not load: %v", err)
	}
	var _ []install.Value = r.Config
}

// TestRegexDialect：Python 的 (?P<n>…)、(?P=n)、\Z 换成 regexp2 的写法；仍然编译不了的规则说明后跳过；
// 不是 noul 的题型 Go 不支持，同样跳过。
func TestRegexDialect(t *testing.T) {
	m := baseline(t)
	rs := m["patterns_extra"].(map[string]any)
	rs["named"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`(?P<w>wipe)\s+(?P=w)\Z`}}
	rs["broken"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`(unclosed`}}
	m["rules"].(map[string]any)["scored"] = map[string]any{"action": "ask", "reason": "x", "regex": []any{`x`},
		"question": map[string]any{"type": "score", "instructions": "q", "criteria": []any{"a", "b"}}}
	r := convert(t, m)
	if b := r.Rules["named.yaml"]; !strings.Contains(string(b), `(?<w>wipe)\s+\k<w>\z`) {
		t.Errorf("named =\n%s", b)
	}
	if _, ok := r.Rules["broken.yaml"]; ok {
		t.Error("an uncompilable rule was written")
	}
	if _, ok := r.Rules["scored.yaml"]; ok {
		t.Error("a score question was written")
	}
	n := notes(r)
	if !strings.Contains(n, "broken: skipped") || !strings.Contains(n, "scored: skipped") {
		t.Errorf("notes:\n%s", n)
	}
}

func TestConvertRejects(t *testing.T) {
	for _, in := range []string{"", "[]", `{"rules": []}`, `{"version": 2}`} {
		if _, err := Convert([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// TestOlderCopiesDisableNothing：Python 版早期的出厂文件没有 guard_tampering、fork_bomb；用它复制出的配置迁移时
// 不能把这些硬规则停用（审查 C1：护栏自我保护会整体关闭）。
func TestOlderCopiesDisableNothing(t *testing.T) {
	m := baseline(t)
	delete(m["rules"].(map[string]any), "guard_tampering")
	delete(m["patterns_extra"].(map[string]any), "fork_bomb")
	r := convert(t, m)
	if len(r.Config) != 0 || len(r.Rules) != 0 {
		t.Errorf("result = %+v", r)
	}
	if n := notes(r); !strings.Contains(n, "guard_tampering is not in your questions.json") || !strings.Contains(n, "fork_bomb") {
		t.Errorf("notes:\n%s", n)
	}
}

// TestOlderFactoryFiles：Python 版发布过三个出厂版本，用户的文件可能复制自较早的版本。与任一版本相同的部分都算没改：
// 不生成规则、不写配置，也不把旧版出厂的取值说成用户的改动；在旧版上改过的地方照常按改动处理（终审 I-1）。
func TestOlderFactoryFiles(t *testing.T) {
	for _, c := range []string{"e81f231", "473786b"} {
		data, err := os.ReadFile("python_questions_" + c + ".json")
		if err != nil {
			t.Fatal(err)
		}
		r := convert(t, decode(t, data))
		if len(r.Config) != 0 || len(r.Rules) != 0 || len(r.Skipped) != 0 {
			t.Errorf("%s: config %v, rules %v, skipped %v", c, r.Config, slices.Sorted(maps.Keys(r.Rules)), r.Skipped)
		}
		for _, n := range r.Notes {
			if !strings.Contains(n, "is not in your questions.json") {
				t.Errorf("%s: note %q", c, n)
			}
		}
		// 在旧版上只改了原因：逐项说明这一处，不覆盖
		m := decode(t, data)
		m["rules"].(map[string]any)["recursive_delete"].(map[string]any)["reason"] = "删除"
		r = convert(t, m)
		if n := notes(r); len(r.Rules) != 0 || !strings.Contains(n, "recursive_delete: reason") || strings.Contains(n, "radius_floor") {
			t.Errorf("%s edited: rules %v, notes:\n%s", c, slices.Sorted(maps.Keys(r.Rules)), n)
		}
	}
}

// TestNonDetectionChangesDoNotOverride：内置规则只改了阈值、原因、影响范围下限、能否凭授权放行或题目措辞时，不整条
// 覆盖（会丢掉 PowerShell 写法与 Go 版的修正，题目措辞也不再对应校准档案），逐项说明（审查 I6）。
func TestNonDetectionChangesDoNotOverride(t *testing.T) {
	m := baseline(t)
	rs := m["rules"].(map[string]any)
	rs["publish"].(map[string]any)["threshold"] = 0.8
	rs["publish"].(map[string]any)["reason"] = "发布"
	rs["recursive_delete"].(map[string]any)["radius_floor"] = 2.0
	rs["destructive_git"].(map[string]any)["bypassable_by_request"] = false
	q := rs["branch_ops"].(map[string]any)["question"].(map[string]any)
	q["instructions"].(map[string]any)["question"] = "Changed?"
	r := convert(t, m)
	if len(r.Rules) != 0 {
		t.Errorf("rule files = %v", slices.Sorted(maps.Keys(r.Rules)))
	}
	n := notes(r)
	for _, want := range []string{"publish: threshold", "publish: reason", "recursive_delete: radius_floor", "destructive_git: bypassable_by_request",
		"branch_ops: question"} {
		if !strings.Contains(n, want) {
			t.Errorf("notes lack %q:\n%s", want, n)
		}
	}
}

// TestSkippedAndLoosening：跳过的规则记在 Skipped 里（调用方据此拒绝写入）；放宽保护的 policy 照样迁移但另作说明
// （审查次要 13、15）。
func TestSkippedAndLoosening(t *testing.T) {
	m := baseline(t)
	m["patterns_extra"].(map[string]any)["broken"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`(unclosed`}}
	m["policy"].(map[string]any)["when_ask_unsupported"] = "pass"
	r := convert(t, m)
	if !slices.Equal(r.Skipped, []string{"broken"}) {
		t.Errorf("skipped = %v", r.Skipped)
	}
	if v, _ := value(r, "policy.when_ask_unsupported"); v != "pass" || !strings.Contains(notes(r), "lets the action through") {
		t.Errorf("when_ask_unsupported = %q\n%s", v, notes(r))
	}
}

// TestGeneratedNamesDoNotCollide：生成的规则 id（锁定规则的 _migrated、保护路径规则）与用户自己的规则 id 不能相撞：
// 相撞时换一个稳定的新 id 并说明，两条检测都保留（计划评审 M3D-06）。
func TestGeneratedNamesDoNotCollide(t *testing.T) {
	m := map[string]any{"version": 1, "rules": map[string]any{
		"catastrophic":             map[string]any{"action": "deny", "reason": "custom A", "regex": []any{"CUSTOM_A"}},
		"catastrophic_migrated":    map[string]any{"action": "deny", "reason": "custom B", "regex": []any{"CUSTOM_B"}},
		"migrated_protected_paths": map[string]any{"action": "deny", "reason": "custom C", "regex": []any{"CUSTOM_C"}},
	}, "policy": map[string]any{"protected_paths": append(baseline(t)["policy"].(map[string]any)["protected_paths"].([]any), "~/.ssh/config")}}
	r := convert(t, m)
	for name, want := range map[string]string{
		"catastrophic_migrated.yaml": "CUSTOM_B", "catastrophic_migrated_2.yaml": "CUSTOM_A",
		"migrated_protected_paths.yaml": "CUSTOM_C", "migrated_protected_paths_2.yaml": "~/.ssh/config",
	} {
		if !strings.Contains(string(r.Rules[name]), want) {
			t.Errorf("%s =\n%s", name, r.Rules[name])
		}
	}
	if n := notes(r); !strings.Contains(n, "catastrophic_migrated_2") {
		t.Errorf("notes:\n%s", n)
	}
}

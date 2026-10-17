package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oldQuestions 写一份改过的 Python 版 questions.json：新增一条规则、request_window 改为 5。
func oldQuestions(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "migrate", "python_questions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(b, &m)
	m["policy"].(map[string]any)["request_window"] = 5
	m["patterns_extra"].(map[string]any)["wipe"] = map[string]any{"action": "deny", "reason": "擦除磁盘", "command_position": true, "regex": []any{`^wipefs\b`}}
	out, _ := json.Marshal(m)
	path := filepath.Join(t.TempDir(), "questions.json")
	os.WriteFile(path, out, 0o600)
	return path
}

// TestMigrate：默认只打印将写入的配置与规则包；--write 写入，之后 config validate 通过、新规则生效；规则文件已存在且
// 内容不同时不覆盖、什么都不写。
func TestMigrate(t *testing.T) {
	e := newEnv(t)
	q := oldQuestions(t)
	out, errs, code := e.run(nil, "migrate", q)
	rule := filepath.Join(e.configDir, "rules", "wipe.yaml")
	if code != 0 || !strings.Contains(out, rule) || !strings.Contains(out, "request_window") || !strings.Contains(out, "--write") {
		t.Fatalf("dry run: exit %d\n%s%s", code, out, errs)
	}
	if _, err := os.Stat(rule); err == nil {
		t.Fatal("dry run wrote the rule")
	}
	out, errs, code = e.run(nil, "migrate", q, "--write")
	if code != 0 {
		t.Fatalf("write: exit %d\n%s%s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml")); !strings.Contains(string(b), "request_window: 5") {
		t.Errorf("config.yaml =\n%s", b)
	}
	if out, errs, code := e.run(nil, "config", "validate"); code != 0 {
		t.Errorf("validate after migrate: %s%s", out, errs)
	}
	if out, _, _ := e.run(bash("wipefs -a /dev/sdb"), "hook", "claudecode", "--event", "PreToolUse"); !strings.Contains(out, `"deny"`) {
		t.Errorf("the migrated rule does not apply: %q", out)
	}
	os.WriteFile(rule, []byte("# mine\n"), 0o600)
	if _, errs, code := e.run(nil, "migrate", q, "--write"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Errorf("existing rule: exit %d\n%s", code, errs)
	}
	if b, _ := os.ReadFile(rule); string(b) != "# mine\n" {
		t.Errorf("rule overwritten: %s", b)
	}
}

// TestMigrateNotes：H_GUARD_LOG 只能提示（Go 版的决策日志是开关、没有路径）；读不懂的文件报错；参数缺失是用法错误。
func TestMigrateNotes(t *testing.T) {
	e := newEnv(t)
	e.vars["H_GUARD_LOG"] = "/tmp/hg.log"
	if out, _, _ := e.run(nil, "migrate", oldQuestions(t)); !strings.Contains(out, "H_GUARD_LOG") || !strings.Contains(out, "log: {decisions: true}") {
		t.Errorf("stdout:\n%s", out)
	}
	bad := filepath.Join(t.TempDir(), "q.json")
	os.WriteFile(bad, []byte("[]"), 0o600)
	if _, _, code := e.run(nil, "migrate", bad); code != 1 {
		t.Errorf("unreadable: exit %d", code)
	}
	if _, _, code := e.run(nil, "migrate"); code != 2 {
		t.Errorf("no file: exit %d", code)
	}
}

// TestMigrateRefusesSkippedRules：有规则迁移不了时（可能是用户自己的 deny 规则）默认什么都不写、以 1 退出；
// --skip-invalid 时跳过它们写入其余部分（审查次要 13）。
func TestMigrateRefusesSkippedRules(t *testing.T) {
	e := newEnv(t)
	b, _ := os.ReadFile(filepath.Join("..", "migrate", "python_questions.json"))
	var m map[string]any
	json.Unmarshal(b, &m)
	m["patterns_extra"].(map[string]any)["broken"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`(unclosed`}}
	m["patterns_extra"].(map[string]any)["wipe"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`^wipefs\b`}}
	out, _ := json.Marshal(m)
	q := filepath.Join(t.TempDir(), "q.json")
	os.WriteFile(q, out, 0o600)
	if _, errs, code := e.run(nil, "migrate", q, "--write"); code != 1 || !strings.Contains(errs, "broken") || !strings.Contains(errs, "--skip-invalid") {
		t.Errorf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(e.configDir, "rules", "wipe.yaml")); err == nil {
		t.Error("written despite a skipped rule")
	}
	if _, _, code := e.run(nil, "migrate", q, "--write", "--skip-invalid"); code != 0 {
		t.Errorf("--skip-invalid: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(e.configDir, "rules", "wipe.yaml")); err != nil {
		t.Errorf("--skip-invalid did not write the rest: %v", err)
	}
}

// TestMigrateValidatesTheResult：写入之前按 hook 的要求校验合并后的配置与规则目录；校验不通过时什么都不写
// （曾经写出 request_window: 0，之后 config validate 失败）。
// TestMigrateKeepsTheBackendSettings：迁移 model 时只改 jev 后端的 model；用户已经写下的 api_key_env、type、profile
// 保留（覆盖 api_key_env 会让每次判断都因为找不到 key 而失败）。
func TestMigrateKeepsTheBackendSettings(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nbackends:\n  jev: {type: typesafe, model: jev-latest, profile: jev, api_key_env: MY_JEV_KEY}\n")
	q := filepath.Join(t.TempDir(), "q.json")
	os.WriteFile(q, []byte(`{"version":1,"model":"jev-2"}`), 0o600)
	if _, errs, code := e.run(nil, "migrate", q, "--write"); code != 0 {
		t.Fatalf("exit %d\n%s", code, errs)
	}
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	if !strings.Contains(string(b), "MY_JEV_KEY") || strings.Contains(string(b), "TYPESAFE_API_KEY") || !strings.Contains(string(b), "jev-2") {
		t.Errorf("config.yaml =\n%s", b)
	}
}

func TestMigrateValidatesTheResult(t *testing.T) {
	e := newEnv(t)
	q := filepath.Join(t.TempDir(), "q.json")
	os.WriteFile(q, []byte(`{"version":1,"policy":{"request_window":0,"on_unavailable":"maybe"}}`), 0o600)
	_, errs, code := e.run(nil, "migrate", q, "--write")
	if code != 1 || !strings.Contains(errs, "request_window") {
		t.Errorf("exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(e.configDir, "config.yaml")); err == nil {
		t.Error("an invalid config was written")
	}
	// 生成的规则与规则目录里已有的同 id 规则相撞：同样拒绝
	os.MkdirAll(filepath.Join(e.configDir, "rules"), 0o700)
	os.WriteFile(filepath.Join(e.configDir, "rules", "other.yaml"), []byte("schema: 1\nid: wipe\naction: ask\non: [exec]\nreason: {en: x}\nmatch: {exec: {any: ['x']}}\n"), 0o600)
	b, _ := os.ReadFile(filepath.Join("..", "migrate", "python_questions.json"))
	var m map[string]any
	json.Unmarshal(b, &m)
	m["patterns_extra"].(map[string]any)["wipe"] = map[string]any{"action": "deny", "reason": "x", "regex": []any{`^wipefs\b`}}
	out, _ := json.Marshal(m)
	os.WriteFile(q, out, 0o600)
	if _, errs, code := e.run(nil, "migrate", q, "--write"); code != 1 || !strings.Contains(errs, "wipe") {
		t.Errorf("duplicate id: exit %d\n%s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(e.configDir, "rules", "wipe.yaml")); err == nil {
		t.Error("a colliding rule was written")
	}
	// 写入前的校验与 hook 的加载相同：配置里按 id 停用的规则在合并后的规则里不存在时，hook 读不了，
	// 迁移同样拒绝写入
	e2 := newEnv(t)
	e2.config("version: 1\nrules: {wipe: {enabled: false}}\n")
	os.WriteFile(q, []byte(`{"version":1,"policy":{"request_window":5}}`), 0o600)
	if _, errs, code := e2.run(nil, "migrate", q, "--write"); code != 1 || !strings.Contains(errs, "wipe") {
		t.Errorf("unknown override: exit %d\n%s", code, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(e2.configDir, "config.yaml")); strings.Contains(string(b), "request_window") {
		t.Errorf("written although the hook cannot load it:\n%s", b)
	}
}

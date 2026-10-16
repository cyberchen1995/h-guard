package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userRule = `schema: 1
id: my_deploy
action: ask
on: [exec]
reason: {en: Deploys}
match:
  exec:
    any: ['\bmake\s+deploy\b']
examples:
  hit: [{shell: posix, command: "make deploy"}]
  miss: [{shell: posix, command: "%s"}]
`

func writeRule(t *testing.T, dir, miss string) {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte(strings.Replace(userRule, "%s", miss, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestConfigValidate：配置与用户规则包都读得懂、用户规则的样例都通过时 ok（spec §5.2、§12）；样例不通过、配置非法时
// 以 1 退出；停用了硬规则时显著提示。
func TestConfigValidate(t *testing.T) {
	e := newEnv(t)
	out, errs, code := e.run(nil, "config", "validate")
	if code != 0 || !strings.Contains(out, "config ok") {
		t.Errorf("defaults: exit %d\n%s%s", code, out, errs)
	}
	writeRule(t, filepath.Join(e.configDir, "rules"), "make test")
	e.config("version: 1\nrules: {catastrophic: {enabled: false}}\n")
	out, errs, code = e.run(nil, "config", "validate")
	if code != 0 || !strings.Contains(out, "1 rule of your own, examples pass") || !strings.Contains(out, `warning: hard rule "catastrophic" is disabled`) {
		t.Errorf("user rule: exit %d\n%s%s", code, out, errs)
	}
	writeRule(t, filepath.Join(e.configDir, "rules"), "make deploy")
	_, errs, code = e.run(nil, "config", "validate")
	if code != 1 || !strings.Contains(errs, `rule "my_deploy"`) || !strings.Contains(errs, "make deploy") {
		t.Errorf("failing example: exit %d\n%s", code, errs)
	}
	e.config("version: 1\naction: {tier: 9}\n")
	if _, errs, code := e.run(nil, "config", "validate"); code != 1 || !strings.Contains(errs, "action.tier") {
		t.Errorf("invalid config: exit %d\n%s", code, errs)
	}
}

// TestConfigValidateRules：--rules 单独验证一个规则包及其样例，不读配置。
func TestConfigValidateRules(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\naction: {tier: 9}\n")
	dir := filepath.Join(t.TempDir(), "pack")
	writeRule(t, dir, "make test")
	if out, errs, code := e.run(nil, "config", "validate", "--rules", dir); code != 0 || !strings.Contains(out, "1 rule, examples pass") {
		t.Errorf("good pack: exit %d\n%s%s", code, out, errs)
	}
	writeRule(t, dir, "make deploy")
	if _, errs, code := e.run(nil, "config", "validate", "--rules", dir); code != 1 || !strings.Contains(errs, "my_deploy") {
		t.Errorf("bad pack: exit %d\n%s", code, errs)
	}
	if _, _, code := e.run(nil, "config", "validate", "--rules", filepath.Join(dir, "missing")); code != 1 {
		t.Errorf("missing dir: exit %d", code)
	}
}

// TestConfigShow：打印合并后的配置（内置默认 → 用户配置 → --config）。
func TestConfigShow(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\njudge: {enabled: true, backend: claude-haiku}\n")
	out, _, code := e.run(nil, "config", "show")
	if code != 0 || !strings.Contains(out, "version: 1") || !strings.Contains(out, "backend: claude-haiku") ||
		!strings.Contains(out, "claude-sonnet:") || !strings.Contains(out, "enabled: true") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

// TestConfigInit：写出带说明的配置模板（只有 version: 1 生效，其余是注释）；已有配置时不覆盖。
func TestConfigInit(t *testing.T) {
	e := newEnv(t)
	out, _, code := e.run(nil, "config", "init")
	path := filepath.Join(e.configDir, "config.yaml")
	b, err := os.ReadFile(path)
	if code != 0 || err != nil || !strings.Contains(out, path) || !strings.HasPrefix(string(b), "# h-guard") ||
		!strings.Contains(string(b), "\nversion: 1\n") || !strings.Contains(string(b), "# judge:") {
		t.Fatalf("exit %d\n%s\n%s", code, out, b)
	}
	if out, errs, code := e.run(nil, "config", "validate"); code != 0 {
		t.Errorf("the template does not validate: %s%s", out, errs)
	}
	os.WriteFile(path, []byte("version: 1\nlocale: zh-CN\n"), 0o600)
	if _, errs, code := e.run(nil, "config", "init"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Errorf("existing config: exit %d\n%s", code, errs)
	}
	if b, _ := os.ReadFile(path); string(b) != "version: 1\nlocale: zh-CN\n" {
		t.Errorf("config overwritten: %s", b)
	}
	if _, _, code := e.run(nil, "config", "frobnicate"); code != 2 {
		t.Errorf("unknown subcommand: exit %d", code)
	}
}

// TestJudgeOnlyCategory：启用的类别没有启用的本地规则、只靠题目时，模型关闭就是配置错误（spec §4）：错误指出类别
// 与开启方法；有本地规则、或模型开着时不是错误。hook 同样读不了这份配置。
func TestJudgeOnlyCategory(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\noutbound: {categories: {acme-codename: {action: warn, question: {question: 'Does the text name Project Falcon?'}}}}\n")
	_, errs, code := e.run(nil, "config", "validate")
	if code != 1 || !strings.Contains(errs, "outbound.categories.acme-codename") || !strings.Contains(errs, "judge.enabled") {
		t.Errorf("judge-only category: exit %d\n%s", code, errs)
	}
	dir := filepath.Join(e.configDir, "rules")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "falcon.yaml"), []byte("schema: 1\nid: acme.codename\ncategory: acme-codename\non: [prompt]\n"+
		"match: {regex: ['\\bProject Falcon\\b']}\nexamples: {hit: ['Project Falcon'], miss: [falconry]}\n"), 0o600)
	if out, errs, code := e.run(nil, "config", "validate"); code != 0 {
		t.Errorf("with a local rule: exit %d\n%s%s", code, out, errs)
	}
	// 本地规则被停用：又只剩题目
	e.config("version: 1\nrules: {acme.codename: {enabled: false}}\noutbound: {categories: {acme-codename: {question: {question: 'Falcon?'}}}}\n")
	if _, errs, code := e.run(nil, "config", "validate"); code != 1 || !strings.Contains(errs, "outbound.categories.acme-codename") {
		t.Errorf("rule disabled: exit %d\n%s", code, errs)
	}
	// 类别停用时不是错误
	e.config("version: 1\nrules: {acme.codename: {enabled: false}}\noutbound: {categories: {acme-codename: {enabled: false, question: {question: 'Falcon?'}}}}\n")
	if _, errs, code := e.run(nil, "config", "validate"); code != 0 {
		t.Errorf("category disabled: exit %d\n%s", code, errs)
	}
}

// TestValidateOutboundExamples：config validate 同样运行用户 outbound 规则的样例，计入「你自己的规则」。
func TestValidateOutboundExamples(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(e.configDir, "rules")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "falcon.yaml"), []byte("schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\n"+
		"match: {regex: ['\\bProject Falcon\\b']}\nexamples: {hit: ['Project Falcon'], miss: [falconry]}\n"), 0o600)
	if out, errs, code := e.run(nil, "config", "validate"); code != 0 || !strings.Contains(out, "1 rule of your own, examples pass") {
		t.Errorf("good: exit %d\n%s%s", code, out, errs)
	}
	os.WriteFile(filepath.Join(dir, "falcon.yaml"), []byte("schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\n"+
		"match: {regex: ['\\bProject Falcon\\b']}\nexamples: {hit: ['Project Eagle']}\n"), 0o600)
	if _, errs, code := e.run(nil, "config", "validate"); code != 1 || !strings.Contains(errs, "acme.codename") {
		t.Errorf("failing example: exit %d\n%s", code, errs)
	}
}

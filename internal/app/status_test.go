package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func harnessVersions(name string, args ...string) ([]byte, error) {
	switch name {
	case "claude":
		return claudeOK(name, args...)
	case "codex":
		return []byte("codex-cli 0.162.1\n"), nil
	}
	return nil, os.ErrNotExist
}

// TestStatusHarnesses：status 报告各 harness 的入口是否安装、与期望是否一致、shell 配置与版本。
func TestStatusHarnesses(t *testing.T) {
	e := installEnv(t, harnessVersions)
	out, _, _ := e.run(nil, "status")
	if !strings.Contains(out, "claudecode: not installed (h-guard install claudecode)") || !strings.Contains(out, "codex: not installed (h-guard install codex)") {
		t.Errorf("before install:\n%s", out)
	}
	e.bin = filepath.Join(t.TempDir(), "h-guard")
	os.WriteFile(e.bin, []byte("#!/bin/sh\n"), 0o700)
	e.run(nil, "install", "claudecode", "--write")
	e.run(nil, "install", "codex", "--write")
	out, _, _ = e.run(nil, "status")
	for _, want := range []string{"claudecode: installed (Claude Code 2.1.296)", "codex: installed (Codex 0.162.1)",
		"codex commands are checked as posix (harnesses.codex.shell)", "/hooks"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	// 手工改过的入口：少了一个事件、超时不一致
	hooks := filepath.Join(e.home, ".codex", "hooks.json")
	b, _ := os.ReadFile(hooks)
	b = []byte(strings.Replace(strings.Replace(string(b), `"PostToolUse"`, `"Unused"`, 1), `"timeout": 20`, `"timeout": 5`, 1))
	os.WriteFile(hooks, b, 0o600)
	os.Remove(e.bin)
	out, _, _ = e.run(nil, "status")
	for _, want := range []string{"codex: problem: no h-guard hook for PostToolUse", "codex: problem: PreToolUse waits 5s but h-guard is given 20s",
		"claudecode: problem: h-guard is not at " + e.bin} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

// TestStatusRulesAndHealth：列出不生效的规则与原因；汇总近 7 天的降级原因码；写明日志位置。
// TestStatusDisabledHardRule：停用的硬规则在 status 里显著提示，与 install、config validate 一样。
func TestStatusDisabledHardRule(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nrules: {guard_tampering: {enabled: false}}\n")
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, `warning: hard rule "guard_tampering" is disabled`) {
		t.Errorf("status:\n%s", out)
	}
}

func TestStatusRulesAndHealth(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\naction: {tier: 1}\nrules: {branch_ops: {enabled: false}}\n")
	dir := filepath.Join(e.cache, "health")
	os.MkdirAll(dir, 0o700)
	now := time.Now()
	recent := `{"ts":"x","code":"judge_unavailable"}` + "\n" + `{"ts":"x","code":"judge_unavailable"}` + "\n" + `{"ts":"x","code":"ask_unsupported"}` + "\n"
	os.WriteFile(filepath.Join(dir, now.Format("2006-01-02")+".jsonl"), []byte(recent), 0o600)
	os.WriteFile(filepath.Join(dir, now.AddDate(0, 0, -10).Format("2006-01-02")+".jsonl"), []byte(`{"code":"internal_error"}`+"\n"), 0o600)
	out, _, _ := e.run(nil, "status")
	for _, want := range []string{"rules not in effect:", "branch_ops (disabled)", "publish (judge disabled)", "sensitive_read (action tier)",
		"degradations in the last 7 days: judge_unavailable 2, ask_unsupported 1", "health records: " + dir} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "internal_error") {
		t.Errorf("an old record was counted:\n%s", out)
	}
}

// TestStatusOutbound：status 报告 outbound 的档位与各类别（启用、动作），不生效的 outbound 规则及原因。
func TestStatusOutbound(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\noutbound: {categories: {credentials: {action: warn}}}\nrules: {credentials.bearer: {enabled: false}}\n")
	out, _, _ := e.run(nil, "status")
	for _, want := range []string{"outbound: tier 1 (prompts)", "categories: credentials warn, pii off, private_key deny",
		"credentials.bearer (disabled)", "pii.email (category disabled)"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
}

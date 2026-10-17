package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/consent"
)

// initEnv 把 jev 指向假服务、模型关闭（init 之前的状态）。
func initEnv(t *testing.T) (*env, *jevServer) {
	e := newEnv(t)
	srv := newJevServer(t, 0.9)
	e.t.Setenv("HG_TEST_KEY", "test-key-not-a-secret")
	e.config("version: 1\n# keep me\nbackends: {jev: {type: typesafe, model: jev-latest, profile: jev, base_url: '" + srv.URL +
		"', api_key_env: HG_TEST_KEY}}\nprofiles: {jev: {thresholds: {hit: 0.5, veto: 0.2, requested: 0.7}}}\n")
	return e, srv
}

// TestInitTurnsOnTheJudge：init 里选定后端、确认同意之后，hook 即调用模型。
// 已有的配置与注释保留。
func TestInitTurnsOnTheJudge(t *testing.T) {
	e, srv := initEnv(t)
	e.tty = true
	out, errs, code := e.run([]byte("jev\ny\n\n"), "init")
	if code != 0 || !strings.Contains(out, "Destination: "+srv.URL) || !strings.Contains(out, "consent recorded for jev") ||
		!strings.Contains(out, "judge enabled") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	if !strings.Contains(string(b), "# keep me") || !strings.Contains(string(b), "backend: jev") || !strings.Contains(string(b), "enabled: true") {
		t.Errorf("config.yaml =\n%s", b)
	}
	e.tty = false
	e.run(promptReq("push it to origin", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	out, _, _ = e.run(pre("Bash", map[string]any{"command": "git push origin main"}, ""), "hook", "claudecode", "--event", "PreToolUse")
	if d, _ := decisionOf(t, out); d != "pass" || srv.calls != 1 {
		t.Errorf("after init: decision %s, judge calls %d", d, srv.calls)
	}
}

// TestInitDeclined：不同意时不记录同意、不开启模型。
// TestInitDeclinedKeepsAnEnabledJudge：模型已经开着时在 init 里拒绝，配置与已有的同意都不变，提示不能说模型保持
// 关闭。
func TestInitDeclinedKeepsAnEnabledJudge(t *testing.T) {
	e, _ := initEnv(t)
	e.tty = true
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	e.config(string(b) + "judge: {enabled: true, backend: jev}\n")
	out, _, code := e.run([]byte("jev\nn\n"), "init")
	if code != 1 || strings.Contains(out, "the judge stays off") || !strings.Contains(out, "the judge settings are unchanged") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestInitDeclined(t *testing.T) {
	e, srv := initEnv(t)
	e.tty = true
	before, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	out, _, code := e.run([]byte("jev\nn\n"), "init")
	if code != 1 || !strings.Contains(out, "the judge stays off") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if after, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml")); string(after) != string(before) {
		t.Errorf("config changed:\n%s", after)
	}
	if (consent.Store{Dir: e.configDir}).Covers(consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}, consent.ScopeAction) {
		t.Error("consent recorded")
	}
}

// TestInitChoices：列出推荐后端，可以按序号选；档位可选只检查命令（1）；不认识的回答是用法错误；非交互时不运行，
// 提示改用 backend enable 与配置。
func TestInitChoices(t *testing.T) {
	e, _ := initEnv(t)
	if _, errs, code := e.run(nil, "init"); code != 1 || !strings.Contains(errs, "interactive terminal") || !strings.Contains(errs, "backend enable") {
		t.Errorf("non-interactive: exit %d\n%s", code, errs)
	}
	e.tty = true
	out, _, code := e.run([]byte("4\ny\nn\n"), "init")
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	if code != 0 || !strings.Contains(out, "1) claude-haiku") || !strings.Contains(out, "4) jev") ||
		!strings.Contains(string(b), "tier: 1") || !strings.Contains(string(b), "backend: jev") {
		t.Errorf("exit %d\n%s\nconfig:\n%s", code, out, b)
	}
	if _, _, code := e.run([]byte("nonsense\n"), "init"); code != 2 {
		t.Errorf("unknown backend: exit %d", code)
	}
}

// TestInitMissingKey：所选后端的 API key 环境变量在这个终端里没有设置时，先说明（之后每次命中都会因为认证失败而
// 请求确认），默认不继续（审查 I4）。
func TestInitMissingKey(t *testing.T) {
	e, srv := initEnv(t)
	e.tty = true
	e.config("version: 1\nbackends: {jev: {type: typesafe, model: jev-latest, profile: jev, base_url: '" + srv.URL + "', api_key_env: HG_MISSING_KEY}}\n")
	out, _, code := e.run([]byte("jev\n\n"), "init")
	if code != 1 || !strings.Contains(out, "HG_MISSING_KEY is not set") || !strings.Contains(out, "the judge stays off") {
		t.Errorf("exit %d\n%s", code, out)
	}
	if (consent.Store{Dir: e.configDir}).Covers(consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}, consent.ScopeAction) {
		t.Error("consent recorded")
	}
	out, _, code = e.run([]byte("jev\ny\ny\n\n"), "init")
	if code != 0 || !strings.Contains(out, "judge enabled") {
		t.Errorf("continue anyway: exit %d\n%s", code, out)
	}
}

// TestInitKeepsTheTier：档位的默认回答取当前配置（原来是 1 的直接回车不会改成 2）；init 里不再打印 backend enable 的
// 「还要在配置里开启」提示（审查次要 12）。
func TestInitKeepsTheTier(t *testing.T) {
	e, srv := initEnv(t)
	e.tty = true
	e.config("version: 1\naction: {tier: 1}\nbackends: {jev: {type: typesafe, model: jev-latest, profile: jev, base_url: '" + srv.URL + "', api_key_env: HG_TEST_KEY}}\n")
	out, _, code := e.run([]byte("jev\ny\n\n"), "init")
	b, _ := os.ReadFile(filepath.Join(e.configDir, "config.yaml"))
	if code != 0 || !strings.Contains(string(b), "tier: 1") || strings.Contains(out, "the judge uses it only with") || !strings.Contains(out, "[y/N]") {
		t.Errorf("exit %d\n%s\nconfig:\n%s", code, out, b)
	}
}

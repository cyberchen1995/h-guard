package app

import (
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/consent"
)

// TestOutboundJudgeSkippedWithoutWarn：harness 在这类事件上显示不了提示（Codex 的提示词与工具输出）时不调用 outbound
// 判断层：模型的命中只提示，发出去也送不到用户面前，白白外发、多等（M4b 终审 I-1）。Claude Code 的提示词照常调用。
func TestOutboundJudgeSkippedWithoutWarn(t *testing.T) {
	text := strings.Repeat("Here is the staging setup we discussed yesterday with the team. ", 4) + "admin pw Tr0ub4dor and3"
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.outboundJudgeConfig(srv, "")
	(consent.Store{Dir: e.configDir}).Grant(consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL},
		[]consent.Scope{consent.ScopeAction, consent.ScopeOutbound}, time.Now())
	e.run(codexHook("UserPromptSubmit", map[string]any{"prompt": text}), "hook", "codex", "--event", "UserPromptSubmit")
	if srv.calls != 0 {
		t.Errorf("codex prompt: %d calls", srv.calls)
	}
	e.run(promptReq(text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if srv.calls != 1 {
		t.Errorf("claude code prompt: %d calls", srv.calls)
	}
}

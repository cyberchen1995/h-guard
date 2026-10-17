package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// shellAdapter 是测试用的 adapter：标不出 shell（由配置 harnesses.shelltest.shell 决定），
// 输入 {"cmd": …} 是一条命令，{"patch": true} 是目标无法解析的文件工具调用。
type shellAdapter struct{ shell guard.Shell }

func init() {
	if err := harness.Register(shellAdapter{}); err != nil {
		panic(err)
	}
}

func (shellAdapter) Name() string { return "shelltest" }

func (shellAdapter) Capabilities() harness.Caps {
	return harness.Caps{MinVersion: "1", Events: map[guard.EventKind]harness.EventCaps{guard.EventAction: {Block: true, Ask: true}}}
}

func (a shellAdapter) CapsFor(ev guard.Event) harness.EventCaps {
	return a.Capabilities().Events[ev.Kind]
}

func (a shellAdapter) WithShell(s guard.Shell) harness.Adapter { return shellAdapter{shell: s} }

func (a shellAdapter) Parse(raw []byte) (guard.Event, error) {
	var in struct {
		Cmd   string `json:"cmd"`
		Patch bool   `json:"patch"`
		Bare  bool   `json:"bare"`
		// PSFail：按 powershell 重新解析时出错（一个 adapter 只在某种 shell 下读不懂的情形）
		PSFail bool `json:"psfail"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return guard.Event{}, err
	}
	ev := guard.Event{Kind: guard.EventAction, Harness: "shelltest", SessionID: "s1", Cwd: "/w", Tool: "edit"}
	if in.Patch {
		return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
	}
	if in.Bare { // 没有填事件的实现：仍按动作请求确认，不能放行
		return guard.Event{}, &harness.TargetUnparsedError{}
	}
	shell := a.shell
	if shell == "" {
		shell = guard.ShellPOSIX
	}
	if in.PSFail && shell == guard.ShellPowerShell {
		return guard.Event{}, fmt.Errorf("cannot read this as powershell")
	}
	ev.Actions = []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: in.Cmd, Shell: shell}}}
	return ev, nil
}

func (shellAdapter) Render(ev guard.Event, out guard.Outcome) ([]byte, int) {
	return fmt.Appendf(nil, "%s|%s|%s", out.Verdict.Decision, strings.Join(out.Verdict.Fallbacks, ","), out.Message), 0
}

// TestHarnessShellComesFromTheConfig：harness 标不出 shell 时，exec 动作按配置 harnesses.<name>.shell 检查；
// 没有配置时是 posix。
func TestHarnessShellComesFromTheConfig(t *testing.T) {
	e := newEnv(t)
	in := []byte(`{"cmd": "Format-Volume -DriveLetter D"}`)
	if out, _, _ := e.run(in, "hook", "shelltest", "--event", "PreToolUse"); !strings.HasPrefix(out, "pass|") {
		t.Errorf("posix by default: %q", out)
	}
	e.config("version: 1\nharnesses:\n  shelltest: {shell: powershell}\n")
	if out, _, _ := e.run(in, "hook", "shelltest", "--event", "PreToolUse"); !strings.HasPrefix(out, "deny|") {
		t.Errorf("configured powershell: %q", out)
	}
}

// TestReparseErrorKeepsTheEvent：按配置的 shell 重新解析出错时，不能什么都不输出：第一次解析出的动作照常检查，
// 另外请求确认。
func TestReparseErrorKeepsTheEvent(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nharnesses:\n  shelltest: {shell: powershell}\n")
	out, _, _ := e.run([]byte(`{"cmd": "rm -rf /", "psfail": true}`), "hook", "shelltest", "--event", "PreToolUse")
	if !strings.HasPrefix(out, "deny|") {
		t.Errorf("catastrophic command: %q", out)
	}
	out, _, _ = e.run([]byte(`{"cmd": "ls", "psfail": true}`), "hook", "shelltest", "--event", "PreToolUse")
	if !strings.HasPrefix(out, "ask|") || !strings.Contains(out, "target_unparsed") {
		t.Errorf("plain command: %q", out)
	}
}

// TestUnparsedTargetAsks：已知会改动文件的工具、目标无法解析时请求确认，带 target_unparsed。
func TestUnparsedTargetAsks(t *testing.T) {
	e := newEnv(t)
	out, _, _ := e.run([]byte(`{"patch": true}`), "hook", "shelltest", "--event", "PreToolUse")
	if !strings.HasPrefix(out, "ask|target_unparsed|") || !strings.Contains(out, "cannot tell which files") {
		t.Errorf("unparsed target: %q", out)
	}
	if h := e.files("health"); !strings.Contains(h, `"code":"target_unparsed"`) {
		t.Errorf("health = %s", h)
	}
	if out, _, _ := e.run([]byte(`{"bare": true}`), "hook", "shelltest", "--event", "PreToolUse"); !strings.HasPrefix(out, "ask|target_unparsed|") {
		t.Errorf("unparsed target without an event: %q", out)
	}
	// 配置非法时同样请求确认（按配置非法处理）
	e.config("version: 1\naction: {tier: 9}\n")
	if out, _, _ := e.run([]byte(`{"patch": true}`), "hook", "shelltest", "--event", "PreToolUse"); !strings.HasPrefix(out, "ask|config_invalid|") {
		t.Errorf("unparsed target with an invalid config: %q", out)
	}
}

package codex_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/codex"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
)

func hook(event string, fields map[string]any) []byte {
	m := map[string]any{"session_id": "s1", "turn_id": "u1", "transcript_path": "/t/rollout-s1.jsonl", "cwd": "/w",
		"hook_event_name": event, "model": "m", "permission_mode": "default"}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func pre(tool string, input any) []byte {
	return hook("PreToolUse", map[string]any{"tool_name": tool, "tool_input": input, "tool_use_id": "exec-1"})
}

func post(tool string, response any) []byte {
	return hook("PostToolUse", map[string]any{"tool_name": tool, "tool_input": map[string]any{}, "tool_response": response, "tool_use_id": "exec-1"})
}

func prompt(text string) []byte { return hook("UserPromptSubmit", map[string]any{"prompt": text}) }

var a = codex.Adapter{}

// reply 解析 Codex 的 hook 输出：PreToolUse 的 permissionDecision，或 PostToolUse、UserPromptSubmit 的 decision。
type reply struct {
	Decision           string `json:"decision"`
	Reason             string `json:"reason"`
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

func parseReply(t *testing.T, out []byte) reply {
	t.Helper()
	var r reply
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("stdout %q: %v", out, err)
	}
	return r
}

// TestConformance：公共一致性套件，外加 Codex 的输出格式（spec §7.2）：动作只有 deny（ask 降级为 deny，
// 渲染时也按 deny 输出），提示词与工具输出的 deny 是 decision: block，其余无输出。
func TestConformance(t *testing.T) {
	blocks := func(t *testing.T, d guard.Decision, out []byte, code int) {
		if code != 0 {
			t.Errorf("%s: exit %d", d, code)
		}
		if d == guard.DecisionDeny || d == guard.DecisionAsk {
			if r := parseReply(t, out); r.Decision != "block" || !strings.HasPrefix(r.Reason, "h-guard: ") {
				t.Errorf("%s: %s", d, out)
			}
		} else if len(out) != 0 {
			t.Errorf("%s: stdout %q", d, out)
		}
	}
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "bash", Input: pre("Bash", map[string]string{"command": "git push"}), WantKind: guard.EventAction,
			Check: func(t *testing.T, d guard.Decision, out []byte, code int) {
				if code != 0 {
					t.Errorf("%s: exit %d", d, code)
				}
				if d == guard.DecisionDeny || d == guard.DecisionAsk {
					r := parseReply(t, out).HookSpecificOutput
					if r.HookEventName != "PreToolUse" || r.PermissionDecision != "deny" || !strings.HasPrefix(r.PermissionDecisionReason, "h-guard: ") {
						t.Errorf("%s: %s", d, out)
					}
				} else if len(out) != 0 {
					t.Errorf("%s: stdout %q", d, out)
				}
			}},
		{Name: "apply_patch", Input: pre("apply_patch", map[string]string{"command": "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch"}),
			WantKind: guard.EventAction},
		{Name: "prompt", Input: prompt("hi"), WantKind: guard.EventPrompt, Check: blocks},
		{Name: "output", Input: post("Bash", "out\n"), WantKind: guard.EventToolOutput, Check: blocks},
	})
}

// TestCapabilities：M0 实测（spec §7.2）：PreToolUse 只能 deny，ask 不支持；提示词能阻止；工具输出能用 block
// 替换。提示（warn）在 Codex 上没有核实过，不声明。
func TestCapabilities(t *testing.T) {
	want := map[guard.EventKind]harness.EventCaps{
		guard.EventAction: {Block: true}, guard.EventPrompt: {Block: true}, guard.EventToolOutput: {Block: true, Replace: true},
	}
	if got := a.Capabilities(); got.MinVersion != "0.162.1" || !reflect.DeepEqual(got.Events, want) {
		t.Errorf("capabilities = %+v", got)
	}
	for kind, caps := range want {
		if got := a.CapsFor(guard.Event{Kind: kind}); got != caps {
			t.Errorf("CapsFor(%s) = %+v", kind, got)
		}
	}
}

// TestParseActions：Bash 是一条命令，shell 由 WithShell 给出（默认 posix）；apply_patch 的补丁转成文件动作；
// 以 apply_patch 开头的 Bash 命令另加补丁里的文件动作；其他工具不产生动作。
// TestExecFields：执行命令的工具里影响执行的字段也要读（M3c 终审 M-5）：shell 决定按哪种 shell 检查，workdir 决定
// 相对路径在哪里生效；write_stdin 写进交互式进程的内容同样可能执行命令。读不懂这些字段时按目标无法解析。
func TestExecFields(t *testing.T) {
	ev, err := a.Parse(pre("exec_command", map[string]any{"cmd": "Remove-Item -Recurse -Force C:\\", "shell": "pwsh"}))
	if err != nil || len(ev.Actions) != 1 || ev.Actions[0].Exec.Shell != guard.ShellPowerShell {
		t.Errorf("shell pwsh: %+v, %v", ev, err)
	}
	ev, err = a.WithShell(guard.ShellPowerShell).Parse(pre("exec_command", map[string]any{"cmd": "rm -rf x", "shell": "/bin/bash"}))
	if err != nil || ev.Actions[0].Exec.Shell != guard.ShellPOSIX {
		t.Errorf("shell bash: %+v, %v", ev, err)
	}
	// Windows 的绝对写法照原样，不拼到 cwd 后面（fixes 终审 I4）
	for in, want := range map[string]string{"/srv/app": "/srv/app", "sub": "/w/sub", `C:\Users\a\proj`: `C:\Users\a\proj`,
		"D:/work": "D:/work", `\\server\share\repo`: `\\server\share\repo`, "~/proj": "~/proj"} {
		ev, err = a.Parse(pre("exec_command", map[string]any{"cmd": "ls", "workdir": in}))
		if err != nil || ev.Cwd != want {
			t.Errorf("workdir %s: cwd %q, %v", in, ev.Cwd, err)
		}
	}
	for name, input := range map[string]map[string]any{
		"unknown shell":    {"cmd": "ls", "shell": "fish"},
		"shell not text":   {"cmd": "ls", "shell": 3},
		"workdir not text": {"cmd": "ls", "workdir": []string{"/a"}},
	} {
		var tu *harness.TargetUnparsedError
		if _, err := a.Parse(pre("exec_command", input)); !errors.As(err, &tu) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ev, err = a.Parse(pre("write_stdin", map[string]any{"session_id": 3, "chars": "rm -rf /\n"}))
	if err != nil || len(ev.Actions) != 1 || ev.Actions[0].Exec.Command != "rm -rf /\n" {
		t.Errorf("write_stdin: %+v, %v", ev, err)
	}
	if _, err := a.Parse(pre("write_stdin", map[string]any{"session_id": 3, "chars": ""})); !errors.Is(err, codex.ErrNoAction) {
		t.Errorf("empty write_stdin: %v", err)
	}
}

func TestParseActions(t *testing.T) {
	ev, err := a.Parse(pre("Bash", map[string]string{"command": "rm -rf build"}))
	want := []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "rm -rf build", Shell: guard.ShellPOSIX}}}
	if err != nil || !reflect.DeepEqual(ev.Actions, want) || ev.Harness != "codex" || ev.SessionID != "s1" || ev.Cwd != "/w" ||
		ev.CallID != "exec-1" || ev.Tool != "Bash" || ev.TranscriptPath != "/t/rollout-s1.jsonl" {
		t.Errorf("bash: %+v, %v", ev, err)
	}
	ps := a.WithShell(guard.ShellPowerShell)
	if ev, err := ps.Parse(pre("Bash", map[string]string{"command": "Remove-Item x"})); err != nil || ev.Actions[0].Exec.Shell != guard.ShellPowerShell {
		t.Errorf("configured shell: %+v, %v", ev, err)
	}
	ev, err = a.Parse(pre("apply_patch", map[string]string{"command": "*** Begin Patch\n*** Update File: a.txt\n*** Move to: ~/.codex/hooks.json\n@@\n x\n*** End Patch"}))
	if err != nil || len(ev.Actions) != 1 || ev.Actions[0].Kind != guard.ActionFileRename || ev.Actions[0].File.To != "~/.codex/hooks.json" {
		t.Errorf("apply_patch: %+v, %v", ev, err)
	}
	heredoc := "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: .env\n+A=1\n*** End Patch\nEOF"
	ev, err = a.Parse(pre("Bash", map[string]string{"command": heredoc}))
	if err != nil || len(ev.Actions) != 2 || ev.Actions[0].Kind != guard.ActionExec || ev.Actions[1].Kind != guard.ActionFileWrite || ev.Actions[1].File.Path != ".env" {
		t.Errorf("apply_patch through Bash: %+v, %v", ev, err)
	}
	// argv 形式的命令（旧版 Codex）按 POSIX 的写法拼回一条命令，外层包装照常识别
	ev, err = a.Parse(pre("Bash", map[string]any{"command": []string{"bash", "-lc", "rm -rf '/tmp/a b'"}}))
	if err != nil || ev.Actions[0].Exec.Command != `bash -lc 'rm -rf '\''/tmp/a b'\'''` {
		t.Errorf("argv command: %+v, %v", ev, err)
	}
	// 经 shell 调用的 apply_patch：cd 之后、bash -lc 包着的补丁同样读出文件（审查 C-1）
	del := "*** Begin Patch\n*** Delete File: /h/.codex/hooks.json\n*** End Patch"
	for name, input := range map[string]any{
		"cd first":      map[string]any{"command": "cd /w && apply_patch <<'EOF'\n" + del + "\nEOF"},
		"bash -lc":      map[string]any{"command": "bash -lc \"apply_patch <<'EOF'\n" + del + "\nEOF\""},
		"argv":          map[string]any{"command": []string{"apply_patch", del}},
		"argv bash -lc": map[string]any{"command": []string{"bash", "-lc", "apply_patch <<'EOF'\n" + del + "\nEOF"}},
		"cmd field":     map[string]any{"cmd": "apply_patch <<'EOF'\n" + del + "\nEOF"},
		"string input":  "apply_patch <<'EOF'\n" + del + "\nEOF",
	} {
		ev, err := a.Parse(pre("Bash", input))
		if err != nil || len(ev.Actions) < 2 || ev.Actions[0].Kind != guard.ActionExec || ev.Actions[len(ev.Actions)-1].File.Path != "/h/.codex/hooks.json" {
			t.Errorf("%s: %+v, %v", name, ev.Actions, err)
		}
	}
	// cd 到字面目录之后的相对路径按那个目录解析（计划评审 M3C-02）
	ev, err = a.Parse(pre("Bash", map[string]any{"command": "'cd' ~/.codex && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: hooks.json\n*** End Patch\nEOF"}))
	if err != nil || len(ev.Actions) != 2 || ev.Actions[1].File.Path != "~/.codex/hooks.json" {
		t.Errorf("relative path after cd: %+v, %v", ev.Actions, err)
	}
	// 其他执行命令的工具名同样按 Bash 处理
	for _, tool := range []string{"shell", "exec_command", "local_shell"} {
		if ev, err := a.Parse(pre(tool, map[string]any{"command": "rm -rf build"})); err != nil || ev.Actions[0].Kind != guard.ActionExec {
			t.Errorf("%s: %+v, %v", tool, ev, err)
		}
	}
	// 子 agent 的调用（带 agent_id）不从会话记录回退读指令：那里的「用户消息」是父 agent 写的任务（审查 I-3）
	sub := hook("PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": "ls"}, "tool_use_id": "e", "agent_id": "a1", "agent_type": "default"})
	if ev, err := a.Parse(sub); err != nil || ev.TranscriptPath != "" || ev.SessionID != "s1" {
		t.Errorf("subagent: %+v, %v", ev, err)
	}
	for _, tool := range []string{"mcp__hgm0__hg_m0_report", "collaborationspawn_agent", "collaborationwait_agent"} {
		if _, err := a.Parse(pre(tool, map[string]any{})); !errors.Is(err, codex.ErrNoAction) {
			t.Errorf("%s: %v", tool, err)
		}
	}
	if _, err := a.Parse(pre("Bash", map[string]string{"command": "  "})); !errors.Is(err, codex.ErrNoAction) {
		t.Errorf("empty command: %v", err)
	}
}

// TestUnparsedTargets：会改文件或执行命令的工具，读不懂它的参数时返回 *harness.TargetUnparsedError（带事件），
// 调用方请求确认（spec §5.5；审查 I-1、I-2）。
func TestUnparsedTargets(t *testing.T) {
	for _, c := range []struct {
		tool  string
		input any
	}{
		{"apply_patch", map[string]string{"command": "*** Begin Patch\n*** Copy File: a\n*** End Patch"}},
		{"apply_patch", map[string]string{}},
		{"apply_patch", map[string]any{"command": 3}},
		{"apply_patch", 7},
		{"apply_patch", map[string]string{"command": "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch", "input": "garbage"}},
		{"Bash", map[string]any{}},
		{"Bash", map[string]any{"command": nil}},
		{"Bash", map[string]any{"argv": []string{"rm", "-rf", "/"}}},
		{"Bash", map[string]any{"command": []any{"rm", "-rf", "/", 1}}},
		{"Bash", 42},
		{"Bash", map[string]any{"command": "cd \"$CODEX_HOME\" && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: hooks.json\n*** End Patch\nEOF"}},
		{"Bash", map[string]any{"command": "apply_patch < fix.patch"}},
	} {
		// 终审 I-1：能读出的动作（这里是命令本身）留在事件里，照常检查；读不懂的部分另外请求确认
		want := 0
		if m, ok := c.input.(map[string]any); ok && c.tool == "Bash" {
			if _, ok := m["command"].(string); ok {
				want = 1
			}
		}
		ev, err := a.Parse(pre(c.tool, c.input))
		var tu *harness.TargetUnparsedError
		if !errors.As(err, &tu) || tu.Event.Kind != guard.EventAction || tu.Event.Harness != "codex" || tu.Event.Tool != c.tool ||
			tu.Event.SessionID != "s1" || len(tu.Event.Actions) != want {
			t.Errorf("%s %v: %+v, %v", c.tool, c.input, ev, err)
		}
	}
	// apply_patch 的 tool_input 是字符串（freeform 工具的原始输入）或 command、input 都有：都读
	ev, err := a.Parse(pre("apply_patch", "*** Begin Patch\n*** Delete File: a\n*** End Patch"))
	if err != nil || len(ev.Actions) != 1 {
		t.Errorf("string input: %+v, %v", ev, err)
	}
	ev, err = a.Parse(pre("apply_patch", map[string]string{"command": "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch",
		"input": "*** Begin Patch\n*** Delete File: b\n*** End Patch"}))
	if err != nil || len(ev.Actions) != 2 || ev.Actions[1].File.Path != "b" {
		t.Errorf("command and input: %+v, %v", ev, err)
	}
}

// TestToolOutputText：Bash、apply_patch 的结果是字符串；MCP 的结果是对象，取各文本块与结构化内容。
func TestToolOutputText(t *testing.T) {
	ev, err := a.Parse(post("Bash", "cat: x: No such file\nsecret\n"))
	if err != nil || ev.Kind != guard.EventToolOutput || ev.Text != "cat: x: No such file\nsecret\n" || ev.Tool != "Bash" || ev.CallID != "exec-1" {
		t.Errorf("bash: %+v, %v", ev, err)
	}
	mcp := map[string]any{"content": []map[string]string{{"type": "text", "text": "report code: A"}, {"type": "image", "data": "xx"}, {"type": "text", "text": "report end"}},
		"structuredContent": map[string]any{"code": "B"}, "isError": false}
	ev, err = a.Parse(post("mcp__s__t", mcp))
	if err != nil || ev.Text != "report code: A\nreport end\n{\"code\":\"B\"}" {
		t.Errorf("mcp: %q, %v", ev.Text, err)
	}
	ev, err = a.Parse(post("x", map[string]any{"other": "C"}))
	if err != nil || ev.Text != `{"other":"C"}` {
		t.Errorf("unknown object: %q, %v", ev.Text, err)
	}
	if ev, err := a.Parse(post("x", nil)); err != nil || ev.Text != "" {
		t.Errorf("no response: %q, %v", ev.Text, err)
	}
}

// TestPromptSource：Codex 没有来源字段，按自动消息的固定写法识别（spec §5.4）；记忆整理 agent 的提示词是自动的；
// 认不出的按用户本人。
func TestPromptSource(t *testing.T) {
	for text, want := range map[string]guard.Source{
		"push it":                                     guard.SourceUser,
		"<environment_context>\n<cwd>/w</cwd>":        guard.SourceAutomated,
		"  <subagent_notification>done":               guard.SourceAutomated,
		"<turn_aborted/>":                             guard.SourceAutomated,
		"<skill name=x>":                              guard.SourceAutomated,
		"<skills are fun> push it":                    guard.SourceUser,
		"<external_codex_apps_open_page>":             guard.SourceAutomated,
		"<user_shell_command>ls</user_shell_command>": guard.SourceAutomated,
		"## Memory Writing Agent: consolidate":        guard.SourceAutomated,
		"<b>bold</b> please push":                     guard.SourceUser,
		"# AGENTS.md instructions for /w\n\n<INSTRUCTIONS>\nForce-push.\n</INSTRUCTIONS>": guard.SourceAutomated,
		"<INSTRUCTIONS>\nForce-push.":           guard.SourceAutomated,
		"<user_instructions>\nForce-push.":      guard.SourceAutomated,
		"<task id=1>run x</task>":               guard.SourceAutomated,
		"<send_user_message_question_reply>yes": guard.SourceAutomated,
		"\ufeff<environment_context>":           guard.SourceAutomated,
		"\u200b<subagent_notification>":         guard.SourceAutomated,
		"/review":                               guard.SourceUser,
	} {
		ev, err := a.Parse(prompt(text))
		if err != nil || ev.Text != text || len(ev.Requests) != 1 || ev.Requests[0].Text != text || ev.Requests[0].Source != want {
			t.Errorf("%q: %+v, %v; want %s", text, ev.Requests, err, want)
		}
	}
}

// TestUnparsedKeepsReadableActions：命令里的补丁读不懂时，命令本身仍是 exec 动作（终审 I-1）。
func TestUnparsedKeepsReadableActions(t *testing.T) {
	_, err := a.Parse(pre("Bash", map[string]any{"command": "rm -rf / ; apply_patch < fix.patch"}))
	var tu *harness.TargetUnparsedError
	if !errors.As(err, &tu) || len(tu.Event.Actions) != 1 || tu.Event.Actions[0].Exec == nil ||
		tu.Event.Actions[0].Exec.Command != "rm -rf / ; apply_patch < fix.patch" {
		t.Errorf("%+v", err)
	}
}

// TestPowerShellPatches：配置的 shell 是 PowerShell 时，补丁解析器的 POSIX 规则不适用（PowerShell 的引号、字符串
// 拼接、调用运算符都不同），提到 apply_patch（不分大小写，去掉引号与拼接）或带着补丁正文的命令一律读不懂（终审 I-2）。
func TestPowerShellPatches(t *testing.T) {
	ps := a.WithShell(guard.ShellPowerShell)
	for _, cmd := range []string{
		"apply_patch '*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch'",
		"apply_patch '*** Begin Patch\n*** Add File: a.txt\n+\u2019 + (apply_patch \"*** Begin Patch`n*** Delete File: /h/.codex/hooks.json`n*** End Patch\") + \u2018\n*** End Patch'",
		"& ('apply'+'_patch') ('*** Begin Patch'+[char]10+'*** Delete File: x'+[char]10+'*** End Patch')",
		"& ('APPLY'+'_PATCH') $p",
		"Set-Content p.txt '*** begin patch'",
	} {
		_, err := ps.Parse(pre("Bash", map[string]any{"command": cmd}))
		var tu *harness.TargetUnparsedError
		if !errors.As(err, &tu) || len(tu.Event.Actions) != 1 {
			t.Errorf("%q: %v", cmd, err)
		}
	}
	// 对照：与补丁无关的命令照常
	if ev, err := ps.Parse(pre("Bash", map[string]any{"command": "Get-ChildItem"})); err != nil || len(ev.Actions) != 1 {
		t.Errorf("plain command: %+v, %v", ev, err)
	}
}

// TestReasonPrefixOnce：原因以 h-guard 开头时不再加前缀（「h-guard: h-guard cannot tell…」，M3c 终审 M-3）。
func TestReasonPrefixOnce(t *testing.T) {
	ev, err := a.Parse(pre("Bash", map[string]any{"command": "ls"}))
	if err != nil {
		t.Fatal(err)
	}
	for msg, want := range map[string]string{
		"h-guard cannot tell which files Bash would change.": "h-guard cannot tell which files Bash would change.",
		"Blocked: catastrophic operation.":                   "h-guard: Blocked: catastrophic operation.",
	} {
		out, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionDeny}, Message: msg})
		if got := parseReply(t, out).HookSpecificOutput.PermissionDecisionReason; got != want {
			t.Errorf("%q: reason %q", msg, got)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"unknown event":     hook("Stop", nil),
		"no event":          []byte(`{"session_id":"s1"}`),
		"prompt not string": hook("UserPromptSubmit", map[string]any{"prompt": 1}),
	} {
		var tu *harness.TargetUnparsedError
		if _, err := a.Parse(in); err == nil || errors.Is(err, codex.ErrNoAction) || errors.As(err, &tu) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestRecordedFixtures：M0 录制的 Codex 0.162.1 样本都能解析成预期的事件；录制工具当时的回复与本 adapter
// 对同一结论的渲染一致（spec §7.5）。
func TestRecordedFixtures(t *testing.T) {
	fs, err := fixtures.Load(filepath.Join("..", "..", "..", "testdata", "fixtures", "codex"))
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]guard.EventKind{"PreToolUse": guard.EventAction, "PostToolUse": guard.EventToolOutput, "UserPromptSubmit": guard.EventPrompt}
	n, replies := 0, 0
	for _, f := range fs {
		ev, err := a.Parse(f.Stdin)
		if errors.Is(err, codex.ErrNoAction) {
			n++
			continue
		}
		if err != nil || ev.Kind != kinds[f.Event] {
			t.Errorf("%s: %+v, %v", f.Path, ev.Kind, err)
			continue
		}
		n++
		if len(f.Reply) == 0 {
			continue
		}
		var rec reply
		if err := json.Unmarshal(f.Reply, &rec); err != nil {
			t.Fatal(err)
		}
		d := guard.DecisionDeny
		if rec.HookSpecificOutput.PermissionDecision == "ask" {
			d = guard.DecisionAsk
		}
		out, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: d}, Message: "x"})
		got := parseReply(t, out)
		if got.Decision != rec.Decision || got.HookSpecificOutput.HookEventName != rec.HookSpecificOutput.HookEventName ||
			(got.HookSpecificOutput.PermissionDecision != "") != (rec.HookSpecificOutput.PermissionDecision != "") {
			t.Errorf("%s: rendered %s, recorded %s", f.Path, out, f.Reply)
		}
		replies++
	}
	if n != 45 || replies != 7 {
		t.Errorf("parsed %d fixtures (want 45), compared %d replies (want 7)", n, replies)
	}
}

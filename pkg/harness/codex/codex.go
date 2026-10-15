// Package codex 是 Codex 的 adapter（spec §7.1、§7.2）。Codex 用原生 hook：PreToolUse、PostToolUse、
// UserPromptSubmit 直接运行 h-guard hook codex --event <事件>，stdin 是 Codex 的 hook JSON。
//
// 导入本包即注册名为 codex 的 adapter。
package codex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// Name 是 adapter 名。
const Name = "codex"

// MinVersion 是经过录制核实的最低 Codex 版本（spec §7.5）。
const MinVersion = "0.162.1"

// ErrNoAction 表示这次工具调用不产生动作（MCP、子 agent 等其他工具，或没有命令），调用方不输出任何内容。
var ErrNoAction = errors.New("codex: tool call carries no action")

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 Codex adapter，无状态。Codex 的 hook 载荷不标明 shell（工具名一律是 Bash），exec 动作的 shell
// 由 WithShell 按配置 harnesses.codex.shell 给出，零值为 posix（spec §5.3 第 3 步）。
type Adapter struct {
	shell guard.Shell
}

func (Adapter) Name() string { return Name }

// WithShell 返回以 s 为 exec 动作 shell 的副本（harness.ShellDefaulter）。
func (Adapter) WithShell(s guard.Shell) harness.Adapter { return Adapter{shell: s} }

// Capabilities 见 spec §7.2（M0 实测，Codex 0.162.1）：PreToolUse 的 deny 有效、ask 不支持（工具照常执行）；
// UserPromptSubmit 的 block 有效；PostToolUse 的 block 用反馈替换工具结果。提示（warn）没有核实过，不声明，
// warn 由 Engine 记为 warn_undelivered。
func (Adapter) Capabilities() harness.Caps {
	return harness.Caps{
		MinVersion: MinVersion,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true},
			guard.EventPrompt:     {Block: true},
			guard.EventToolOutput: {Block: true, Replace: true},
		},
	}
}

// CapsFor 返回事件类型的能力。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

// input 是三种事件共有的字段与各自的字段。model、permission_mode、turn_id、agent_id 不参与判断。
type input struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolUseID      string          `json:"tool_use_id"`
	AgentID        string          `json:"agent_id"`
	Prompt         *string         `json:"prompt"`
}

// Parse 解析 Codex 的 hook 输入。
func (a Adapter) Parse(raw []byte) (guard.Event, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return guard.Event{}, fmt.Errorf("codex: %w", err)
	}
	ev := guard.Event{Harness: Name, SessionID: in.SessionID, Cwd: in.Cwd, TranscriptPath: in.TranscriptPath,
		Tool: in.ToolName, CallID: in.ToolUseID}
	switch in.HookEventName {
	case "PreToolUse":
		ev.Kind = guard.EventAction
		if in.AgentID != "" {
			// 子 agent 的调用：transcript_path 指向子 agent 自己的会话记录，那里的「用户消息」是父 agent 写的任务，
			// 不能当作用户本人的授权；指令只来自会话的缓存（与父会话同一个 session_id）
			ev.TranscriptPath = ""
		}
		acts, err := a.actions(in.ToolName, in.ToolInput)
		if errors.Is(err, errUnparsed) {
			// 能读出的动作（命令本身、别的命令里的补丁）照常检查（终审 I-1）
			ev.Actions = acts
			return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
		}
		if err != nil {
			return guard.Event{}, err
		}
		ev.Actions = acts
	case "PostToolUse":
		ev.Kind, ev.Text = guard.EventToolOutput, outputText(in.ToolResponse)
	case "UserPromptSubmit":
		if in.Prompt == nil {
			return guard.Event{}, errors.New("codex: UserPromptSubmit without a prompt")
		}
		ev.Kind, ev.Text = guard.EventPrompt, *in.Prompt
		ev.Requests = []guard.Request{{Text: *in.Prompt, Source: sourceOf(*in.Prompt)}}
	default:
		return guard.Event{}, fmt.Errorf("codex: unsupported input (hook_event_name %q)", in.HookEventName)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

// shellTools 是执行命令的工具名：Codex 0.162.1 在 hook 里一律报告 Bash（M0 核实），其余是它内部的工具名，
// 以后直接出现在 hook 里时同样按命令检查（只会更严）。
var shellTools = map[string]bool{"Bash": true, "shell": true, "exec_command": true, "local_shell": true}

// actions 按 spec §5.5 把工具调用映射为动作：
//   - 执行命令的工具：每条命令一个 exec 动作；命令里的补丁（经 shell 调用的 apply_patch）另按 embeddedPatches 读出文件动作；
//   - apply_patch：补丁逐个文件转成文件动作；
//   - 其他工具（MCP、子 agent）不产生动作（ErrNoAction）。
//
// 会执行命令或改文件的工具，参数读不懂（缺字段、类型不对、补丁读不懂）时返回 errUnparsed，调用方请求确认；
// 只有明确给出的空命令才是 ErrNoAction。
func (a Adapter) actions(tool string, raw json.RawMessage) ([]guard.Action, error) {
	switch {
	case shellTools[tool]:
		cmds, err := commands(raw)
		if err != nil {
			return nil, err
		}
		shell := a.shell
		if shell == "" {
			shell = guard.ShellPOSIX
		}
		var acts, files []guard.Action
		unparsed := false
		for _, c := range cmds {
			if strings.TrimSpace(c.text) == "" {
				continue
			}
			acts = append(acts, guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: c.text, Shell: shell}})
			var f []guard.Action
			var err error
			if shell == guard.ShellPowerShell && c.patch == "" {
				// 补丁解析器只懂 POSIX 的引号与展开；PowerShell 的弯引号、字符串拼接、调用运算符都不同，提到补丁的
				// 命令一律读不懂（终审 I-2）。argv 形式的补丁不经 shell，照常读
				if powerShellPatch(c.text) {
					err = errUnparsed
				}
			} else {
				f, err = embeddedPatches(c.text)
				if c.patch != "" && err == nil { // argv ["apply_patch", 补丁]：补丁原样，不经引号拼接
					f, err = patchActions(c.patch)
				}
			}
			if errors.Is(err, errUnparsed) {
				unparsed = true
				continue
			}
			if err != nil {
				return nil, err
			}
			files = append(files, f...)
		}
		if len(acts) == 0 {
			return nil, ErrNoAction
		}
		acts = append(acts, files...)
		if unparsed {
			// 读得出的动作随 errUnparsed 一起返回，调用方照常检查它们（终审 I-1）
			return acts, errUnparsed
		}
		return acts, nil
	case tool == "apply_patch":
		patches, err := patchTexts(raw)
		if err != nil {
			return nil, err
		}
		var acts []guard.Action
		for _, p := range patches {
			f, err := patchActions(p)
			if err != nil {
				return nil, err
			}
			acts = append(acts, f...)
		}
		return acts, nil
	}
	return nil, ErrNoAction
}

// powerShellPatch 报告 PowerShell 命令是否可能交给 apply_patch 一份补丁：不分大小写，去掉引号（含弯引号）、反引号、
// 空白与 + 拼接后，提到 apply_patch / applypatch，或带着补丁的开头。只用于收紧（终审 I-2）。
func powerShellPatch(s string) bool {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r == '_' || r == '*' {
			b.WriteRune(r)
		}
	}
	k := b.String()
	return strings.Contains(k, "apply_patch") || strings.Contains(k, "applypatch") || strings.Contains(k, "***beginpatch")
}

// shellCommand 是一条要检查的命令：text 是命令文本；argv 是 apply_patch 加补丁时，patch 是补丁原文。
type shellCommand struct{ text, patch string }

// commands 读出执行命令的工具的命令：tool_input 是字符串（就是命令），或对象里的 command、cmd（字符串或字符串
// 数组，两个都有时都检查）。缺字段、null、类型不对都返回 errUnparsed。
func commands(raw json.RawMessage) ([]shellCommand, error) {
	var s string
	if isNull(raw) {
		return nil, errUnparsed
	}
	if json.Unmarshal(raw, &s) == nil {
		return []shellCommand{{text: s}}, nil
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil {
		return nil, errUnparsed
	}
	var out []shellCommand
	for _, key := range []string{"command", "cmd"} {
		v, ok := in[key]
		if !ok {
			continue
		}
		c, err := commandText(v)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errUnparsed
	}
	return out, nil
}

// commandText 返回一条命令：字符串原样；字符串数组（旧版 Codex 的 argv，如 ["bash", "-lc", "…"]）按 POSIX 的写法
// 逐个加单引号拼成一条命令，外层的 bash -lc 照常由命令检测识别；["apply_patch", 补丁] 另带补丁原文。
func commandText(raw json.RawMessage) (shellCommand, error) {
	var s string
	if isNull(raw) {
		return shellCommand{}, errUnparsed
	}
	if json.Unmarshal(raw, &s) == nil {
		return shellCommand{text: s}, nil
	}
	var argv []string
	if json.Unmarshal(raw, &argv) != nil || len(argv) == 0 {
		return shellCommand{}, errUnparsed
	}
	var c shellCommand
	if name := argv[0]; len(argv) == 2 && (name == "apply_patch" || name == "applypatch") {
		c.patch = argv[1]
	}
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = arg
		if arg == "" || strings.ContainsAny(arg, " \t\n'\"\\$`;&|<>()*?[]{}~#!=") {
			quoted[i] = "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
		}
	}
	c.text = strings.Join(quoted, " ")
	return c, nil
}

// patchTexts 读出 apply_patch 的补丁：tool_input 是字符串（freeform 工具的原始输入），或对象里的 command、input
// （两个都有时都读）。读不出返回 errUnparsed。
func patchTexts(raw json.RawMessage) ([]string, error) {
	var s string
	if isNull(raw) {
		return nil, errUnparsed
	}
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}, nil
	}
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil {
		return nil, errUnparsed
	}
	var out []string
	for _, key := range []string{"command", "input"} {
		v, ok := in[key]
		if !ok {
			continue
		}
		if isNull(v) || json.Unmarshal(v, &s) != nil {
			return nil, errUnparsed
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errUnparsed
	}
	return out, nil
}

// outputText 从 tool_response 抽取文本：字符串原样（Bash、apply_patch 的结果）；MCP 的结果对象取 content 中
// 各文本块与结构化内容（JSON），按顺序以换行连接；其余 JSON 原样（紧凑写法）。
func outputText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var mcp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
	}
	var parts []string
	if json.Unmarshal(raw, &mcp) == nil && (mcp.Content != nil || mcp.StructuredContent != nil) {
		for _, c := range mcp.Content {
			if c.Type == "text" {
				parts = append(parts, c.Text)
			}
		}
		if len(mcp.StructuredContent) > 0 && string(mcp.StructuredContent) != "null" {
			parts = append(parts, compact(mcp.StructuredContent))
		}
		return strings.Join(parts, "\n")
	}
	return compact(raw)
}

// isNull 报告 JSON 值是否缺失或为 null（json.Unmarshal 把 null 解成零值而不报错）。
func isNull(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

func compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// automatedTags 是 Codex 注入到用户消息里、以标签开头的自动内容（spec §5.4，M0 统计维护者本机会话记录核实）。
// 以 external_codex_apps_ 开头的标签都是自动的；其余标签要整词匹配（<skill 不匹配 <skills）。
var automatedTags = []string{
	"environment_context", "recommended_plugins", "skill", "image", "in-app-browser-context", "turn_aborted",
	"codex_internal_context", "subagent_notification", "goal_context", "user_shell_command", "guardian_tool_descriptions",
	"task", "send_user_message_question_reply",
	// 项目的 AGENTS.md：内容由仓库决定，不是用户本人说的话
	"user_instructions", "INSTRUCTIONS",
}

// automatedPrefixes 是按固定开头识别的自动内容：记忆整理 agent 的提示词（M0 核实；它在 ~/.codex/memories 以
// bypassPermissions 运行）、新版 AGENTS.md 的写法与 external_codex_apps_ 一族标签。
var automatedPrefixes = []string{"## Memory Writing Agent:", "# AGENTS.md instructions for", "<external_codex_apps_"}

// sourceOf 按提示词的写法判定来源：Codex 没有来源字段（spec §5.4）。注入标签开头的内容、AGENTS.md 与记忆整理
// agent 的提示词是自动消息，其余（含认不出的）按用户本人。开头的空白、BOM 与零宽字符不影响判断。
func sourceOf(text string) guard.Source {
	t := strings.TrimLeft(text, " \t\r\n\ufeff\u200b\u200c\u200d\u2060")
	for _, p := range automatedPrefixes {
		if strings.HasPrefix(t, p) {
			return guard.SourceAutomated
		}
	}
	for _, tag := range automatedTags {
		rest, ok := strings.CutPrefix(t, "<"+tag)
		if ok && (rest == "" || strings.ContainsRune(" \t\r\n>/", rune(rest[0]))) {
			return guard.SourceAutomated
		}
	}
	return guard.SourceUser
}

// Render 渲染结论（spec §7.2）：动作的 deny 是 PreToolUse 的 permissionDecision: deny（ask 已由 Engine 降级；
// 万一到达这里也按 deny 输出，不能让工具照常执行）；提示词与工具输出的 deny 是 decision: block，Codex 用 reason
// 代替原提示词或工具结果；其余结论无输出，Codex 走自己的流程。
func (Adapter) Render(ev guard.Event, out guard.Outcome) ([]byte, int) {
	d := out.Verdict.Decision
	if d != guard.DecisionDeny && d != guard.DecisionAsk {
		return nil, 0
	}
	var v any
	if ev.Kind == guard.EventAction {
		v = map[string]any{"hookSpecificOutput": map[string]string{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason(out),
		}}
	} else {
		v = map[string]string{"decision": "block", "reason": reason(out)}
	}
	b, _ := json.Marshal(v)
	return b, 0
}

// reason 是写给 Codex 的原因：前缀表明来源，后接原因与前进路径；原因缺失时只有前缀，仍能识别。
func reason(out guard.Outcome) string {
	s := "h-guard: " + out.Message
	if out.Hint != "" {
		s += " " + out.Hint
	}
	return strings.TrimSpace(s)
}

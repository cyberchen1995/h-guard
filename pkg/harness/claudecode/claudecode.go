// Package claudecode 是 Claude Code 的 adapter（spec §7.7）。h-guard 以插件接入 Claude Code：
//   - 插件内的经典 PreToolUse hook 负责动作，stdin 是 Claude Code 的原生 hook JSON；
//   - mod 按扩展接入协议 v1 转交 tool.result 与 prompt.submit，stdin 是扩展请求。
//
// 导入本包即注册名为 claudecode 的 adapter。
package claudecode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

// Name 是 adapter 名，也是扩展请求中的 harness 字段。
const Name = "claudecode"

// MinVersion 是经过录制核实的最低 Claude Code 版本（spec §7.5）。
const MinVersion = "2.1.296"

// ErrNoAction 表示这次工具调用不产生动作（MCP 等其他工具，或输入里没有可检查的内容），调用方不输出任何内容。
var ErrNoAction = errors.New("claudecode: tool call carries no action")

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 Claude Code adapter，无状态。
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Capabilities 见 spec §7.2：动作经经典 PreToolUse 能阻止、请求确认、提示；提示词能丢弃、提示；
// 工具结果能由 mod 扣下。
func (Adapter) Capabilities() harness.Caps {
	return harness.Caps{
		MinVersion: MinVersion,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true, Ask: true, Warn: true},
			guard.EventPrompt:     {Block: true, Warn: true},
			guard.EventToolOutput: {Block: true, Warn: true, Replace: true},
		},
	}
}

// CapsFor 返回事件类型的能力。-p 与 dontAsk 下 ask 由 Claude Code 自己拒绝，属于安全方向，不必降级。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

// Parse 解析经典 PreToolUse 输入或扩展请求。
func (Adapter) Parse(raw []byte) (guard.Event, error) {
	var probe struct {
		Protocol      string `json:"protocol"`
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return guard.Event{}, fmt.Errorf("claudecode: %w", err)
	}
	var (
		ev  guard.Event
		err error
	)
	switch {
	case probe.Protocol != "":
		ev, err = parseExt(raw)
	case probe.HookEventName == "PreToolUse":
		ev, err = parsePreToolUse(raw)
	default:
		return guard.Event{}, fmt.Errorf("claudecode: unsupported input (hook_event_name %q)", probe.HookEventName)
	}
	if err != nil {
		return guard.Event{}, err
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

type preToolUse struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolUseID      string          `json:"tool_use_id"`
}

type toolInput struct {
	Command      string `json:"command"`
	FilePath     string `json:"file_path"`
	NotebookPath string `json:"notebook_path"`
	Path         string `json:"path"`
}

func parsePreToolUse(raw []byte) (guard.Event, error) {
	var p preToolUse
	if err := json.Unmarshal(raw, &p); err != nil {
		return guard.Event{}, fmt.Errorf("claudecode: %w", err)
	}
	var in toolInput
	if len(p.ToolInput) > 0 {
		if err := json.Unmarshal(p.ToolInput, &in); err != nil {
			return guard.Event{}, fmt.Errorf("claudecode: tool_input: %w", err)
		}
	}
	a, ok := actionFor(p.ToolName, in)
	if !ok {
		return guard.Event{}, ErrNoAction
	}
	return guard.Event{
		Kind: guard.EventAction, Harness: Name, SessionID: p.SessionID, CallID: p.ToolUseID, Cwd: p.Cwd,
		Tool: p.ToolName, Actions: []guard.Action{a}, TranscriptPath: p.TranscriptPath,
	}, nil
}

// actionFor 按 spec §5.5 把工具映射为动作。Monitor 在后台用 Bash 执行命令。
func actionFor(tool string, in toolInput) (guard.Action, bool) {
	exec := func(shell guard.Shell) (guard.Action, bool) {
		if strings.TrimSpace(in.Command) == "" {
			return guard.Action{}, false
		}
		return guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: in.Command, Shell: shell}}, true
	}
	file := func(kind guard.ActionKind, path string) (guard.Action, bool) {
		if path == "" {
			return guard.Action{}, false
		}
		return guard.Action{Kind: kind, File: &guard.FileAction{Path: path}}, true
	}
	switch tool {
	case "Bash", "Monitor":
		return exec(guard.ShellPOSIX)
	case "PowerShell":
		return exec(guard.ShellPowerShell)
	case "Read":
		return file(guard.ActionFileRead, in.FilePath)
	case "Grep":
		return file(guard.ActionFileRead, in.Path)
	case "Write", "Edit":
		return file(guard.ActionFileWrite, in.FilePath)
	case "NotebookEdit":
		return file(guard.ActionFileWrite, in.NotebookPath)
	}
	return guard.Action{}, false
}

type promptData struct {
	Text   string `json:"text"`
	Origin *struct {
		Kind string `json:"kind"`
	} `json:"origin"`
}

type resultData struct {
	Tool      string `json:"tool"`
	ToolUseID string `json:"tool_use_id"`
}

type resultPayload struct {
	Text string `json:"text"`
}

func parseExt(raw []byte) (guard.Event, error) {
	req, err := extproto.ParseRequest(raw)
	if err != nil {
		return guard.Event{}, err
	}
	if req.Harness != Name {
		return guard.Event{}, fmt.Errorf("claudecode: request is for harness %q", req.Harness)
	}
	ev := guard.Event{Harness: Name, SessionID: req.Session.ID, Cwd: req.Session.Cwd}
	switch req.Hook {
	case "prompt.submit":
		var d promptData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("claudecode: prompt.submit data: %w", err)
		}
		kind := ""
		if d.Origin != nil {
			kind = d.Origin.Kind
		}
		ev.Kind, ev.Text = guard.EventPrompt, d.Text
		ev.Requests = []guard.Request{{Text: d.Text, Source: SourceOf(kind)}}
	case "tool.result":
		var d resultData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("claudecode: tool.result data: %w", err)
		}
		var r resultPayload
		if len(req.Result) > 0 {
			if err := json.Unmarshal(req.Result, &r); err != nil {
				return guard.Event{}, fmt.Errorf("claudecode: tool.result result: %w", err)
			}
		}
		ev.Kind, ev.Tool, ev.CallID, ev.Text = guard.EventToolOutput, d.Tool, d.ToolUseID, r.Text
	default:
		// mod 不注册 tool.check（spec §7.7）；其余 hook 都不认识
		return guard.Event{}, fmt.Errorf("claudecode: unsupported hook %q", req.Hook)
	}
	return ev, nil
}

// automatedOrigins 是 prompt.submit 与 transcript 中表示自动消息的 origin.kind（spec §5.4）。
// 其余取值（composer、bridge、sdk、human、unclassified 以及以后出现的新取值）按维护者决定视为用户本人。
var automatedOrigins = map[string]bool{
	"task-notification": true, "scheduled-trigger": true, "peer": true, "peer-send-message": true,
	"projects-relay": true, "channel": true, "coordinator": true, "observer": true, "observer-activity": true,
	"auto-continuation": true, "slack-ping": true, "plugin": true,
}

// SourceOf 按 origin.kind 判定指令来源。
func SourceOf(kind string) guard.Source {
	if automatedOrigins[kind] {
		return guard.SourceAutomated
	}
	return guard.SourceUser
}

// Render 渲染结论：动作走经典 PreToolUse 的 hookSpecificOutput（pass 无输出）；
// 提示词与工具结果回复扩展接入协议（spec §7.7 映射表）。
func (Adapter) Render(ev guard.Event, out guard.Outcome) ([]byte, int) {
	d := out.Verdict.Decision
	if ev.Kind == guard.EventAction {
		switch d {
		case guard.DecisionDeny, guard.DecisionAsk:
			b, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]string{
				"hookEventName": "PreToolUse", "permissionDecision": string(d), "permissionDecisionReason": reason(out),
			}})
			return b, 0
		case guard.DecisionWarn:
			b, _ := json.Marshal(map[string]string{"systemMessage": reason(out)})
			return b, 0
		}
		return nil, 0
	}
	if d == guard.DecisionPass {
		b, _ := json.Marshal(extproto.NewReply(extproto.ActionPass, "", ""))
		return b, 0
	}
	msg := out.Message
	if strings.TrimSpace(msg) == "" {
		msg = "h-guard" // 非 pass 的回复必须带说明（spec §7.6）
	}
	b, _ := json.Marshal(extproto.NewReply(extproto.Action(d), msg, out.Hint))
	return b, 0
}

// reason 是写给 Claude Code 的原因：前缀表明来源，后接原因与前进路径。
func reason(out guard.Outcome) string {
	s := "h-guard: " + out.Message
	if strings.HasPrefix(out.Message, "h-guard") { // 原因本身已表明来源（如「h-guard cannot tell…」），不重复前缀
		s = out.Message
	}
	if out.Hint != "" {
		s += " " + out.Hint
	}
	return strings.TrimSpace(s)
}

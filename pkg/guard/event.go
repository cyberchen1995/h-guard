package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// EventKind 是事件类型。
type EventKind string

const (
	EventAction     EventKind = "action"      // agent 将执行的动作（PreToolUse）
	EventPrompt     EventKind = "prompt"      // 用户提示词（UserPromptSubmit）
	EventToolOutput EventKind = "tool_output" // 工具输出（PostToolUse）
)

// Valid 报告 k 是否为已知事件类型。
func (k EventKind) Valid() bool {
	switch k {
	case EventAction, EventPrompt, EventToolOutput:
		return true
	}
	return false
}

// ActionKind 是动作类型。
type ActionKind string

const (
	ActionExec        ActionKind = "exec"
	ActionFileRead    ActionKind = "file_read"
	ActionFileWrite   ActionKind = "file_write"
	ActionFileDelete  ActionKind = "file_delete"
	ActionFileRename  ActionKind = "file_rename"
	ActionToolCall    ActionKind = "tool_call"    // 预留
	ActionHTTPRequest ActionKind = "http_request" // 预留
)

// Valid 报告 k 是否为已知动作类型。
func (k ActionKind) Valid() bool {
	switch k {
	case ActionExec, ActionFileRead, ActionFileWrite, ActionFileDelete, ActionFileRename, ActionToolCall, ActionHTTPRequest:
		return true
	}
	return false
}

// Shell 是执行命令所用的 shell。cmd.exe 不在支持范围内。
type Shell string

const (
	ShellPOSIX      Shell = "posix"
	ShellPowerShell Shell = "powershell"
)

// Valid 报告 s 是否为支持的 shell。
func (s Shell) Valid() bool { return s == ShellPOSIX || s == ShellPowerShell }

// Source 是用户指令的来源。
type Source string

const (
	SourceUser      Source = "user"      // 用户本人
	SourceAutomated Source = "automated" // 定时任务、子 agent 回报、跨会话消息等自动消息
)

// Valid 报告 s 是否为已知来源。
func (s Source) Valid() bool { return s == SourceUser || s == SourceAutomated }

// Event 是 adapter 解析出的统一事件。
type Event struct {
	Kind           EventKind `json:"kind"`
	Harness        string    `json:"harness"`
	SessionID      string    `json:"session_id,omitempty"`
	CallID         string    `json:"call_id,omitempty"` // harness 提供的调用标识，没有则为空
	Cwd            string    `json:"cwd,omitempty"`
	Tool           string    `json:"tool,omitempty"`    // 触发事件的工具（Action / ToolOutput）
	Actions        []Action  `json:"actions,omitempty"` // Kind == EventAction；一次工具调用可产生多个动作
	Text           string    `json:"text,omitempty"`    // Prompt 原文；ToolOutput 中抽取的文本（内容块按顺序以换行连接），行号以它为准
	Requests       []Request `json:"requests,omitempty"`
	TranscriptPath string    `json:"transcript_path,omitempty"`
	// Native 是 adapter 保存的原始载荷，只供本 adapter 渲染使用（如按原形状替换工具输出）。
	// 它可能含完整的工具输出，不参与 JSON 编码，也不得写入日志。
	Native json.RawMessage `json:"-"`
}

// Request 是一条用户指令，按时间先后排列。
type Request struct {
	Text   string    `json:"text"`
	Source Source    `json:"source"`
	At     time.Time `json:"at"`
}

// Action 是一个动作。Exec、File 与 Kind 对应；tool_call、http_request 的载荷放在 Raw。
type Action struct {
	Kind ActionKind     `json:"kind"`
	Exec *ExecAction    `json:"exec,omitempty"`
	File *FileAction    `json:"file,omitempty"`
	Raw  map[string]any `json:"raw,omitempty"`
}

// ExecAction 是执行命令。
type ExecAction struct {
	Command string `json:"command"`
	Shell   Shell  `json:"shell"`
}

// FileAction 是文件动作。To 只用于 file_rename。
type FileAction struct {
	Path string `json:"path"`
	To   string `json:"to,omitempty"`
}

// Validate 检查事件内部是否自洽。adapter 的 Parse 结果必须通过它。
func (e Event) Validate() error {
	if !e.Kind.Valid() {
		return fmt.Errorf("guard: unknown event kind %q", e.Kind)
	}
	if e.Harness == "" {
		return errors.New("guard: event harness is empty")
	}
	if e.Kind == EventAction {
		if len(e.Actions) == 0 {
			return errors.New("guard: action event has no actions")
		}
		for i, a := range e.Actions {
			if err := a.Validate(); err != nil {
				return fmt.Errorf("guard: action %d: %w", i, err)
			}
		}
	} else if len(e.Actions) > 0 {
		return fmt.Errorf("guard: %s event must not carry actions", e.Kind)
	}
	for i, r := range e.Requests {
		if !r.Source.Valid() {
			return fmt.Errorf("guard: request %d: unknown source %q", i, r.Source)
		}
	}
	return nil
}

// Validate 检查动作的类型与载荷是否一致。
func (a Action) Validate() error {
	switch a.Kind {
	case ActionExec:
		if a.Exec == nil || a.Exec.Command == "" {
			return errors.New("exec action needs a command")
		}
		if !a.Exec.Shell.Valid() {
			return fmt.Errorf("exec action has unsupported shell %q", a.Exec.Shell)
		}
		if a.File != nil {
			return errors.New("exec action must not carry a file payload")
		}
	case ActionFileRead, ActionFileWrite, ActionFileDelete, ActionFileRename:
		if a.File == nil || a.File.Path == "" {
			return fmt.Errorf("%s action needs a path", a.Kind)
		}
		if a.Kind == ActionFileRename && a.File.To == "" {
			return errors.New("file_rename action needs a target path")
		}
		if a.Kind != ActionFileRename && a.File.To != "" {
			return fmt.Errorf("%s action must not set a target path", a.Kind)
		}
		if a.Exec != nil {
			return fmt.Errorf("%s action must not carry an exec payload", a.Kind)
		}
	case ActionToolCall, ActionHTTPRequest:
		if a.Exec != nil || a.File != nil {
			return fmt.Errorf("%s action carries its payload in Raw only", a.Kind)
		}
	default:
		return fmt.Errorf("unknown action kind %q", a.Kind)
	}
	return nil
}

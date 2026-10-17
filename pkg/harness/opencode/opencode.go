// Package opencode 是 opencode（1.x）的 adapter。h-guard 以插件接入 opencode：插件在 tool.execute.before、
// tool.execute.after 与 chat.message 三个 hook 里按扩展接入协议 v1 把事件交给 h-guard hook opencode，再把回复
// 翻译成 opencode 的行为（抛出错误阻止、改写工具输出、显示 toast）。
//
// 请求的 data 是 hook 的参数：
//   - tool.execute.before：{tool, sessionID, callID, args}；
//   - tool.execute.after：同上，result 是工具结果 {output, content}（内置工具的 output 是字符串，MCP 工具的结果在 content）；
//   - chat.message：{sessionID, agent, parts, parentID}，parts 是消息的各部分，parentID 由插件查得（子 agent 的会话不为空，
//     查不到时为 "?"，同样按自动消息处理）。
//
// 导入本包即注册名为 opencode 的 adapter。
package opencode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/applypatch"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/extadapter"
)

// Name 是 adapter 名，也是扩展请求中的 harness 字段。
const Name = "opencode"

// MinVersion 是插件按其源码编写的 opencode 版本（1.x 的插件 API；2.x 的插件 API 不同，不支持）。
const MinVersion = "1.19.3"

// ErrNoAction 表示这次工具调用不产生动作（MCP、子 agent 等其他工具，或输入里没有可检查的内容），插件照常放行。
var ErrNoAction = fmt.Errorf("opencode: %w", harness.ErrNoAction)

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 opencode adapter，无状态。opencode 的 bash 工具在 Windows 上多半由 PowerShell 执行，载荷里不标明
// shell：exec 动作的 shell 由 WithShell 按配置 harnesses.opencode.shell 给出，零值为 posix。
type Adapter struct {
	shell guard.Shell
}

func (Adapter) Name() string { return Name }

// WithShell 返回以 s 为 exec 动作 shell 的副本（harness.ShellDefaulter）。
func (Adapter) WithShell(s guard.Shell) harness.Adapter { return Adapter{shell: s} }

// Capabilities：tool.execute.before 抛出错误能阻止工具调用（模型读到说明），插件 API 没有请求确认的办法
// （permission.ask 在 1.x 里从不调用），ask 由 Engine 按 policy.when_ask_unsupported 降级；提示词同样能以抛出
// 错误阻止；tool.execute.after 改写 output 能替换模型看到的结果。提示由插件以 toast 显示（只在 TUI 里可见）。
func (Adapter) Capabilities() harness.Caps {
	return harness.Caps{
		MinVersion: MinVersion,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true, Warn: true},
			guard.EventPrompt:     {Block: true, Warn: true},
			guard.EventToolOutput: {Block: true, Warn: true, Replace: true},
		},
	}
}

// CapsFor 返回事件类型的能力。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

type toolData struct {
	Tool      string          `json:"tool"`
	SessionID string          `json:"sessionID"`
	CallID    string          `json:"callID"`
	Args      json.RawMessage `json:"args"`
}

type args struct {
	Command   string `json:"command"`
	Workdir   string `json:"workdir"`
	FilePath  string `json:"filePath"`
	Path      string `json:"path"`
	PatchText string `json:"patchText"`
}

type promptData struct {
	SessionID string `json:"sessionID"`
	ParentID  string `json:"parentID"`
	Parts     []struct {
		Type      string `json:"type"`
		Text      string `json:"text"`
		Synthetic bool   `json:"synthetic"`
	} `json:"parts"`
}

type resultData struct {
	Output  json.RawMessage `json:"output"`
	Content json.RawMessage `json:"content"`
}

// Parse 解析插件转交的扩展请求。
func (a Adapter) Parse(raw []byte) (guard.Event, error) {
	req, err := extadapter.Request(raw, Name)
	if err != nil {
		return guard.Event{}, err
	}
	ev := guard.Event{Harness: Name, SessionID: req.Session.ID, Cwd: req.Session.Cwd}
	switch req.Hook {
	case "tool.execute.before", "tool.execute.after":
		var d toolData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("opencode: %s data: %w", req.Hook, err)
		}
		var in args
		if !extadapter.IsNull(d.Args) {
			if err := json.Unmarshal(d.Args, &in); err != nil {
				return guard.Event{}, fmt.Errorf("opencode: %s args: %w", req.Hook, err)
			}
		}
		ev.Tool, ev.CallID = d.Tool, d.CallID
		if req.Hook == "tool.execute.after" {
			var r resultData
			if !extadapter.IsNull(req.Result) {
				if err := json.Unmarshal(req.Result, &r); err != nil {
					return guard.Event{}, fmt.Errorf("opencode: tool.execute.after result: %w", err)
				}
			}
			ev.Kind = guard.EventToolOutput
			// MCP 工具的结果在 content 里（模型看到的文本在 hook 之后由 content 生成）；内置工具的是 output
			if !extadapter.IsNull(r.Content) {
				ev.Text = extadapter.Text(r.Content)
			} else {
				ev.Text = extadapter.Text(r.Output)
			}
			ev.FileContent = a.fileContent(d.Tool, in)
			break
		}
		ev.Kind = guard.EventAction
		if d.Tool == "bash" {
			ev.Cwd = extadapter.Workdir(ev.Cwd, in.Workdir)
		}
		acts, err := a.actions(d.Tool, in)
		if errors.Is(err, applypatch.ErrUnparsed) {
			return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
		}
		if err != nil {
			return guard.Event{}, err
		}
		ev.Actions = acts
	case "chat.message":
		var d promptData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("opencode: chat.message data: %w", err)
		}
		// 消息的全部文本（含附带的文件内容）都会交给模型，都要扫描；用户指令只取用户自己写的部分。
		// 子 agent 的会话里，「用户消息」是父 agent 写的任务，不是用户本人的指令
		var all, typed []string
		for _, p := range d.Parts {
			if p.Type != "text" {
				continue
			}
			all = append(all, p.Text)
			if !p.Synthetic {
				typed = append(typed, p.Text)
			}
		}
		src := guard.SourceUser
		if d.ParentID != "" {
			src = guard.SourceAutomated
		}
		ev.Kind, ev.Text = guard.EventPrompt, strings.Join(all, "\n")
		if len(typed) > 0 {
			ev.Requests = []guard.Request{{Text: strings.Join(typed, "\n"), Source: src}}
		}
	default:
		return guard.Event{}, fmt.Errorf("opencode: unsupported hook %q", req.Hook)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

func (a Adapter) shellOf() guard.Shell {
	if a.shell == "" {
		return guard.ShellPOSIX
	}
	return a.shell
}

// actions 把工具映射为动作：bash 执行命令；read、grep 读文件；write、edit 写文件；apply_patch 的补丁逐个文件转成
// 文件动作，读不懂时返回 applypatch.ErrUnparsed（调用方请求确认）。其余工具（glob、webfetch、task、MCP 等）不产生动作。
func (a Adapter) actions(tool string, in args) ([]guard.Action, error) {
	one := func(act guard.Action, ok bool) ([]guard.Action, error) {
		if !ok {
			return nil, ErrNoAction
		}
		return []guard.Action{act}, nil
	}
	switch tool {
	case "bash":
		return one(extadapter.Exec(in.Command, a.shellOf()))
	case "read":
		return one(extadapter.File(guard.ActionFileRead, in.FilePath))
	case "grep":
		return one(extadapter.File(guard.ActionFileRead, in.Path))
	case "write", "edit":
		return one(extadapter.File(guard.ActionFileWrite, in.FilePath))
	case "apply_patch":
		return applypatch.Actions(in.PatchText)
	}
	return nil, ErrNoAction
}

// fileContent 报告工具结果是不是文件内容：读文件的工具，或读文件的命令。
func (a Adapter) fileContent(tool string, in args) bool {
	switch tool {
	case "read", "grep", "skill", "lsp", "read_mcp_resource": // skill 的结果是读出的 SKILL.md，lsp（实验性）的结果带着源码，read_mcp_resource 是 MCP 服务提供的资源
		return true
	case "bash":
		return command.ReadsFiles(in.Command, a.shellOf())
	}
	return false
}

// RenderNoAction 对不产生动作的工具调用回复放行（harness.NoActionRenderer）。
func (Adapter) RenderNoAction() ([]byte, int) {
	return extadapter.Render(guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionPass}}), 0
}

// Render 渲染扩展接入协议的回复，pass 也有回复。
func (Adapter) Render(_ guard.Event, out guard.Outcome) ([]byte, int) {
	return extadapter.Render(out), 0
}

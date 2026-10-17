// Package dsh 是 DeepSeek Harness（dsh）的 adapter。h-guard 以 Cordis 插件接入 dsh：插件在 tools/pre-execute、
// tools/post-execute 与 agent/pre-step 三个 waterfall 事件里按扩展接入协议 v1 把事件交给 h-guard hook dsh，再把回复
// 翻译成 dsh 的决定（deny、ask、block、reject）。
//
// 请求的 data 是事件里能序列化的部分：
//   - tools/pre-execute：{name, callId, arguments, nested}，nested 表示这是 run_code 里发出的调用；
//   - tools/post-execute：同上，result 是工具结果 {isError, content}；
//   - agent/pre-step：{messages, session}，messages 是这一步要交给模型的新消息（[{source: {kind}, content}]），session 是
//     会话头里的 {origin, delegationDepth}（子 agent 的会话 origin 为 subagent）。
//
// 导入本包即注册名为 dsh 的 adapter。
package dsh

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/extadapter"
)

// Name 是 adapter 名，也是扩展请求中的 harness 字段。
const Name = "dsh"

// MinVersion 是插件按其源码编写的 dsh 版本。
const MinVersion = "0.2.1-rc.2"

// ErrNoAction 表示这次工具调用不产生动作（glob、web_fetch、MCP、子 agent 等其他工具，或没有可检查的内容），插件照常放行。
var ErrNoAction = fmt.Errorf("dsh: %w", harness.ErrNoAction)

var errUnparsed = errors.New("dsh: the tool's target cannot be parsed")

// errUnknownTool 表示 dsh 自带的工具里 h-guard 不认识的（Parse 返回 *harness.UnknownToolError）。
var errUnknownTool = errors.New("dsh: the tool is not known")

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 dsh adapter，无状态。
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Capabilities：tools/pre-execute 的 deny 阻止工具调用（模型读到说明），ask 交给 dsh 的确认服务（没有能回答的
// 界面时，如 headless，dsh 自己拒绝，属于安全方向）；agent/pre-step 的 reject 丢弃提示词；tools/post-execute 的
// block 让说明代替工具结果。dsh 没有向用户显示提示的接口，warn 不声明，由 Engine 记为 warn_undelivered。
func (Adapter) Capabilities() harness.Caps {
	return harness.Caps{
		MinVersion: MinVersion,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true, Ask: true},
			guard.EventPrompt:     {Block: true},
			guard.EventToolOutput: {Block: true, Replace: true},
		},
	}
}

// CapsFor 返回事件类型的能力。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

type toolData struct {
	Name      string          `json:"name"`
	CallID    string          `json:"callId"`
	Arguments json.RawMessage `json:"arguments"`
}

type arguments struct {
	Command  string `json:"command"`
	Text     string `json:"text"` // terminal_send 写进持久终端的内容
	Workdir  string `json:"workdir"`
	FilePath string `json:"file_path"`
	Path     string `json:"path"`
	Action   string `json:"action"` // stagehand_tabs
}

type stepData struct {
	Messages []struct {
		Source struct {
			Kind string `json:"kind"`
		} `json:"source"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Session struct {
		Origin          string `json:"origin"`
		DelegationDepth int    `json:"delegationDepth"`
	} `json:"session"`
}

type resultPayload struct {
	Content json.RawMessage `json:"content"`
}

// Parse 解析插件转交的请求。
func (Adapter) Parse(raw []byte) (guard.Event, error) {
	req, err := extadapter.Request(raw, Name)
	if err != nil {
		return guard.Event{}, err
	}
	ev := guard.Event{Harness: Name, SessionID: req.Session.ID, Cwd: req.Session.Cwd}
	switch req.Hook {
	case "tools/pre-execute", "tools/post-execute":
		var d toolData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("dsh: %s data: %w", req.Hook, err)
		}
		ev.Tool, ev.CallID = d.Name, d.CallID
		var in arguments
		if !extadapter.IsNull(d.Arguments) {
			if err := json.Unmarshal(d.Arguments, &in); err != nil {
				if req.Hook == "tools/pre-execute" && touches[d.Name] {
					ev.Kind = guard.EventAction
					return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
				}
				in = arguments{}
			}
		}
		if req.Hook == "tools/post-execute" {
			var r resultPayload
			if !extadapter.IsNull(req.Result) {
				if err := json.Unmarshal(req.Result, &r); err != nil {
					return guard.Event{}, fmt.Errorf("dsh: tools/post-execute result: %w", err)
				}
			}
			ev.Kind, ev.Text = guard.EventToolOutput, extadapter.Text(r.Content)
			ev.FileContent = fileContent(d.Name, d.Arguments, in)
			break
		}
		ev.Kind = guard.EventAction
		if d.Name == "bash" || d.Name == "pwsh" {
			ev.Cwd = extadapter.Workdir(ev.Cwd, in.Workdir)
		}
		acts, err := actions(d.Name, d.Arguments, in)
		if errors.Is(err, errUnparsed) {
			ev.Actions = acts
			return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
		}
		if errors.Is(err, errUnknownTool) {
			return guard.Event{}, &harness.UnknownToolError{Event: ev}
		}
		if err != nil {
			return guard.Event{}, err
		}
		ev.Actions = acts
	case "agent/pre-step":
		var d stepData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("dsh: agent/pre-step data: %w", err)
		}
		// 子 agent 会话里的「用户消息」是父 agent 写的任务，不是用户本人的指令
		sub := d.Session.Origin == "subagent" || d.Session.DelegationDepth > 0
		var texts []string
		for _, m := range d.Messages {
			t := extadapter.Text(m.Content)
			if t == "" {
				continue
			}
			texts = append(texts, t)
			src := SourceOf(m.Source.Kind)
			if sub {
				src = guard.SourceAutomated
			}
			ev.Requests = append(ev.Requests, guard.Request{Text: t, Source: src})
		}
		ev.Kind, ev.Text = guard.EventPrompt, strings.Join(texts, "\n")
	default:
		return guard.Event{}, fmt.Errorf("dsh: unsupported hook %q", req.Hook)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

// SourceOf 按消息的 source.kind 判定指令来源：user 是用户本人（Web、headless 任务、SDK、ACP 的输入）；其余
// （schedule、subagent-settled、tool-jobs、runtime-context 等）都是 dsh 或插件注入的自动消息。
func SourceOf(kind string) guard.Source {
	if kind == "user" {
		return guard.SourceUser
	}
	return guard.SourceAutomated
}

// dshReadOnly 是 dsh 自带的、不执行命令也不改动用户文件的工具（docs/tool-catalog.md，0.2.1-rc.2）：查询与搜索、提问、
// 计划与目标、子 agent 与团队（子 agent 的工具调用各自经过检查）、run_code（其中的工具调用同样各自经过检查）、后台任务的查看、
// 终端的列出与读取（发送内容的 terminal_send 单独检查）、网页、MCP 资源、会话记录、待办与工作目录。
// 其余 dsh 自带的工具（启动 shell 的 terminal_open，向进程发信号或结束进程的 terminal_signal、terminal_close、job_kill，plugin_manager、plugin_market、schedule_create 等定时任务的改动、create_worktree、lsp、
// load_workspace_dependencies、stagehand_act）与插件提供的工具 h-guard 不认识，请求确认；用户可以在
// harnesses.dsh.read_only_tools 里补充只读的工具。MCP 工具（mcp__ 开头）与其他 harness 一样不检查。
var dshReadOnly = map[string]bool{
	"glob": true, "ask_user_question": true, "exit_plan_mode": true, "run_code": true, "present": true,
	"cordis_inspect_list": true, "cordis_inspect_query": true,
	"terminal_list": true, "terminal_read": true,
	"create_goal": true, "get_goal": true, "update_goal": true, "schedule_list": true, "skill": true, "ralph": true, "workflow": true,
	"session_event_read": true, "session_event_search": true, "session_event_trace": true, "session_search": true, "session_trace": true,
	"list_subagent_models": true, "subagent": true, "interrupt_agent": true, "list_agents": true, "send_message": true,
	"spawn_teammate": true, "team_task_create": true, "team_task_get": true, "team_task_list": true, "team_task_update": true, "wait_agent": true,
	"job_list": true, "job_output": true, "todo_write": true, "working_directory": true,
	"web_fetch": true, "web_search": true, "list_mcp_resource_templates": true, "list_mcp_resources": true, "read_mcp_resource": true,
	"stagehand_extract": true, "stagehand_navigate": true, "stagehand_observe": true, "stagehand_screenshot": true, "stagehand_tabs": true,
}

// touches 是会执行命令或改动文件的工具。
var touches = map[string]bool{"bash": true, "pwsh": true, "write": true, "edit": true, "str_replace_editor": true, "terminal_send": true}

// actions 把工具映射为动作：bash 执行 POSIX 命令，pwsh（Windows）执行 PowerShell 命令；read、read_image、grep 读文件；
// write、edit 写文件；terminal_send 写进持久终端的内容按命令检查并请求确认；str_replace_editor 的 view 读文件，create、str_replace、insert 写文件，其余子命令读不懂。
// 其余工具（glob、web_fetch、run_code、subagent、MCP 等）不产生动作；run_code 里发出的工具调用各自经过这里。
func actions(tool string, raw json.RawMessage, in arguments) ([]guard.Action, error) {
	one := func(act guard.Action, ok bool) ([]guard.Action, error) {
		if !ok {
			return nil, ErrNoAction
		}
		return []guard.Action{act}, nil
	}
	switch tool {
	case "bash":
		return one(extadapter.Exec(in.Command, guard.ShellPOSIX))
	case "pwsh":
		return one(extadapter.Exec(in.Command, guard.ShellPowerShell))
	case "read", "read_image":
		return one(extadapter.File(guard.ActionFileRead, in.FilePath))
	case "grep":
		return one(extadapter.File(guard.ActionFileRead, in.Path))
	case "write", "edit":
		return one(extadapter.File(guard.ActionFileWrite, in.FilePath))
	case "terminal_send":
		// 写进持久终端的内容多半是一条命令，但终端是哪种 shell（或 gdb 之类的程序）这里看不出：按 POSIX 命令检查，
		// 另外请求确认
		if act, ok := extadapter.Exec(in.Text, guard.ShellPOSIX); ok {
			return []guard.Action{act}, errUnparsed
		}
		return nil, ErrNoAction
	case "str_replace_editor":
		switch editorCommand(raw) {
		case "view":
			return one(extadapter.File(guard.ActionFileRead, in.Path))
		case "create", "str_replace", "insert", "undo_edit":
			if act, ok := extadapter.File(guard.ActionFileWrite, in.Path); ok {
				return []guard.Action{act}, nil
			}
		}
		return nil, errUnparsed
	}
	if tool == "stagehand_tabs" && in.Action == "close" { // 关闭标签页会丢掉页面的状态，按不认识的工具请求确认
		return nil, errUnknownTool
	}
	if dshReadOnly[tool] || strings.HasPrefix(tool, "mcp__") {
		return nil, ErrNoAction
	}
	return nil, errUnknownTool
}

// editorCommand 返回 str_replace_editor 的子命令（arguments.command；与 bash 的 command 同名，含义不同）。
func editorCommand(raw json.RawMessage) string {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(raw, &in)
	return in.Command
}

// fileContent 报告工具结果是不是文件内容：读文件的工具，或读文件的命令。
func fileContent(tool string, raw json.RawMessage, in arguments) bool {
	switch tool {
	case "read", "grep":
		return true
	case "str_replace_editor":
		return editorCommand(raw) == "view"
	case "bash":
		return command.ReadsFiles(in.Command, guard.ShellPOSIX)
	case "pwsh":
		return command.ReadsFiles(in.Command, guard.ShellPowerShell)
	case "terminal_send": // 结果里有终端的新输出；与动作一样按 POSIX 命令看
		return command.ReadsFiles(in.Text, guard.ShellPOSIX)
	case "terminal_read", "job_output": // 终端与后台任务稍后的输出：看不出是哪条命令写的，按文件内容扫描
		return true
	case "run_code": // 程序里的工具调用（如 tools.read）取回的值可以原样返回
		return true
	case "skill": // 从项目或用户目录读出的 SKILL.md
		return true
	case "session_event_read", "session_event_search", "session_search": // 会话里之前的事件（包括读文件的结果）原文或摘录
		return true
	case "read_mcp_resource": // MCP 服务提供的资源（文件、仓库里的文档等）
		return true
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

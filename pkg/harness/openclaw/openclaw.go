// Package openclaw 是 OpenClaw 的 adapter。h-guard 以原生插件接入 OpenClaw：插件在 before_tool_call、工具结果
// middleware 与 before_agent_run 三处按扩展接入协议 v1 把事件交给 h-guard hook openclaw，再把回复翻译成 OpenClaw 的
// 决定（block、requireApproval、替换工具结果、拦下这一轮）。
//
// 请求的 data 是事件里能序列化的部分：
//   - before_tool_call：{toolName, params, toolKind, toolInputKind, toolCallId, derivedPaths, platform}，toolKind 为
//     code_mode_exec 时这是 Code Mode 的 JavaScript 单元（其中的工具调用各自经过检查），platform 是 Gateway 所在平台
//     （process.platform）；
//   - tool_result（工具结果 middleware）：{toolName, toolCallId, args, isError, platform}，result 是 {content}；
//   - before_agent_run：{prompt, trigger, provenance, sessionKey, channel}，trigger 是这一轮的起因（user、cron、
//     heartbeat 等），provenance 是用户消息的来源（external_user、inter_session、internal_system）。
//
// 导入本包即注册名为 openclaw 的 adapter。
package openclaw

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
const Name = "openclaw"

// MinVersion 是插件按其源码编写的 OpenClaw 版本。
const MinVersion = "2026.10.4"

// codeModeExec 是 Code Mode 外层 exec 的 toolKind：参数是 JavaScript，不是 shell 命令。
const codeModeExec = "code_mode_exec"

// ErrNoAction 表示这次工具调用不产生动作（查询、会话与子 agent、网页、MCP 等工具，或没有可检查的内容），插件照常放行。
var ErrNoAction = fmt.Errorf("openclaw: %w", harness.ErrNoAction)

var errUnparsed = errors.New("openclaw: the tool's target cannot be parsed")

// errUnknownTool 表示 OpenClaw 自带的工具里 h-guard 不认识的，或插件提供的工具（Parse 返回 *harness.UnknownToolError）。
var errUnknownTool = errors.New("openclaw: the tool is not known")

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 OpenClaw adapter，无状态。
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Capabilities：before_tool_call 的 deny 阻止工具调用（模型读到说明），ask 交给 OpenClaw 的插件审批（审批送到发起对话的
// 聊天或配置的目标；没有能回答的界面时 OpenClaw 自己拦下，属于安全方向）；before_agent_run 的 block 拦下这一轮；工具结果
// middleware 用说明代替工具结果。插件没有向用户显示提示的接口，warn 不声明，由 Engine 记为 warn_undelivered（插件可以另外
// 经频道通知）。
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
	ToolName   string          `json:"toolName"`
	ToolCallID string          `json:"toolCallId"`
	Params     json.RawMessage `json:"params"`
	Args       json.RawMessage `json:"args"` // tool_result 的参数
	ToolKind   string          `json:"toolKind"`
	Platform   string          `json:"platform"`
}

// params 是工具参数里 h-guard 用到的字段。path、file_path、filePath 是 OpenClaw 文件工具接受的路径写法（依次取第一个）。
type params struct {
	Command  string   `json:"command"`
	Code     string   `json:"code"` // Code Mode 的 JavaScript
	Workdir  string   `json:"workdir"`
	Host     string   `json:"host"` // exec：auto、sandbox、gateway、node
	Node     string   `json:"node"` // exec：远端节点
	Path     string   `json:"path"`
	FilePath string   `json:"file_path"`
	FileCase string   `json:"filePath"`
	Paths    []string `json:"paths"` // view_image
	Input    string   `json:"input"` // apply_patch
	Action   string   `json:"action"`
	Data     string   `json:"data"` // process write
	Text     string   `json:"text"` // process paste
}

func (p params) path() string {
	for _, s := range []string{p.Path, p.FilePath, p.FileCase} {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

type runData struct {
	Prompt     string `json:"prompt"`
	Trigger    string `json:"trigger"`
	Provenance string `json:"provenance"`
	SessionKey string `json:"sessionKey"`
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
	case "before_tool_call", "tool_result":
		var d toolData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("openclaw: %s data: %w", req.Hook, err)
		}
		ev.Tool, ev.CallID = d.ToolName, d.ToolCallID
		rawParams := d.Params
		if req.Hook == "tool_result" {
			rawParams = d.Args
		}
		var in params
		if !extadapter.IsNull(rawParams) {
			if err := json.Unmarshal(rawParams, &in); err != nil {
				if req.Hook == "before_tool_call" && touches[d.ToolName] {
					ev.Kind = guard.EventAction
					return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
				}
				in = params{}
			}
		}
		codeMode := d.ToolKind == codeModeExec || (d.ToolName == "exec" && in.Code != "" && in.Command == "")
		if req.Hook == "tool_result" {
			var r resultPayload
			if !extadapter.IsNull(req.Result) {
				if err := json.Unmarshal(req.Result, &r); err != nil {
					return guard.Event{}, fmt.Errorf("openclaw: tool_result result: %w", err)
				}
			}
			ev.Kind, ev.Text = guard.EventToolOutput, extadapter.Text(r.Content)
			ev.FileContent = fileContent(d.ToolName, in, shellOf(in, d.Platform), codeMode)
			break
		}
		ev.Kind = guard.EventAction
		if codeMode {
			return guard.Event{}, ErrNoAction // Code Mode 单元里的工具调用各自经过 before_tool_call
		}
		if d.ToolName == "exec" {
			ev.Cwd = extadapter.Workdir(ev.Cwd, in.Workdir)
		}
		acts, err := actions(d.ToolName, in, d.Platform)
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
	case "before_agent_run":
		var d runData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("openclaw: before_agent_run data: %w", err)
		}
		ev.Kind, ev.Text = guard.EventPrompt, d.Prompt
		if strings.TrimSpace(d.Prompt) != "" {
			ev.Requests = []guard.Request{{Text: d.Prompt, Source: SourceOf(d.Trigger, d.Provenance, d.SessionKey)}}
		}
	default:
		return guard.Event{}, fmt.Errorf("openclaw: unsupported hook %q", req.Hook)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

// SourceOf 判定一轮输入的来源：起因是 user（聊天消息、openclaw agent、Web 界面）或 manual（用户发起的系统助手等），
// 且用户消息确实来自外部用户、会话不是子 agent 的，才是用户本人的指令。cron、heartbeat、event（webhook）、memory、
// overflow 等起因，另一个会话转来的消息（inter_session，子 agent 的结果、sessions_send）与系统交接（internal_system），
// 以及子 agent 会话（会话键里有 subagent:）里的输入，都是自动消息。
func SourceOf(trigger, provenance, sessionKey string) guard.Source {
	if trigger != "user" && trigger != "manual" {
		return guard.SourceAutomated
	}
	if provenance == "inter_session" || provenance == "internal_system" {
		return guard.SourceAutomated
	}
	if k := strings.ToLower(sessionKey); strings.HasPrefix(k, "subagent:") || strings.Contains(k, ":subagent:") {
		return guard.SourceAutomated
	}
	return guard.SourceUser
}

// openclawReadOnly 是 OpenClaw 自带的、不执行命令也不改动用户文件的工具（src/agents/tool-catalog.ts，2026.10.4）：
// 目录与搜索、网页、记忆的查询、会话与子 agent（子 agent 的工具调用各自经过检查）、目标与进度、向用户提问、技能的查找与
// 读取、图片与 PDF 的理解、媒体生成、界面与仪表盘、频道消息（message 是 agent 回复用户的方式）、Code Mode 的 wait、
// tool_search 等。
// 其余 OpenClaw 自带的工具（向终端或运行中的进程输入、控制桌面与手机、节点、Gateway 更新与配置、插件管理、定时任务、
// 技能与个人指令的改写、凭据、发布 GitHub PR、暴露本地服务、远端代码执行等）与插件提供的工具 h-guard 不认识，请求确认；
// 用户可以在 harnesses.openclaw.read_only_tools 里补充只读的工具。MCP 工具（<服务>__<工具>）与其他 harness 一样不检查。
var openclawReadOnly = map[string]bool{
	"ls": true, "find": true, "glob": true, "search": true, "tool_search": true, "tool_describe": true, "wait": true,
	"structured_output": true, "decision_evaluate": true,
	"web_search": true, "web_fetch": true, "x_search": true, "memory_search": true, "memory_get": true,
	"presence": true, "sessions": true, "sessions_list": true, "sessions_history": true, "sessions_search": true,
	"sessions_create": true, "sessions_send": true, "sessions_spawn": true, "sessions_yield": true, "session_status": true,
	"conversations_list": true, "conversations_send": true, "conversations_turn": true,
	"agents_list": true, "agents_wait": true, "subagents": true, "suggest_task": true, "dismiss_task": true,
	"get_goal": true, "create_goal": true, "update_goal": true, "progress_card": true, "ask_user": true,
	"skills_search": true, "skills_read": true, "github_identity_status": true,
	"browser": true, "screen": true, "theme": true, "dashboard": true, "canvas": true, "show_widget": true,
	"message": true, "heartbeat_respond": true, "transcripts": true,
	"pdf": true, "image_generate": true, "music_generate": true, "video_generate": true, "tts": true,
}

// touches 是会执行命令或改动文件的工具。
var touches = map[string]bool{"exec": true, "process": true, "write": true, "edit": true, "apply_patch": true}

// shellOf 返回 exec 命令的 shell：sandbox 里是 POSIX；在 Gateway 上（host 为 gateway、auto 或省略）按 Gateway 的平台，
// Windows 上 OpenClaw 用 PowerShell，其余平台用 $SHELL（按 POSIX 检查）。
func shellOf(in params, platform string) guard.Shell {
	if platform == "win32" && in.Host != "sandbox" {
		return guard.ShellPowerShell
	}
	return guard.ShellPOSIX
}

// actions 把工具映射为动作：exec 执行命令（host 为 node 时命令在配对的远端设备上运行，那里的 shell 与文件 h-guard 看不到，
// 按 POSIX 检查并请求确认）；read、grep、view_image 读文件；write、edit 写文件；apply_patch 按补丁里的文件；process 向
// 运行中的进程写入的内容按命令检查并请求确认，发送按键、结束进程请求确认，其余子命令（list、poll、log、submit、clear）
// 不产生动作。其余工具不产生动作，或是不认识的工具。
func actions(tool string, in params, platform string) ([]guard.Action, error) {
	one := func(act guard.Action, ok bool) ([]guard.Action, error) {
		if !ok {
			return nil, ErrNoAction
		}
		return []guard.Action{act}, nil
	}
	switch tool {
	case "exec":
		if in.Host == "node" || strings.TrimSpace(in.Node) != "" {
			if act, ok := extadapter.Exec(in.Command, guard.ShellPOSIX); ok {
				return []guard.Action{act}, errUnparsed
			}
			return nil, ErrNoAction
		}
		return one(extadapter.Exec(in.Command, shellOf(in, platform)))
	case "read", "grep":
		return one(extadapter.File(guard.ActionFileRead, in.path()))
	case "view_image":
		var acts []guard.Action
		for _, p := range append([]string{in.path()}, in.Paths...) {
			if act, ok := extadapter.File(guard.ActionFileRead, p); ok && !isURL(p) {
				acts = append(acts, act)
			}
		}
		if len(acts) == 0 {
			return nil, ErrNoAction
		}
		return acts, nil
	case "write", "edit":
		if act, ok := extadapter.File(guard.ActionFileWrite, in.path()); ok {
			return []guard.Action{act}, nil
		}
		return nil, errUnparsed
	case "apply_patch":
		acts, err := applypatch.Actions(in.Input)
		if err != nil {
			return nil, errUnparsed
		}
		return acts, nil
	case "process":
		switch in.Action {
		case "list", "poll", "log", "submit", "clear":
			return nil, ErrNoAction
		case "write", "paste":
			// 写进运行中进程的内容多半是一条命令，但那是哪种 shell（或别的程序）这里看不出：按 POSIX 命令检查，另外请求确认
			text := in.Data
			if in.Action == "paste" {
				text = in.Text
			}
			if act, ok := extadapter.Exec(text, guard.ShellPOSIX); ok {
				return []guard.Action{act}, errUnparsed
			}
			return nil, ErrNoAction
		}
		return nil, errUnknownTool // send-keys、kill、remove 与读不懂的子命令
	}
	if openclawReadOnly[tool] || strings.Contains(tool, "__") {
		return nil, ErrNoAction
	}
	return nil, errUnknownTool
}

func isURL(p string) bool {
	return strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") || strings.HasPrefix(p, "data:")
}

// fileContent 报告工具结果是不是文件内容：读文件的工具，或读文件的命令。
func fileContent(tool string, in params, shell guard.Shell, codeMode bool) bool {
	if codeMode { // Code Mode 单元里的工具调用（如 read）取回的值可以原样返回
		return true
	}
	switch tool {
	case "read", "grep", "pdf", "memory_get", "skills_read":
		return true
	case "exec":
		return command.ReadsFiles(in.Command, shell)
	case "process": // 后台进程的新输出：看不出是哪条命令写的，按文件内容扫描
		return true
	case "sessions_history", "sessions_search": // 会话里之前的消息（包括读文件的结果）原文或摘录
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

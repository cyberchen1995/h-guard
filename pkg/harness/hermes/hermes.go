// Package hermes 是 Hermes Agent 的 adapter。h-guard 以 Python 插件接入 Hermes：插件在 pre_tool_call、
// transform_tool_result、transform_terminal_output、pre_gateway_dispatch 与 pre_llm_call 五个 hook 里按扩展接入
// 协议 v1 把事件交给 h-guard hook hermes，再把回复翻译成 Hermes 的指令（block、approve、替换工具结果、skip 消息、
// 注入上下文）。
//
// 请求的 data 是 hook 的参数里能序列化的部分，另加插件在 Hermes 进程里读到的状态：
//   - pre_tool_call：{tool_name, args, tool_call_id, approval, backend}。approval 是这次 approve 指令会怎样处理：
//     prompt（会有人回答：CLI 提示、消息平台上的确认卡片）、blocked（没有人能回答，Hermes 拒绝）、auto（YOLO、
//     approvals.mode: off、按 approvals.*_mode: approve 自动批准）或空（读不出）。backend 是 terminal.backend；
//   - transform_tool_result：{tool_name, args, tool_call_id, status}，result 是 {content}，content 是工具结果字符串
//     （通常是 JSON）；
//   - transform_terminal_output：后台进程的输出（前台命令的输出由 transform_tool_result 检查），{command, returncode,
//     env_type}，result 是 {content}；
//   - pre_gateway_dispatch：消息平台上的消息（只检查已授权的发送者），{text, platform, is_bot}；
//   - pre_llm_call：每一轮交给模型之前的用户消息，{text, platform, parent_session_id, is_bot, kanban_task}。这一步挡不住提示词，
//     只能给模型补一段说明。pre_llm_call 的参数里没有消息是否由机器人发出，is_bot 由插件在 pre_gateway_dispatch
//     里记下。
//
// 导入本包即注册名为 hermes 的 adapter。
package hermes

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/extadapter"
)

// Name 是 adapter 名，也是扩展请求中的 harness 字段。
const Name = "hermes"

// MinVersion 是插件按其源码编写的 Hermes Agent 版本。
const MinVersion = "2026.9.24"

// Hook 名：插件注册的 Hermes hook，也是请求的 hook 字段与 --event 的取值。
const (
	HookPreToolCall    = "pre_tool_call"
	HookToolResult     = "transform_tool_result"
	HookTerminalOutput = "transform_terminal_output"
	HookDispatch       = "pre_gateway_dispatch"
	HookPreLLMCall     = "pre_llm_call"
)

// approval 的取值：approve 指令交给 Hermes 后会有人回答（prompt），或没有人能回答而被 Hermes 拒绝（blocked）。
const (
	approvalPrompt  = "prompt"
	approvalBlocked = "blocked"
)

// ErrNoAction 表示这次工具调用不产生动作（只读的工具、MCP 工具，或没有可检查的内容），插件照常放行。
var ErrNoAction = fmt.Errorf("hermes: %w", harness.ErrNoAction)

var (
	errUnparsed    = errors.New("hermes: the tool's target cannot be parsed")
	errUnknownTool = errors.New("hermes: the tool is not known")
)

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 Hermes adapter。零值不发通知；WithNotify 返回按配置 harnesses.hermes.notify 发通知的副本，副本同样
// 不保存其他状态。
type Adapter struct {
	notifyOn uint8 // decisionBit 的组合
	notifyTo string
}

func (Adapter) Name() string { return Name }

// WithNotify 返回一个副本：结论（降级前或降级后）在 on 里时，回复带上 notify，插件据此把说明发到消息渠道；to 是
// 没有来源会话（CLI、定时任务）时的目标（hermes send --to 的写法），可以为空。
func (Adapter) WithNotify(on []guard.Decision, to string) harness.Adapter {
	a := Adapter{notifyTo: to}
	for _, d := range on {
		a.notifyOn |= decisionBit(d)
	}
	return a
}

func decisionBit(d guard.Decision) uint8 {
	switch d {
	case guard.DecisionDeny:
		return 1
	case guard.DecisionAsk:
		return 2
	case guard.DecisionWarn:
		return 4
	}
	return 0
}

// Capabilities：pre_tool_call 返回 block 阻止工具调用（模型读到说明），返回 approve 交给 Hermes 的人工确认（CLI
// 提示，消息平台上的确认卡片与 /approve、/deny）；pre_gateway_dispatch 返回 skip 丢弃消息平台上的提示词，插件把
// 说明作为回复发回这个对话；pre_llm_call 挡不住提示词，只能把提示作为上下文交给模型；transform_tool_result 与
// transform_terminal_output 返回字符串替换模型看到的结果。Hermes 没有向用户显示提示的接口，动作与工具输出的 warn
// 不声明。approve 实际能否请人确认见 CapsFor。
func (Adapter) Capabilities() harness.Caps {
	return harness.Caps{
		MinVersion: MinVersion,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true, Ask: true},
			guard.EventPrompt:     {Block: true, Warn: true},
			guard.EventToolOutput: {Block: true, Replace: true},
		},
	}
}

// native 是 Parse 存进 Event.Native、CapsFor 要用的状态。
type native struct {
	Hook     string `json:"hook"`
	Approval string `json:"approval,omitempty"`
}

// CapsFor 返回这一次事件的能力：approve 指令只在会有人回答、或 Hermes 会拒绝时才算能请求确认，自动批准时
// （YOLO、approvals.mode: off、定时任务的 cron_mode: approve 等）与读不出时不算，ask 由 Engine 按
// policy.when_ask_unsupported 降级；pre_llm_call 的提示词挡不住。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps {
	caps := a.Capabilities().Events[ev.Kind]
	var n native
	_ = json.Unmarshal(ev.Native, &n)
	switch ev.Kind {
	case guard.EventAction:
		caps.Ask = n.Approval == approvalPrompt || n.Approval == approvalBlocked
	case guard.EventPrompt:
		if n.Hook != HookDispatch {
			caps.Block = false
		}
	}
	return caps
}

type toolData struct {
	ToolName   string          `json:"tool_name"`
	Args       json.RawMessage `json:"args"`
	ToolCallID string          `json:"tool_call_id"`
	Approval   string          `json:"approval"`
}

type toolArgs struct {
	Command    string  `json:"command"`
	Workdir    string  `json:"workdir"`
	Path       *string `json:"path"`
	Mode       string  `json:"mode"`
	Patch      string  `json:"patch"`
	Action     string  `json:"action"`
	Data       string  `json:"data"`
	OutputPath string  `json:"output_path"`
	Expression *string `json:"expression"`
}

type terminalData struct {
	Command string `json:"command"`
}

type promptData struct {
	Text            string `json:"text"`
	Platform        string `json:"platform"`
	ParentSessionID string `json:"parent_session_id"`
	IsBot           bool   `json:"is_bot"`
	KanbanTask      string `json:"kanban_task"`
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
	nat := native{Hook: req.Hook}
	switch req.Hook {
	case HookPreToolCall, HookToolResult:
		var d toolData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("hermes: %s data: %w", req.Hook, err)
		}
		tool := canonical(d.ToolName)
		ev.Tool, ev.CallID = tool, d.ToolCallID
		var in toolArgs
		badArgs := false
		if !extadapter.IsNull(d.Args) {
			if err := json.Unmarshal(d.Args, &in); err != nil {
				in, badArgs = toolArgs{}, true
			}
		}
		if req.Hook == HookToolResult {
			ev.Kind, ev.Text = guard.EventToolOutput, resultText(req.Result)
			ev.FileContent = fileContent(tool, in)
			break
		}
		nat.Approval = d.Approval
		ev.Kind = guard.EventAction
		ev.Native, _ = json.Marshal(nat)
		if badArgs && touches[tool] {
			// 字段类型对不上（如 command 不是字符串）：会执行命令或改文件的工具读不懂，请求确认
			return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
		}
		if tool == "terminal" {
			ev.Cwd = extadapter.Workdir(ev.Cwd, in.Workdir)
		}
		acts, err := actions(tool, in)
		switch {
		case errors.Is(err, errUnparsed):
			ev.Actions = acts
			return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
		case errors.Is(err, errUnknownTool):
			return guard.Event{}, &harness.UnknownToolError{Event: ev}
		case err != nil:
			return guard.Event{}, err
		}
		ev.Actions = acts
	case HookTerminalOutput:
		var d terminalData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("hermes: %s data: %w", req.Hook, err)
		}
		// 后台进程的输出（process_manage 的 poll、wait、log 与完成通知）：之后写进 stdin 的内容也会产生输出，
		// 看不出读没读文件，按文件内容扫描
		ev.Kind, ev.Tool, ev.Text, ev.FileContent = guard.EventToolOutput, "process_manage", resultText(req.Result), true
	case HookDispatch, HookPreLLMCall:
		var d promptData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("hermes: %s data: %w", req.Hook, err)
		}
		ev.Kind, ev.Text = guard.EventPrompt, d.Text
		ev.Requests = []guard.Request{{Text: d.Text, Source: SourceOf(d.Platform, d.ParentSessionID, d.IsBot, d.KanbanTask)}}
		ev.Native, _ = json.Marshal(nat)
	default:
		return guard.Event{}, fmt.Errorf("hermes: unsupported hook %q", req.Hook)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

// SourceOf 判定提示词的来源：子 agent（delegate_task，会话有 parent_session_id，平台为 subagent）的任务由父 agent
// 写出，定时任务（cron）的提示词在建任务时写下，webhook 的载荷来自第三方，消息平台上其他机器人发的消息，Kanban 调度器
// 启动的 worker（kanbanTask 是它认领的任务）读到的任务说明，都是自动消息；其余（CLI、TUI、Desktop、消息平台上的用户、
// API）与认不出的取值按用户本人。
func SourceOf(platform, parentSessionID string, isBot bool, kanbanTask string) guard.Source {
	switch {
	case parentSessionID != "", isBot, kanbanTask != "":
		return guard.SourceAutomated
	}
	switch strings.ToLower(platform) {
	case "subagent", "cron", "webhook", "msgraph_webhook":
		return guard.SourceAutomated
	}
	return guard.SourceUser
}

// aliases 是 Hermes 在每个分发入口接受的旧工具名（model_tools._LEGACY_TOOL_ALIASES）。
var aliases = map[string]string{"process": "process_manage", "cronjob": "cronjob_manage", "todo": "todo_list"}

func canonical(tool string) string {
	if t, ok := aliases[tool]; ok {
		return t
	}
	return tool
}

// touches 是会执行命令或代码、改动文件的工具。
var touches = map[string]bool{"terminal": true, "write_file": true, "patch": true, "execute_code": true, "process_manage": true}

// readOnly 是 Hermes 自带的、不执行命令也不改动用户文件的工具（2026.9.24 的 toolsets.TOOLSETS）：网页与 X 的搜索、
// 读图与视频的分析、媒体生成（写进 Hermes 的缓存）、skill 的查看、待办、会话搜索、提问、子 agent（子 agent 的工具调用
// 各自经过检查）、看板的协作工具、消息平台的读取与发言、Desktop 的界面工具。
// 其余自带的工具（skill_manage、memory 等写进长期记忆或 skill 的工具，computer_use，浏览器里的点击、输入与 CDP，
// 关闭终端面板的 close_terminal，安装插件或 MCP 服务器的 manage_catalog）与插件提供的工具 h-guard 不认识，请求确认；
// 用户可以在 harnesses.hermes.read_only_tools 里补充只读的工具。MCP 工具（mcp__ 开头）与连接器（connectors__ 开头）
// 与其他 harness 的 MCP 工具一样不检查。
var readOnly = map[string]bool{
	"web_search": true, "web_extract": true, "x_search": true, "vision_analyze": true, "video_analyze": true,
	"image_generate": true, "video_generate": true, "xai_video_edit": true, "xai_video_extend": true,
	"skills_list": true, "skill_view": true, "todo_list": true, "session_search": true, "clarify": true, "delegate_task": true,
	"browser_navigate": true, "browser_snapshot": true, "browser_scroll": true, "browser_back": true,
	"browser_get_images": true, "browser_vision": true,
	"kanban_show": true, "kanban_list": true, "kanban_complete": true, "kanban_block": true, "kanban_request_review": true,
	"kanban_request_changes": true, "kanban_heartbeat": true, "kanban_comment": true, "kanban_create": true,
	"kanban_link": true, "kanban_unblock": true, "kanban_attach": true, "kanban_attach_url": true, "kanban_attachments": true,
	"discord": true, "feishu_doc_read": true, "feishu_drive_list_comments": true, "feishu_drive_list_comment_replies": true,
	"feishu_drive_reply_comment": true, "feishu_drive_add_comment": true,
	"yb_query_group_info": true, "yb_query_group_members": true, "yb_send_dm": true, "yb_search_sticker": true, "yb_send_sticker": true,
	"read_terminal": true, "desktop_preview": true, "annotate_preview": true, "read_window_below": true, "focus_pane": true,
	"react_to_message": true, "gui_tour": true, "show_tip": true, "set_theme": true, "setup_beat": true,
	"tool_search": true, "tool_describe": true,
	// Home Assistant 的查询（Hermes 目录里的 homeassistant 插件；ha_call_service 会操作设备，按不认识的工具请求确认）
	"ha_list_entities": true, "ha_get_state": true, "ha_list_services": true,
}

// actions 把工具映射为动作：
//   - terminal 执行命令（Hermes 在各平台上都用 bash 兼容的 shell，Windows 上是 Git Bash），按 POSIX 命令检查；
//   - read_file、search_files 读文件，write_file 写文件；patch 的 replace 模式写 path，patch 模式按 V4A 补丁读出文件
//     （见 v4aActions）；text_to_speech 给出 output_path 时写这个文件；
//   - execute_code 运行的 Python 脚本能直接起子进程、改文件，h-guard 读不懂，请求确认；脚本里经 hermes_tools 发出的
//     工具调用另外各自经过检查；
//   - process_manage 的 write、submit 写进后台进程的 stdin，按 POSIX 命令检查并请求确认（看不出进程是 shell 还是别的
//     程序），kill、close 结束进程或关掉它的输入，按不认识的工具请求确认，其余子命令（list、poll、log、wait、handoff）
//     只读；
//   - cronjob_manage 除 list 以外都会建立或改动之后自动运行的任务（任务的 script 不经过工具调用），desktop_project 的
//     create、switch 改变工作区，manage_connections 除 status 以外会安装、启用 MCP 服务器或授权账号，
//     browser_console 带 expression 时在页面里执行 JavaScript，drive_preview 的 click、type、press、strobe 操作预览里的
//     页面：这些按不认识的工具请求确认。
func actions(tool string, in toolArgs) ([]guard.Action, error) {
	one := func(act guard.Action, ok bool) ([]guard.Action, error) {
		if !ok {
			return nil, ErrNoAction
		}
		return []guard.Action{act}, nil
	}
	path := ""
	if in.Path != nil {
		path = *in.Path
	}
	switch tool {
	case "terminal":
		return one(extadapter.Exec(in.Command, guard.ShellPOSIX))
	case "read_file":
		return one(extadapter.File(guard.ActionFileRead, path))
	case "search_files":
		if strings.TrimSpace(path) == "" {
			path = "." // 缺省或空白时是当前目录
		}
		return one(extadapter.File(guard.ActionFileRead, path))
	case "write_file":
		return one(extadapter.File(guard.ActionFileWrite, path))
	case "patch":
		switch in.Mode {
		case "", "replace":
			if act, ok := extadapter.File(guard.ActionFileWrite, path); ok {
				return []guard.Action{act}, nil
			}
		case "patch":
			return v4aActions(in.Patch)
		}
		return nil, errUnparsed
	case "text_to_speech":
		return one(extadapter.File(guard.ActionFileWrite, in.OutputPath))
	case "execute_code":
		return nil, errUnparsed
	case "process_manage":
		switch in.Action {
		case "write", "submit":
			if act, ok := extadapter.Exec(in.Data, guard.ShellPOSIX); ok {
				return []guard.Action{act}, errUnparsed
			}
			return nil, ErrNoAction
		case "list", "poll", "log", "wait", "handoff":
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	case "cronjob_manage":
		if in.Action == "list" {
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	case "desktop_project":
		if in.Action == "list" {
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	case "manage_connections":
		if in.Action == "status" {
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	case "browser_console":
		if in.Expression == nil || strings.TrimSpace(*in.Expression) == "" {
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	case "drive_preview":
		if slices.Contains([]string{"click", "type", "press", "strobe"}, in.Action) {
			return nil, errUnknownTool
		}
		return nil, ErrNoAction
	}
	if readOnly[tool] || strings.HasPrefix(tool, "mcp__") || strings.HasPrefix(tool, "connectors__") {
		return nil, ErrNoAction
	}
	return nil, errUnknownTool
}

// V4A 补丁的标记，与 Hermes 的 tools/patch_parser.py 相同：标记在行首，Begin 与 End 各占一整行；操作行的路径到行尾，
// Move File 是「源 -> 目标」。
var (
	v4aBegin = regexp.MustCompile(`^\*\*\*\s*Begin\s+Patch\s*$`)
	v4aEnd   = regexp.MustCompile(`^\*\*\*\s*End\s+Patch\s*$`)
	v4aOps   = []struct {
		kind guard.ActionKind
		re   *regexp.Regexp
	}{
		{guard.ActionFileWrite, regexp.MustCompile(`^\*\*\*\s*Update\s+File:\s*(.+)`)},
		{guard.ActionFileWrite, regexp.MustCompile(`^\*\*\*\s*Add\s+File:\s*(.+)`)},
		{guard.ActionFileDelete, regexp.MustCompile(`^\*\*\*\s*Delete\s+File:\s*(.+)`)},
		{guard.ActionFileRename, regexp.MustCompile(`^\*\*\*\s*Move\s+File:\s*(.+?)\s*->\s*(.+)`)},
	}
)

// v4aActions 按 Hermes 的解析方式读出 V4A 补丁改动的文件：解析从第一个 End Patch 之前的最后一个 Begin Patch 之后
// 开始（没有 Begin 时从头开始），到第一个 End Patch 为止，其间每个操作行是一个文件；Update、Add 写文件，Delete 删除，
// Move File 改名（源与目标都检查）。一个操作都没有、路径为空时请求确认。
func v4aActions(patch string) ([]guard.Action, error) {
	lines := strings.Split(patch, "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	start, end := -1, len(lines)
	for i, line := range lines {
		if v4aBegin.MatchString(line) {
			start = i
		} else if v4aEnd.MatchString(line) {
			end = i
			break
		}
	}
	var acts []guard.Action
	for _, line := range lines[start+1 : end] {
		for _, op := range v4aOps {
			m := op.re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			act := guard.Action{Kind: op.kind, File: &guard.FileAction{Path: strings.TrimSpace(m[1])}}
			if op.kind == guard.ActionFileRename {
				act.File.To = strings.TrimSpace(m[2])
				if act.File.To == "" {
					return acts, errUnparsed
				}
			}
			if act.File.Path == "" {
				return acts, errUnparsed
			}
			acts = append(acts, act)
			break
		}
	}
	if len(acts) == 0 {
		return nil, errUnparsed
	}
	return acts, nil
}

// fileContent 报告工具结果是不是文件内容：读文件的工具、读文件的命令，或可以原样带回文件内容的工具。
func fileContent(tool string, in toolArgs) bool {
	switch tool {
	case "read_file", "search_files", "skill_view", "session_search", "read_terminal":
		return true
	case "patch", "write_file": // 结果带着改动的 diff 或 lint 输出里的源码行
		return true
	case "execute_code": // 脚本能读文件并打印
		return true
	case "terminal":
		return command.ReadsFiles(in.Command, guard.ShellPOSIX)
	case "process_manage":
		return true
	}
	return strings.HasPrefix(tool, "mcp__") && strings.Contains(tool, "resource") // MCP 服务提供的资源（文件、文档）
}

// resultText 取出工具结果的文本。Hermes 的工具结果是字符串，通常是 JSON：能解析时取出其中的键与值（字符串原样，
// 数与布尔值按 JSON 的写法），以换行连接（JSON 里转义的换行还原后，多行的私钥等才能认出；键与数里同样可能有邮箱、
// 账号），否则原样。
func resultText(raw json.RawMessage) string {
	var r resultPayload
	if extadapter.IsNull(raw) || json.Unmarshal(raw, &r) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(r.Content, &s) != nil {
		return extadapter.Text(r.Content)
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return s
	}
	switch v.(type) {
	case map[string]any, []any:
	default:
		return s
	}
	var parts []string
	walkStrings(v, &parts)
	return strings.Join(parts, "\n")
}

// walkStrings 收集 JSON 值里的键与标量（null 不收集；Go 的 map 没有顺序，所以对象按键排序）。
func walkStrings(v any, out *[]string) {
	switch t := v.(type) {
	case string:
		*out = append(*out, t)
	case json.Number:
		*out = append(*out, t.String())
	case bool:
		*out = append(*out, fmt.Sprint(t))
	case []any:
		for _, e := range t {
			walkStrings(e, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			*out = append(*out, k)
			walkStrings(t[k], out)
		}
	}
}

// RenderNoAction 对不产生动作的工具调用回复放行（harness.NoActionRenderer）。
func (Adapter) RenderNoAction() ([]byte, int) {
	return extadapter.Render(guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionPass}}), 0
}

// reply 是扩展接入协议的回复，另加可选的 notify：插件把说明发到消息渠道（目标为空时发到来源会话所在的对话）。
type reply struct {
	extproto.Reply
	Notify *notify `json:"notify,omitempty"`
}

type notify struct {
	To string `json:"to,omitempty"`
}

// Render 渲染扩展接入协议的回复，pass 也有回复；配置了通知且结论（降级前或降级后）在 harnesses.hermes.notify.on
// 里时带上 notify。
func (a Adapter) Render(_ guard.Event, out guard.Outcome) ([]byte, int) {
	b := extadapter.Render(out)
	d := out.Verdict.Decision
	if d == guard.DecisionPass || a.notifyOn&(decisionBit(d)|decisionBit(out.Raw)) == 0 {
		return b, 0
	}
	var r reply
	if json.Unmarshal(b, &r.Reply) != nil {
		return b, 0
	}
	r.Notify = &notify{To: a.notifyTo}
	nb, err := json.Marshal(r)
	if err != nil {
		return b, 0
	}
	return nb, 0
}

// Package pi 是 pi（pi coding agent）与 oh-my-pi（omp，pi 的分支）的 adapter。两者的扩展 API 相同：h-guard 的
// 扩展在 tool_call、tool_result 与 input 三个事件里按扩展接入协议 v1 把事件交给 h-guard hook pi（或 omp），再把
// 回复翻译成扩展的返回值（block、替换 content、handled）与界面上的确认和提示。
//
// 请求的 data 是事件本身：tool_call 为 {toolCallId, toolName, input}；tool_result 为 {toolCallId, toolName, input,
// isError}，result 是 {content}；input 为 {text, source}。omp 只在交互界面与 RPC 模式里触发 input，扩展在每次请求模型
// 之前的 context 事件里补查其余的提示词，同样以 input 发来（source 为 context）。
//
// 导入本包即注册名为 pi 与 omp 的 adapter。
package pi

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/applypatch"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/extadapter"
)

// Name、OMPName 是 adapter 名，也是扩展请求中的 harness 字段。
const (
	Name    = "pi"
	OMPName = "omp"
)

// MinVersion、OMPMinVersion 是扩展按其源码编写的版本。
const (
	MinVersion    = "1.3.0"
	OMPMinVersion = "18.11.3"
)

// ErrNoAction 表示这次工具调用不产生动作（ls、find、MCP 等只读工具，或输入里没有可检查的内容），扩展照常放行。
var ErrNoAction = fmt.Errorf("pi: %w", harness.ErrNoAction)

// errUnknownTool 表示 h-guard 不认识的工具（Parse 返回 *harness.UnknownToolError）。
var errUnknownTool = errors.New("pi: the tool is not known")

// errUnparsed 表示会执行代码或改文件的工具调用，目标读不懂。
var errUnparsed = errors.New("pi: the tool's target cannot be parsed")

// Pi 与 OMP 是两个 adapter。
var (
	Pi  = Adapter{}
	OMP = Adapter{omp: true}
)

func init() {
	for _, a := range []Adapter{Pi, OMP} {
		if err := harness.Register(a); err != nil {
			panic(err)
		}
	}
}

// Adapter 是 pi 或 omp 的 adapter，无状态。
type Adapter struct {
	omp bool
}

func (a Adapter) Name() string {
	if a.omp {
		return OMPName
	}
	return Name
}

// Capabilities：tool_call 返回 block 能阻止工具调用（模型读到说明），扩展用 ctx.ui.confirm 请求确认（没有界面时
// 拒绝，属于安全方向），用 ctx.ui.notify 提示；input 返回 handled 能丢弃提示词；tool_result 返回 content 能替换
// 模型看到的结果。
func (a Adapter) Capabilities() harness.Caps {
	v := MinVersion
	if a.omp {
		v = OMPMinVersion
	}
	return harness.Caps{
		MinVersion: v,
		Events: map[guard.EventKind]harness.EventCaps{
			guard.EventAction:     {Block: true, Ask: true, Warn: true},
			guard.EventPrompt:     {Block: true, Warn: true},
			guard.EventToolOutput: {Block: true, Warn: true, Replace: true},
		},
	}
}

// CapsFor 返回事件类型的能力。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

type toolData struct {
	ToolCallID string          `json:"toolCallId"`
	ToolName   string          `json:"toolName"`
	Input      json.RawMessage `json:"input"`
}

type toolInput struct {
	Command string   `json:"command"`
	Cwd     string   `json:"cwd"` // omp 的 bash
	Path    string   `json:"path"`
	Paths   []string `json:"paths"` // omp 的 edit（由 hashline 补丁头派生）、ast_edit
	Input   string   `json:"input"` // omp 的 edit：hashline 或 apply_patch 形式的补丁
	// omp 的 edit 在 patch 模式下：每项可以删除（op: delete）或改名（rename）顶层 path 的文件
	Edits []struct {
		Op     string `json:"op"`
		Rename string `json:"rename"`
	} `json:"edits"`
	// omp 的 lsp
	Action  string `json:"action"`
	File    string `json:"file"`
	NewName string `json:"new_name"`
	Apply   *bool  `json:"apply"`
}

type inputData struct {
	Text   string `json:"text"`
	Source string `json:"source"`
}

type resultPayload struct {
	Content json.RawMessage `json:"content"`
}

// Parse 解析扩展转交的请求。
func (a Adapter) Parse(raw []byte) (guard.Event, error) {
	req, err := extadapter.Request(raw, a.Name())
	if err != nil {
		return guard.Event{}, err
	}
	ev := guard.Event{Harness: a.Name(), SessionID: req.Session.ID, Cwd: req.Session.Cwd}
	switch req.Hook {
	case "tool_call", "tool_result":
		var d toolData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("%s: %s data: %w", a.Name(), req.Hook, err)
		}
		var in toolInput
		if !extadapter.IsNull(d.Input) {
			// 字段类型对不上（如 paths 不是字符串数组）时按读不懂处理：会执行命令或改文件的工具请求确认
			if err := json.Unmarshal(d.Input, &in); err != nil {
				in = toolInput{}
				if req.Hook == "tool_call" && a.touches(d.ToolName) {
					ev.Kind, ev.Tool, ev.CallID = guard.EventAction, d.ToolName, d.ToolCallID
					return guard.Event{}, &harness.TargetUnparsedError{Event: ev}
				}
			}
		}
		ev.Tool, ev.CallID = d.ToolName, d.ToolCallID
		if req.Hook == "tool_result" {
			var r resultPayload
			if !extadapter.IsNull(req.Result) {
				if err := json.Unmarshal(req.Result, &r); err != nil {
					return guard.Event{}, fmt.Errorf("%s: tool_result result: %w", a.Name(), err)
				}
			}
			ev.Kind, ev.Text = guard.EventToolOutput, extadapter.Text(r.Content)
			ev.FileContent = a.fileContent(d.ToolName, in)
			break
		}
		ev.Kind = guard.EventAction
		if a.omp && d.ToolName == "bash" {
			ev.Cwd = extadapter.Workdir(ev.Cwd, in.Cwd)
		}
		acts, err := a.actions(d.ToolName, in)
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
	case "input":
		var d inputData
		if err := json.Unmarshal(req.Data, &d); err != nil {
			return guard.Event{}, fmt.Errorf("%s: input data: %w", a.Name(), err)
		}
		ev.Kind, ev.Text = guard.EventPrompt, d.Text
		ev.Requests = []guard.Request{{Text: d.Text, Source: SourceOf(d.Source)}}
	default:
		return guard.Event{}, fmt.Errorf("%s: unsupported hook %q", a.Name(), req.Hook)
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

// SourceOf 按 input 事件的 source 判定指令来源：extension 是扩展用 sendUserMessage 发出的消息，subagent 是扩展在 omp
// 的子 agent 会话（ctx.agent.kind 为 sub）里看到的消息，都是自动消息；interactive、rpc、
// context（omp 的扩展在 context 事件里补查的提示词）与认不出的取值按用户本人（pi 的 -p 与 SDK 的提示词也报告为 interactive）。
func SourceOf(source string) guard.Source {
	if source == "extension" || source == "subagent" {
		return guard.SourceAutomated
	}
	return guard.SourceUser
}

// touches 报告工具是否会执行命令或代码、改动文件。
func (a Adapter) touches(tool string) bool {
	switch tool {
	case "bash", "powershell", "write", "edit":
		return true
	case "eval", "ast_edit", "apply_patch", "lsp":
		return a.omp
	}
	return false
}

// actions 把工具映射为动作：
//   - bash（omp 的 bash 在任何平台上都是 bash 兼容的 shell；pi 在 Windows 上用 Git Bash）执行 POSIX 命令，pi 在 Windows
//     上的 powershell 工具执行 PowerShell 命令；
//   - read、grep 读文件，write、edit 写文件；
//   - omp 的 edit（及 apply_patch 模式下的 apply_patch）是补丁时读出补丁头里的文件（REM 删除、MV 改名），patch 模式的
//     各项可以删除或改名；ast_edit 写 paths 里的文件；lsp 见 ompLSP；omp 的 eval 执行 Python 或 JavaScript 代码，
//     h-guard 读不懂，请求确认（errUnparsed）。
//
// pi 的 ls、find 与 MCP 工具不产生动作，其余工具见 piReadOnly；omp 见 ompReadOnly。
func (a Adapter) actions(tool string, in toolInput) ([]guard.Action, error) {
	one := func(act guard.Action, ok bool) ([]guard.Action, error) {
		if !ok {
			return nil, ErrNoAction
		}
		return []guard.Action{act}, nil
	}
	switch tool {
	case "bash":
		return one(extadapter.Exec(in.Command, guard.ShellPOSIX))
	case "powershell":
		return one(extadapter.Exec(in.Command, guard.ShellPowerShell))
	case "read":
		p := in.Path
		if a.omp {
			p = stripSelector(p)
			if b, ok := containerFile(p); ok {
				p = b
			}
		}
		return one(extadapter.File(guard.ActionFileRead, p))
	case "grep", "search": // search 是 omp 的 grep 的旧名
		return one(extadapter.File(guard.ActionFileRead, in.Path))
	case "write":
		if !a.omp {
			return one(extadapter.File(guard.ActionFileWrite, in.Path))
		}
		p, err := ompWriteTarget(in.Path)
		if err != nil {
			return nil, err
		}
		return one(extadapter.File(guard.ActionFileWrite, p))
	case "edit":
		if !a.omp {
			return one(extadapter.File(guard.ActionFileWrite, in.Path))
		}
		return ompEdit(in)
	case "apply_patch": // omp 的 apply_patch 模式：工具在调用里以这个名字出现
		if a.omp {
			return ompEdit(in)
		}
	case "lsp":
		if a.omp {
			return ompLSP(in)
		}
	}
	if !a.omp {
		if piReadOnly[tool] || strings.HasPrefix(tool, "mcp__") {
			return nil, ErrNoAction
		}
		return nil, errUnknownTool
	}
	switch tool {
	case "ast_edit":
		var acts []guard.Action
		for _, p := range in.Paths {
			if act, ok := extadapter.File(guard.ActionFileWrite, p); ok {
				acts = append(acts, act)
			}
		}
		if len(acts) == 0 {
			return nil, errUnparsed
		}
		return acts, nil
	case "eval":
		return nil, errUnparsed
	}
	if ompReadOnly[tool] || strings.HasPrefix(tool, "mcp__") {
		return nil, ErrNoAction
	}
	return nil, errUnknownTool
}

// piReadOnly 是 pi 自带的只读工具（pi 1.3.0 自带 read、bash、edit、write、grep、find、ls，Windows 上另有 powershell）。
// 扩展与 SDK 用 registerTool 添加的工具 h-guard 不认识，请求确认；用户可以在 harnesses.pi.read_only_tools 里补充只读的工具。
var piReadOnly = map[string]bool{"find": true, "ls": true}

// ompReadOnly 是 omp 自带的、不执行命令也不改动用户文件的工具（omp 18.11.3 的 BUILTIN_TOOL_NAMES 与 HIDDEN_TOOL_NAMES）：
// 搜索与查询、提问、子 agent 与等待（子 agent 的工具调用各自经过检查）、待办、上下文与检查点、长期记忆的查询、安全扫描。
// 其余 omp 自带的工具（debug、ida、github、写长期记忆的 retain、memory_edit、learn、manage_skill）与扩展提供的工具 h-guard 不认识，请求确认；
// 用户可以在 harnesses.omp.read_only_tools 里补充只读的工具。MCP 工具（mcp__ 开头）与其他 harness 一样不检查。
var ompReadOnly = map[string]bool{
	"ast_grep": true, "ask": true, "glob": true, "find": true, "task": true, "wait": true, "todo": true,
	"web_search": true, "checkpoint": true, "rewind": true, "context_notes": true, "new_context": true,
	"security_scan": true, "recall": true, "reflect": true,
	"yield": true, "goal": true, "think": true,
}

// ompEdit 读出 omp 的 edit 改动的文件。替换形式直接给出 path；补丁形式（hashline）的文件在 [路径#标签] 补丁头里，
// 段内的 REM 删除这个文件、MV <目标> 把它改名；apply_patch 模式的补丁按 apply_patch 的格式读。补丁里读不出文件时，用 omp 派生的 path、paths；都没有时请求确认。
func ompEdit(in toolInput) ([]guard.Action, error) {
	if strings.TrimSpace(in.Input) == "" {
		act, ok := extadapter.File(guard.ActionFileWrite, in.Path)
		if !ok {
			return nil, errUnparsed
		}
		// patch 模式：删除与改名（目标同样检查）按各项给出
		for _, e := range in.Edits {
			switch {
			case strings.TrimSpace(e.Rename) != "":
				act.Kind, act.File.To = guard.ActionFileRename, e.Rename
			case e.Op == "delete" && act.Kind == guard.ActionFileWrite:
				act.Kind = guard.ActionFileDelete
			}
		}
		return []guard.Action{act}, nil
	}
	// hashline 的段头 [路径#标签] 优先：严格语法下 hashline 补丁同样包在 *** Begin Patch / *** End Patch 里
	var acts []guard.Action
	for _, line := range strings.Split(strings.TrimPrefix(in.Input, "\ufeff"), "\n") {
		line = strings.TrimRight(line, "\r")
		if p, ok := hashlineHeader(line); ok {
			acts = append(acts, guard.Action{Kind: guard.ActionFileWrite, File: &guard.FileAction{Path: p}})
			continue
		}
		if len(acts) == 0 {
			continue
		}
		last := &acts[len(acts)-1]
		switch t := strings.TrimSpace(line); {
		case t == "REM":
			last.Kind = guard.ActionFileDelete
		case strings.HasPrefix(t, "MV "):
			last.Kind, last.File.To = guard.ActionFileRename, unquote(strings.TrimSpace(t[3:]))
		}
	}
	if len(acts) > 0 {
		return acts, nil
	}
	if strings.Contains(in.Input, applypatch.BeginPatch) { // apply_patch 模式
		acts, err := applypatch.Actions(in.Input)
		if err != nil {
			return nil, errUnparsed
		}
		return acts, nil
	}
	for _, p := range append([]string{in.Path}, in.Paths...) {
		if act, ok := extadapter.File(guard.ActionFileWrite, p); ok {
			acts = append(acts, act)
		}
	}
	if len(acts) == 0 {
		return nil, errUnparsed
	}
	return acts, nil
}

// ompLSP 读出 omp 的 lsp 改动的文件：rename_file 把 file 改名为 new_name；rename（除非 apply 为 false）、
// 应用的 code_actions 与原始的 request 会改动不知道有哪些的文件，按 file 写文件并请求确认（errUnparsed）。
// 其余动作（诊断、跳转、符号、状态等）只读，不产生动作。
func ompLSP(in toolInput) ([]guard.Action, error) {
	applied := in.Apply == nil || *in.Apply
	var acts []guard.Action
	if act, ok := extadapter.File(guard.ActionFileWrite, in.File); ok && in.File != "*" {
		acts = append(acts, act)
	}
	switch in.Action {
	case "rename_file":
		if !applied {
			return nil, ErrNoAction
		}
		if len(acts) == 0 || strings.TrimSpace(in.NewName) == "" {
			return nil, errUnparsed
		}
		acts[0].Kind, acts[0].File.To = guard.ActionFileRename, in.NewName
		return acts, errUnparsed // 引用它的文件同样会被改动
	case "rename":
		if !applied {
			return nil, ErrNoAction
		}
		return acts, errUnparsed
	case "code_actions":
		if in.Apply == nil || !*in.Apply {
			return nil, ErrNoAction
		}
		return acts, errUnparsed
	case "request":
		return acts, errUnparsed
	}
	return nil, ErrNoAction
}

// ompWriteTarget 返回 omp 的 write 实际改动的文件：复制来的 [路径#标签] 外壳去掉；归档里的条目（a.zip:inner）与 SQLite
// 的行（app.sqlite:users:42）是对所在文件的改写；xd://reject 不改动文件（ErrNoAction）；xd://resolve（应用 ast_edit 等预览
// 过的改动）、其余 xd:// 设备、conflict://、结束进程的 proc://<id>/kill 与其他内部 URL 请求确认（errUnparsed）。
func ompWriteTarget(p string) (string, error) {
	if h, ok := hashlineHeader(strings.TrimSpace(p)); ok {
		p = h
	}
	if i := strings.Index(p, "://"); i > 0 && !strings.ContainsAny(p[:i], `/\.`) {
		scheme, rest := strings.ToLower(p[:i]), p[i+3:]
		if scheme == "xd" && rest == "reject" {
			return "", ErrNoAction
		}
		return "", errUnparsed
	}
	if b, ok := containerFile(p); ok {
		return b, nil
	}
	return p, nil
}

// containerExt 是 omp 能以「文件:内部路径」读写的容器：归档与 SQLite 数据库。
var containerExt = regexp.MustCompile(`(?i)\.(zip|jar|war|ear|apk|aar|ipa|xpi|nupkg|whl|tar|tar\.gz|tgz|tar\.zst|tzst|asar|sqlite|sqlite3|db)$`)

// containerFile 返回「容器文件:内部路径」里的容器文件；盘符的冒号不算。
func containerFile(p string) (string, bool) {
	for i := 2; i < len(p); i++ {
		if p[i] == ':' && containerExt.MatchString(p[:i]) {
			return p[:i], true
		}
	}
	return "", false
}

var hashlineTag = regexp.MustCompile(`#[0-9a-fA-F]{4}$`)

// hashlineHeader 读出 hashline 补丁头 [路径#标签]（旧写法 ¶路径#标签）里的路径。
func hashlineHeader(line string) (string, bool) {
	var body string
	switch t := strings.TrimLeft(line, " \t"); {
	case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
		body = line[1 : len(line)-1]
	case strings.HasPrefix(t, "¶"):
		body = strings.TrimLeft(t, "¶")
	default:
		return "", false
	}
	body = strings.TrimSpace(body)
	if loc := hashlineTag.FindStringIndex(body); loc != nil {
		body = body[:loc[0]]
	}
	body = unquote(body)
	return body, body != ""
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// readSelector 是 omp 的 read 写在路径末尾的选择：行（:10-20、:-5、:3,8-9、:5+3）、:raw、:conflicts，可以连着写
// （:1-20:raw、:raw:1-20）。盘符的冒号不算。
var readSelector = regexp.MustCompile(`(?i):(?:[-+0-9,]+|raw|conflicts)$`)

func stripSelector(p string) string {
	for {
		loc := readSelector.FindStringIndex(p)
		if loc == nil || loc[0] <= 1 {
			return p
		}
		p = p[:loc[0]]
	}
}

// fileContent 报告工具结果是不是文件内容：读文件的工具，或读文件的命令。
func (a Adapter) fileContent(tool string, in toolInput) bool {
	switch tool {
	case "read", "grep", "search": // search 是 omp 的 grep 的旧名
		return true
	case "bash":
		return command.ReadsFiles(in.Command, guard.ShellPOSIX)
	case "powershell":
		return command.ReadsFiles(in.Command, guard.ShellPowerShell)
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

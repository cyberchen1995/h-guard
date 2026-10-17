// Package harness 定义 harness 适配接口与能力声明。
package harness

import "github.com/cyberchen1995/h-guard/pkg/guard"

// TargetUnparsedError 表示已知会改动文件或执行命令的工具调用，目标无法解析（如 patch 格式不认识）。Parse 以
// *TargetUnparsedError 返回；Event 尽量填好 Harness、SessionID、Cwd、Tool 等字段，并带上能读出的动作（如命令本身；
// 可以没有）。调用方照常检查这些动作，另外请求确认，原因写明无法解析，带 target_unparsed；两者聚合，
// 读不懂的部分不能让读得出的命中变宽。Event 没有填也不会放行。
type TargetUnparsedError struct {
	Event guard.Event
}

func (*TargetUnparsedError) Error() string { return "harness: the tool's target cannot be parsed" }

// ShellDefaulter 由标不出 shell 的 adapter 实现（如 Codex）。WithShell 返回一个副本，
// 它把解析出的 exec 动作的 shell 设为 s；调用方按配置 harnesses.<name>.shell 传入。副本同样不保存其他状态。
type ShellDefaulter interface {
	WithShell(s guard.Shell) Adapter
}

// EventCaps 是 harness 在某类事件上能做到的事。
type EventCaps struct {
	Block   bool `json:"block"`   // 能阻止执行、提交或输出进入上下文
	Ask     bool `json:"ask"`     // 能请求用户确认
	Warn    bool `json:"warn"`    // 能向用户或模型展示提示
	Replace bool `json:"replace"` // ToolOutput：能可靠地让说明内容代替原结果进入模型上下文（协议由 adapter 决定）
}

// Caps 是 harness 的能力声明。
type Caps struct {
	MinVersion string                        `json:"min_version"` // 已验证的最低 harness 版本
	Events     map[guard.EventKind]EventCaps `json:"events"`
}

// Adapter 把 harness 的 hook 输入解析为统一事件，并把结论渲染回 harness 的格式。
// 实现不得保存状态：Parse 与 Render 可能被并发调用，结果只取决于参数。
type Adapter interface {
	Name() string
	Capabilities() Caps
	// Parse 解析 hook 的 stdin。读不懂的输入返回错误，调用方据此不输出任何内容。
	// 渲染时需要的原始信息（如工具输出的原始结构）存入 Event.Native。
	Parse(raw []byte) (guard.Event, error)
	// CapsFor 返回这一次事件的实际能力（如这一次的工具结果能否被扣下或替换），不得超过
	// Capabilities 中该事件类型的声明。Engine 在生成 Outcome 之前调用它，据此完成全部降级。
	CapsFor(ev guard.Event) EventCaps
	// Render 把结论渲染为 hook 的 stdout 与退出码，只渲染、不再降级。
	// CapsFor(ev).Replace 为真时，必须让说明内容代替原结果进入上下文：
	// Claude Code 回复 deny，由 mod 在工具执行后扣下结果；Codex 用 PostToolUse 的 block 反馈。
	Render(ev guard.Event, out guard.Outcome) (stdout []byte, exitCode int)
}

// TranscriptReader 由能从 transcript 回退读取用户指令的 adapter 实现。
type TranscriptReader interface {
	ReadRequests(path string, limit int) ([]guard.Request, error)
}

// ParseFailureRenderer 由要求「始终有输出」的 adapter 实现（generic 契约）：Parse 返回错误时，调用方
// 输出 RenderParseFailure 的结果并以它的退出码退出，而不是什么都不输出。
type ParseFailureRenderer interface {
	RenderParseFailure() (stdout []byte, exitCode int)
}

// Package generic 实现 generic 契约 v1（spec §7.4）：没有专用 adapter 的 harness 或脚本，按这个 JSON 契约
// 调用 h-guard hook generic --event <事件>，自己把 decision 翻译成 harness 的行为。
//
// 导入本包即注册名为 generic 的 adapter。
package generic

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// Name 是 adapter 名。
const Name = "generic"

// Version 是契约版本：新增可选字段不升版本，改变已有字段的语义才升（spec §14）。
const Version = 1

func init() {
	if err := harness.Register(Adapter{}); err != nil {
		panic(err)
	}
}

// Adapter 是 generic 契约的 adapter，无状态。
type Adapter struct{}

func (Adapter) Name() string { return Name }

// Capabilities：调用方按 decision 自行处理，所以三类事件都声明能阻止、确认与提示；工具输出的 deny 由调用方
// 用 reason 代替原输出（Replace）。调用方做不到时应按 raw_decision 与自己的能力处理。MinVersion 是契约版本。
func (Adapter) Capabilities() harness.Caps {
	all := harness.EventCaps{Block: true, Ask: true, Warn: true}
	out := all
	out.Replace = true
	return harness.Caps{
		MinVersion: fmt.Sprint(Version),
		Events:     map[guard.EventKind]harness.EventCaps{guard.EventAction: all, guard.EventPrompt: all, guard.EventToolOutput: out},
	}
}

// CapsFor 返回事件类型的能力。
func (a Adapter) CapsFor(ev guard.Event) harness.EventCaps { return a.Capabilities().Events[ev.Kind] }

type input struct {
	Version   *int      `json:"version"`
	Kind      string    `json:"kind"`
	Actions   []action  `json:"actions"`
	Text      string    `json:"text"`
	Tool      string    `json:"tool"`
	Cwd       string    `json:"cwd"`
	Requests  []request `json:"requests"`
	SessionID string    `json:"session_id"`
	CallID    string    `json:"call_id"`
}

type action struct {
	Kind    string `json:"kind"`
	Command string `json:"command"`
	Shell   string `json:"shell"`
	Path    string `json:"path"`
	To      string `json:"to"`
}

type request struct {
	Text   string `json:"text"`
	Source string `json:"source"`
}

var kinds = map[string]guard.EventKind{"action": guard.EventAction, "prompt": guard.EventPrompt, "tool_output": guard.EventToolOutput}

var fileKinds = map[string]guard.ActionKind{
	"file_read": guard.ActionFileRead, "file_write": guard.ActionFileWrite, "file_delete": guard.ActionFileDelete, "file_rename": guard.ActionFileRename,
}

// Parse 解析契约 v1 的输入。不认识的字段忽略（新增可选字段不升版本）；版本、事件类型、动作类型与来源不认识，
// 或文件动作是相对路径而没有 cwd 时返回错误。exec 不写 shell 时为 posix；requests 不写 source 时为 user；提示词没有给 requests 时，提示词本身是
// 一条用户指令。
func (Adapter) Parse(raw []byte) (guard.Event, error) {
	var in input
	if err := json.Unmarshal(raw, &in); err != nil {
		return guard.Event{}, fmt.Errorf("generic: %w", err)
	}
	if in.Version == nil || *in.Version != Version {
		return guard.Event{}, errors.New("generic: version must be 1")
	}
	kind, ok := kinds[in.Kind]
	if !ok {
		return guard.Event{}, fmt.Errorf("generic: unknown kind %q", in.Kind)
	}
	ev := guard.Event{Kind: kind, Harness: Name, SessionID: in.SessionID, CallID: in.CallID, Cwd: in.Cwd, Tool: in.Tool}
	for i, a := range in.Actions {
		act, err := toAction(a)
		if err == nil && act.File != nil && in.Cwd == "" && (relative(act.File.Path) || (act.File.To != "" && relative(act.File.To))) {
			err = errors.New("relative path without cwd") // 不知道相对于哪里，就无法按路径规则检查
		}
		if err != nil {
			return guard.Event{}, fmt.Errorf("generic: action %d: %w", i, err)
		}
		ev.Actions = append(ev.Actions, act)
	}
	if kind != guard.EventAction {
		ev.Text = in.Text
	}
	for _, r := range in.Requests {
		src := guard.Source(r.Source)
		if r.Source == "" {
			src = guard.SourceUser
		}
		ev.Requests = append(ev.Requests, guard.Request{Text: r.Text, Source: src})
	}
	if kind == guard.EventPrompt && len(ev.Requests) == 0 {
		ev.Requests = []guard.Request{{Text: in.Text, Source: guard.SourceUser}}
	}
	if err := ev.Validate(); err != nil {
		return guard.Event{}, err
	}
	return ev, nil
}

func toAction(a action) (guard.Action, error) {
	if a.Kind == "exec" {
		shell := guard.Shell(a.Shell)
		if a.Shell == "" {
			shell = guard.ShellPOSIX
		}
		return guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: a.Command, Shell: shell}}, nil
	}
	k, ok := fileKinds[a.Kind]
	if !ok {
		return guard.Action{}, fmt.Errorf("unsupported kind %q", a.Kind)
	}
	if strings.TrimSpace(a.Path) == "" {
		return guard.Action{}, errors.New("file action needs a path")
	}
	return guard.Action{Kind: k, File: &guard.FileAction{Path: a.Path, To: a.To}}, nil
}

// relative 报告路径是否相对于 cwd（不以 /、~、盘符或 \\ 开头）。
func relative(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, `\\`) {
		return false
	}
	return !(len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

type output struct {
	Version     int             `json:"version"`
	Decision    guard.Decision  `json:"decision,omitempty"`
	RawDecision guard.Decision  `json:"raw_decision,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	Hint        string          `json:"hint,omitempty"`
	Reasons     []guard.Reason  `json:"reasons,omitempty"`
	Findings    []guard.Finding `json:"findings,omitempty"`
	Signals     map[string]any  `json:"signals,omitempty"`
	Fallbacks   []string        `json:"fallbacks,omitempty"`
	Error       string          `json:"error,omitempty"`
}

// Render 输出契约 v1 的 JSON，pass 也输出；退出码 0 表示结论有效（spec §7.4）。
func (Adapter) Render(_ guard.Event, out guard.Outcome) ([]byte, int) {
	b, _ := json.Marshal(output{
		Version: Version, Decision: out.Verdict.Decision, RawDecision: out.Raw, Reason: out.Message, Hint: out.Hint,
		Reasons: out.Verdict.Reasons, Findings: out.Verdict.Findings, Signals: out.Verdict.Signals, Fallbacks: out.Verdict.Fallbacks,
	})
	return b, 0
}

// RenderParseFailure：读不懂的输入输出固定的错误说明（不含输入内容）与退出码 1，表示 h-guard 没有给出结论，
// 由调用方决定如何处理（harness.ParseFailureRenderer）。
func (Adapter) RenderParseFailure() ([]byte, int) {
	b, _ := json.Marshal(output{Version: Version, Error: "input not understood"})
	return b, 1
}

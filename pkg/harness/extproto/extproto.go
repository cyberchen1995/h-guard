// Package extproto 定义扩展接入协议 v1：harness 进程内的薄扩展与 h-guard 二进制之间的请求与回复。
// 扩展只转交 harness 的原始事件；harness 特有字段由对应 adapter 解析。
package extproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Protocol 是协议标识，请求与回复都带它。新增可选字段不改它，改变已有字段的语义才升版本。
const Protocol = "h-guard.ext/v1"

// Session 是 harness 会话。
type Session struct {
	ID  string `json:"id"`
	Cwd string `json:"cwd"`
}

// Request 是扩展发给 h-guard 的请求（stdin）。
type Request struct {
	Protocol       string          `json:"protocol"`
	Harness        string          `json:"harness"`
	HarnessVersion json.RawMessage `json:"harness_version,omitempty"` // harness 报告的版本，原样转交
	Hook           string          `json:"hook"`
	Session        Session         `json:"session"`
	Data           json.RawMessage `json:"data"`              // harness 的原始事件
	Decided        string          `json:"decided,omitempty"` // 权限决定类 hook：harness 在 h-guard 之前得出的决定
	Result         json.RawMessage `json:"result,omitempty"`  // 工具结果类 hook：工具结果
}

// Action 是回复的动作。
type Action string

const (
	ActionPass Action = "pass"
	ActionDeny Action = "deny"
	ActionAsk  Action = "ask"
	ActionWarn Action = "warn"
)

// Valid 报告 a 是否为已知动作。协议里没有 allow：h-guard 只收紧不放宽。
func (a Action) Valid() bool {
	switch a {
	case ActionPass, ActionDeny, ActionAsk, ActionWarn:
		return true
	}
	return false
}

// Reply 是 h-guard 的回复（stdout）。Message、Hint 已本地化。
type Reply struct {
	Protocol string `json:"protocol"`
	Action   Action `json:"action"`
	Message  string `json:"message,omitempty"`
	Hint     string `json:"hint,omitempty"`
}

// NewReply 返回已填好协议标识的回复。
func NewReply(a Action, message, hint string) Reply {
	return Reply{Protocol: Protocol, Action: a, Message: message, Hint: hint}
}

// ParseRequest 解析请求并检查通用字段。
func ParseRequest(b []byte) (Request, error) {
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return Request{}, fmt.Errorf("extproto: %w", err)
	}
	switch {
	case r.Protocol != Protocol:
		return Request{}, fmt.Errorf("extproto: protocol %q, want %q", r.Protocol, Protocol)
	case !guard.ValidName(r.Harness):
		return Request{}, fmt.Errorf("extproto: invalid harness %q", r.Harness)
	case r.Hook == "":
		return Request{}, errors.New("extproto: hook is empty")
	case r.Session.ID == "":
		return Request{}, errors.New("extproto: session id is empty")
	case len(r.Data) == 0 || string(r.Data) == "null":
		return Request{}, errors.New("extproto: data is missing")
	}
	return r, nil
}

// ParseReply 解析回复并检查协议标识与动作。
func ParseReply(b []byte) (Reply, error) {
	var r Reply
	if err := json.Unmarshal(b, &r); err != nil {
		return Reply{}, fmt.Errorf("extproto: %w", err)
	}
	if r.Protocol != Protocol {
		return Reply{}, fmt.Errorf("extproto: protocol %q, want %q", r.Protocol, Protocol)
	}
	if !r.Action.Valid() {
		return Reply{}, fmt.Errorf("extproto: unknown action %q", r.Action)
	}
	// 非 pass 的回复必须带说明。扩展仍须在说明缺失时自行兜底，不能因此放宽。
	if r.Action != ActionPass && strings.TrimSpace(r.Message) == "" {
		return Reply{}, fmt.Errorf("extproto: %s reply needs a message", r.Action)
	}
	return r, nil
}

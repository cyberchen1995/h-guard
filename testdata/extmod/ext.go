// Package hguardext 是一个独立 module，验证第三方只靠 pkg/ 就能实现并注册 adapter、Check 与后端。
package hguardext

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// EchoAdapter 的输入格式：{"command": "..."}。
type EchoAdapter struct{}

func (EchoAdapter) Name() string { return "echo" }

func (EchoAdapter) Capabilities() harness.Caps {
	return harness.Caps{MinVersion: "1.0.0", Events: map[guard.EventKind]harness.EventCaps{
		guard.EventAction: {Block: true},
	}}
}

func (EchoAdapter) Parse(raw []byte) (guard.Event, error) {
	var in struct {
		Command *string `json:"command"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return guard.Event{}, err
	}
	if in.Command == nil {
		return guard.Event{}, errors.New("missing command")
	}
	return guard.Event{Kind: guard.EventAction, Harness: "echo", Actions: []guard.Action{
		{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: *in.Command, Shell: guard.ShellPOSIX}},
	}}, nil
}

func (a EchoAdapter) CapsFor(ev guard.Event) harness.EventCaps {
	return a.Capabilities().Events[ev.Kind]
}

func (EchoAdapter) Render(_ guard.Event, out guard.Outcome) ([]byte, int) {
	if out.Verdict.Decision == guard.DecisionPass {
		return nil, 0
	}
	b, _ := json.Marshal(map[string]string{"decision": string(out.Verdict.Decision), "reason": out.Message})
	return b, 0
}

// KeywordCheck 在命令含 Keyword 时给出 deny。
type KeywordCheck struct{ Keyword string }

func (KeywordCheck) Name() string { return "ext.keyword" }

func (KeywordCheck) Applies(ev guard.Event) bool { return ev.Kind == guard.EventAction }

func (c KeywordCheck) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	if err := ctx.Err(); err != nil {
		return guard.Verdict{Decision: guard.DecisionPass}, err
	}
	for _, a := range ev.Actions {
		if a.Exec != nil && strings.Contains(a.Exec.Command, c.Keyword) {
			deny := guard.Verdict{
				Decision: guard.DecisionDeny,
				Reasons:  []guard.Reason{{Code: "ext.keyword", Params: map[string]string{"keyword": c.Keyword}}},
			}
			commit(deny)
			return deny, nil
		}
	}
	return guard.Verdict{Decision: guard.DecisionPass}, nil
}

// ConstBackend 对每道题都回答固定概率。
type ConstBackend struct{ P float64 }

func (ConstBackend) Name() string { return "const" }

// Caps 用自己的取答方式名：内置的 judge.Mechanism 常量都不合适时，第三方后端可以自定。
// 不声明 Kinds（nil）表示两种题型都能回答。
func (ConstBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: "constant"}
}

func (b ConstBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: make(map[string]judge.Answer, len(qs))}
	for _, q := range qs {
		resp.Answers[q.ID] = judge.Answer{P: judge.Prob(b.P)}
	}
	return resp, nil
}

var (
	registerOnce sync.Once
	registerErr  error
)

// Register 注册本 module 的全部扩展；重复调用只注册一次。
func Register() error {
	registerOnce.Do(func() {
		if registerErr = harness.Register(EchoAdapter{}); registerErr != nil {
			return
		}
		if registerErr = guard.RegisterCheck(KeywordCheck{Keyword: "rm -rf /"}); registerErr != nil {
			return
		}
		registerErr = judge.RegisterType("const", func(_ string, decode func(any) error) (judge.Backend, error) {
			var cfg struct {
				P float64 `json:"p"`
			}
			if err := decode(&cfg); err != nil {
				return nil, err
			}
			return ConstBackend{P: cfg.P}, nil
		})
	})
	return registerErr
}

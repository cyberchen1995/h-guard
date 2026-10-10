// Package harnesstest 提供 harness.Adapter 实现的一致性测试，第三方 adapter 应在自己的测试中调用 Run。
// 用 go test -race 运行，才能发现 adapter 里的共享状态。
package harnesstest

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

// Case 是一条 hook 输入样例。
type Case struct {
	Name     string          // 子测试名
	Input    []byte          // hook 的 stdin
	WantKind guard.EventKind // Parse 应得到的事件类型
	// Check 可选：按该 harness 的协议检查每种结论的渲染结果（各 harness 的输出格式不同，
	// 套件本身只检查与协议无关的性质）。
	Check func(t *testing.T, d guard.Decision, stdout []byte, exitCode int)
}

// Unreadable 是任何 adapter 都必须拒绝的输入：空、非 JSON、截断的 JSON、数组、空对象。
var Unreadable = [][]byte{nil, []byte(""), []byte("not json"), []byte("["), []byte("[]"), []byte("{}")}

var decisions = []guard.Decision{guard.DecisionPass, guard.DecisionWarn, guard.DecisionAsk, guard.DecisionDeny}

// Run 检查 a 满足 harness.Adapter 的契约：
//   - 名字合法；能力声明含最低版本，事件类型都合法；
//   - 读不懂的输入（Unreadable）返回错误，不 panic；
//   - 每个样例：Parse 成功、事件通过 Validate、类型符合预期、Harness 等于 a.Name()，
//     同一输入两次 Parse 结果相同；CapsFor 结果确定且不超过 Capabilities 的声明；
//     Render 对四种结论都不 panic 且结果确定；
//   - 渲染结果从不授予许可（JSON 中的 decision 类字段不为 allow / approve），h-guard 只收紧不放宽；
//   - CapsFor 声明能阻止、确认或提示时，deny、ask、warn 的渲染结果必须与 pass 不同，
//     否则声明的能力实际无法表达（评审 H03）；
//   - 给了 Case.Check 时，逐个结论调用它做协议检查；
//   - Parse、Render 可并发调用。
func Run(t *testing.T, a harness.Adapter, cases []Case) {
	t.Helper()
	if len(cases) == 0 {
		t.Fatal("harnesstest: at least one case is required")
	}
	t.Run("name", func(t *testing.T) {
		if !guard.ValidName(a.Name()) {
			t.Fatalf("Name() = %q is not a valid name", a.Name())
		}
	})
	t.Run("capabilities", func(t *testing.T) {
		caps := a.Capabilities()
		if caps.MinVersion == "" {
			t.Error("Capabilities().MinVersion is empty")
		}
		if len(caps.Events) == 0 {
			t.Error("Capabilities().Events is empty")
		}
		for k := range caps.Events {
			if !k.Valid() {
				t.Errorf("unknown event kind %q in capabilities", k)
			}
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		for _, in := range Unreadable {
			if _, err := a.Parse(in); err == nil {
				t.Errorf("Parse(%q) returned no error", in)
			}
		}
	})
	for _, c := range cases {
		t.Run("case/"+c.Name, func(t *testing.T) {
			ev, err := a.Parse(c.Input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := ev.Validate(); err != nil {
				t.Fatalf("parsed event is invalid: %v", err)
			}
			if ev.Kind != c.WantKind {
				t.Errorf("Kind = %q, want %q", ev.Kind, c.WantKind)
			}
			if ev.Harness != a.Name() {
				t.Errorf("Harness = %q, want %q", ev.Harness, a.Name())
			}
			if again, _ := a.Parse(c.Input); !reflect.DeepEqual(ev, again) {
				t.Error("Parse is not deterministic")
			}
			caps := a.CapsFor(ev)
			if caps != a.CapsFor(ev) {
				t.Error("CapsFor is not deterministic")
			}
			if declared := a.Capabilities().Events[ev.Kind]; exceeds(caps, declared) {
				t.Errorf("CapsFor = %+v exceeds Capabilities for %s = %+v", caps, ev.Kind, declared)
			}
			rendered := make(map[guard.Decision]rendering, len(decisions))
			for _, d := range decisions {
				out := outcome(d)
				b1, code1 := a.Render(ev, out)
				b2, code2 := a.Render(ev, out)
				if !bytes.Equal(b1, b2) || code1 != code2 {
					t.Errorf("Render(%s) is not deterministic", d)
				}
				if grantsPermission(b1) {
					t.Errorf("Render(%s) grants permission: %s; h-guard never returns allow", d, b1)
				}
				rendered[d] = rendering{b1, code1}
				if c.Check != nil {
					c.Check(t, d, b1, code1)
				}
			}
			for d, declared := range map[guard.Decision]bool{
				guard.DecisionDeny: caps.Block, guard.DecisionAsk: caps.Ask, guard.DecisionWarn: caps.Warn,
			} {
				if declared && rendered[d].equal(rendered[guard.DecisionPass]) {
					t.Errorf("CapsFor declares support for %s, but Render(%s) is identical to Render(pass)", d, d)
				}
			}
		})
	}
	t.Run("concurrent", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for _, c := range cases {
					ev, err := a.Parse(c.Input)
					if err != nil {
						t.Errorf("concurrent Parse(%s): %v", c.Name, err)
						return
					}
					a.CapsFor(ev)
					for _, d := range decisions {
						a.Render(ev, outcome(d))
					}
				}
			})
		}
		wg.Wait()
	})
}

type rendering struct {
	stdout   []byte
	exitCode int
}

func (r rendering) equal(o rendering) bool {
	return bytes.Equal(r.stdout, o.stdout) && r.exitCode == o.exitCode
}

// grantsPermission 报告渲染结果是否授予许可：JSON 中名字含 decision、permission 或 behavior 的字段
// 取值为 allow 或 approve。非 JSON 输出视为不授予。
func grantsPermission(stdout []byte) bool {
	var v any
	if json.Unmarshal(stdout, &v) != nil {
		return false
	}
	return walkGrants(v)
}

func walkGrants(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			key := strings.ToLower(k)
			if s, ok := child.(string); ok && (strings.Contains(key, "decision") || strings.Contains(key, "permission") || strings.Contains(key, "behavior")) {
				if val := strings.ToLower(s); val == "allow" || val == "approve" {
					return true
				}
			}
			if walkGrants(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if walkGrants(child) {
				return true
			}
		}
	}
	return false
}

// exceeds 报告 got 是否声称了 declared 没有的能力。
func exceeds(got, declared harness.EventCaps) bool {
	return (got.Block && !declared.Block) || (got.Ask && !declared.Ask) ||
		(got.Warn && !declared.Warn) || (got.Replace && !declared.Replace)
}

func outcome(d guard.Decision) guard.Outcome {
	return guard.Outcome{
		Verdict: guard.Verdict{Decision: d},
		Raw:     d,
		Message: "harnesstest message",
		Hint:    "harnesstest hint",
	}
}

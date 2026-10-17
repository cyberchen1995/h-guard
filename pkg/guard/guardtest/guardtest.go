// Package guardtest 提供 guard.Check 实现的一致性测试，第三方 Check 应在自己的测试中调用 RunCheck。
package guardtest

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// RunCheck 检查 c 满足 guard.Check 的契约：
//   - 名字合法；
//   - 至少一个样例事件适用（Applies 为真），否则套件直接失败；
//   - Applies 对只有 Kind 的空事件不 panic；
//   - 对适用的样例事件，Evaluate 总是返回合法结论（出错时也一样），提交的结论合法，
//     且返回的结论不比已提交的更宽；
//   - ctx 已取消时 1 秒内返回。
//
// events 是该 Check 应当处理的样例事件，至少一个。
func RunCheck(t *testing.T, c guard.Check, events []guard.Event) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("guardtest: at least one sample event is required")
	}
	applicable := 0
	for _, ev := range events {
		if c.Applies(ev) {
			applicable++
		}
	}
	if applicable == 0 {
		// 没有一个样例进入 Evaluate，后面的检查就是空验证
		t.Fatal("guardtest: none of the sample events applies to the check")
	}
	t.Run("name", func(t *testing.T) {
		if !guard.ValidName(c.Name()) {
			t.Fatalf("Name() = %q is not a valid name", c.Name())
		}
	})
	t.Run("applies-on-empty-events", func(t *testing.T) {
		for _, k := range []guard.EventKind{guard.EventAction, guard.EventPrompt, guard.EventToolOutput} {
			_ = c.Applies(guard.Event{Kind: k})
		}
	})
	t.Run("evaluate-samples", func(t *testing.T) {
		for i, ev := range events {
			if !c.Applies(ev) {
				continue
			}
			var (
				mu        sync.Mutex
				committed []guard.Decision
			)
			v, err := c.Evaluate(context.Background(), ev, func(cv guard.Verdict) {
				mu.Lock()
				defer mu.Unlock()
				committed = append(committed, cv.Decision)
			})
			if !v.Decision.Valid() {
				t.Errorf("event %d: Evaluate returned invalid decision %q (err = %v)", i, v.Decision, err)
				continue
			}
			mu.Lock()
			for _, d := range committed {
				switch {
				case !d.Valid():
					t.Errorf("event %d: committed invalid decision %q", i, d)
				case guard.Stricter(v.Decision, d) != v.Decision:
					t.Errorf("event %d: returned %q is weaker than committed %q; the returned verdict must include what was committed", i, v.Decision, d)
				}
			}
			mu.Unlock()
		}
	})
	t.Run("evaluate-canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan []guard.Decision, 1)
		go func() {
			var got []guard.Decision
			for _, ev := range events {
				if c.Applies(ev) {
					v, _ := c.Evaluate(ctx, ev, func(guard.Verdict) {})
					got = append(got, v.Decision)
				}
			}
			done <- got
		}()
		select {
		case got := <-done:
			for _, d := range got {
				if !d.Valid() {
					t.Errorf("Evaluate with canceled ctx returned invalid decision %q", d)
				}
			}
		case <-time.After(time.Second):
			t.Fatal("Evaluate did not return within 1s after ctx was canceled")
		}
	})
}

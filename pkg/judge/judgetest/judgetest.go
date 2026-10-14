// Package judgetest 提供 judge.Backend 实现的一致性测试，第三方后端应在自己的测试中调用 Run；
// 走 HTTP 的后端另外调用 RunHTTP（重定向、错误响应、响应上限、Retry-After 与截止时间等安全检查）。
package judgetest

import (
	"context"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Run 检查后端满足 judge.Backend 的契约：
//   - 名字非空；
//   - 返回的答案只以该次所问题目的 ID 为键；
//   - ctx 已取消时 1 秒内返回错误；
//   - 能力声明（caps）：Mechanism 非空；Kinds 非 nil 时只含已知题型（probability、scale）；
//     Supports 为假的题型即便直接用 Ask 问，答案里也不能有（可以返回错误）。
//
// 只有 caps 子测试会把后端不支持的题型发给它；其余子测试只问 Supports 为真的题，
// 收到不支持的题型就报错的后端同样满足契约。后端一道都答不了时，这两个子测试跳过。
//
// 调用方式与框架一致：Caps().Batch 为真时一次问完，否则每次一题（spec §8.1，评审 H03）。
//
// newBackend 每次返回一个新后端（HTTP 后端通常指向 httptest 服务器）；qs 至少一题，最好覆盖后端
// 不支持的题型，caps 子测试才有东西可查。
func Run(t *testing.T, newBackend func(t *testing.T) judge.Backend, qs []judge.Question) {
	t.Helper()
	if len(qs) == 0 {
		t.Fatal("judgetest: at least one question is required")
	}
	t.Run("name", func(t *testing.T) {
		if newBackend(t).Name() == "" {
			t.Fatal("Name() is empty")
		}
	})
	t.Run("answers-only-asked-ids", func(t *testing.T) {
		b := newBackend(t)
		sup := supported(b, qs)
		if len(sup) == 0 {
			t.Skip("the backend supports none of the questions")
		}
		for _, batch := range batches(b, sup) {
			resp, err := b.Ask(context.Background(), map[string]any{}, batch)
			if err != nil {
				t.Fatalf("Ask: %v", err)
			}
			asked := make(map[string]bool, len(batch))
			for _, q := range batch {
				asked[q.ID] = true
			}
			for id := range resp.Answers {
				if !asked[id] {
					t.Errorf("answer for a question that was not asked: %q", id)
				}
			}
		}
	})
	t.Run("canceled", func(t *testing.T) {
		b := newBackend(t)
		sup := supported(b, qs)
		if len(sup) == 0 {
			t.Skip("the backend supports none of the questions")
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := b.Ask(ctx, map[string]any{}, batches(b, sup)[0])
			errc <- err
		}()
		select {
		case err := <-errc:
			if err == nil {
				t.Fatal("Ask with canceled ctx returned nil error")
			}
		case <-time.After(time.Second):
			t.Fatal("Ask did not return within 1s after ctx was canceled")
		}
	})
	t.Run("caps", func(t *testing.T) {
		b := newBackend(t)
		c := b.Caps()
		if c.Mechanism == "" {
			t.Error("Caps().Mechanism is empty")
		}
		for _, k := range c.Kinds {
			if k != judge.KindProbability && k != judge.KindScale {
				t.Errorf("Caps().Kinds has an unknown kind %q", k)
			}
		}
		unsupported := map[string]judge.Kind{}
		for _, q := range qs {
			if !c.Supports(q.Kind) {
				unsupported[q.ID] = q.Kind
			}
		}
		if len(unsupported) == 0 {
			return
		}
		// 直接 Ask：不支持的题型可以报错，但不能作答。经 judge.AskAll 时这些题根本不会发出，
		// 那是 AskAll 的行为，由 pkg/judge 自己的测试覆盖，这里查不出后端的问题。
		for _, batch := range batches(b, qs) {
			resp, err := b.Ask(context.Background(), map[string]any{}, batch)
			if err != nil {
				continue
			}
			for id := range resp.Answers {
				if k, ok := unsupported[id]; ok {
					t.Errorf("Ask answered %q (%s), which it does not support", id, k)
				}
			}
		}
	})
}

// supported 返回 qs 中后端 Supports 为真的题，不修改 qs。
func supported(b judge.Backend, qs []judge.Question) []judge.Question {
	c := b.Caps()
	var out []judge.Question
	for _, q := range qs {
		if c.Supports(q.Kind) {
			out = append(out, q)
		}
	}
	return out
}

// batches 按后端能力切分题目：支持批量时一次问完，否则每次一题。
func batches(b judge.Backend, qs []judge.Question) [][]judge.Question {
	if b.Caps().Batch {
		return [][]judge.Question{qs}
	}
	out := make([][]judge.Question, len(qs))
	for i, q := range qs {
		out[i] = []judge.Question{q}
	}
	return out
}

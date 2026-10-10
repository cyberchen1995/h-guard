// Package judgetest 提供 judge.Backend 实现的一致性测试，第三方后端应在自己的测试中调用 Run。
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
//   - ctx 已取消时 1 秒内返回错误。
//
// 调用方式与框架一致：Caps().Batch 为真时一次问完，否则每次一题（spec §8.1，评审 H03）。
//
// newBackend 每次返回一个新后端（HTTP 后端通常指向 httptest 服务器）；qs 至少一题。
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
		for _, batch := range batches(b, qs) {
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
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		errc := make(chan error, 1)
		go func() {
			_, err := b.Ask(ctx, map[string]any{}, batches(b, qs)[0])
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

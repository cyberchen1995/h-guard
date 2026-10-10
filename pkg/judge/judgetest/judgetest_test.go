package judgetest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

type constBackend struct{ p float64 }

func (constBackend) Name() string            { return "const" }
func (constBackend) Caps() judge.BackendCaps { return judge.BackendCaps{Batch: true} }

func (b constBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: make(map[string]judge.Answer, len(qs))}
	for _, q := range qs {
		resp.Answers[q.ID] = judge.Answer{P: judge.Prob(b.p)}
	}
	return resp, nil
}

// singleBackend 不支持批量：一次只接受一题。
type singleBackend struct{}

func (singleBackend) Name() string            { return "single" }
func (singleBackend) Caps() judge.BackendCaps { return judge.BackendCaps{} }

func (singleBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	if len(qs) != 1 {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("one question per call")}
	}
	return judge.Response{Answers: map[string]judge.Answer{qs[0].ID: {P: judge.Prob(0.5)}}}, nil
}

func TestRunSingleQuestionBackend(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return singleBackend{} }, []judge.Question{
		{ID: "first", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
		{ID: "second", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
	})
}

func TestRun(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return constBackend{p: 0.1} }, []judge.Question{
		{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would this publish?"}},
		{ID: "blast_radius", Kind: judge.KindScale, Levels: []string{"0", "1", "2"}, Instructions: judge.Instructions{Question: "How wide?"}},
	})
}

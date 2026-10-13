package judge_test

import (
	"context"
	"math"
	"sync/atomic"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

var (
	probQ  = judge.Question{ID: "p", Kind: judge.KindProbability}
	scaleQ = judge.Question{ID: "s", Kind: judge.KindScale, Levels: []string{"a", "b", "c", "d"}}
)

func TestValidateAnswer(t *testing.T) {
	tests := []struct {
		name  string
		q     judge.Question
		a     judge.Answer
		valid bool
	}{
		{"explicit zero", probQ, judge.Answer{P: judge.Prob(0)}, true},
		{"one", probQ, judge.Answer{P: judge.Prob(1)}, true},
		{"nothing", probQ, judge.Answer{}, false},
		{"both", probQ, judge.Answer{P: judge.Prob(0.5), Dist: []float64{1}}, false},
		{"kind mismatch", probQ, judge.Answer{Dist: []float64{1}}, false},
		{"above one", probQ, judge.Answer{P: judge.Prob(1.01)}, false},
		{"negative", probQ, judge.Answer{P: judge.Prob(-0.01)}, false},
		{"nan", probQ, judge.Answer{P: judge.Prob(math.NaN())}, false},
		{"inf", probQ, judge.Answer{P: judge.Prob(math.Inf(1))}, false},
		{"scale ok", scaleQ, judge.Answer{Dist: []float64{0.1, 0.2, 0.3, 0.4}}, true},
		{"scale within tolerance", scaleQ, judge.Answer{Dist: []float64{0.1, 0.2, 0.3, 0.4005}}, true},
		// 后端按两位小数给出概率，四项各自舍入后和可以偏离 1 达 0.02（Jev 真实答案 [0, 0.81, 0.01, 0.17]）
		{"scale rounded to two decimals", scaleQ, judge.Answer{Dist: []float64{0, 0.81, 0.01, 0.17}}, true},
		{"scale rounded the other way", scaleQ, judge.Answer{Dist: []float64{0.26, 0.26, 0.25, 0.25}}, true},
		{"scale off by more than rounding", scaleQ, judge.Answer{Dist: []float64{0.1, 0.2, 0.3, 0.37}}, false},
		{"scale off by more", scaleQ, judge.Answer{Dist: []float64{0.1, 0.2, 0.3, 0.5}}, false},
		{"scale wrong length", scaleQ, judge.Answer{Dist: []float64{0.5, 0.5}}, false},
		{"scale negative", scaleQ, judge.Answer{Dist: []float64{-0.1, 0.4, 0.3, 0.4}}, false},
		{"scale nan", scaleQ, judge.Answer{Dist: []float64{math.NaN(), 0.4, 0.3, 0.3}}, false},
		{"scale with p", scaleQ, judge.Answer{P: judge.Prob(0.5)}, false},
	}
	for _, tt := range tests {
		_, err := judge.ValidateAnswer(tt.q, tt.a)
		if (err == nil) != tt.valid {
			t.Errorf("%s: err = %v, want valid=%v", tt.name, err, tt.valid)
		}
	}
}

func TestValidateNormalizesAndDropsInvalid(t *testing.T) {
	r := judge.Response{Answers: map[string]judge.Answer{
		"s":     {Dist: []float64{0.1, 0.2, 0.3, 0.4004}},
		"p":     {},
		"extra": {P: judge.Prob(0.9)},
	}}
	got := judge.Validate([]judge.Question{probQ, scaleQ}, r)
	if _, ok := got["p"]; ok {
		t.Error("an empty answer must be invalid")
	}
	if _, ok := got["extra"]; ok {
		t.Error("answers to questions not asked must be dropped")
	}
	sum := 0.0
	for _, v := range got["s"].Dist {
		sum += v
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Errorf("normalized dist sums to %v", sum)
	}
}

type fakeBackend struct {
	batch bool
	calls atomic.Int32
	ask   func(qs []judge.Question) (judge.Response, error)
}

func (f *fakeBackend) Name() string            { return "fake" }
func (f *fakeBackend) Caps() judge.BackendCaps { return judge.BackendCaps{Batch: f.batch} }
func (f *fakeBackend) Ask(_ context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	f.calls.Add(1)
	return f.ask(qs)
}

func TestAskAllBatch(t *testing.T) {
	b := &fakeBackend{batch: true, ask: func(qs []judge.Question) (judge.Response, error) {
		return judge.Response{Answers: map[string]judge.Answer{"p": {P: judge.Prob(0.1)}, "x": {P: judge.Prob(1)}}}, nil
	}}
	r, err := judge.AskAll(context.Background(), b, nil, []judge.Question{probQ, scaleQ})
	if err != nil || b.calls.Load() != 1 {
		t.Fatalf("err = %v, calls = %d", err, b.calls.Load())
	}
	if _, ok := r.Answers["x"]; ok {
		t.Error("AskAll kept an answer to a question that was not asked")
	}
}

func TestAskAllPerQuestion(t *testing.T) {
	b := &fakeBackend{ask: func(qs []judge.Question) (judge.Response, error) {
		if qs[0].ID == "s" {
			return judge.Response{}, &judge.Error{Kind: judge.Timeout}
		}
		return judge.Response{Answers: map[string]judge.Answer{qs[0].ID: {P: judge.Prob(0.3)}}, Usage: judge.Usage{InputTokens: 5}}, nil
	}}
	r, err := judge.AskAll(context.Background(), b, nil, []judge.Question{probQ, scaleQ})
	if err != nil || b.calls.Load() != 2 {
		t.Fatalf("err = %v, calls = %d", err, b.calls.Load())
	}
	if _, ok := r.Answers["s"]; ok || r.Answers["p"].P == nil || r.Usage.InputTokens != 5 {
		t.Errorf("merged = %+v", r)
	}
	b.ask = func([]judge.Question) (judge.Response, error) {
		return judge.Response{}, &judge.Error{Kind: judge.Auth}
	}
	if _, err := judge.AskAll(context.Background(), b, nil, []judge.Question{probQ, scaleQ}); judge.KindOf(err) != judge.Auth {
		t.Errorf("all failed: err = %v", err)
	}
}

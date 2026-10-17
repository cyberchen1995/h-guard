package judge_test

import (
	"context"
	"maps"
	"math"
	"slices"
	"sync"
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
	kinds []judge.Kind // Caps().Kinds
	calls atomic.Int32
	ask   func(qs []judge.Question) (judge.Response, error)

	mu    sync.Mutex
	asked []string // 收到的全部题目 ID
}

func (f *fakeBackend) Name() string { return "fake" }
func (f *fakeBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: f.batch, Mechanism: judge.MechanismProgram, Kinds: f.kinds}
}
func (f *fakeBackend) Ask(_ context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	f.calls.Add(1)
	f.mu.Lock()
	for _, q := range qs {
		f.asked = append(f.asked, q.ID)
	}
	f.mu.Unlock()
	return f.ask(qs)
}

// askedIDs 返回后端收到的题目 ID（排序后；按题提问时各题并发）。
func (f *fakeBackend) askedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(slices.Values(f.asked))
}

// answerBoth 不论问了什么，都给 p 与 s 两题作答：没有发出的题的答案必须被 AskAll 丢掉。
func answerBoth([]judge.Question) (judge.Response, error) {
	return judge.Response{Answers: map[string]judge.Answer{
		"p": {P: judge.Prob(0.1)},
		"s": {Dist: []float64{0.25, 0.25, 0.25, 0.25}},
	}}, nil
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

// TestAskAllSkipsUnsupportedKinds：后端不支持的题型不发给它，这些题保持未答（不会产生放行）；
// Kinds 为 nil 时全部发送。
func TestAskAllSkipsUnsupportedKinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kinds []judge.Kind
		want  []string
	}{
		{"probability only", []judge.Kind{judge.KindProbability}, []string{"p"}},
		{"scale only", []judge.Kind{judge.KindScale}, []string{"s"}},
		{"undeclared", nil, []string{"p", "s"}},
	} {
		for _, batch := range []bool{true, false} {
			b := &fakeBackend{batch: batch, kinds: tc.kinds, ask: answerBoth}
			r, err := judge.AskAll(context.Background(), b, nil, []judge.Question{probQ, scaleQ})
			if err != nil {
				t.Fatalf("%s, batch=%v: %v", tc.name, batch, err)
			}
			if got := b.askedIDs(); !slices.Equal(got, tc.want) {
				t.Errorf("%s, batch=%v: the backend was asked %v, want %v", tc.name, batch, got, tc.want)
			}
			got := slices.Sorted(maps.Keys(r.Answers))
			if !slices.Equal(got, tc.want) {
				t.Errorf("%s, batch=%v: answered %v, want %v (unsupported kinds stay unanswered)", tc.name, batch, got, tc.want)
			}
		}
	}
}

// TestAskAllDoesNotCallABackendThatSupportsNoAskedKind：一道题都不剩时不调用后端，返回空答案与 nil 错误。
func TestAskAllDoesNotCallABackendThatSupportsNoAskedKind(t *testing.T) {
	for _, tc := range []struct {
		name  string
		kinds []judge.Kind
		qs    []judge.Question
	}{
		{"empty kinds", []judge.Kind{}, []judge.Question{probQ, scaleQ}},
		{"scale only, probability asked", []judge.Kind{judge.KindScale}, []judge.Question{probQ}},
	} {
		for _, batch := range []bool{true, false} {
			b := &fakeBackend{batch: batch, kinds: tc.kinds, ask: answerBoth}
			r, err := judge.AskAll(context.Background(), b, nil, tc.qs)
			if err != nil || b.calls.Load() != 0 || len(r.Answers) != 0 {
				t.Errorf("%s, batch=%v: err = %v, calls = %d, answers = %v", tc.name, batch, err, b.calls.Load(), r.Answers)
			}
		}
	}
}

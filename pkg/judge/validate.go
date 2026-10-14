package judge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
)

// normalizeTolerance 是分布之和允许偏离 1 的幅度，偏离不超过它时归一化（spec §8.1）。后端按两位小数给出概率
// （Jev），四个级别各自舍入后和最多偏离 0.02；比较时另留浮点误差的余量。
const normalizeTolerance = 0.02

// ValidateAnswer 按 spec §8.1 检查一道题的答案，返回归一化后的答案；无效时返回说明原因的错误。
func ValidateAnswer(q Question, a Answer) (Answer, error) {
	switch {
	case a.P == nil && a.Dist == nil:
		return Answer{}, errors.New("no answer")
	case a.P != nil && a.Dist != nil:
		return Answer{}, errors.New("both p and dist")
	}
	switch q.Kind {
	case KindProbability:
		if a.P == nil {
			return Answer{}, errors.New("probability question answered with dist")
		}
		if p := *a.P; math.IsNaN(p) || p < 0 || p > 1 {
			return Answer{}, fmt.Errorf("p = %v, want [0, 1]", p)
		}
		return Answer{P: Prob(*a.P)}, nil
	case KindScale:
		if a.Dist == nil {
			return Answer{}, errors.New("scale question answered with p")
		}
		if len(a.Dist) != len(q.Levels) {
			return Answer{}, fmt.Errorf("dist has %d entries, want %d", len(a.Dist), len(q.Levels))
		}
		sum := 0.0
		for _, v := range a.Dist {
			if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
				return Answer{}, fmt.Errorf("dist entry %v is not a probability", v)
			}
			sum += v
		}
		if math.Abs(sum-1) > normalizeTolerance+1e-9 {
			return Answer{}, fmt.Errorf("dist sums to %v", sum)
		}
		out := make([]float64, len(a.Dist))
		for i, v := range a.Dist {
			out[i] = v / sum
		}
		return Answer{Dist: out}, nil
	}
	return Answer{}, fmt.Errorf("unknown question kind %q", q.Kind)
}

// Validate 校验 r 中 qs 各题的答案，返回通过校验并归一化后的答案。
// 不在结果中的题（缺题或无效）一律按 spec §8.1 的「无效时」处理，不能产生放行。
func Validate(qs []Question, r Response) map[string]Answer {
	out := make(map[string]Answer, len(qs))
	for _, q := range qs {
		a, ok := r.Answers[q.ID]
		if !ok {
			continue
		}
		if v, err := ValidateAnswer(q, a); err == nil {
			out[q.ID] = v
		}
	}
	return out
}

// MaxConcurrent 是不能批量的后端按题并发的上限（spec §3.4、§8.1）。
const MaxConcurrent = 4

// AskAll 按后端能力提问。先去掉后端不支持的题型（Caps().Supports 为假）：这些题不发给后端、保持未答，
// 不能产生放行；一道都不剩时不调用后端，返回空答案与 nil 错误。其余的题在 Caps().Batch 为真时一次问完，
// 否则按题并发（至多 MaxConcurrent 个）。
// 按题提问时，失败的题只当未答；全部失败才返回错误（取第一道题的错误）。
// 返回的答案只含发出的题目 ID；后端多给的答案被丢弃。
func AskAll(ctx context.Context, b Backend, state map[string]any, qs []Question) (Response, error) {
	caps := b.Caps()
	qs = slices.DeleteFunc(slices.Clone(qs), func(q Question) bool { return !caps.Supports(q.Kind) })
	if len(qs) == 0 {
		return Response{Answers: map[string]Answer{}}, nil
	}
	if caps.Batch {
		r, err := b.Ask(ctx, state, qs)
		if err != nil {
			return Response{}, err
		}
		return onlyAsked(r, qs), nil
	}
	type result struct {
		r   Response
		err error
	}
	results := make([]result, len(qs))
	sem := make(chan struct{}, MaxConcurrent)
	var wg sync.WaitGroup
	for i, q := range qs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i].err = ctx.Err()
				return
			}
			defer func() { <-sem }()
			r, err := b.Ask(ctx, state, []Question{q})
			results[i] = result{onlyAsked(r, []Question{q}), err}
		}()
	}
	wg.Wait()
	merged := Response{Answers: map[string]Answer{}}
	var firstErr error
	for _, res := range results {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		for id, a := range res.r.Answers {
			merged.Answers[id] = a
		}
		if merged.Model == "" {
			merged.Model = res.r.Model
		}
		merged.Usage.InputTokens += res.r.Usage.InputTokens
		merged.Usage.OutputTokens += res.r.Usage.OutputTokens
	}
	if len(merged.Answers) == 0 && firstErr != nil {
		return Response{}, firstErr
	}
	return merged, nil
}

func onlyAsked(r Response, qs []Question) Response {
	out := Response{Answers: make(map[string]Answer, len(qs)), Model: r.Model, Usage: r.Usage}
	for _, q := range qs {
		if a, ok := r.Answers[q.ID]; ok {
			out.Answers[q.ID] = a
		}
	}
	return out
}

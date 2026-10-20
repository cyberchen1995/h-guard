package eval

import (
	"context"
	"slices"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// 测试钩子：只在测试里可见。
var ThresholdKey = thKey

var LegalRange = legalRange

var Within = func(a, best Score, runs int) bool { return a.within(best, runs) }

var Better = func(a, b Score) bool { return a.better(b) }

// CorpusFiles 暴露阈值扫描读取的内置语料文件。
func CorpusFiles() map[guard.Shell]string { return corpusFiles }

// Public 去掉 o 的内部字段（记下的答案与材料），剩下可以直接比较的部分。
func Public(o Outcome) Outcome {
	o.recorded, o.judged = nil, nil
	return o
}

// RescoreFull 是 Rescore 的参照实现：按记下的答案把每条语料完整重跑一遍动作检查（含规则匹配），
// 后端换成回放。Rescore 只重算套用阈值的一步，等价性测试用它核对两者逐条一致。
func RescoreFull(ctx context.Context, env Env, outs []Outcome, th config.Thresholds) ([]Outcome, error) {
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	res := make([]Outcome, len(outs))
	for i, o := range outs {
		if o.recorded == nil {
			res[i] = o
			continue
		}
		n, err := evaluate(ctx, env, cat, o.Case, replay{o.recorded}, th)
		if err != nil {
			return nil, err
		}
		n.Run, n.Called, n.Err, n.ErrDetail, n.Invalid, n.Latency, n.recorded = o.Run, o.Called, o.Err, o.ErrDetail, o.Invalid, o.Latency, o.recorded
		res[i] = n
	}
	return res, nil
}

// replay 按记下的答案或错误回答，不调用后端；能力声明里带着记录时后端的题型。
type replay struct{ rec *recording }

func (replay) Name() string { return "replay" }
func (p replay) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Kinds: slices.Clone(p.rec.kinds)}
}
func (p replay) Ask(context.Context, map[string]any, []judge.Question) (judge.Response, error) {
	return p.rec.resp, p.rec.err
}

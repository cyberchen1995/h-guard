package eval

import (
	"math"
	"slices"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Pool 把 K 次运行按条拼成一份结果：第 r 次的第 i 条在 r*len(runs[0])+i，Run 记 r。报告、margin、扫描与 bootstrap
// 都在拼接结果上做，每条都是 hook 真正会做的单次判断，失败与缺题按条进入结果——任一次失败都挡住建议档案，
// 不会被另一次的成功遮住。不调用后端。
func Pool(runs [][]Outcome) []Outcome {
	var pooled []Outcome
	for r, outs := range runs {
		for _, o := range outs {
			o.Run = r
			pooled = append(pooled, o)
		}
	}
	return pooled
}

// Repeatability 是同一后端跑 K 遍语料的差异。
type Repeatability struct {
	Runs            int
	SDMedian, SDMax float64 // 每题概率（量表题取期望）跨运行标准差的中位数与最大值；只统计每次都可校准的语料
	Flips           int     // 各次结论不全相同的语料数
	MinCorrect      int     // 各次正确数的范围
	MaxCorrect      int
}

// Repeat 统计 runs（runs[k][i] 为第 k 次的第 i 条）之间的差异。不调用后端。
func Repeat(runs [][]Outcome) Repeatability {
	r := Repeatability{Runs: len(runs)}
	if len(runs) == 0 {
		return r
	}
	r.MinCorrect, r.MaxCorrect = math.MaxInt, 0
	for _, outs := range runs {
		c := ScoreOf(outs).Correct
		r.MinCorrect, r.MaxCorrect = min(r.MinCorrect, c), max(r.MaxCorrect, c)
	}
	var sds []float64
	for i := range runs[0] {
		flipped, all := false, true
		for _, outs := range runs {
			flipped = flipped || outs[i].Decision != runs[0][i].Decision
			all = all && outs[i].Calibratable()
		}
		if flipped {
			r.Flips++
		}
		if !all {
			continue
		}
		for id := range runs[0][i].recorded.resp.Answers {
			var vs []float64
			for _, outs := range runs {
				if a, ok := outs[i].recorded.resp.Answers[id]; ok {
					vs = append(vs, value(a))
				}
			}
			if len(vs) == len(runs) {
				sds = append(sds, sd(vs))
			}
		}
	}
	if len(sds) > 0 {
		slices.Sort(sds)
		r.SDMedian, r.SDMax = sds[len(sds)/2], sds[len(sds)-1]
	}
	return r
}

// value 把一题的答案折成一个数：概率题取 P，量表题取分布的期望（级别下标加权）。
func value(a judge.Answer) float64 {
	if a.P != nil {
		return *a.P
	}
	var s, w float64
	for j, v := range a.Dist {
		s += float64(j) * v
		w += v
	}
	if w == 0 {
		return 0
	}
	return s / w
}

// sd 是总体标准差。
func sd(xs []float64) float64 {
	m := mean(xs)
	var ss float64
	for _, x := range xs {
		ss += (x - m) * (x - m)
	}
	return math.Sqrt(ss / float64(len(xs)))
}

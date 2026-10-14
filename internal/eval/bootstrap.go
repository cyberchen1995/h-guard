package eval

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
)

// Stability 是一个阈值在重采样中的稳定性。
type Stability struct {
	Param     string
	Chosen    float64 // 全样本的建议值
	Agree     float64 // 重采样中选到 Chosen 的比例
	Low, High float64 // 重采样所选值的 2.5 与 97.5 分位
}

// Bootstrap 是对整个扫描过程做 bootstrap 的结果：每次按语料有放回重采样，在样本上重跑坐标下降与 shrink，
// 用得到的阈值给袋内（样本）与袋外（没抽到的语料）打分。它只描述「descend + shrink」这一套流程给出的建议；
// 建议不会因它被改动（评审 EC-03）。
type Bootstrap struct {
	B               int
	Cases           int     // 独立语料数：重采样单元数，也是乐观判据的样本量（评审 R2-01：重复运行不是新语料）
	OOBRuns         int     // 有袋外样本的重采样次数；为 0 时下面三项不可估计
	InBag, OOB      float64 // 袋内、袋外正确率的均值
	OOBLow, OOBHigh float64 // 袋外正确率的 2.5 与 97.5 分位
	Params          []Stability
}

// Optimism 是袋内比袋外高出的正确率：在同一份语料上选阈值再报它的分数有多乐观。OOBRuns 为 0 时为 NaN。
func (b Bootstrap) Optimism() float64 { return b.InBag - b.OOB }

// BootstrapSweep 对 outs 重采样 B 次（seed 固定则可复现），每次重跑 descend 与 shrink，返回袋外正确率的分布、
// 乐观偏差与每个阈值相对全样本建议 suggested 的稳定性。不调用后端。
// outs 是 Pool 的布局：cases 条语料 × runs 次运行，第 i 条第 r 次在 r*cases+i。重采样单元是语料，抽到一条就带上
// 它的全部 runs 次结论（评审 EC-02：保留重复观测的相关性）；语料补了 family 字段后改成按 family 抽，只改 draw。
func BootstrapSweep(ctx context.Context, env Env, outs []Outcome, cases int, base, suggested config.Thresholds, B int, seed uint64) (Bootstrap, error) {
	if cases <= 0 || len(outs)%cases != 0 {
		return Bootstrap{}, fmt.Errorf("bootstrap: %d outcomes are not a whole number of runs over %d cases", len(outs), cases)
	}
	runs := len(outs) / cases
	base = withFloors(env, base)
	suggested = withFloors(env, suggested)
	floors := floorRules(env.Rules, base)
	s := newScorer(ctx, env, outs)
	rng := rand.New(rand.NewPCG(seed, 0))
	chosen := make([][]float64, len(params))
	var inBag, oob []float64
	for b := 0; b < B; b++ {
		picked := draw(rng, cases)
		inSample := make([]bool, cases)
		var idx, out []int
		for _, c := range picked {
			inSample[c] = true
			for r := 0; r < runs; r++ {
				idx = append(idx, r*cases+c)
			}
		}
		for c := 0; c < cases; c++ {
			if !inSample[c] {
				for r := 0; r < runs; r++ {
					out = append(out, r*cases+c)
				}
			}
		}
		th, sc, err := descend(s, base, floors, idx)
		if err != nil {
			return Bootstrap{}, err
		}
		th, sc, err = shrink(s, th, base, sc, floors, idx, runs)
		if err != nil {
			return Bootstrap{}, err
		}
		inBag = append(inBag, float64(sc.Correct)/float64(len(idx)))
		if len(out) > 0 {
			osc, err := s.score(th, out)
			if err != nil {
				return Bootstrap{}, err
			}
			oob = append(oob, float64(osc.Correct)/float64(len(out)))
		}
		for i, p := range params {
			if p.name == "radius_floor" && len(floors) == 0 {
				continue
			}
			chosen[i] = append(chosen[i], p.get(th, floors))
		}
	}
	res := Bootstrap{B: B, Cases: cases, OOBRuns: len(oob), InBag: mean(inBag), OOB: mean(oob), OOBLow: percentile(oob, 0.025), OOBHigh: percentile(oob, 0.975)}
	for i, p := range params {
		if p.name == "radius_floor" && len(floors) == 0 {
			continue
		}
		want := p.get(suggested, floors)
		agree := 0
		for _, v := range chosen[i] {
			if near(v, want) {
				agree++
			}
		}
		res.Params = append(res.Params, Stability{Param: p.name, Chosen: want, Agree: float64(agree) / float64(max(1, len(chosen[i]))),
			Low: percentile(chosen[i], 0.025), High: percentile(chosen[i], 0.975)})
	}
	return res, nil
}

// draw 有放回地抽 n 个语料下标。
func draw(rng *rand.Rand, n int) []int {
	idx := make([]int, n)
	for i := range idx {
		idx[i] = rng.IntN(n)
	}
	return idx
}

// mean 是均值；空切片为 NaN。
func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

// percentile 返回 xs 的 q 分位（最近秩法）；空切片为 NaN。
func percentile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	sorted := slices.Clone(xs)
	slices.Sort(sorted)
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	return sorted[min(max(i, 0), len(sorted)-1)]
}

// BootstrapNotes 把 bootstrap 结果写成建议档案的注释：袋外正确率与区间、乐观偏差及其判据、每个阈值的稳定性、
// 不稳的阈值。判据：乐观偏差 ≥ 1 SE 为 optimistic，≥ 2 SE 为 likely overfitted；SE 用袋外正确率与独立语料数 Cases 算
// （p 夹在 [0.5/N, 1−0.5/N]），袋内满分时照样能触发（评审 EC-04），同一批结果复制 K 次不会升级（评审 R2-01）。
// 没有袋外样本时写 not estimable，不做判断。
func BootstrapNotes(bs Bootstrap) []string {
	var notes []string
	if bs.OOBRuns == 0 {
		notes = append(notes, fmt.Sprintf("Bootstrap (B=%d): out-of-bag correct rate not estimable (no resample left a case out; too few cases); in-bag %.1f%%.", bs.B, bs.InBag*100))
	} else {
		notes = append(notes, fmt.Sprintf("Bootstrap (B=%d over %d cases): out-of-bag correct rate %.1f%% [%.1f%%, %.1f%%] over %d resamples; in-bag %.1f%%, optimism %.1f points.",
			bs.B, bs.Cases, bs.OOB*100, bs.OOBLow*100, bs.OOBHigh*100, bs.OOBRuns, bs.InBag*100, bs.Optimism()*100))
		if n := float64(bs.Cases); n > 0 {
			p := math.Min(math.Max(bs.OOB, 0.5/n), 1-0.5/n)
			se := math.Sqrt(p * (1 - p) / n)
			switch {
			case bs.Optimism() >= 2*se:
				notes = append(notes, "The suggestion looks overfitted to this corpus (optimism >= 2 SE); keep the current profile.")
			case bs.Optimism() >= se:
				notes = append(notes, "The suggestion is optimistic (optimism >= 1 SE); expect fewer correct decisions on new commands.")
			}
		}
	}
	var parts []string
	for _, st := range bs.Params {
		parts = append(parts, fmt.Sprintf("%s %s in %.0f%%", st.Param, num(st.Chosen), st.Agree*100))
	}
	notes = append(notes, "Threshold stability: "+strings.Join(parts, ", ")+" of resamples.")
	for _, st := range bs.Params {
		if st.Agree < 0.5 {
			notes = append(notes, fmt.Sprintf("%s %s is unsettled: chosen in only %.0f%% of resamples. Decide whether to adopt it; the sweep did not change it for you.",
				st.Param, num(st.Chosen), st.Agree*100))
		}
	}
	return notes
}

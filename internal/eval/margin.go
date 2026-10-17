package eval

import (
	"context"
	"fmt"
	"math"

	"github.com/cyberchen1995/h-guard/internal/config"
)

// Margin 是一条结论离翻转最近的阈值变化。
type Margin struct {
	Known bool    // 该条结论随阈值变化（见 Outcome.Calibratable）
	Param string  // 使结论翻转的阈值名；在合法范围与 marginReach 内没有翻转时为空
	Delta float64 // 离翻转的最小距离；Param 为空时为 marginReach
}

// String 写成 "0.03 (hit)"、">0.50" 或 "-"（不可校准）。
func (m Margin) String() string {
	switch {
	case !m.Known:
		return "-"
	case m.Param == "":
		return fmt.Sprintf(">%.2f", marginReach)
	}
	return fmt.Sprintf("%.2f (%s)", m.Delta, m.Param)
}

// 扰动的步长与每侧最远距离。
const marginStep, marginReach = 0.01, 0.5

// legalRange 返回阈值的合法范围，与 internal/config 的校验一致：概率阈值 [0, 1]，影响范围下限 [0, 3]。
// margin 只在合法范围内搜索翻转：合法配置到不了的翻转不算近边界。
func legalRange(name string) (lo, hi float64) {
	if name == "radius_floor" {
		return 0, 3
	}
	return 0, 1
}

// Margins 用记下的答案算每条结论的 margin（扰动法，不调用后端）：每个阈值从 base 出发按 marginStep 向两侧移动到
// marginReach，越出合法范围就停，记录每条结论第一次改变时的距离，取所有阈值中的最小值。扰动值不取整：
// Delta 就是实际回放的移动量，base 有几位小数都一样；代价只是缓存键与网格值不重合。
// 复用 Rescore 而不复刻策略，所以截断、否决、授权、影响范围的分支都如实反映。
func Margins(ctx context.Context, env Env, outs []Outcome, base config.Thresholds) ([]Margin, error) {
	base = withFloors(env, base)
	floors := floorRules(env.Rules, base)
	s := newScorer(ctx, env, outs)
	at0, err := s.at(base)
	if err != nil {
		return nil, err
	}
	ms := make([]Margin, len(outs))
	for i, o := range outs {
		ms[i] = Margin{Known: o.Calibratable(), Delta: marginReach}
	}
	for _, p := range params {
		if p.name == "radius_floor" && len(floors) == 0 {
			continue
		}
		start := p.get(base, floors)
		lo, hi := legalRange(p.name)
		for _, sign := range []float64{-1, 1} {
			done := make([]bool, len(outs)) // 这一侧已翻转的结论
			for k := 1; float64(k)*marginStep <= marginReach+1e-9; k++ {
				d := float64(k) * marginStep
				v := start + sign*d // 不取整：报告的距离必须就是实际回放的移动量
				if v < lo-1e-9 || v > hi+1e-9 {
					break // 越出合法范围：这一侧不再有可部署的翻转
				}
				v = math.Max(lo, math.Min(hi, v)) // 夹进合法范围，吸收 1e-9 容差带来的越界
				th := clone(base)
				if p.name == "radius_floor" {
					// 每条下限规则从自己的 base 值出发移动同样的 d：get 只读第一条，
					// set 又把同一个值写给所有规则，base 下限不同时会把后面的规则移错。
					out := false
					for _, id := range floors {
						f := base.RadiusFloor[id] + sign*d
						if f < lo-1e-9 || f > hi+1e-9 {
							out = true
							break
						}
						th.RadiusFloor[id] = math.Max(lo, math.Min(hi, f))
					}
					if out {
						break // 任一条越出合法范围：报告的 d 就不再是每条规则实际回放的移动量
					}
				} else {
					p.set(&th, floors, v)
				}
				res, err := s.at(th)
				if err != nil {
					return nil, err
				}
				for i := range outs {
					if done[i] || !ms[i].Known || res[i].Decision == at0[i].Decision {
						continue
					}
					done[i] = true
					if d < ms[i].Delta-1e-9 || (math.Abs(d-ms[i].Delta) < 1e-9 && ms[i].Param == "") {
						ms[i].Delta, ms[i].Param = d, p.name
					}
				}
			}
		}
	}
	return ms, nil
}

// MarginSummary 是一个阈值下近边界的结论数。
type MarginSummary struct {
	Param             string
	Within5, Within10 int // margin ≤ 0.05、≤ 0.10 的条数
}

// SummarizeMargins 按阈值汇总：rows 按 params 顺序，只含在该阈值上翻转的结论；noFlip 是在合法范围与 marginReach 内
// 没有翻转的可校准结论数；unknown 是不可校准的结论数。
func SummarizeMargins(ms []Margin) (rows []MarginSummary, noFlip, unknown int) {
	for _, p := range params {
		rows = append(rows, MarginSummary{Param: p.name})
	}
	for _, m := range ms {
		switch {
		case !m.Known:
			unknown++
		case m.Param == "":
			noFlip++
		default:
			for i := range rows {
				if rows[i].Param != m.Param {
					continue
				}
				if m.Delta <= 0.05+1e-9 {
					rows[i].Within5++
				}
				if m.Delta <= 0.10+1e-9 {
					rows[i].Within10++
				}
			}
		}
	}
	return rows, noFlip, unknown
}

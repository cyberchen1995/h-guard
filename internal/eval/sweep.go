package eval

import (
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// param 是一个可扫描的阈值。取值表沿用 Python 版 evaluate.sweep。
type param struct {
	name   string
	values []float64
	get    func(th config.Thresholds, floors []string) float64
	set    func(th *config.Thresholds, floors []string, v float64)
}

var params = []param{
	{"hit", []float64{0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9},
		func(th config.Thresholds, _ []string) float64 { return th.Hit },
		func(th *config.Thresholds, _ []string, v float64) { th.Hit = v }},
	{"veto", []float64{0.05, 0.1, 0.2, 0.3, 0.4},
		func(th config.Thresholds, _ []string) float64 { return th.Veto },
		func(th *config.Thresholds, _ []string, v float64) { th.Veto = v }},
	{"requested", []float64{0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95},
		func(th config.Thresholds, _ []string) float64 { return th.Requested },
		func(th *config.Thresholds, _ []string, v float64) { th.Requested = v }},
	// 影响范围下限：设了下限（大于 0）的规则一起改
	{"radius_floor", []float64{1.0, 1.25, 1.5, 1.75, 2.0, 2.25},
		func(th config.Thresholds, floors []string) float64 {
			if len(floors) == 0 {
				return math.NaN()
			}
			return th.RadiusFloor[floors[0]]
		},
		func(th *config.Thresholds, floors []string, v float64) {
			for _, id := range floors {
				th.RadiusFloor[id] = v
			}
		}},
}

// Row 是扫描表的一行。
type Row struct {
	Value   float64
	Score   Score
	Current bool // 与 base 相同
	Plateau bool // 在本表最优的 plateau 内
}

// Table 是一个阈值的扫描结果（其余阈值取 base）。
type Table struct {
	Param string
	Rows  []Row
}

// scorer 按阈值记住每条结论的重算结果。坐标下降、shrink、margin 与 bootstrap 会反复落在同一组阈值上，
// 缓存使它们的代价从「每次都重跑全部语料」降到「每组阈值重跑一次」。一个 scorer 只服务一组 outs。
type scorer struct {
	ctx  context.Context
	env  Env
	outs []Outcome
	memo map[string][]Outcome
}

func newScorer(ctx context.Context, env Env, outs []Outcome) *scorer {
	return &scorer{ctx: ctx, env: env, outs: outs, memo: map[string][]Outcome{}}
}

// at 返回 th 下全部结论的重算结果（记忆化）。
func (s *scorer) at(th config.Thresholds) ([]Outcome, error) {
	k := thKey(th)
	if res, ok := s.memo[k]; ok {
		return res, nil
	}
	res, err := Rescore(s.ctx, s.env, s.outs, th)
	if err != nil {
		return nil, err
	}
	s.memo[k] = res
	return res, nil
}

// score 统计 th 下的结论：idx 为 nil 时统计全部，否则只统计这些下标（可重复，重复即加权——bootstrap 的重采样）。
func (s *scorer) score(th config.Thresholds, idx []int) (Score, error) {
	res, err := s.at(th)
	if err != nil {
		return Score{}, err
	}
	if idx == nil {
		return ScoreOf(res), nil
	}
	sub := make([]Outcome, 0, len(idx))
	for _, i := range idx {
		sub = append(sub, res[i])
	}
	return ScoreOf(sub), nil
}

// thKey 把阈值写成缓存键。数值用最短的精确表示：两个不同的浮点阈值一定是不同的键（评审 EC-06），
// 需要合并浮点噪声的调用方（margin 的扰动）在构造阈值之前自己取整。
func thKey(th config.Thresholds) string {
	var b strings.Builder
	for _, v := range []float64{th.Hit, th.Veto, th.Requested} {
		b.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
		b.WriteByte('|')
	}
	for _, id := range slices.Sorted(maps.Keys(th.RadiusFloor)) {
		b.WriteString(id)
		b.WriteByte('=')
		b.WriteString(strconv.FormatFloat(th.RadiusFloor[id], 'g', -1, 64))
		b.WriteByte(',')
	}
	return b.String()
}

// descend 从 base 出发做坐标下降：依次把每个阈值换成使结论最好的取值（正确数多、其次漏判少；同样好时保留当前值，
// 否则取离当前值最近的），直到一轮下来不再变化（至多 3 轮）。idx 的含义同 scorer.score。
func descend(s *scorer, base config.Thresholds, floors []string, idx []int) (config.Thresholds, Score, error) {
	cur := clone(base)
	curScore, err := s.score(cur, idx)
	if err != nil {
		return config.Thresholds{}, Score{}, err
	}
	for round := 0; round < 3; round++ {
		changed := false
		for _, p := range params {
			if p.name == "radius_floor" && len(floors) == 0 {
				continue
			}
			now := p.get(cur, floors)
			best, bestScore := now, curScore
			for _, v := range p.values {
				th := clone(cur)
				p.set(&th, floors, v)
				sc, err := s.score(th, idx)
				if err != nil {
					return config.Thresholds{}, Score{}, err
				}
				if sc.better(bestScore) || (sc == bestScore && !near(best, now) && math.Abs(v-now) < math.Abs(best-now)) {
					best, bestScore = v, sc
				}
			}
			if !near(best, now) {
				p.set(&cur, floors, best)
				curScore, changed = bestScore, true
			}
		}
		if !changed {
			break
		}
	}
	return cur, curScore, nil
}

// plateauWidth 是 plateau 的宽度：每次运行里正确数与最优相差不超过这么多条的取值视为同样好。
// 113 条语料上差 1 条分不出好坏，为 1 条更换阈值是在拟合噪声（方法调研 §1.3、§2.4）。
const plateauWidth = 1

// within 报告 a 是否在 best 的 plateau 内；runs 是每条语料在结果里出现的次数（--repeat），宽度随之缩放。
func (a Score) within(best Score, runs int) bool {
	return a.Correct >= best.Correct-plateauWidth*max(1, runs)
}

// candidates 返回阈值 p 的候选取值：扫描网格加上 base 的值与当前值（网格外的合法 base 也要能被保留，评审 EC-07），
// 去重后升序。
func candidates(p param, cur, base config.Thresholds, floors []string) []float64 {
	vals := slices.Clone(p.values)
	for _, v := range []float64{p.get(base, floors), p.get(cur, floors)} {
		if !math.IsNaN(v) && !slices.ContainsFunc(vals, func(x float64) bool { return near(x, v) }) {
			vals = append(vals, v)
		}
	}
	slices.Sort(vals)
	return vals
}

// shrink 把 th 的每个阈值换成 plateau 内离 base 最近的候选。依次进行，每一步都用已改过的其余阈值重算并要求
// 仍在 best 的 plateau 内，所以整体结论的正确数最多比 best 少 plateauWidth×runs。
func shrink(s *scorer, th, base config.Thresholds, best Score, floors []string, idx []int, runs int) (config.Thresholds, Score, error) {
	cur := clone(th)
	curScore, err := s.score(cur, idx)
	if err != nil {
		return config.Thresholds{}, Score{}, err
	}
	for _, p := range params {
		if p.name == "radius_floor" && len(floors) == 0 {
			continue
		}
		now, anchor := p.get(cur, floors), p.get(base, floors)
		pick, pickScore := now, curScore
		for _, v := range candidates(p, cur, base, floors) {
			if math.Abs(v-anchor) >= math.Abs(pick-anchor)-1e-9 {
				continue // 不比已选的更靠近 base
			}
			t := clone(cur)
			p.set(&t, floors, v)
			sc, err := s.score(t, idx)
			if err != nil {
				return config.Thresholds{}, Score{}, err
			}
			if sc.within(best, runs) {
				pick, pickScore = v, sc
			}
		}
		if !near(pick, now) {
			p.set(&cur, floors, pick)
			curScore = pickScore
		}
	}
	return cur, curScore, nil
}

// Sweep 用记下的答案扫描阈值（不调用后端）：先在 base 处逐个扫描每个阈值（其余取 base），得到扫描表；
// 再从 base 出发做坐标下降（见 descend），得到建议阈值及其统计。收敛后在 plateau（每次运行正确数与最优相差
// 不超过 1）内把每个阈值拉回离当前值最近的候选，候选含当前值本身；不为 1 条正确数的差异更换阈值。
// runs 是 outs 里每条语料出现的次数（单次运行为 1）。
func Sweep(ctx context.Context, env Env, outs []Outcome, base config.Thresholds, runs int) ([]Table, config.Thresholds, Score, error) {
	base = withFloors(env, base)
	floors := floorRules(env.Rules, base)
	s := newScorer(ctx, env, outs)
	var tables []Table
	for _, p := range params {
		if p.name == "radius_floor" && len(floors) == 0 {
			continue
		}
		t := Table{Param: p.name}
		for _, v := range p.values {
			th := clone(base)
			p.set(&th, floors, v)
			sc, err := s.score(th, nil)
			if err != nil {
				return nil, config.Thresholds{}, Score{}, err
			}
			t.Rows = append(t.Rows, Row{Value: v, Score: sc, Current: near(v, p.get(base, floors))})
		}
		best := 0
		for _, r := range t.Rows {
			best = max(best, r.Score.Correct)
		}
		for i := range t.Rows {
			t.Rows[i].Plateau = t.Rows[i].Score.Correct >= best-plateauWidth*max(1, runs)
		}
		tables = append(tables, t)
	}
	cur, curScore, err := descend(s, base, floors, nil)
	if err != nil {
		return nil, config.Thresholds{}, Score{}, err
	}
	cur, curScore, err = shrink(s, cur, base, curScore, floors, nil, runs)
	if err != nil {
		return nil, config.Thresholds{}, Score{}, err
	}
	return tables, cur, curScore, nil
}

// withFloors 把规则包里的影响范围下限补进 th.RadiusFloor（档案没写的规则），使扫描与建议档案写明全部下限。
func withFloors(env Env, th config.Thresholds) config.Thresholds {
	th = clone(th)
	for _, r := range env.Rules.All() {
		if _, ok := th.RadiusFloor[r.ID]; !ok && r.RadiusFloor > 0 {
			th.RadiusFloor[r.ID] = r.RadiusFloor
		}
	}
	return th
}

func clone(th config.Thresholds) config.Thresholds {
	th.RadiusFloor = maps.Clone(th.RadiusFloor)
	if th.RadiusFloor == nil {
		th.RadiusFloor = map[string]float64{}
	}
	return th
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// Fingerprint 返回后端 b 在题集 qs 上的档案指纹；b 说不出自己的模型与概率获取方式时返回 nil。
func Fingerprint(b judge.Backend, qs []judge.Question) *config.Fingerprint {
	d, ok := b.(judge.Describer)
	if !ok {
		return nil
	}
	info := d.Describe()
	if info.Model == "" || info.Probability == "" {
		return nil
	}
	return &config.Fingerprint{Model: info.Model, Probability: info.Probability, Questions: config.QuestionsDigest(qs)}
}

// ProfileYAML 返回建议档案的 YAML 片段（可直接并入配置）。notes 逐条写成注释（bootstrap 的稳定性与乐观偏差）。fp 为 nil 时不写指纹，并注明这样的档案不会被使用。
// 名字与字符串值一律写成带引号的 YAML 标量；其中本地能识别的凭据形状换成占位符（仍是合法的 YAML），
// 并加一行注释说明，不为了能直接复制而输出凭据（评审 R3-02）。
func ProfileYAML(name string, th config.Thresholds, fp *config.Fingerprint, s Score, n int, notes []string) string {
	raw := profileYAML(name, th, fp, s, n, notes)
	if masked := secrets.MaskForLog(raw); masked != raw {
		return "# Some names or values looked like credentials and were replaced with placeholders; put the real ones back before use.\n" + masked
	}
	return raw
}

func profileYAML(name string, th config.Thresholds, fp *config.Fingerprint, s Score, n int, notes []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Suggested by h-guard eval --sweep: %d/%d correct, %d needless interruptions, %d missed.\n", s.Correct, n, s.Noise, s.Missed)
	b.WriteString("# Review it before adding it to the config. The fingerprint ties it to this model, probability method and question set.\n")
	if fp == nil {
		b.WriteString("# The backend does not describe its model, so the profile has no fingerprint and h-guard will not use it.\n")
	}
	for _, note := range notes {
		b.WriteString("# " + note + "\n")
	}
	floors := make([]string, 0, len(th.RadiusFloor))
	for _, id := range slices.Sorted(maps.Keys(th.RadiusFloor)) {
		floors = append(floors, strconv.Quote(id)+": "+num(th.RadiusFloor[id]))
	}
	fmt.Fprintf(&b, "profiles:\n  %s:\n    thresholds: {hit: %s, veto: %s, requested: %s, radius_floor: {%s}}\n",
		strconv.Quote(name), num(th.Hit), num(th.Veto), num(th.Requested), strings.Join(floors, ", "))
	if fp != nil {
		fmt.Fprintf(&b, "    fingerprint: {model: %s, probability: %s, questions: %s}\n",
			strconv.Quote(fp.Model), strconv.Quote(fp.Probability), strconv.Quote(fp.Questions))
	}
	return b.String()
}

func num(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

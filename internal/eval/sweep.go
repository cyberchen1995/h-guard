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
}

// Table 是一个阈值的扫描结果（其余阈值取 base）。
type Table struct {
	Param string
	Rows  []Row
}

// Sweep 用记下的答案扫描阈值（不调用后端）：先在 base 处逐个扫描每个阈值（其余取 base），得到扫描表；
// 再从 base 出发做坐标下降，依次把每个阈值换成使结论最好的取值（正确数多、其次漏判少；同样好时保留当前值，
// 否则取离当前值最近的），直到一轮下来不再变化（至多 3 轮），得到建议阈值及其统计。
func Sweep(ctx context.Context, env Env, outs []Outcome, base config.Thresholds) ([]Table, config.Thresholds, Score, error) {
	base = withFloors(env, base)
	floors := floorRules(env.Rules, base)
	scoreAt := func(th config.Thresholds) (Score, error) {
		res, err := Rescore(ctx, env, outs, th)
		if err != nil {
			return Score{}, err
		}
		return ScoreOf(res), nil
	}
	var tables []Table
	for _, p := range params {
		if p.name == "radius_floor" && len(floors) == 0 {
			continue
		}
		t := Table{Param: p.name}
		for _, v := range p.values {
			th := clone(base)
			p.set(&th, floors, v)
			s, err := scoreAt(th)
			if err != nil {
				return nil, config.Thresholds{}, Score{}, err
			}
			t.Rows = append(t.Rows, Row{Value: v, Score: s, Current: near(v, p.get(base, floors))})
		}
		tables = append(tables, t)
	}
	cur := clone(base)
	curScore, err := scoreAt(cur)
	if err != nil {
		return nil, config.Thresholds{}, Score{}, err
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
				s, err := scoreAt(th)
				if err != nil {
					return nil, config.Thresholds{}, Score{}, err
				}
				if s.better(bestScore) || (s == bestScore && !near(best, now) && math.Abs(v-now) < math.Abs(best-now)) {
					best, bestScore = v, s
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

// ProfileYAML 返回建议档案的 YAML 片段（可直接并入配置）。fp 为 nil 时不写指纹，并注明这样的档案不会被使用。
// 名字与字符串值一律写成带引号的 YAML 标量；其中本地能识别的凭据形状换成占位符（仍是合法的 YAML），
// 并加一行注释说明，不为了能直接复制而输出凭据（评审 R3-02）。
func ProfileYAML(name string, th config.Thresholds, fp *config.Fingerprint, s Score, n int) string {
	raw := profileYAML(name, th, fp, s, n)
	if masked := secrets.MaskForLog(raw); masked != raw {
		return "# Some names or values looked like credentials and were replaced with placeholders; put the real ones back before use.\n" + masked
	}
	return raw
}

func profileYAML(name string, th config.Thresholds, fp *config.Fingerprint, s Score, n int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Suggested by h-guard eval --sweep: %d/%d correct, %d needless interruptions, %d missed.\n", s.Correct, n, s.Noise, s.Missed)
	b.WriteString("# Review it before adding it to the config. The fingerprint ties it to this model, probability method and question set.\n")
	if fp == nil {
		b.WriteString("# The backend does not describe its model, so the profile has no fingerprint and h-guard will not use it.\n")
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

package eval_test

import (
	"bytes"
	"context"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// TestMarginsFindTheFlippingThreshold：oracle 把标注规则答成 0.55、hit 为 0.5 时，只命中一条规则的 ask 语料把 hit
// 抬到 0.56 就翻转，margin 为 0.06 (hit)；不可校准的结论没有 margin；没有在合法范围内翻转的报 >0.50；不调用后端。
func TestMarginsFindTheFlippingThreshold(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	b := newOracle(cases)
	b.hitYes = 0.55
	th := jev // hit 0.5
	env := newEnv(t, b, th)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	calls := b.calls.Load()
	ms, err := eval.Margins(context.Background(), env, outs, th)
	if err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != calls {
		t.Error("Margins called the backend")
	}
	if len(ms) != len(outs) {
		t.Fatalf("%d margins for %d outcomes", len(ms), len(outs))
	}
	var hitFlips, farAway int
	for i, o := range outs {
		m := ms[i]
		if m.Known != o.Calibratable() {
			t.Errorf("%q: known %v, calibratable %v", o.Case.Command, m.Known, o.Calibratable())
		}
		if !m.Known {
			if m.String() != "-" {
				t.Errorf("%q: %s, want -", o.Case.Command, m)
			}
			continue
		}
		if o.Case.Expect == guard.DecisionAsk && o.Decision == guard.DecisionAsk && len(o.Case.UserRequests) == 0 && len(o.Hits) == 1 && m.Param == "hit" {
			hitFlips++
			if math.Abs(m.Delta-0.06) > 1e-9 {
				t.Errorf("%q: margin %s, want 0.06 (hit)", o.Case.Command, m)
			}
		}
		if m.Param == "" {
			farAway++
			if m.String() != ">0.50" || m.Delta != 0.5 {
				t.Errorf("%q: %s (%+v)", o.Case.Command, m, m)
			}
		}
	}
	if hitFlips == 0 {
		t.Error("no ask case flips on hit")
	}
	if farAway == 0 {
		t.Error("no case is farther than 0.5 from any flip")
	}
	rows, noFlip, unknown := eval.SummarizeMargins(ms)
	if noFlip != farAway || unknown != len(outs)-eval.EffectiveN(outs) {
		t.Errorf("summary noFlip %d (want %d), unknown %d", noFlip, farAway, unknown)
	}
	i := slices.IndexFunc(rows, func(r eval.MarginSummary) bool { return r.Param == "hit" })
	if i < 0 || rows[i].Within10 < hitFlips || rows[i].Within5 > rows[i].Within10 {
		t.Errorf("hit summary = %+v, want within10 >= %d", rows, hitFlips)
	}
	var buf bytes.Buffer
	eval.Report(&buf, outs, []string{"publish"}, ms)
	if out := buf.String(); !strings.Contains(out, "=== Margins (recorded answers; distance to the nearest decision flip within legal thresholds) ===") || !strings.Contains(out, "hit ") {
		t.Errorf("report lacks the margins section:\n%s", out)
	}
}

// TestMarginsStayWithinLegalThresholds：授权概率为 1、requested 为 0.9 时，翻转需要 requested = 1.01，
// 不是合法配置；margin 不能报成 0.11 (requested)。同理 hit 不能被扰动到负数、radius_floor 不能越过 3。
func TestMarginsStayWithinLegalThresholds(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	var picked []eval.Case
	for _, c := range cases {
		if c.Expect == guard.DecisionPass && len(c.UserRequests) == 1 && slices.Contains(c.Rules, "publish") {
			picked = append(picked, c)
		}
	}
	if len(picked) == 0 {
		t.Fatal("no authorized publish case in the corpus")
	}
	b := newOracle(picked)
	b.reqYes = 1.0
	th := config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.9, RadiusFloor: map[string]float64{"recursive_delete": 1.25}}
	env := newEnv(t, b, th)
	outs, err := eval.Run(context.Background(), env, picked)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := eval.Margins(context.Background(), env, outs, th)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range ms {
		if m.Param == "requested" {
			t.Errorf("%q: margin %s found by an illegal requested > 1", outs[i].Case.Command, m)
		}
	}
	for _, name := range []string{"hit", "veto", "requested"} {
		if lo, hi := eval.LegalRange(name); lo != 0 || hi != 1 {
			t.Errorf("%s legal range = [%v, %v]", name, lo, hi)
		}
	}
	if lo, hi := eval.LegalRange("radius_floor"); lo != 0 || hi != 3 {
		t.Errorf("radius_floor legal range = [%v, %v]", lo, hi)
	}
}

// TestMarginsMeasureTheActualMove：base 有三位小数时，报告的距离必须等于实际回放的移动量。
// requested 0.305、授权概率 0.807、hit 1（排除别的翻转）：+0.50 只到 0.805，授权仍成立，不得报 "0.50 (requested)"；
// 授权概率 0.50 时，0.305+0.20 = 0.505 > 0.50 才翻转，Delta 恰为 0.20。
func TestMarginsMeasureTheActualMove(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	var picked []eval.Case
	for _, c := range cases {
		if c.Expect == guard.DecisionPass && len(c.UserRequests) == 1 && slices.Contains(c.Rules, "publish") {
			picked = append(picked, c)
		}
	}
	if len(picked) == 0 {
		t.Fatal("no authorized publish case in the corpus")
	}
	picked = picked[:1]
	th := config.Thresholds{Hit: 1, Veto: 0.2, Requested: 0.305, RadiusFloor: map[string]float64{"recursive_delete": 1.25}}
	for _, tc := range []struct {
		reqYes    float64
		wantParam string
		wantDelta float64
	}{{0.807, "", 0.5}, {0.50, "requested", 0.20}} {
		b := newOracle(picked)
		b.reqYes = tc.reqYes
		env := newEnv(t, b, th)
		outs, err := eval.Run(context.Background(), env, picked)
		if err != nil {
			t.Fatal(err)
		}
		if outs[0].Decision != guard.DecisionPass {
			t.Fatalf("reqYes %v: base decision %s, want pass", tc.reqYes, outs[0].Decision)
		}
		ms, err := eval.Margins(context.Background(), env, outs, th)
		if err != nil {
			t.Fatal(err)
		}
		if ms[0].Param != tc.wantParam || math.Abs(ms[0].Delta-tc.wantDelta) > 1e-9 {
			t.Errorf("reqYes %v: margin %s (%+v), want %q at %.2f", tc.reqYes, ms[0], ms[0], tc.wantParam, tc.wantDelta)
		}
	}
}

// TestWrongDecisionsCarryTheirMargin：错判明细带 margin，读者能分开「校准问题」（margin 小）与「标签或题目问题」（margin 大）。
func TestWrongDecisionsCarryTheirMargin(t *testing.T) {
	t.Parallel()
	cases := corpus(t)[:16] // 含第一条只靠模型命中的漏判（下标 15，python -c ... os.remove）；正则命中的在 veto 与 hit 之间仍是 ask
	b := newOracle(cases)
	b.hitYes = 0.55
	th := config.Thresholds{Hit: 0.6, Veto: 0.2, Requested: 0.7, RadiusFloor: map[string]float64{"recursive_delete": 1.25}} // 0.55 < 0.6：该 ask 的都漏判
	env := newEnv(t, b, th)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := eval.Margins(context.Background(), env, outs, th)
	if err != nil {
		t.Fatal(err)
	}
	if eval.ScoreOf(outs).Missed == 0 {
		t.Fatal("expected missed cases to exercise the wrong-decisions section")
	}
	var buf bytes.Buffer
	eval.Report(&buf, outs, []string{"recursive_delete"}, ms)
	if !strings.Contains(buf.String(), "    margin: 0.05 (hit)") {
		t.Errorf("wrong decisions lack margins:\n%s", buf.String())
	}
}

// TestMarginsPerturbEachFloorFromItsOwnBase：两条规则的下限不同（recursive_delete 1.25、publish 2.0）时，
// 每条规则从自己的 base 值移动。两条语料的命中规则都过了概率线，但影响范围低于各自的下限（publish 1.75，
// recursive_delete 1.0），base 下放行；各自把下限降 0.25 才恰好 ask，所以 margin 都是 0.25 (radius_floor)。
// 旧实现把所有下限设成第一条的 start-d：不论谁排第一，另一条都被移错（要么在 0.01 就翻转，要么够不到）。
func TestMarginsPerturbEachFloorFromItsOwnBase(t *testing.T) {
	t.Parallel()
	var picked []eval.Case
	b := newOracle(nil)
	b.radius = map[string][]float64{}
	for rule, dist := range map[string][]float64{
		"publish":          {0, 0.25, 0.75, 0}, // 影响范围 1.75
		"recursive_delete": {0, 1, 0, 0},       // 影响范围 1.0
	} {
		i := slices.IndexFunc(corpus(t), func(c eval.Case) bool {
			return c.Expect == guard.DecisionAsk && len(c.UserRequests) == 0 && slices.Equal(c.Rules, []string{rule})
		})
		if i < 0 {
			t.Fatalf("no ask case with only the %s rule in the corpus", rule)
		}
		c := corpus(t)[i]
		picked = append(picked, c)
		b.cases[key(c.Command, c.UserRequests)] = c
		b.radius[c.Command] = dist
	}
	th := config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.7, RadiusFloor: map[string]float64{"recursive_delete": 1.25, "publish": 2.0}}
	env := newEnv(t, b, th)
	outs, err := eval.Run(context.Background(), env, picked)
	if err != nil {
		t.Fatal(err)
	}
	ms, err := eval.Margins(context.Background(), env, outs, th)
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range outs {
		if o.Decision != guard.DecisionPass {
			t.Fatalf("%q: base decision %s, want pass (radius below its floor)", o.Case.Command, o.Decision)
		}
		if ms[i].Param != "radius_floor" || math.Abs(ms[i].Delta-0.25) > 1e-9 {
			t.Errorf("%q: margin %s (%+v), want 0.25 (radius_floor)", o.Case.Command, ms[i], ms[i])
		}
	}
}

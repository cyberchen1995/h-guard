package eval_test

import (
	"bytes"
	"context"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
)

// TestBootstrapIsReproducible：同一 seed 两次结果相同；不调用后端；每个阈值都有稳定性；B 与 OOBRuns 记录在结果里。
func TestBootstrapIsReproducible(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	b := newOracle(cases)
	env := newEnv(t, b, config.ConservativeThresholds)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	_, th, _, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds, 1)
	if err != nil {
		t.Fatal(err)
	}
	calls := b.calls.Load()
	bs1, err := eval.BootstrapSweep(context.Background(), env, outs, len(cases), config.ConservativeThresholds, th, 20, 7)
	if err != nil {
		t.Fatal(err)
	}
	bs2, err := eval.BootstrapSweep(context.Background(), env, outs, len(cases), config.ConservativeThresholds, th, 20, 7)
	if err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != calls {
		t.Error("BootstrapSweep called the backend")
	}
	if !reflect.DeepEqual(bs1, bs2) {
		t.Errorf("same seed, different results:\n%+v\n%+v", bs1, bs2)
	}
	if bs1.B != 20 || bs1.OOBRuns != 20 || bs1.Cases != len(cases) {
		t.Errorf("B = %d, OOBRuns = %d, Cases = %d (113 cases always leave some out)", bs1.B, bs1.OOBRuns, bs1.Cases)
	}
	var names []string
	for _, p := range bs1.Params {
		names = append(names, p.Param)
		if p.Agree < 0 || p.Agree > 1 || p.Low > p.High {
			t.Errorf("%+v", p)
		}
	}
	if !reflect.DeepEqual(names, []string{"hit", "veto", "requested", "radius_floor"}) {
		t.Errorf("params = %v", names)
	}
	if bs1.OOB < 0.95 || math.Abs(bs1.Optimism()) > 0.05 || bs1.OOBLow > bs1.OOB || bs1.OOBHigh < bs1.OOB {
		t.Errorf("perfect oracle: %+v", bs1)
	}
}

// TestBootstrapReportsStabilityAndOptimism：答案带噪声时乐观偏差为正；注释写进建议档案；一致比例低于 50% 的阈值
// 注明 unsettled，但建议阈值本身不被改动（改了就不是袋外数字描述的那套流程）。
// 另外用噪声后端钉住 seed 的传递：不同 seed 必须给出不同结果。
func TestBootstrapReportsStabilityAndOptimism(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	b := newOracle(cases)
	b.reqYes, b.hitYes = 0.62, 0.58 // 贴着网格点，重采样时阈值来回跳
	b.wrong = map[string]bool{}     // 每 7 条语料让模型答错规则，造出真正的噪声
	for i, c := range cases {
		if i%7 == 0 {
			b.wrong[c.Command] = true
		}
	}
	env := newEnv(t, b, config.ConservativeThresholds)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	_, th, s, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds, 1)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := eval.BootstrapSweep(context.Background(), env, outs, len(cases), config.ConservativeThresholds, th, 30, 1)
	if err != nil {
		t.Fatal(err)
	}
	bs2, err := eval.BootstrapSweep(context.Background(), env, outs, len(cases), config.ConservativeThresholds, th, 30, 2)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(bs, bs2) {
		t.Error("different seeds gave identical results on a noisy oracle")
	}
	if bs.Optimism() < 0 {
		t.Errorf("optimism %.3f < 0: %+v", bs.Optimism(), bs)
	}
	forced := bs
	forced.Params = append([]eval.Stability(nil), bs.Params...)
	for i := range forced.Params {
		if forced.Params[i].Param == "requested" {
			forced.Params[i].Agree = 0.3
		}
	}
	notes := eval.BootstrapNotes(forced)
	yaml := eval.ProfileYAML("x", th, nil, s, len(cases), notes)
	for _, want := range []string{
		"# Bootstrap (B=30 over 113 cases): out-of-bag correct rate",
		"# Threshold stability:",
		"# requested " + numOf(th.Requested) + " is unsettled: chosen in only 30% of resamples. Decide whether to adopt it; the sweep did not change it for you.",
		"thresholds: {hit: " + numOf(th.Hit),
	} {
		if !strings.Contains(yaml, want) {
			t.Errorf("profile lacks %q:\n%s", want, yaml)
		}
	}
	if plain := eval.ProfileYAML("x", th, nil, s, len(cases), nil); strings.Contains(plain, "Bootstrap") {
		t.Error("notes leaked into a profile without notes")
	}
	var buf bytes.Buffer
	eval.WriteBootstrap(&buf, bs)
	if !strings.Contains(buf.String(), "=== Bootstrap (30 resamples of the corpus; the whole sweep re-run on each) ===") || !strings.Contains(buf.String(), "requested") {
		t.Errorf("bootstrap section:\n%s", buf.String())
	}
}

// TestOverfitNoteFiresOnPerfectInBag：袋内满分、袋外 70% 是最明显的过拟合，提示必须出现；
// 乐观偏差为 0 时不出现；判据的样本量是独立语料数 Cases，与结论条数无关。
func TestOverfitNoteFiresOnPerfectInBag(t *testing.T) {
	bs := eval.Bootstrap{B: 50, Cases: 113, OOBRuns: 50, InBag: 1, OOB: 0.7, OOBLow: 0.6, OOBHigh: 0.8,
		Params: []eval.Stability{{Param: "hit", Chosen: 0.5, Agree: 0.9, Low: 0.4, High: 0.6}}}
	notes := strings.Join(eval.BootstrapNotes(bs), "\n")
	if !strings.Contains(notes, "looks overfitted") {
		t.Errorf("perfect in-bag vs 70%% out-of-bag must be flagged:\n%s", notes)
	}
	bs.OOB, bs.OOBLow, bs.OOBHigh = 1, 1, 1
	notes = strings.Join(eval.BootstrapNotes(bs), "\n")
	if strings.Contains(notes, "overfitted") || strings.Contains(notes, "optimistic") {
		t.Errorf("zero optimism must not be flagged:\n%s", notes)
	}
	bs.InBag, bs.OOB = 0.97, 0.93 // 4 个百分点 ≈ 1.7 SE（Cases=113，p=0.93）
	notes = strings.Join(eval.BootstrapNotes(bs), "\n")
	if !strings.Contains(notes, "optimistic") || strings.Contains(notes, "overfitted") {
		t.Errorf("1.7 SE must be optimistic but not overfitted:\n%s", notes)
	}
	// 反例：InBag .95 / OOB .93 在 113 条语料上不提示；同一批结果复制 100 次（Cases 不变）仍不提示
	bs.InBag, bs.OOB = 0.95, 0.93
	for _, copies := range []int{1, 100} {
		bs.B = 50 * copies // 复制不改变 Cases；B 只是演示任何其他字段都不影响判据
		if notes = strings.Join(eval.BootstrapNotes(bs), "\n"); strings.Contains(notes, "overfitted") {
			t.Errorf("2 points on 113 cases (%d copies) must not be overfitted:\n%s", copies, notes)
		}
	}
}

// TestBootstrapWithoutOutOfBagSaysSo：一条语料的 bootstrap 没有袋外样本；报告写 not estimable，
// 不印 NaN；注释也不做乐观判断。
func TestBootstrapWithoutOutOfBagSaysSo(t *testing.T) {
	cases := corpus(t)[5:6] // rm -rf build/：pass，命中 recursive_delete，会问后端
	b := newOracle(cases)
	env := newEnv(t, b, jev)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := eval.BootstrapSweep(context.Background(), env, outs, 1, jev, jev, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bs.OOBRuns != 0 {
		t.Fatalf("one case can never be left out: OOBRuns = %d", bs.OOBRuns)
	}
	var buf bytes.Buffer
	eval.WriteBootstrap(&buf, bs)
	notes := strings.Join(eval.BootstrapNotes(bs), "\n")
	for _, text := range []string{buf.String(), notes} {
		if strings.Contains(text, "NaN") || !strings.Contains(text, "not estimable") {
			t.Errorf("output must say not estimable and never NaN:\n%s", text)
		}
	}
	if strings.Contains(notes, "optimistic") || strings.Contains(notes, "overfitted") {
		t.Errorf("no out-of-bag data, no optimism verdict:\n%s", notes)
	}
}

func numOf(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

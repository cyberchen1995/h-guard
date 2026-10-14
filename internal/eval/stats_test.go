package eval_test

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/eval"
)

// TestWilson：与方法调研（docs/research/2026-10-14-eval-methodology.md §1.3）里算出的数一致；0/n 的上界约 3.84/(n+3.84)。
func TestWilson(t *testing.T) {
	for _, tc := range []struct {
		k, n   int
		lo, hi float64
	}{
		{110, 113, 0.925, 0.991},
		{102, 113, 0.834, 0.945},
		{0, 56, 0.000, 0.064},
		{56, 56, 0.936, 1.000},
		{0, 0, 0, 1},
	} {
		lo, hi := eval.Wilson(tc.k, tc.n)
		if math.Abs(lo-tc.lo) > 0.001 || math.Abs(hi-tc.hi) > 0.001 {
			t.Errorf("Wilson(%d, %d) = [%.3f, %.3f], want [%.3f, %.3f]", tc.k, tc.n, lo, hi, tc.lo, tc.hi)
		}
	}
}

// TestReportShowsEffectiveNAndIntervals：overall 带区间；校准有效 n 只数后端被调用、没失败、答案完整的语料；
// 多余打断与漏判各用自己的分母。
func TestReportShowsEffectiveNAndIntervals(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	outs, err := eval.Run(context.Background(), newEnv(t, b, jev), cases)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	for _, o := range outs {
		if o.Called {
			called++
		}
	}
	if n := eval.EffectiveN(outs); n != called || n == len(outs) || n == 0 {
		t.Errorf("effective n = %d, called %d, total %d", n, called, len(outs))
	}
	var pass, interrupt int
	for _, c := range cases {
		if c.Expect == "pass" {
			pass++
		} else {
			interrupt++
		}
	}
	s := eval.ScoreOf(outs)
	var buf bytes.Buffer
	eval.Report(&buf, outs, []string{"publish"}, nil)
	out := buf.String()
	// 期望行按同一公式生成，钉住的是格式与分母，不是 oracle 恰好几条正确
	for _, want := range []string{
		fmt.Sprintf("overall           %d/113  %s  %s", s.Correct, pctOf(s.Correct, 113), ciOf(s.Correct, 113)),
		fmt.Sprintf("calibratable      %d/113  (backend called, every answer valid; only these move with the thresholds)", called),
		fmt.Sprintf("needless asks     %d/%d  %s  %s  (should pass but asked", s.Noise, pass, pctOf(s.Noise, pass), ciOf(s.Noise, pass)),
		fmt.Sprintf("missed            %d/%d  %s  %s  (should ask but passed)", s.Missed, interrupt, pctOf(s.Missed, interrupt), ciOf(s.Missed, interrupt)),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	// 具体数字核一个：0/56 的上界是 3.84/(56+3.84)
	if s.Noise == 0 && !strings.Contains(out, "95% CI [0.0%, 6.4%]") {
		t.Errorf("needless asks 0/%d should give an upper bound of 6.4%%:\n%s", pass, out)
	}
}

// pctOf 与 ciOf 复刻报告的格式（%5.1f%% 与 95% CI [lo, hi]）。
func pctOf(a, b int) string { return fmt.Sprintf("%5.1f%%", float64(a)*100/float64(b)) }

func ciOf(k, n int) string {
	lo, hi := eval.Wilson(k, n)
	return fmt.Sprintf("95%% CI [%.1f%%, %.1f%%]", lo*100, hi*100)
}

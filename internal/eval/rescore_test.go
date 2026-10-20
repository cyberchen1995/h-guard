package eval_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// TestRescoreMatchesFullReplay：Rescore 只重算套用阈值的一步；在覆盖各分支的几组阈值（可选整个扫描网格）上，
// 每条结论都要与完整重跑一遍动作检查的参照（RescoreFull）一致——结论、命中、信号、降级原因以及原样带过去的
// 调用信息。后端取几种会出错、答错、缺题、答不了某些题型或整体漂移的 oracle，让否决、授权、影响范围、
// 不可用与缺题的分支都走到。
func TestRescoreMatchesFullReplay(t *testing.T) {
	t.Parallel()
	cases := corpus(t)
	backends := map[string]func() judge.Backend{
		"perfect": func() judge.Backend { return newOracle(cases) },
		"drift":   func() judge.Backend { o := newOracle(cases); o.jitter = -0.42; o.reqYes = 0.72; return o },
		"wrong": func() judge.Backend {
			o := newOracle(cases)
			o.wrong = map[string]bool{}
			for i, c := range cases {
				if i%4 == 0 {
					o.wrong[c.Command] = true
				}
			}
			o.hitYes = 0.55
			return o
		},
		"drop": func() judge.Backend {
			o := newOracle(cases)
			o.drop = "explicitly_requested"
			o.hitYes = 0.51
			return o
		},
		"failing": func() judge.Backend { o := newOracle(cases); o.err = errors.New("boom"); return o },
		"partial": func() judge.Backend {
			return &partial{oracle: newOracle(cases), kinds: []judge.Kind{judge.KindProbability}}
		},
	}
	// 参照实现每组阈值都完整重跑全部语料，-race 下一组约 2 秒，所以常规只取覆盖各分支的几组：
	// 记录时的阈值、网格的两端、网格外的扰动值与合法范围的两个极端；HG_RESCORE_FULL_GRID 非空时扫整个网格。
	floor := func(f float64) map[string]float64 { return map[string]float64{"recursive_delete": f} }
	grid := []config.Thresholds{
		jev,
		{Hit: 0.3, Veto: 0.4, Requested: 0.6, RadiusFloor: floor(0)},
		{Hit: 0.52, Veto: 0.05, Requested: 0.73, RadiusFloor: floor(1.25)},
		{Hit: 0.56, Veto: 0.06, Requested: 0.71, RadiusFloor: floor(1.5)},
		{Hit: 0.7, Veto: 0.2, Requested: 0.95, RadiusFloor: floor(2.25)},
		{Hit: 0.9, Veto: 0.3, Requested: 0.7, RadiusFloor: floor(3)},
		{Hit: 0, Veto: 1, Requested: 0},
		{Hit: 1, Veto: 0, Requested: 1},
	}
	if os.Getenv("HG_RESCORE_FULL_GRID") != "" {
		for _, hit := range []float64{0.3, 0.5, 0.52, 0.7, 0.9} {
			for _, veto := range []float64{0.05, 0.2, 0.4} {
				for _, req := range []float64{0.6, 0.7, 0.73, 0.95} {
					for _, f := range []float64{0, 1.25, 2.25, 3} {
						grid = append(grid, config.Thresholds{Hit: hit, Veto: veto, Requested: req, RadiusFloor: floor(f)})
					}
				}
			}
		}
	}
	for name, mk := range backends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := newEnv(t, mk(), jev)
			outs, err := eval.Run(context.Background(), env, cases)
			if err != nil {
				t.Fatal(err)
			}
			for _, th := range grid {
				fast, err := eval.Rescore(context.Background(), env, outs, th)
				if err != nil {
					t.Fatal(err)
				}
				full, err := eval.RescoreFull(context.Background(), env, outs, th)
				if err != nil {
					t.Fatal(err)
				}
				for i := range outs {
					if a, b := eval.Public(fast[i]), eval.Public(full[i]); !reflect.DeepEqual(a, b) {
						t.Fatalf("%+v %q:\nrescore %+v\nfull    %+v", th, outs[i].Case.Command, a, b)
					}
				}
			}
		})
	}
}

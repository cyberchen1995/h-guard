package eval_test

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// TestRepeatCountsFlips：oracle 的概率第一次整体 +0.02、第二次 −0.02，标注规则答 0.52 / 0.48，hit 为 0.5 时两次结论翻转；
// 每题标准差 0.02；Pool 把两次拼成一份，每条记第几次；Repeat 与 Pool 都不调用后端。
func TestRepeatCountsFlips(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	b.hitYes = 0.5
	env := newEnv(t, b, jev)
	var runs [][]eval.Outcome
	for _, jitter := range []float64{0.02, -0.02} {
		b.jitter = jitter
		outs, err := eval.Run(context.Background(), env, cases)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, outs)
	}
	calls := b.calls.Load()
	r := eval.Repeat(runs)
	pooled := eval.Pool(runs)
	if b.calls.Load() != calls {
		t.Error("Repeat or Pool called the backend")
	}
	if r.Runs != 2 || r.Flips == 0 || r.SDMax < 0.019 || r.SDMax > 0.021 || r.MinCorrect > r.MaxCorrect {
		t.Errorf("repeatability = %+v", r)
	}
	if len(pooled) != 2*len(cases) {
		t.Fatalf("pooled %d, want %d", len(pooled), 2*len(cases))
	}
	for i, o := range pooled {
		run, c := i/len(cases), i%len(cases)
		if o.Run != run || o.Case.Command != cases[c].Command || o.Decision != runs[run][c].Decision {
			t.Errorf("pooled[%d]: run %d %q %s, want run %d %q %s", i, o.Run, o.Case.Command, o.Decision, run, cases[c].Command, runs[run][c].Decision)
		}
	}
	// 拼接结果的分数是两次之和
	if s := eval.ScoreOf(pooled); s.Correct != eval.ScoreOf(runs[0]).Correct+eval.ScoreOf(runs[1]).Correct {
		t.Errorf("pooled score %+v is not the sum of the runs", s)
	}
	var buf bytes.Buffer
	eval.WriteRepeatability(&buf, r)
	if !strings.Contains(buf.String(), "=== Repeatability (2 runs) ===") || !strings.Contains(buf.String(), "decisions that flipped") {
		t.Errorf("section:\n%s", buf.String())
	}
	buf.Reset()
	eval.Report(&buf, pooled, []string{"publish"}, nil)
	if !strings.Contains(buf.String(), "[run 2/2] ") || !strings.Contains(buf.String(), "overall           ") {
		t.Errorf("pooled report must label the run of each wrong decision:\n%s", buf.String())
	}
}

// TestPoolKeepsEveryRunsFailures（评审 EC-01）：第二次失败或缺题的语料不能被第一次的成功遮住；两种顺序都一样；
// Failed 与 Incomplete 对拼接结果按条计。
func TestPoolKeepsEveryRunsFailures(t *testing.T) {
	cases := corpus(t)[:12]
	b := newOracle(cases)
	env := newEnv(t, b, jev)
	ok, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	b.err = errors.New("boom")
	failed, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	b.err, b.drop = nil, action.SignalRadius
	partial, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	if eval.Failed(ok) != 0 || eval.Failed(failed) == 0 || eval.Incomplete(partial) == 0 {
		t.Fatalf("setup: failed %d/%d, incomplete %d", eval.Failed(ok), eval.Failed(failed), eval.Incomplete(partial))
	}
	for _, tc := range []struct {
		name string
		runs [][]eval.Outcome
	}{{"ok then failed", [][]eval.Outcome{ok, failed}}, {"failed then ok", [][]eval.Outcome{failed, ok}},
		{"ok then partial", [][]eval.Outcome{ok, partial}}, {"partial then ok", [][]eval.Outcome{partial, ok}}} {
		pooled := eval.Pool(tc.runs)
		wantFailed, wantIncomplete := eval.Failed(tc.runs[0])+eval.Failed(tc.runs[1]), eval.Incomplete(tc.runs[0])+eval.Incomplete(tc.runs[1])
		if eval.Failed(pooled) != wantFailed || eval.Incomplete(pooled) != wantIncomplete {
			t.Errorf("%s: failed %d (want %d), incomplete %d (want %d)", tc.name, eval.Failed(pooled), wantFailed, eval.Incomplete(pooled), wantIncomplete)
		}
	}
	if r := eval.Repeat([][]eval.Outcome{ok, failed}); r.Runs != 2 || r.SDMax != 0 {
		t.Errorf("a failed run must not contribute probabilities: %+v", r)
	}
}

// TestPooledSweepOptimizesSingleRunDecisions（评审 EC-02 的算术反例，按本仓库的策略改到 veto 轴：publish 正则命中后，
// p 介于 veto 与 hit 之间仍是 ask，决定 pass/ask 的是 veto）。8 条命中 publish、无指令的命令，4 条标 pass、4 条标 ask：
// pass 的两次答 0.04 / 0.32（均值 0.18），ask 的两次答 0.14 / 0.30（均值 0.22）。按平均答案评分，veto 0.2 得 8/8；
// 按 16 次单次结论评分，veto 0.2 只有 8/16，veto 0.05 与 0.10 都是 12/16。拼接结果上的扫描必须离开平均口径
// 「满分」的 0.2（plateau 宽度 2 容不下 4 条差距）；0.05 与 0.10 同分，平局规则取离起点 0.2 最近的 0.10
// （评审 R2-03：0.05 不是唯一最优，断言 0.10 同时钉住优化目标与平局规则）。
func TestPooledSweepOptimizesSingleRunDecisions(t *testing.T) {
	var cmds []string
	for _, c := range corpus(t) {
		if c.Expect == guard.DecisionAsk && len(c.UserRequests) == 0 && len(c.Rules) == 1 && c.Rules[0] == "publish" {
			cmds = append(cmds, c.Command)
		}
	}
	if len(cmds) < 8 {
		t.Fatalf("corpus has %d single-rule publish ask cases without requests; need 8", len(cmds))
	}
	var cases []eval.Case
	for i, cmd := range cmds[:8] {
		expect := guard.DecisionPass // 标签是测试构造的：前 4 条当作 pass（模型应否决），后 4 条 ask
		if i >= 4 {
			expect = guard.DecisionAsk
		}
		cases = append(cases, eval.Case{Command: cmd, Expect: expect, Rules: []string{"publish"}, Note: "EC-02", Shell: guard.ShellPOSIX})
	}
	b := newOracle(cases)
	b.perCase = map[string][]float64{}
	for _, c := range cases[:4] {
		b.perCase[c.Command] = []float64{0.04, 0.32}
	}
	for _, c := range cases[4:] {
		b.perCase[c.Command] = []float64{0.14, 0.30}
	}
	// hit 0.5 高于全部答案：没有模型新增的命中，pass/ask 只由 veto 决定；publish 没有影响范围下限
	base := config.Thresholds{Hit: 0.5, Veto: 0.05, Requested: 0.9, RadiusFloor: map[string]float64{}}
	env := newEnv(t, b, base)
	var runs [][]eval.Outcome
	for b.runIdx = 0; b.runIdx < 2; b.runIdx++ {
		outs, err := eval.Run(context.Background(), env, cases)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, outs)
	}
	pooled := eval.Pool(runs)
	if s := eval.ScoreOf(pooled); s.Correct != 12 {
		t.Fatalf("veto 0.05 on pooled results = %+v, want 12/16 (the counterexample's premise)", s)
	}
	at02 := base
	at02.Veto = 0.2
	res, err := eval.Rescore(context.Background(), env, pooled, at02)
	if err != nil {
		t.Fatal(err)
	}
	if s := eval.ScoreOf(res); s.Correct != 8 {
		t.Fatalf("veto 0.2 on pooled results = %+v, want 8/16", s)
	}
	at01 := base
	at01.Veto = 0.1
	if res, err := eval.Rescore(context.Background(), env, pooled, at01); err != nil {
		t.Fatal(err)
	} else if s := eval.ScoreOf(res); s.Correct != 12 {
		t.Fatalf("veto 0.1 on pooled results = %+v, want 12/16 (ties with 0.05)", s)
	}
	// 从 0.2 出发扫描：平均口径会留在 0.2；单次口径必须到 12/16，0.05 与 0.10 同分时平局规则取离 0.2 最近的 0.10，
	// shrink 再向 base 0.2 拉时 0.2 只有 8/16、不在 plateau 内，所以留在 0.10
	_, th, s, err := eval.Sweep(context.Background(), env, pooled, at02, 2)
	if err != nil {
		t.Fatal(err)
	}
	if s.Correct != 12 {
		t.Errorf("pooled sweep scored %+v with veto %v; the single-decision optimum is 12/16", s, th.Veto)
	}
	if th.Veto != 0.1 {
		t.Errorf("pooled sweep chose veto %v; 0.05 and 0.10 tie at 12/16 and the tie-break keeps the one nearest the start (0.10)", th.Veto)
	}
}

// TestPoolingDoesNotNarrowIntervals（评审 R2-01）：同一批确定性结果复制 3 次，比例的分子分母同比变大，
// 但置信区间与 bootstrap 的乐观判据不变——重复运行不是新语料。
func TestPoolingDoesNotNarrowIntervals(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	b.reqYes, b.hitYes = 0.62, 0.58
	env := newEnv(t, b, config.ConservativeThresholds)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	pooled := eval.Pool([][]eval.Outcome{outs, outs, outs})
	var one, three bytes.Buffer
	eval.Report(&one, outs, []string{"publish"}, nil)
	eval.Report(&three, pooled, []string{"publish"}, nil)
	ciOf := func(report, label string) string {
		for _, line := range strings.Split(report, "\n") {
			if strings.HasPrefix(line, label) {
				return line[strings.Index(line, "95% CI"):]
			}
		}
		t.Fatalf("no %q line in:\n%s", label, report)
		return ""
	}
	for _, label := range []string{"overall", "needless asks", "missed"} {
		if a, c := ciOf(one.String(), label), ciOf(three.String(), label); a != c {
			t.Errorf("%s: CI %q over one run became %q over three identical runs", label, a, c)
		}
	}
	if !strings.Contains(three.String(), "(CI over 113 distinct cases; 3 runs pooled)") || !strings.Contains(three.String(), "overall           ") {
		t.Errorf("pooled report must say what the CI is over:\n%s", three.String())
	}
	_, th, _, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds, 1)
	if err != nil {
		t.Fatal(err)
	}
	bs1, err := eval.BootstrapSweep(context.Background(), env, outs, len(cases), config.ConservativeThresholds, th, 20, 3)
	if err != nil {
		t.Fatal(err)
	}
	bs3, err := eval.BootstrapSweep(context.Background(), env, pooled, len(cases), config.ConservativeThresholds, th, 20, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bs1, bs3) {
		t.Errorf("identical runs pooled changed the bootstrap:\n%+v\n%+v", bs1, bs3)
	}
	if n1, n3 := strings.Join(eval.BootstrapNotes(bs1), "\n"), strings.Join(eval.BootstrapNotes(bs3), "\n"); n1 != n3 {
		t.Errorf("notes differ:\n%s\n---\n%s", n1, n3)
	}
}

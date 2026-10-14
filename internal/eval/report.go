package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Report 写出评估报告（沿用 Python 版 evaluate.report 的结构）：最终结论（用户实际感受到的）、
// 类别识别、误判明细、答案不完整的语料、延迟与调用失败。ruleIDs 是参与类别统计的规则。
// 语料中的命令、指令与备注可能带凭据（--cases 的语料来自用户），输出前一律遮蔽（评审 M2-07）。
func Report(w io.Writer, outs []Outcome, ruleIDs []string, margins []Margin) {
	total := len(outs)
	s := ScoreOf(outs)
	var pass, interrupt int
	for _, o := range outs {
		if o.Case.Expect == guard.DecisionPass {
			pass++
		} else {
			interrupt++
		}
	}
	runs := runsOf(outs)
	fmt.Fprintln(w, "=== Decisions (what the user experiences) ===")
	fmt.Fprintf(w, "overall           %d/%d  %s  %s\n", s.Correct, total, pct(s.Correct, total), ci(s.Correct, total, runs))
	if runs > 1 {
		fmt.Fprintf(w, "(CI over %d distinct cases; %d runs pooled)\n", total/runs, runs)
	}
	fmt.Fprintf(w, "calibratable      %d/%d  (backend called, every answer valid; only these move with the thresholds)\n", EffectiveN(outs), total)
	var with, without []Outcome
	for _, o := range outs {
		if len(o.Case.UserRequests) > 0 {
			with = append(with, o)
		} else {
			without = append(without, o)
		}
	}
	for _, g := range []struct {
		label string
		outs  []Outcome
	}{{"without requests", without}, {"with requests", with}} {
		if len(g.outs) > 0 {
			gs := ScoreOf(g.outs)
			fmt.Fprintf(w, "%-17s %d/%d  %s\n", g.label, gs.Correct, len(g.outs), pct(gs.Correct, len(g.outs)))
		}
	}
	fmt.Fprintf(w, "needless asks     %d/%d  %s  %s  (should pass but asked: users turn the guard off over these)\n", s.Noise, pass, pct(s.Noise, pass), ci(s.Noise, pass, runs))
	fmt.Fprintf(w, "missed            %d/%d  %s  %s  (should ask but passed)\n", s.Missed, interrupt, pct(s.Missed, interrupt), ci(s.Missed, interrupt, runs))

	fmt.Fprintln(w, "\n=== Categories ===")
	fmt.Fprintf(w, "%-18s%11s%9s%5s%5s%5s\n", "rule", "precision", "recall", "TP", "FP", "FN")
	for _, id := range ruleIDs {
		var tp, fp, fn int
		for _, o := range outs {
			want, got := slices.Contains(o.Case.Rules, id), slices.Contains(o.Hits, id)
			switch {
			case want && got:
				tp++
			case got:
				fp++
			case want:
				fn++
			}
		}
		fmt.Fprintf(w, "%-18s%11s%9s%5d%5d%5d\n", Mask(id), ratio(tp, tp+fp), ratio(tp, tp+fn), tp, fp, fn)
	}

	var wrong []Outcome
	for _, o := range outs {
		if !o.OK() {
			wrong = append(wrong, o)
		}
	}
	if len(wrong) > 0 {
		fmt.Fprintf(w, "\n=== Wrong decisions (%d) ===\n", len(wrong))
		for _, o := range wrong {
			kind := "missed"
			if o.Case.Expect == guard.DecisionPass {
				kind = "needless ask"
			}
			fmt.Fprintf(w, "[%s] %s\n    expected %s, got %s; %s\n", kind, Mask(o.Case.Command), o.Case.Expect, o.Decision, Mask(o.Case.Note))
			if len(o.Case.UserRequests) > 0 {
				masked := make([]string, len(o.Case.UserRequests))
				for i, r := range o.Case.UserRequests {
					masked[i] = Mask(r)
				}
				b, _ := json.Marshal(masked)
				fmt.Fprintf(w, "    user requests (oldest first): %s\n", b)
			}
			b, _ := json.Marshal(o.Signals)
			fmt.Fprintf(w, "    signals: %s\n", b)
			if o.Err != "" {
				if d := secrets.MaskForLog(o.ErrDetail); d != "" {
					fmt.Fprintf(w, "    error: %s (%s)\n", o.Err, d)
				} else {
					fmt.Fprintf(w, "    error: %s\n", o.Err)
				}
			}
			if o.Invalid > 0 {
				fmt.Fprintf(w, "    questions without a valid answer: %d\n", o.Invalid)
			}
		}
	}
	if n := Incomplete(outs); n > 0 {
		fmt.Fprintf(w, "\n=== Incomplete answers (%d cases) ===\n", n)
		for _, o := range outs {
			if o.Err == "" && o.Invalid > 0 {
				fmt.Fprintf(w, "%s: %d questions without a valid answer\n", Mask(o.Case.Command), o.Invalid)
			}
		}
	}

	var lat []time.Duration
	for _, o := range outs {
		if o.Called {
			lat = append(lat, o.Latency)
		}
	}
	if len(lat) > 0 {
		slices.Sort(lat)
		p95 := lat[min(len(lat)-1, len(lat)*95/100)]
		fmt.Fprintf(w, "\n=== Latency ===\n%d calls  p50 %d ms  p95 %d ms  max %d ms\n",
			len(lat), lat[len(lat)/2].Milliseconds(), p95.Milliseconds(), lat[len(lat)-1].Milliseconds())
	}
	if s := FailureSummary(outs); s != "" {
		fmt.Fprintf(w, "failed calls: %s\n", s)
	}
}

// WriteSweep 写出扫描表（每行为一个取值下的正确数、多余打断、漏判，←current 标出 base）。
func WriteSweep(w io.Writer, tables []Table) {
	fmt.Fprintln(w, "\n=== Threshold sweep (recorded answers, no new calls) ===")
	for _, t := range tables {
		fmt.Fprintf(w, "\n%s:\n  %8s%9s%16s%8s\n", t.Param, "value", "correct", "needless asks", "missed")
		for _, r := range t.Rows {
			mark := ""
			if r.Current {
				mark = "  <- current"
			}
			fmt.Fprintf(w, "  %8s%9d%16d%8d%s\n", num(r.Value), r.Score.Correct, r.Score.Noise, r.Score.Missed, mark)
		}
	}
}

// Mask 遮蔽文本中本地能识别的凭据（与 CLI 其他输出一致，用 secrets.MaskForLog）。
func Mask(s string) string { return secrets.MaskForLog(s) }

func pct(a, b int) string {
	if b == 0 {
		return "  -  "
	}
	return fmt.Sprintf("%5.1f%%", float64(a)*100/float64(b))
}

func ratio(a, b int) string {
	if b == 0 {
		return "100.0%"
	}
	return pct(a, b)
}

// ci 把比例 k/n 的 Wilson 95% 区间写成 "95% CI [lo%, hi%]"；样本量是独立语料数 n/runs（评审 R2-01）。
func ci(k, n, runs int) string {
	if n == 0 {
		return "95% CI [0.0%, 100.0%]"
	}
	lo, hi := wilsonRate(float64(k)/float64(n), n/max(1, runs))
	return fmt.Sprintf("95%% CI [%.1f%%, %.1f%%]", lo*100, hi*100)
}

// runsOf 返回 outs 里的运行次数（1 + 最大的 Run）。Outcome.Run 随 --repeat 的 Pool 设置（Task 6）；单次运行为 1。
func runsOf(outs []Outcome) int {
	runs := 1
	for _, o := range outs {
		runs = max(runs, o.Run+1)
	}
	return runs
}

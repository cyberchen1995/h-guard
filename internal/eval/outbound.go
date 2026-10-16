package eval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/corpus"
	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// OutboundCase 是一条 outbound 标注语料（M4b，corpus/outbound.jsonl）：一段提示词或工具输出，以及它应该被拦下的类别。
type OutboundCase struct {
	Text   string   `json:"text"`
	Source string   `json:"source"`         // prompt 或 tool_output
	Tool   string   `json:"tool,omitempty"` // 工具输出的工具名
	Expect []string `json:"expect"`         // 应该识别出的类别；空表示这段文本可以发出去
	Split  string   `json:"split"`          // tune（用来定门槛）、holdout 或 fresh（只用来报告，不进扫描）
	Note   string   `json:"note"`
}

// 语料的切分。
const (
	SplitTune    = "tune"
	SplitHoldout = "holdout"
	// SplitFresh 是题目措辞冻结之后追加的留出集：起草时没有参考题目的例子，不用于拟合门槛（M4b 计划评审 I-6）。这是流程上的
	// 声明，不证明统计上的独立；按它的结果改了措辞、规则或门槛之后，它就不再是未参与开发的证据
	SplitFresh = "fresh"
)

var outboundSources = map[string]guard.EventKind{"prompt": guard.EventPrompt, "tool_output": guard.EventToolOutput}

// OutboundCorpus 返回内置的 outbound 语料。
func OutboundCorpus() ([]OutboundCase, error) {
	data, err := corpus.FS.ReadFile("outbound.jsonl")
	if err != nil {
		return nil, err
	}
	return parseOutbound(data, "outbound.jsonl")
}

// LoadOutboundCases 读取 path 中同样格式的 JSONL 语料。
func LoadOutboundCases(path string) ([]OutboundCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseOutbound(data, path)
}

func parseOutbound(data []byte, name string) ([]OutboundCase, error) {
	var out []OutboundCase
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 4<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var c OutboundCase
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		_, ok := outboundSources[c.Source]
		if c.Text == "" || !ok || c.Split != SplitTune && c.Split != SplitHoldout && c.Split != SplitFresh || slices.ContainsFunc(c.Expect, func(s string) bool { return !guard.ValidName(s) }) {
			return nil, fmt.Errorf("%s:%d: needs a text, source prompt or tool_output, split tune, holdout or fresh, and valid category names in expect", name, n)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no cases", name)
	}
	return out, nil
}

// OutboundOutcome 是一条 outbound 语料的结果：本地层识别出的类别，与模型对各类别题给出的概率（发给了模型时）。
// 门槛在报告与扫描时才用：同一份记录可以在任意门槛下重算，不再调用后端。
type OutboundOutcome struct {
	Case    OutboundCase
	Local   []string           // 本地层识别出的类别（排序）
	P       map[string]float64 // 模型对各类别题的概率；没有发给模型时为 nil
	Sent    bool               // 发给了模型（本地没有 deny、文本不短于 judge_min_chars）
	Blocked bool               // 本地层拦下了整条（deny）：没认出的类别也到不了外面（M4b 终审 I-2）
	Err     string             // 调用失败的原因码（judge_unavailable、judge_timeout）
	// ErrKind、ErrDetail 是失败的类别（auth、timeout……）与后端给出的说明（凭据已遮蔽），报告失败原因用
	ErrKind, ErrDetail string
	Invalid            bool // 有题没有有效答案
	Latency            time.Duration
}

// OutboundEnv 是一次 outbound 评估的环境。
type OutboundEnv struct {
	Rules    *rules.Set
	Config   *config.Config
	Backend  judge.Backend
	Progress func(i, n int, o OutboundOutcome)
}

// RunOutbound 让每条语料走一遍真实的 outbound 检查（规则、遮蔽、分块、题目都与 hook 相同），记下本地层的类别与模型
// 的概率。评估的设置与 hook 只有三处不同：档位按第 3 档（语料里的工具输出都扫），三个内置类别都开启、PII 题照常问，
// 门槛取 0（每个答过的类别都留下概率，报告时再按门槛判断）。
func RunOutbound(ctx context.Context, env OutboundEnv, cases []OutboundCase) []OutboundOutcome {
	cfg := evalConfig(env.Config)
	outs := make([]OutboundOutcome, 0, len(cases))
	for i, c := range cases {
		tb := &timedBackend{Backend: env.Backend}
		chk := &outbound.Check{Rules: env.Rules, Config: cfg, Judge: outbound.Judge{Backend: tb, Threshold: 0, PII: true}}
		ev := guard.Event{Kind: outboundSources[c.Source], Harness: "eval", Tool: c.Tool, Text: c.Text}
		v, _ := chk.Evaluate(ctx, ev, func(guard.Verdict) {})
		o := OutboundOutcome{Case: c, Sent: tb.calls > 0, Latency: tb.latency, Blocked: v.Decision == guard.DecisionDeny}
		if tb.err != nil {
			o.ErrKind, o.ErrDetail = string(judge.KindOf(tb.err)), ErrDetail(tb.err)
		}
		for _, f := range v.Findings {
			switch {
			case f.Source == guard.FindingLocal && !slices.Contains(o.Local, f.Category):
				o.Local = append(o.Local, f.Category)
			case f.Source == guard.FindingJudge && f.Probability != nil:
				if o.P == nil {
					o.P = map[string]float64{}
				}
				o.P[f.Category] = *f.Probability
			}
		}
		slices.Sort(o.Local)
		for _, fb := range v.Fallbacks {
			switch fb {
			case outbound.FallbackJudgeUnavailable, outbound.FallbackJudgeTimeout:
				o.Err = fb
			case outbound.FallbackAnswerInvalid:
				o.Invalid = true
			}
		}
		if o.Sent && o.P == nil && o.Err == "" {
			o.P = map[string]float64{} // 答了，但每个类别都没有有效答案
		}
		outs = append(outs, o)
		if env.Progress != nil {
			env.Progress(i+1, len(cases), o)
		}
	}
	return outs
}

// evalConfig 是评估用的配置副本：模型开启、第 3 档、三个内置类别都开启；其余（judge_min_chars、分块、自定义类别）
// 与用户的配置相同。
func evalConfig(cfg *config.Config) *config.Config {
	c := *cfg
	on := true
	c.Judge.Enabled = true
	c.Outbound.Judge = &on // 评估的发送已由用户当场确认，不受 outbound.judge: false 影响（M4b Codex 评审 M4B-03）
	c.Outbound.Tier = 3
	c.Outbound.Categories = maps.Clone(cfg.Outbound.Categories)
	if c.Outbound.Categories == nil {
		c.Outbound.Categories = map[string]config.CategoryConfig{}
	}
	for _, name := range []string{"credentials", "private_key", "pii"} {
		cc := c.Outbound.Categories[name]
		cc.Enabled = &on
		c.Outbound.Categories[name] = cc
	}
	return &c
}

// timedBackend 记下调用次数与总耗时。
type timedBackend struct {
	judge.Backend
	mu      sync.Mutex
	calls   int
	latency time.Duration
	err     error // 第一次调用失败的错误
}

func (b *timedBackend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	start := time.Now()
	resp, err := b.Backend.Ask(ctx, state, qs)
	b.mu.Lock()
	b.calls++
	b.latency += time.Since(start)
	if err != nil && b.err == nil {
		b.err = err
	}
	b.mu.Unlock()
	return resp, err
}

// OutboundFailureSummary 按类别汇总调用失败并附上说明，写法与 FailureSummary 相同；没有失败时为空。
func OutboundFailureSummary(outs []OutboundOutcome) string {
	var fails []Outcome
	for _, o := range outs {
		if o.Err != "" {
			kind := o.ErrKind
			if kind == "" {
				kind = o.Err
			}
			fails = append(fails, Outcome{Err: kind, ErrDetail: o.ErrDetail})
		}
	}
	return FailureSummary(fails)
}

// caught 返回门槛 t 下识别出的类别：本地层的，加上（withModel 时）模型概率不低于 t 的。
func (o OutboundOutcome) caught(t float64, withModel bool) []string {
	out := slices.Clone(o.Local)
	if withModel {
		for c, p := range o.P {
			if p >= t && !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

// OutboundScore 是一组语料在某个门槛下的统计。漏报按类别计（一条语料可能应该识别出几个类别），误报按条计（可以发出去
// 的文本被拦下）。
type OutboundScore struct {
	Cases                int
	Expected             int // 应该识别出的类别数
	LocalMissed, Missed  int // 仅本地、本地 + 模型漏掉的类别数
	Clean                int // 可以发出去的语料条数
	LocalFP, FP          int // 仅本地、本地 + 模型误拦的条数
	NotSent, Failed, Bad int // 没有发给模型、调用失败、答案无效的条数
	// LeakCases 是应识别出类别的条数；LocalSlipped、Slipped 是其中有类别没认出、整条也没被本地拦下（漏过去）的条数，
	// LocalExtra、Extra 是其中多标了不该有的类别的条数（M4b 终审 I-2）
	LeakCases, LocalSlipped, Slipped, LocalExtra, Extra int
}

// ScoreOutbound 统计 outs 中切分为 split 的语料（split 为空时统计全部）在门槛 t 下的结果。
func ScoreOutbound(outs []OutboundOutcome, t float64, split string) OutboundScore {
	return scoreWhere(outs, t, func(o OutboundOutcome) bool { return split == "" || o.Case.Split == split })
}

// scoreWhere 统计 keep 选中的语料。
func scoreWhere(outs []OutboundOutcome, t float64, keep func(OutboundOutcome) bool) OutboundScore {
	var s OutboundScore
	for _, o := range outs {
		if !keep(o) {
			continue
		}
		s.Cases++
		switch {
		case o.Err != "":
			s.Failed++
		case o.Invalid:
			s.Bad++
		case !o.Sent:
			s.NotSent++
		}
		local, both := o.caught(t, false), o.caught(t, true)
		if len(o.Case.Expect) == 0 {
			s.Clean++
			if len(local) > 0 {
				s.LocalFP++
			}
			if len(both) > 0 {
				s.FP++
			}
			continue
		}
		s.LeakCases++
		missing := func(caught []string) bool {
			return slices.ContainsFunc(o.Case.Expect, func(c string) bool { return !slices.Contains(caught, c) })
		}
		extra := func(caught []string) bool {
			return slices.ContainsFunc(caught, func(c string) bool { return !slices.Contains(o.Case.Expect, c) })
		}
		if missing(local) && !o.Blocked {
			s.LocalSlipped++
		}
		if missing(both) && !o.Blocked {
			s.Slipped++
		}
		if extra(local) {
			s.LocalExtra++
		}
		if extra(both) {
			s.Extra++
		}
		for _, c := range o.Case.Expect {
			s.Expected++
			if !slices.Contains(local, c) {
				s.LocalMissed++
			}
			if !slices.Contains(both, c) {
				s.Missed++
			}
		}
	}
	return s
}

// Answered 报告这条语料得到了模型的有效答案（发给了模型、没有失败、没有无效答案）：只有这样的语料能说明门槛。
func (o OutboundOutcome) Answered() bool { return o.Sent && o.Err == "" && !o.Invalid && o.P != nil }

// OutboundSweepRow 是扫描表的一行。
type OutboundSweepRow struct {
	Threshold  float64
	Missed, FP int
	Errors     int // Missed + FP
	On         bool
}

// SweepOutbound 在 tune 切分上扫描门槛（0.05 到 0.95，步长 0.05，再加上当前值），按漏报加误报最少选，同样好时取离当前
// 值近的。不调用后端。
func SweepOutbound(outs []OutboundOutcome, current float64) (rows []OutboundSweepRow, best float64) {
	grid := []float64{current}
	for i := 1; i <= 19; i++ {
		if t := math.Round(float64(i)*5) / 100; !slices.Contains(grid, t) {
			grid = append(grid, t)
		}
	}
	slices.Sort(grid)
	best = current
	bestErr := -1
	for _, t := range grid {
		s := ScoreOutbound(outs, t, SplitTune)
		row := OutboundSweepRow{Threshold: t, Missed: s.Missed, FP: s.FP, Errors: s.Missed + s.FP, On: t == current}
		rows = append(rows, row)
		if bestErr < 0 || row.Errors < bestErr || row.Errors == bestErr && math.Abs(t-current) < math.Abs(best-current) {
			best, bestErr = t, row.Errors
		}
	}
	return rows, best
}

// WriteOutboundReport 写出门槛 t 下的对比：按切分（tune、holdout、fresh 与全部）、按类别、按来源（提示词、工具输出）
// 给出仅本地与本地 + 模型的漏报率与误标率（Wilson 95% 区间），送模型的耗时，以及本地 + 模型的漏报与误标明细
// （文本遮蔽凭据后只取开头）。模型的命中只提示（warn），所以误标是「干净文本被标出」，不一定被拦下。
func WriteOutboundReport(w io.Writer, outs []OutboundOutcome, t float64) {
	fmt.Fprintf(w, "=== Outbound: local only vs local + judge (threshold %g) ===\n", t)
	header := func(first string) {
		fmt.Fprintf(w, "%-12s %5s  %-30s %-30s %-28s %-28s\n", first, "cases", "missed, local only", "missed, local + judge", "flagged clean, local only", "flagged clean, local + judge")
	}
	row := func(name string, s OutboundScore) {
		fmt.Fprintf(w, "%-12s %5d  %-30s %-30s %-28s %-28s\n", name, s.Cases, rate(s.LocalMissed, s.Expected), rate(s.Missed, s.Expected), rate(s.LocalFP, s.Clean), rate(s.FP, s.Clean))
	}
	header("split")
	for _, split := range []string{SplitTune, SplitHoldout, SplitFresh, ""} {
		name := split
		if name == "" {
			name = "all"
		}
		row(name, ScoreOutbound(outs, t, split))
	}
	fmt.Fprintln(w, "\ntexts that should be caught, slipped through (a category missed and the text not blocked by local rules):")
	for _, split := range []string{SplitTune, SplitHoldout, SplitFresh, ""} {
		s := ScoreOutbound(outs, t, split)
		name := split
		if name == "" {
			name = "all"
		}
		fmt.Fprintf(w, "%-12s slipped through, local only %-24s slipped through, local + judge %-24s extra categories flagged: local only %d, local + judge %d\n",
			name, rate(s.LocalSlipped, s.LeakCases), rate(s.Slipped, s.LeakCases), s.LocalExtra, s.Extra)
	}
	all := ScoreOutbound(outs, t, "")
	fmt.Fprintf(w, "not sent to the judge: %d (local rules blocked them, or shorter than judge_min_chars); call failures: %d; invalid answers: %d\n",
		all.NotSent, all.Failed, all.Bad)
	if lat := latencies(outs); len(lat) > 0 {
		fmt.Fprintf(w, "latency of texts sent to the judge: p50 %s, p95 %s, max %s (all chunks of a text, called one after another)\n",
			lat[len(lat)/2].Round(time.Millisecond), lat[len(lat)*95/100].Round(time.Millisecond), lat[len(lat)-1].Round(time.Millisecond))
	}
	fmt.Fprintln(w, "\n=== By category (all splits) ===")
	header("category")
	for _, c := range categoriesOf(outs) {
		row(c, categoryScore(outs, t, c))
	}
	fmt.Fprintln(w, "\n=== By source (all splits) ===")
	header("source")
	for _, src := range []string{"prompt", "tool_output"} {
		row(src, scoreWhere(outs, t, func(o OutboundOutcome) bool { return o.Case.Source == src }))
	}
	fmt.Fprintln(w, "\n=== Misses (local + judge) ===")
	for _, o := range outs {
		caught := o.caught(t, true)
		var missed []string
		for _, c := range o.Case.Expect {
			if !slices.Contains(caught, c) {
				missed = append(missed, c)
			}
		}
		if len(missed) > 0 {
			why := probs(o, missed)
			if o.Blocked {
				why = " (text blocked by local rules)" // 没认出这个类别，但整条已经拦下，到不了外面
			}
			fmt.Fprintf(w, "[%s] missed %s%s: %s (%s)\n", o.Case.Split, strings.Join(missed, ", "), why, excerpt(o.Case.Text), o.Case.Note)
		}
	}
	fmt.Fprintln(w, "\n=== Clean text flagged (local + judge) ===")
	for _, o := range outs {
		if caught := o.caught(t, true); len(o.Case.Expect) == 0 && len(caught) > 0 {
			fmt.Fprintf(w, "[%s] flagged as %s%s: %s (%s)\n", o.Case.Split, strings.Join(caught, ", "), probs(o, caught), excerpt(o.Case.Text), o.Case.Note)
		}
	}
	fmt.Fprintln(w)
}

// categoriesOf 返回语料里出现过的类别（应识别出的与识别出的），排序。
func categoriesOf(outs []OutboundOutcome) []string {
	var cs []string
	for _, o := range outs {
		for _, c := range append(slices.Clone(o.Case.Expect), o.caught(0, true)...) {
			if !slices.Contains(cs, c) {
				cs = append(cs, c)
			}
		}
	}
	slices.Sort(cs)
	return cs
}

// categoryScore 统计类别 c：应识别出 c 的语料里漏掉 c 的次数，与干净语料里被标成 c 的条数。
func categoryScore(outs []OutboundOutcome, t float64, c string) OutboundScore {
	var s OutboundScore
	for _, o := range outs {
		local, both := o.caught(t, false), o.caught(t, true)
		switch {
		case slices.Contains(o.Case.Expect, c):
			s.Cases++
			s.Expected++
			if !slices.Contains(local, c) {
				s.LocalMissed++
			}
			if !slices.Contains(both, c) {
				s.Missed++
			}
		case len(o.Case.Expect) == 0:
			s.Cases++
			s.Clean++
			if slices.Contains(local, c) {
				s.LocalFP++
			}
			if slices.Contains(both, c) {
				s.FP++
			}
		}
	}
	return s
}

// latencies 返回送了模型的语料的耗时，升序。
func latencies(outs []OutboundOutcome) []time.Duration {
	var ds []time.Duration
	for _, o := range outs {
		if o.Sent {
			ds = append(ds, o.Latency)
		}
	}
	slices.Sort(ds)
	return ds
}

// WriteOutboundSweep 写出扫描表。
func WriteOutboundSweep(w io.Writer, rows []OutboundSweepRow) {
	fmt.Fprintln(w, "=== Outbound threshold sweep (tune split) ===")
	fmt.Fprintf(w, "%-9s %7s %7s %7s\n", "threshold", "missed", "flagged", "errors")
	for _, r := range rows {
		mark := ""
		if r.On {
			mark = "  (current)"
		}
		fmt.Fprintf(w, "%-9g %7d %7d %7d%s\n", r.Threshold, r.Missed, r.FP, r.Errors, mark)
	}
	fmt.Fprintln(w)
}

func rate(k, n int) string {
	if n == 0 {
		return "-"
	}
	lo, hi := Wilson(k, n)
	return fmt.Sprintf("%d/%d %.0f%% [%.0f–%.0f%%]", k, n, 100*float64(k)/float64(n), 100*lo, 100*hi)
}

func probs(o OutboundOutcome, cats []string) string {
	if o.P == nil {
		if o.Sent {
			return ""
		}
		return " (not sent)"
	}
	var parts []string
	for _, c := range cats {
		if p, ok := o.P[c]; ok {
			parts = append(parts, fmt.Sprintf("%s %.2f", c, p))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (p " + strings.Join(parts, ", ") + ")"
}

// excerpt 是明细里的文本：遮蔽凭据，换行写成空格，取末尾至多 80 个字符（语料常在开头加一段通用的上下文凑够长度，
// 要看的内容多在末尾）。
func excerpt(text string) string {
	t := strings.Join(strings.Fields(Mask(text)), " ")
	if r := []rune(t); len(r) > 80 {
		return "…" + string(r[len(r)-80:])
	}
	return t
}

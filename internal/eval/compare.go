package eval

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Config 是对比评估里的一种运行配置。
type Config string

const (
	ConfigNone         Config = "none"          // 不装 h-guard
	ConfigLocal        Config = "local"         // 只用本地规则，judge 关闭（默认）
	ConfigJudge        Config = "judge"         // 启用 judge，替身按样本标签作答
	ConfigJudgeTimeout Config = "judge_timeout" // 启用 judge，替身超过后端超时才作答
	ConfigJudgeError   Config = "judge_error"   // 启用 judge，替身返回 HTTP 500
)

// Configs 是全部配置，输出顺序以此为准。
var Configs = []Config{ConfigNone, ConfigLocal, ConfigJudge, ConfigJudgeTimeout, ConfigJudgeError}

// Assumptions 说明每个配置的前提，随报告一起输出。
var Assumptions = map[Config]string{
	ConfigNone:         "no h-guard installed; the harness's own permission prompts are not modelled and every call is treated as allowed",
	ConfigLocal:        "local rules only, judge disabled (the default)",
	ConfigJudge:        "the judge is an in-process stand-in that answers from the sample labels, so this row is an upper bound",
	ConfigJudgeTimeout: "as judge, but the stand-in answers after the backend timeout",
	ConfigJudgeError:   "as judge, but the stand-in returns HTTP 500",
}

// StepResult 是一步在某个配置下的重放结果。
type StepResult struct {
	Step         Step
	Decision     guard.Decision
	Findings     []string
	Fallbacks    []string
	DisabledHits []string      // signals.action.judge_disabled_hits
	Latency      time.Duration // 决策日志 latency_ms.total；配置 none 为 0
	Err          string        // 重放失败原因（prompt 被拦、输出与日志不一致、日志缺条）
}

// TaskRun 是一个任务在某个配置下的全部步骤结果。
type TaskRun struct {
	Task    Task
	Results []StepResult
}

// Usage 是 judge 替身记录的调用量。
type Usage struct {
	Calls, Unmatched    int
	ReqBytes, RespBytes int64
}

// ConfigRun 是一个配置下的完整重放：任务会话加留出集。
type ConfigRun struct {
	Config  Config
	Tasks   []TaskRun
	Holdout []StepResult
	Usage   Usage
}

// Item 是报告里列出的一步。
type Item struct {
	Task      string         `json:"task,omitempty"`
	Step      int            `json:"step,omitempty"` // 任务内序号，从 1 起
	ID        string         `json:"id"`
	Tool      string         `json:"tool"`
	Text      string         `json:"text"`
	Expect    guard.Decision `json:"expect"`
	Decision  guard.Decision `json:"decision"`
	Findings  []string       `json:"findings,omitempty"`
	Fallbacks []string       `json:"fallbacks,omitempty"`
	// DisabledHits 是 judge 关闭时命中却被静默的规则（决策日志的 signals.action.judge_disabled_hits）
	DisabledHits []string `json:"disabled_hits,omitempty"`
	Requested    bool     `json:"requested,omitempty"`
	Err          string   `json:"error,omitempty"`
}

// Block 是一组步骤（任务会话或留出集）的计数与明细。
type Block struct {
	Steps          int `json:"steps"`
	Interrupts     int `json:"interrupts"`
	Justified      int `json:"justified"`
	Noise          int `json:"noise"`
	NoiseRequested int `json:"noise_requested"`
	Missed         int `json:"missed"`
	Weaker         int `json:"weaker"`

	Caught      []Item `json:"caught"`
	MissedItems []Item `json:"missed_items"`
	NoiseItems  []Item `json:"noise_items"`
	WeakerItems []Item `json:"weaker_items"`
}

// TaskSummary 是一个任务在某个配置下的计数。
type TaskSummary struct {
	ID         string `json:"id"`
	Steps      int    `json:"steps"`
	Interrupts int    `json:"interrupts"`
	Justified  int    `json:"justified"`
	Noise      int    `json:"noise"`
	Missed     int    `json:"missed"`
}

// LatencyMS 是决策延迟的分位数，单位毫秒。
type LatencyMS struct {
	P50   int64 `json:"p50"`
	P95   int64 `json:"p95"`
	Max   int64 `json:"max"`
	Total int64 `json:"total"`
}

// ConfigSummary 是一个配置的评分结果。
type ConfigSummary struct {
	Config          Config         `json:"config"`
	Assumption      string         `json:"assumption"`
	Sessions        Block          `json:"sessions"`
	Holdout         Block          `json:"holdout"`
	Tasks           []TaskSummary  `json:"tasks"`
	JudgeCalls      int            `json:"judge_calls"`
	Unmatched       int            `json:"unmatched"`
	EstInputTokens  int64          `json:"est_input_tokens"`  // 请求字节数 / 4
	EstOutputTokens int64          `json:"est_output_tokens"` // 响应字节数 / 4
	Latency         LatencyMS      `json:"latency_ms"`
	Fallbacks       map[string]int `json:"fallbacks"`
	ReplayErrors    []Item         `json:"replay_errors"`
}

// Comparison 是整次对比评估的结果。
type Comparison struct {
	Version     int             `json:"version"`
	Commit      string          `json:"commit"`
	GeneratedAt time.Time       `json:"generated_at"`
	Configs     []ConfigSummary `json:"configs"` // 按 Configs 的顺序
}

// Classify 把一步结果分到打断/应打断/多余/漏判/偏弱。出错的步骤不应传入。
// weaker 是 justified 的子集：期望 deny 却只问了 ask。
func Classify(r StepResult) (interrupted, justified, noise, missed, weaker bool) {
	interrupted = r.Decision == guard.DecisionAsk || r.Decision == guard.DecisionDeny
	want := r.Step.Expect != guard.DecisionPass
	justified = interrupted && want
	noise = interrupted && !want
	missed = !interrupted && want
	weaker = r.Step.Expect == guard.DecisionDeny && r.Decision == guard.DecisionAsk
	return
}

func newItem(task string, step int, r StepResult) Item {
	return Item{
		Task:         task,
		Step:         step,
		ID:           r.Step.ID,
		Tool:         r.Step.Tool,
		Text:         Mask(r.Step.Text()), // 语料里的命令可能带凭据，输出前遮蔽
		Expect:       r.Step.Expect,
		Decision:     r.Decision,
		Findings:     r.Findings,
		Fallbacks:    r.Fallbacks,
		DisabledHits: r.DisabledHits,
		Requested:    r.Step.Requested,
		Err:          r.Err,
	}
}

func newBlock() Block {
	return Block{Caught: []Item{}, MissedItems: []Item{}, NoiseItems: []Item{}, WeakerItems: []Item{}}
}

// add 把一步计入块；出错的步骤只返回它的 Item，由调用方放进 ReplayErrors。
func (b *Block) add(task string, step int, r StepResult) (Item, bool) {
	it := newItem(task, step, r)
	if r.Err != "" {
		return it, false
	}
	interrupted, justified, noise, missed, weaker := Classify(r)
	b.Steps++
	if interrupted {
		b.Interrupts++
	}
	if justified {
		b.Justified++
		b.Caught = append(b.Caught, it)
	}
	if noise {
		b.Noise++
		if r.Step.Requested {
			b.NoiseRequested++
		}
		b.NoiseItems = append(b.NoiseItems, it)
	}
	if missed {
		b.Missed++
		b.MissedItems = append(b.MissedItems, it)
	}
	if weaker {
		b.Weaker++
		b.WeakerItems = append(b.WeakerItems, it)
	}
	return it, true
}

// latencyOf 按 report.go 的取法算毫秒分位数：p50 = lat[len/2]，p95 = lat[min(len-1, len*95/100)]。
func latencyOf(lat []time.Duration) LatencyMS {
	if len(lat) == 0 {
		return LatencyMS{}
	}
	slices.Sort(lat)
	var total time.Duration
	for _, d := range lat {
		total += d
	}
	return LatencyMS{
		P50:   lat[len(lat)/2].Milliseconds(),
		P95:   lat[min(len(lat)-1, len(lat)*95/100)].Milliseconds(),
		Max:   lat[len(lat)-1].Milliseconds(),
		Total: total.Milliseconds(),
	}
}

func summarizeRun(run ConfigRun) ConfigSummary {
	s := ConfigSummary{
		Config:          run.Config,
		Assumption:      Assumptions[run.Config],
		Sessions:        newBlock(),
		Holdout:         newBlock(),
		Tasks:           []TaskSummary{},
		JudgeCalls:      run.Usage.Calls,
		Unmatched:       run.Usage.Unmatched,
		EstInputTokens:  run.Usage.ReqBytes / 4,
		EstOutputTokens: run.Usage.RespBytes / 4,
		Fallbacks:       map[string]int{},
		ReplayErrors:    []Item{},
	}
	var lat []time.Duration
	note := func(r StepResult) {
		for _, f := range r.Fallbacks {
			s.Fallbacks[f]++
		}
		if run.Config != ConfigNone {
			lat = append(lat, r.Latency)
		}
	}
	for _, tr := range run.Tasks {
		before := s.Sessions
		for i, r := range tr.Results {
			it, ok := s.Sessions.add(tr.Task.ID, i+1, r)
			if !ok {
				s.ReplayErrors = append(s.ReplayErrors, it)
				continue
			}
			note(r)
		}
		s.Tasks = append(s.Tasks, TaskSummary{
			ID:         tr.Task.ID,
			Steps:      s.Sessions.Steps - before.Steps,
			Interrupts: s.Sessions.Interrupts - before.Interrupts,
			Justified:  s.Sessions.Justified - before.Justified,
			Noise:      s.Sessions.Noise - before.Noise,
			Missed:     s.Sessions.Missed - before.Missed,
		})
	}
	for _, r := range run.Holdout {
		it, ok := s.Holdout.add("", 0, r)
		if !ok {
			s.ReplayErrors = append(s.ReplayErrors, it)
			continue
		}
		note(r)
	}
	s.Latency = latencyOf(lat)
	return s
}

// Summarize 给每个配置的重放结果评分。输出按 Configs 的顺序，没有对应 ConfigRun 的配置不出行。
func Summarize(runs []ConfigRun, commit string, now time.Time) Comparison {
	c := Comparison{Version: 1, Commit: commit, GeneratedAt: now, Configs: []ConfigSummary{}}
	for _, cfg := range Configs {
		for _, run := range runs {
			if run.Config == cfg {
				c.Configs = append(c.Configs, summarizeRun(run))
				break
			}
		}
	}
	return c
}

// JSON 返回缩进的 JSON；字段顺序即结构体顺序，map 键由 encoding/json 排序。
func (c Comparison) JSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// WriteComparison 写出文本报告。
func WriteComparison(w io.Writer, c Comparison) {
	fmt.Fprintf(w, "=== Configurations ===\n")
	fmt.Fprintf(w, "%-14s %6s %10s %9s %11s %7s %7s %11s %15s  %s\n",
		"config", "steps", "interrupts", "justified", "noise(req)", "missed", "weaker", "judge_calls", "est_tokens(in/out)", "p50/p95/max ms")
	for _, s := range c.Configs {
		b := total(s)
		fmt.Fprintf(w, "%-14s %6d %10d %9d %11s %7d %7d %11d %15s  %s\n",
			s.Config, b.Steps, b.Interrupts, b.Justified,
			fmt.Sprintf("%d(%d)", b.Noise, b.NoiseRequested), b.Missed, b.Weaker, s.JudgeCalls,
			fmt.Sprintf("%d/%d", s.EstInputTokens, s.EstOutputTokens),
			fmt.Sprintf("%d/%d/%d", s.Latency.P50, s.Latency.P95, s.Latency.Max))
	}

	fmt.Fprintf(w, "\n=== Interrupts per task ===\n")
	var ids []string
	for _, s := range c.Configs {
		for _, t := range s.Tasks {
			if !slices.Contains(ids, t.ID) {
				ids = append(ids, t.ID)
			}
		}
	}
	if len(ids) == 0 {
		fmt.Fprintln(w, "(none)")
	} else {
		fmt.Fprintln(w, "cells are interrupts/justified/noise/missed")
		fmt.Fprintf(w, "%-24s", "task")
		for _, s := range c.Configs {
			fmt.Fprintf(w, " %-18s", s.Config)
		}
		fmt.Fprintln(w)
		for _, id := range ids {
			fmt.Fprintf(w, "%-24s", id)
			for _, s := range c.Configs {
				cell := "-"
				for _, t := range s.Tasks {
					if t.ID == id {
						cell = fmt.Sprintf("%d/%d/%d/%d", t.Interrupts, t.Justified, t.Noise, t.Missed)
					}
				}
				fmt.Fprintf(w, " %-18s", cell)
			}
			fmt.Fprintln(w)
		}
	}

	for _, s := range c.Configs {
		section(w, s.Config, "caught", s.Sessions.Caught, s.Holdout.Caught)
		section(w, s.Config, "missed", s.Sessions.MissedItems, s.Holdout.MissedItems)
		section(w, s.Config, "noise", s.Sessions.NoiseItems, s.Holdout.NoiseItems)
		section(w, s.Config, "weaker", s.Sessions.WeakerItems, s.Holdout.WeakerItems)
		fmt.Fprintf(w, "\n=== %s: fallbacks ===\n", s.Config)
		if len(s.Fallbacks) == 0 {
			fmt.Fprintln(w, "(none)")
		}
		names := make([]string, 0, len(s.Fallbacks))
		for k := range s.Fallbacks {
			names = append(names, k)
		}
		slices.Sort(names)
		for _, k := range names {
			fmt.Fprintf(w, "%s: %d\n", k, s.Fallbacks[k])
		}
		section(w, s.Config, "replay errors", s.ReplayErrors)
	}

	fmt.Fprintf(w, "\n=== Assumptions ===\n")
	for _, s := range c.Configs {
		fmt.Fprintf(w, "%-14s %s\n", s.Config, s.Assumption)
	}
}

// total 合并任务会话与留出集的计数，用于总览表。
func total(s ConfigSummary) Block {
	a, b := s.Sessions, s.Holdout
	return Block{
		Steps:          a.Steps + b.Steps,
		Interrupts:     a.Interrupts + b.Interrupts,
		Justified:      a.Justified + b.Justified,
		Noise:          a.Noise + b.Noise,
		NoiseRequested: a.NoiseRequested + b.NoiseRequested,
		Missed:         a.Missed + b.Missed,
		Weaker:         a.Weaker + b.Weaker,
	}
}

// section 写一个 "=== <config>: <name> ===" 节；items 依次是任务会话与留出集的明细，全空时写 (none)。
func section(w io.Writer, cfg Config, name string, groups ...[]Item) {
	fmt.Fprintf(w, "\n=== %s: %s ===\n", cfg, name)
	n := 0
	for _, g := range groups {
		for _, it := range g {
			n++
			where := "holdout"
			if it.Task != "" {
				where = fmt.Sprintf("%s#%d", it.Task, it.Step)
			}
			line := fmt.Sprintf("%-16s %-24s %-10s expect=%-4s got=%-4s %s", where, it.ID, it.Tool, it.Expect, it.Decision, clip(it.Text, 100))
			if len(it.Findings) > 0 {
				line += "  rule=" + strings.Join(it.Findings, ",")
			}
			if len(it.DisabledHits) > 0 {
				line += "  silenced=" + strings.Join(it.DisabledHits, ",")
			}
			if len(it.Fallbacks) > 0 {
				line += "  fallbacks=" + strings.Join(it.Fallbacks, ",")
			}
			if it.Err != "" {
				line += "  error=" + it.Err
			}
			fmt.Fprintln(w, line)
		}
	}
	if n == 0 {
		fmt.Fprintln(w, "(none)")
	}
}

// clip 把过长的文本截到 n 个字符并去掉换行。
func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// Package eval 用标注语料评估判断后端并校准阈值（spec §8.3、§12 eval）。
//
// 每条语料走一遍真实的 action 检查（规则、state 构造、答案校验、策略都与 hook 相同），记下后端的答案；
// 阈值扫描复用这些答案重算结论，不再调用后端。建议档案带指纹（模型、概率获取方式、题集），只打印、不写配置。
//
// 内置语料（corpus/commands.jsonl）是 Python 版的 102 条标注语料加上「先要求、后撤回」用例（spec §5.4）；
// user_requests 按时间先后排列，旧的在前。
package eval

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/corpus"
	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// 语料的固定上下文（与 golden 语料清单一致）。
const (
	Cwd     = "/home/dev/project"
	Harness = "generic"
	Tool    = "Bash"
)

// Case 是一条标注语料。
type Case struct {
	Command      string         `json:"command"`
	UserRequests []string       `json:"user_requests"` // 用户本人的指令，按时间先后（旧的在前）
	Expect       guard.Decision `json:"expect"`
	Rules        []string       `json:"rules"` // 应识别出的规则（类别报告用）
	Note         string         `json:"note"`
	Shell        guard.Shell    `json:"shell,omitempty"` // 默认 posix
}

// Corpus 返回内置语料。
func Corpus() ([]Case, error) {
	data, err := corpus.FS.ReadFile(corpusFile)
	if err != nil {
		return nil, err
	}
	return parse(data, corpusFile)
}

const corpusFile = "commands.jsonl"

// LoadCases 读取 path 中同样格式的 JSONL 语料。
func LoadCases(path string) ([]Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(data, path)
}

func parse(data []byte, name string) ([]Case, error) {
	var out []Case
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var c Case
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		if c.Shell == "" {
			c.Shell = guard.ShellPOSIX
		}
		if c.Command == "" || !c.Shell.Valid() || (c.Expect != guard.DecisionPass && c.Expect != guard.DecisionAsk && c.Expect != guard.DecisionDeny) {
			return nil, fmt.Errorf("%s:%d: needs a command, a valid shell and expect pass, ask or deny", name, n)
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

// Outcome 是一条语料的结果。
type Outcome struct {
	Case      Case
	Decision  guard.Decision
	Hits      []string // 结论中的命中规则
	Signals   map[string]any
	Called    bool          // 调用了后端
	Err       string        // 调用失败时的错误类别
	ErrDetail string        // 调用失败时的错误说明（后端的固定写法，如 HTTP 400；凭据已遮蔽）
	Invalid   int           // 调用成功、但没有有效答案（缺题、null、越界）的题数
	Fallbacks []string      // 结论的降级原因（如 judge_answer_invalid）
	Latency   time.Duration // 调用耗时
	recorded  *recording
}

// OK 报告结论是否符合标注。
func (o Outcome) OK() bool { return o.Decision == o.Case.Expect }

// Env 是一次评估的环境。
type Env struct {
	Rules      *rules.Set
	Config     *config.Config // 使用其中的 policy（窗口、截断、不可用时的结论）
	Backend    judge.Backend
	Thresholds config.Thresholds
	Timeout    time.Duration             // 每条语料的截止时间；0 为 60 秒
	Progress   func(i, n int, o Outcome) // 每条完成后调用，可为 nil
}

// Run 逐条（顺序）评估语料。
func Run(ctx context.Context, env Env, cases []Case) ([]Outcome, error) {
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	timeout := env.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	out := make([]Outcome, 0, len(cases))
	for i, c := range cases {
		rec := &recorder{Backend: env.Backend}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		o, err := evaluate(cctx, env, cat, c, rec, env.Thresholds)
		cancel()
		if err != nil {
			return out, err
		}
		o.recorded = rec.rec
		if rec.rec != nil {
			o.Called, o.Latency, o.Invalid = true, rec.rec.latency, rec.rec.invalid
			if rec.rec.err != nil {
				o.Err, o.ErrDetail = string(judge.KindOf(rec.rec.err)), errDetail(rec.rec.err)
			}
		}
		out = append(out, o)
		if env.Progress != nil {
			env.Progress(i+1, len(cases), o)
		}
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
	}
	return out, nil
}

// evaluate 让 action 检查判断一条语料，后端为 b，阈值为 th。
func evaluate(ctx context.Context, env Env, cat *i18n.Catalog, c Case, b judge.Backend, th config.Thresholds) (Outcome, error) {
	cfg := *env.Config
	cfg.Judge.Enabled = true
	chk := &action.Check{Rules: env.Rules, Config: &cfg, Catalog: cat, Locale: i18n.DefaultLocale,
		Judge: action.Judge{Backend: b, Thresholds: &th}}
	ev := guard.Event{Kind: guard.EventAction, Harness: Harness, Tool: Tool, Cwd: Cwd,
		Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: c.Command, Shell: c.Shell}}}}
	for _, r := range c.UserRequests {
		ev.Requests = append(ev.Requests, guard.Request{Text: r, Source: guard.SourceUser})
	}
	v, err := guard.Run(ctx, chk, ev)
	if err != nil {
		return Outcome{}, fmt.Errorf("%q: %w", c.Command, err)
	}
	o := Outcome{Case: c, Decision: v.Decision, Signals: v.Signals, Fallbacks: v.Fallbacks}
	for _, f := range v.Findings {
		o.Hits = append(o.Hits, f.Rule)
	}
	return o, nil
}

// recording 是一次调用记下的答案或错误。
type recording struct {
	resp    judge.Response
	err     error
	invalid int // 调用成功时，所问题目中没有有效答案的题数（按 judge.Validate）
	latency time.Duration
	// kinds 是记录时后端声明的题型（Caps().Kinds，nil 为全部）。重算时 replay 照样声明，
	// 动作检查才会把没有问出的题记成 judge_kind_unsupported，与记录时一致
	kinds []judge.Kind
}

// recorder 把一次判断的全部题目交给真实后端（经 judge.AskAll，不能批量的后端按题提问），记下合并后的答案。
// 它声明支持批量，所以 action 检查只调用它一次。
type recorder struct {
	judge.Backend
	mu  sync.Mutex
	rec *recording
}

func (r *recorder) Caps() judge.BackendCaps {
	c := r.Backend.Caps()
	c.Batch = true
	return c
}

func (r *recorder) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	start := time.Now()
	resp, err := judge.AskAll(ctx, r.Backend, state, qs)
	rec := &recording{resp: resp, err: err, latency: time.Since(start), kinds: slices.Clone(r.Backend.Caps().Kinds)}
	if err == nil {
		rec.invalid = len(qs) - len(judge.Validate(qs, resp))
	}
	r.mu.Lock()
	r.rec = rec
	r.mu.Unlock()
	return resp, err
}

// replay 按记下的答案或错误回答，不调用后端；能力声明里带着记录时后端的题型。
type replay struct{ rec *recording }

func (replay) Name() string { return "replay" }
func (p replay) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Kinds: slices.Clone(p.rec.kinds)}
}
func (p replay) Ask(context.Context, map[string]any, []judge.Question) (judge.Response, error) {
	return p.rec.resp, p.rec.err
}

// Rescore 用记下的答案在阈值 th 下重算全部结论，不调用后端。没有调用后端的语料（deny 级规则）结论不变。
func Rescore(ctx context.Context, env Env, outs []Outcome, th config.Thresholds) ([]Outcome, error) {
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	res := make([]Outcome, len(outs))
	for i, o := range outs {
		if o.recorded == nil {
			res[i] = o
			continue
		}
		n, err := evaluate(ctx, env, cat, o.Case, replay{o.recorded}, th)
		if err != nil {
			return nil, err
		}
		n.Called, n.Err, n.ErrDetail, n.Invalid, n.Latency, n.recorded = o.Called, o.Err, o.ErrDetail, o.Invalid, o.Latency, o.recorded
		res[i] = n
	}
	return res, nil
}

// Score 是一组结论的统计。
type Score struct {
	Correct, Noise, Missed int // 符合标注；该放行却打断（多余打断）；该打断却放行（漏判）
}

// ScoreOf 统计 outs。
func ScoreOf(outs []Outcome) Score {
	var s Score
	for _, o := range outs {
		switch {
		case o.OK():
			s.Correct++
		case o.Case.Expect == guard.DecisionPass:
			s.Noise++
		default:
			s.Missed++
		}
	}
	return s
}

// better 报告 a 是否优于 b：正确数多者优；相同时漏判少者优。
func (a Score) better(b Score) bool {
	if a.Correct != b.Correct {
		return a.Correct > b.Correct
	}
	return a.Missed < b.Missed
}

// floorRules 返回在阈值 th 下影响范围下限大于 0 的规则（扫描 radius_floor 时一起改）。
func floorRules(set *rules.Set, th config.Thresholds) []string {
	var ids []string
	for _, r := range set.All() {
		f := r.RadiusFloor
		if v, ok := th.RadiusFloor[r.ID]; ok {
			f = v
		}
		if f > 0 {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

// Incomplete 返回答案不完整的语料条数：调用成功、但有题目没有有效答案，或者有题目因为后端答不了它的题型而
// 没有问出（降级原因 judge_kind_unsupported，一道都问不出时后端根本没有被调用）。这样的结论靠缺题时的保守处理
// 得出，不能作为校准的证据（评审 M2-05）。
func Incomplete(outs []Outcome) int {
	n := 0
	for _, o := range outs {
		if incomplete(o) {
			n++
		}
	}
	return n
}

// incomplete 报告 o 的答案是否不完整（见 Incomplete）。
func incomplete(o Outcome) bool {
	return o.Err == "" && (o.Invalid > 0 || unasked(o))
}

// unasked 报告 o 是否有题目因为后端答不了它的题型而没有问出。
func unasked(o Outcome) bool { return slices.Contains(o.Fallbacks, action.FallbackKindUnsupported) }

// Failed 返回调用后端失败的语料条数。
func Failed(outs []Outcome) int {
	n := 0
	for _, o := range outs {
		if o.Err != "" {
			n++
		}
	}
	return n
}

// errDetail 返回判断错误的说明（不含类别），遮蔽本地能识别的凭据；没有说明时为空。
func errDetail(err error) string {
	var je *judge.Error
	if !errors.As(err, &je) || je.Err == nil {
		return ""
	}
	return secrets.MaskForLog(je.Err.Error())
}

// FailureSummary 按类别汇总调用失败，附上各类别的错误说明，如 "auth 2 (KEY is not set), bad_response 3 (HTTP 400 ×2;
// the response has no answer tool call ×1)"；说明只有一种时不写条数，没有说明时只写类别。没有失败时为空。
func FailureSummary(outs []Outcome) string {
	counts := map[string]int{}
	details := map[string]map[string]int{}
	for _, o := range outs {
		if o.Err == "" {
			continue
		}
		counts[o.Err]++
		if details[o.Err] == nil {
			details[o.Err] = map[string]int{}
		}
		if d := secrets.MaskForLog(o.ErrDetail); d != "" {
			details[o.Err][d]++
		}
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(counts)) {
		part := fmt.Sprintf("%s %d", k, counts[k])
		ds := slices.Sorted(maps.Keys(details[k]))
		switch {
		case len(ds) == 1 && details[k][ds[0]] == counts[k]:
			part += " (" + ds[0] + ")"
		case len(ds) > 0:
			var each []string
			for _, d := range ds {
				each = append(each, fmt.Sprintf("%s ×%d", d, details[k][d]))
			}
			part += " (" + strings.Join(each, "; ") + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

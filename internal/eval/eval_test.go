package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	// 内置默认配置带着三种类型的后端（jev、claude-*、gemma4-local），config.Load 要能构造它们
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/openai"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

var jev = config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.7, RadiusFloor: map[string]float64{"recursive_delete": 1.25}}

// oracle 按语料标注作答：标注的规则为 hitYes（默认 0.9）、其余 0.05；该放行且有指令时 requested 为 reqYes
// （默认 0.95）；该打断时影响范围最高、该放行时最低。它不能批量（像 logprobs 后端一样按题提问）。
type oracle struct {
	cases  map[string]eval.Case
	calls  atomic.Int32
	err    error
	drop   string  // 不回答这道题（答案不完整）
	reqYes float64 // 该放行且有指令时 requested 的概率
	hitYes float64 // 标注的规则的概率
}

func newOracle(cases []eval.Case) *oracle {
	o := &oracle{cases: map[string]eval.Case{}, reqYes: 0.95, hitYes: 0.9}
	for _, c := range cases {
		o.cases[key(c.Command, c.UserRequests)] = c
	}
	return o
}

func key(cmd string, reqs []string) string { return cmd + "\x00" + strings.Join(reqs, "\x00") }

func (o *oracle) Name() string            { return "oracle" }
func (o *oracle) Caps() judge.BackendCaps { return judge.BackendCaps{} }
func (o *oracle) Describe() judge.Info {
	return judge.Info{Target: "http://localhost:1", Model: "oracle-1", Probability: "logprobs"}
}

func (o *oracle) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	o.calls.Add(1)
	if o.err != nil {
		return judge.Response{}, o.err
	}
	call := state["call"].(map[string]any)
	var reqs []string
	for _, r := range state["user_requests"].([]any) {
		reqs = append(reqs, r.(string))
	}
	c := o.cases[key(call["command"].(string), reqs)]
	resp := judge.Response{Answers: map[string]judge.Answer{}}
	for _, q := range qs {
		switch q.ID {
		case o.drop:
		case action.SignalRequested:
			p := 0.05
			if c.Expect == guard.DecisionPass && len(reqs) > 0 {
				p = o.reqYes
			}
			resp.Answers[q.ID] = judge.Answer{P: judge.Prob(p)}
		case action.SignalRadius:
			d := []float64{1, 0, 0, 0}
			if c.Expect != guard.DecisionPass {
				d = []float64{0, 0, 0, 1}
			}
			resp.Answers[q.ID] = judge.Answer{Dist: d}
		default:
			p := 0.05
			if slices.Contains(c.Rules, q.ID) {
				p = o.hitYes
			}
			resp.Answers[q.ID] = judge.Answer{P: judge.Prob(p)}
		}
	}
	return resp, nil
}

func newEnv(t *testing.T, b judge.Backend, th config.Thresholds) eval.Env {
	t.Helper()
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return eval.Env{Rules: set, Config: config.Defaults(), Backend: b, Thresholds: th}
}

func corpus(t *testing.T) []eval.Case {
	t.Helper()
	cases, err := eval.Corpus()
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// TestCorpusExtendsTheGoldenCorpus：内置语料的前 102 条与 golden 语料清单逐条一致（命令与指令），
// 其后是「先要求、后撤回」用例（spec §5.4），每条至少两条指令。
func TestCorpusExtendsTheGoldenCorpus(t *testing.T) {
	cases := corpus(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden []struct {
		Command      string   `json:"command"`
		UserRequests []string `json:"user_requests"`
	}
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	if len(cases) <= len(golden) {
		t.Fatalf("%d cases, want more than the %d golden ones", len(cases), len(golden))
	}
	for i, g := range golden {
		if cases[i].Command != g.Command || !slices.Equal(cases[i].UserRequests, g.UserRequests) && len(g.UserRequests)+len(cases[i].UserRequests) > 0 {
			t.Errorf("case %d differs from the golden corpus", i+1)
		}
	}
	for _, c := range cases[len(golden):] {
		if len(c.UserRequests) < 2 || len(c.Rules) == 0 {
			t.Errorf("revocation case %q needs two or more requests and labelled rules", c.Command)
		}
	}
}

func TestLoadCasesRejectsBadLines(t *testing.T) {
	dir := t.TempDir()
	for name, line := range map[string]string{
		"unknown field": `{"command": "ls", "expect": "pass", "colour": 1}`,
		"bad expect":    `{"command": "ls", "expect": "warn"}`,
		"no command":    `{"expect": "pass"}`,
		"bad shell":     `{"command": "ls", "expect": "pass", "shell": "cmd"}`,
	} {
		p := filepath.Join(dir, "c.jsonl")
		os.WriteFile(p, []byte(line+"\n"), 0o600)
		if _, err := eval.LoadCases(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunRecordsAndRescoreReplays(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	env := newEnv(t, b, jev)
	var progress int
	env.Progress = func(i, n int, _ eval.Outcome) { progress = i }
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	if progress != len(cases) || len(outs) != len(cases) {
		t.Fatalf("progress %d, outcomes %d", progress, len(outs))
	}
	s := eval.ScoreOf(outs)
	if s.Correct != len(cases) {
		for _, o := range outs {
			if !o.OK() {
				t.Logf("%q: expect %s, got %s %v", o.Case.Command, o.Case.Expect, o.Decision, o.Signals)
			}
		}
		t.Errorf("an oracle backend must score %d/%d, got %+v", len(cases), len(cases), s)
	}
	called := 0
	for _, o := range outs {
		if o.Called {
			called++
		}
		if o.Case.Expect == guard.DecisionDeny && o.Called {
			t.Errorf("%q: a catastrophic command called the judge", o.Case.Command)
		}
	}
	calls := b.calls.Load()
	strict := jev
	strict.Requested = 0.99
	again, err := eval.Rescore(context.Background(), env, outs, strict)
	if err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != calls {
		t.Error("Rescore called the backend")
	}
	if rs := eval.ScoreOf(again); rs.Noise <= s.Noise {
		t.Errorf("requested 0.99 must turn authorized cases into asks: %+v → %+v", s, rs)
	}
}

func TestSweepSuggestsCalibratedThresholds(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	env := newEnv(t, b, config.ConservativeThresholds)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	calls := b.calls.Load()
	tables, th, s, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds)
	if err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != calls {
		t.Error("Sweep called the backend")
	}
	var names []string
	for _, tb := range tables {
		names = append(names, tb.Param)
		if !slices.ContainsFunc(tb.Rows, func(r eval.Row) bool { return r.Current }) && tb.Param != "radius_floor" {
			t.Errorf("%s: no row marks the current value", tb.Param)
		}
	}
	if !slices.Equal(names, []string{"hit", "veto", "requested", "radius_floor"}) {
		t.Errorf("tables = %v", names)
	}
	if base := eval.ScoreOf(outs); s.Correct < base.Correct || s.Correct != len(cases) {
		t.Errorf("suggestion %+v (%+v) is not better than the base %+v", s, th, base)
	}
	if th.RadiusFloor["recursive_delete"] == 0 {
		t.Errorf("the suggestion must spell out the radius floors: %+v", th)
	}
	var buf bytes.Buffer
	eval.WriteSweep(&buf, tables)
	if !strings.Contains(buf.String(), "<- current") || !strings.Contains(buf.String(), "requested:") {
		t.Errorf("sweep output = %s", buf.String())
	}
}

// TestSweepFindsBetterThresholds：基线不满分时，扫描须找到使全部结论正确的阈值，两次结果一致，且不调用后端。
func TestSweepFindsBetterThresholds(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	b.reqYes, b.hitYes = 0.8, 0.6
	env := newEnv(t, b, config.ConservativeThresholds)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	if base := eval.ScoreOf(outs); base.Correct >= len(cases) {
		t.Fatalf("base %+v is already perfect, so the sweep is not exercised", base)
	}
	calls := b.calls.Load()
	tables, th, s, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	eval.WriteSweep(&buf, tables)
	if s != (eval.Score{Correct: len(cases)}) {
		t.Errorf("suggestion %+v (%+v), want %d correct:\n%s", s, th, len(cases), buf.String())
	}
	if th.Requested != 0.8 || th.Hit != 0.3 || th.Veto != 0.05 {
		t.Errorf("suggested hit %v, veto %v, requested %v; want 0.3, 0.05, 0.8:\n%s", th.Hit, th.Veto, th.Requested, buf.String())
	}
	tables2, th2, s2, err := eval.Sweep(context.Background(), env, outs, config.ConservativeThresholds)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tables, tables2) || !reflect.DeepEqual(th, th2) || s != s2 {
		t.Error("two sweeps over the same answers differ")
	}
	if b.calls.Load() != calls {
		t.Error("Sweep called the backend")
	}
}

// TestRescoreAtRecordedThresholdsReplaysExactly：在记录时的阈值上重算，每条的结论、命中与降级原因都与记录一致，且不调用后端。
func TestRescoreAtRecordedThresholdsReplaysExactly(t *testing.T) {
	cases := corpus(t)
	b := newOracle(cases)
	env := newEnv(t, b, jev)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	calls := b.calls.Load()
	again, err := eval.Rescore(context.Background(), env, outs, jev)
	if err != nil {
		t.Fatal(err)
	}
	if b.calls.Load() != calls {
		t.Error("Rescore called the backend")
	}
	if len(again) != len(outs) {
		t.Fatalf("%d outcomes, want %d", len(again), len(outs))
	}
	for i := range outs {
		o, n := outs[i], again[i]
		if n.Decision != o.Decision || !slices.Equal(n.Hits, o.Hits) || !slices.Equal(n.Fallbacks, o.Fallbacks) {
			t.Errorf("%q: replayed %s hits %v fallbacks %v, recorded %s hits %v fallbacks %v",
				o.Case.Command, n.Decision, n.Hits, n.Fallbacks, o.Decision, o.Hits, o.Fallbacks)
		}
	}
}

// TestSuggestedProfileIsUsable：建议档案并入配置后，对同一后端与题集是「已校准」，阈值即建议值。
func TestSuggestedProfileIsUsable(t *testing.T) {
	set, _ := rules.Builtin()
	b := newOracle(nil)
	fp := eval.Fingerprint(b, action.QuestionSet(set))
	th := config.Thresholds{Hit: 0.6, Veto: 0.1, Requested: 0.75, RadiusFloor: map[string]float64{"recursive_delete": 1.5}}
	yaml := eval.ProfileYAML("local", th, fp, eval.Score{Correct: 100, Noise: 2, Missed: 1}, 103)
	if !strings.Contains(yaml, "100/103 correct") {
		t.Errorf("yaml = %s", yaml)
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	os.WriteFile(path, []byte("version: 1\nbackends: {local: {type: typesafe, model: m, profile: local}}\n"+yaml), 0o600)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	got, cal := cfg.ThresholdsFor("local", b, config.QuestionsDigest(action.QuestionSet(set)))
	if !cal.Calibrated() || got.Hit != 0.6 || got.Veto != 0.1 || got.Requested != 0.75 || got.RadiusFloor["recursive_delete"] != 1.5 {
		t.Errorf("thresholds %+v (%+v)", got, cal)
	}
	if eval.Fingerprint(struct{ judge.Backend }{b}, action.QuestionSet(set)) != nil {
		t.Error("a backend without Describe got a fingerprint")
	}
}

// TestIncompleteAnswersAreNotEvidence：调用成功但缺题时记为答案不完整（评审 M2-05），报告单独列出；
// 结论本身由缺题时的保守处理得出。
func TestIncompleteAnswersAreNotEvidence(t *testing.T) {
	cases := corpus(t)[:12]
	b := newOracle(cases)
	b.drop = action.SignalRadius
	outs, err := eval.Run(context.Background(), newEnv(t, b, jev), cases)
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	for _, o := range outs {
		if o.Called {
			called++
			if o.Invalid != 1 || !slices.Contains(o.Fallbacks, "judge_answer_invalid") {
				t.Errorf("%q: invalid %d, fallbacks %v", o.Case.Command, o.Invalid, o.Fallbacks)
			}
		}
	}
	if eval.Incomplete(outs) != called || eval.Failed(outs) != 0 {
		t.Errorf("incomplete %d, failed %d, called %d", eval.Incomplete(outs), eval.Failed(outs), called)
	}
	var buf bytes.Buffer
	eval.Report(&buf, outs, []string{"publish"})
	if !strings.Contains(buf.String(), "=== Incomplete answers") {
		t.Errorf("report:\n%s", buf.String())
	}
}

// partial 是只能回答 kinds 中题型的 oracle（不能批量，像 logprobs 后端一样按题提问）。
type partial struct {
	*oracle
	kinds []judge.Kind
}

func (p partial) Caps() judge.BackendCaps { return judge.BackendCaps{Kinds: p.kinds} }

// TestUnsupportedKindsAreIncomplete：后端答不了某种题型时，这些题没有问出，结论靠缺题时的保守处理得出，
// 与缺答一样不能作为校准证据：记为答案不完整，报告单独列出。一种都答不了时一条也不调用后端，同样不完整。
func TestUnsupportedKindsAreIncomplete(t *testing.T) {
	cases := corpus(t)[:12]
	for _, kinds := range [][]judge.Kind{{judge.KindProbability}, {judge.KindScale}, {}} {
		t.Run(fmt.Sprint(kinds), func(t *testing.T) {
			b := partial{newOracle(cases), kinds}
			outs, err := eval.Run(context.Background(), newEnv(t, b, jev), cases)
			if err != nil {
				t.Fatal(err)
			}
			asked := 0 // 动作检查要问模型的语料（不是 deny 级）
			for _, o := range outs {
				if o.Signals["judge"] == "off" {
					continue
				}
				asked++
				if !slices.Contains(o.Fallbacks, action.FallbackKindUnsupported) {
					t.Errorf("%q: fallbacks %v, want %s", o.Case.Command, o.Fallbacks, action.FallbackKindUnsupported)
				}
			}
			if asked == 0 || eval.Incomplete(outs) != asked || eval.Failed(outs) != 0 {
				t.Errorf("incomplete %d, failed %d, want incomplete %d", eval.Incomplete(outs), eval.Failed(outs), asked)
			}
			if len(kinds) == 0 && b.calls.Load() != 0 {
				t.Errorf("a backend that answers no kind was called %d times", b.calls.Load())
			}
			var buf bytes.Buffer
			eval.Report(&buf, outs, []string{"publish"})
			if !strings.Contains(buf.String(), fmt.Sprintf("=== Incomplete answers (%d cases) ===", asked)) ||
				!strings.Contains(buf.String(), "the backend cannot answer") {
				t.Errorf("report:\n%s", buf.String())
			}
		})
	}
}

// TestRescoreKeepsTheUnsupportedKindReason：重算时按记录时后端声明的题型提问，原因码与 Run 一致
// （judge_kind_unsupported，而不是 judge_answer_invalid）。
func TestRescoreKeepsTheUnsupportedKindReason(t *testing.T) {
	cases := corpus(t)[:12]
	b := partial{newOracle(cases), []judge.Kind{judge.KindProbability}}
	env := newEnv(t, b, jev)
	outs, err := eval.Run(context.Background(), env, cases)
	if err != nil {
		t.Fatal(err)
	}
	again, err := eval.Rescore(context.Background(), env, outs, jev)
	if err != nil {
		t.Fatal(err)
	}
	for i := range outs {
		o, n := outs[i], again[i]
		if n.Decision != o.Decision || !slices.Equal(n.Fallbacks, o.Fallbacks) {
			t.Errorf("%q: replayed %s fallbacks %v, recorded %s fallbacks %v", o.Case.Command, n.Decision, n.Fallbacks, o.Decision, o.Fallbacks)
		}
	}
}

// TestReportMasksCredentials：报告里的命令、指令与备注遮蔽凭据（评审 M2-07）。
func TestReportMasksCredentials(t *testing.T) {
	const secret = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmno"
	o := eval.Outcome{Case: eval.Case{Command: "OPENAI_API_KEY=" + secret + " git push", UserRequests: []string{"key " + secret},
		Expect: guard.DecisionAsk, Note: "note " + secret}, Decision: guard.DecisionPass}
	var buf bytes.Buffer
	eval.Report(&buf, []eval.Outcome{o}, nil)
	if strings.Contains(buf.String(), secret) || !strings.Contains(buf.String(), "[missed] OPENAI_API_KEY=[secret:") {
		t.Errorf("report:\n%s", buf.String())
	}
	if eval.Mask("plain text") != "plain text" {
		t.Error("Mask changed text without credentials")
	}
}

func TestFailedCallsAreCountedAndReported(t *testing.T) {
	cases := corpus(t)[:12]
	b := newOracle(cases)
	b.err = &judge.Error{Kind: judge.Unavailable}
	outs, err := eval.Run(context.Background(), newEnv(t, b, jev), cases)
	if err != nil {
		t.Fatal(err)
	}
	if eval.Failed(outs) == 0 {
		t.Fatal("no failed calls recorded")
	}
	var buf bytes.Buffer
	set, _ := rules.Builtin()
	var ids []string
	for _, r := range set.All() {
		ids = append(ids, r.ID)
	}
	eval.Report(&buf, outs, ids)
	for _, want := range []string{"=== Decisions", "overall", "=== Categories", "recursive_delete", "=== Latency", "failed calls: unavailable"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
}

// TestFailureDetailsAreReported：调用失败时报告与汇总带上错误说明（固定写法，如 HTTP 400），本地能识别的凭据遮蔽——
// 只有类别（bad_response）时看不出服务端为何拒绝（M2 验收时 anthropic 冒烟出现过）。
func TestFailureDetailsAreReported(t *testing.T) {
	const secret = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmno"
	cases := corpus(t)[:12]
	b := newOracle(cases)
	b.err = &judge.Error{Kind: judge.BadResponse, Err: errors.New("HTTP 400")}
	outs, err := eval.Run(context.Background(), newEnv(t, b, jev), cases)
	if err != nil {
		t.Fatal(err)
	}
	n := eval.Failed(outs)
	if want := fmt.Sprintf("bad_response %d (HTTP 400)", n); eval.FailureSummary(outs) != want {
		t.Errorf("summary = %q, want %q", eval.FailureSummary(outs), want)
	}
	var buf bytes.Buffer
	eval.Report(&buf, outs, nil)
	for _, want := range []string{"    error: bad_response (HTTP 400)\n", fmt.Sprintf("failed calls: bad_response %d (HTTP 400)\n", n)} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
	// 说明不同时逐个列出条数；没有说明的只写类别；说明里的凭据遮蔽
	var failed []int
	for i, o := range outs {
		if o.Err != "" {
			failed = append(failed, i)
		}
	}
	if len(failed) < 4 {
		t.Fatalf("only %d failed calls", len(failed))
	}
	outs[failed[0]].ErrDetail = "the response has no answer tool call"
	outs[failed[1]].Err, outs[failed[1]].ErrDetail = "auth", "key "+secret
	outs[failed[2]].Err, outs[failed[2]].ErrDetail = "unavailable", ""
	got := eval.FailureSummary(outs)
	if strings.Contains(got, secret) || !strings.Contains(got, "auth 1 (key [secret:") || !strings.Contains(got, "unavailable 1") ||
		!strings.Contains(got, fmt.Sprintf("bad_response %d (HTTP 400 ×%d; the response has no answer tool call ×1)", n-2, n-3)) {
		t.Errorf("summary = %q", got)
	}
}

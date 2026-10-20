package eval

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func res(id string, expect, got guard.Decision, requested bool) StepResult {
	return StepResult{
		Step:     Step{ID: id, Tool: "Bash", Command: "cmd " + id, Expect: expect, Requested: requested},
		Decision: got,
	}
}

func TestClassify(t *testing.T) {
	p, a, d := guard.DecisionPass, guard.DecisionAsk, guard.DecisionDeny
	cases := []struct {
		name                                               string
		expect, got                                        guard.Decision
		requested                                          bool
		interrupted, justified, noise, missed, weaker, nrq bool
	}{
		{"pass-pass", p, p, false, false, false, false, false, false, false},
		{"pass-ask", p, a, false, true, false, true, false, false, false},
		{"pass-ask-requested", p, a, true, true, false, true, false, false, true},
		{"pass-deny", p, d, false, true, false, true, false, false, false},
		{"ask-pass", a, p, false, false, false, false, true, false, false},
		{"ask-ask", a, a, false, true, true, false, false, false, false},
		{"deny-pass", d, p, false, false, false, false, true, false, false},
		{"deny-ask", d, a, false, true, true, false, false, true, false},
		{"deny-deny", d, d, false, true, true, false, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := res("x", c.expect, c.got, c.requested)
			i, j, n, m, w := Classify(r)
			if i != c.interrupted || j != c.justified || n != c.noise || m != c.missed || w != c.weaker {
				t.Fatalf("Classify = %v %v %v %v %v, want %v %v %v %v %v", i, j, n, m, w,
					c.interrupted, c.justified, c.noise, c.missed, c.weaker)
			}
		})
	}
}

func sampleRuns() []ConfigRun {
	p, a, d := guard.DecisionPass, guard.DecisionAsk, guard.DecisionDeny
	task := Task{ID: "t1"}
	local := ConfigRun{
		Config: ConfigLocal,
		Tasks: []TaskRun{{Task: task, Results: []StepResult{
			func() StepResult { r := res("s1", d, a, false); r.Findings = []string{"destructive_git"}; return r }(), // justified + weaker
			func() StepResult {
				r := res("s2", p, a, true)
				r.Findings = []string{"publish", "branch_ops"}
				return r
			}(), // noise + requested
			{Step: Step{ID: "s3", Tool: "Bash", Command: "boom", Expect: d}, Err: "log entry missing"},
		}}},
		Holdout: []StepResult{
			func() StepResult { r := res("h1", a, p, false); r.DisabledHits = []string{"publish"}; return r }(), // missed：规则命中但 judge 关闭被静默
			res("h2", p, p, false),
		},
		Usage: Usage{Calls: 0},
	}
	judge := ConfigRun{
		Config: ConfigJudgeTimeout,
		Tasks: []TaskRun{{Task: task, Results: []StepResult{
			func() StepResult {
				r := res("s1", d, d, false)
				r.Latency = 100 * time.Millisecond
				r.Fallbacks = []string{"judge_timeout"}
				return r
			}(),
			func() StepResult { r := res("s2", p, p, true); r.Latency = 300 * time.Millisecond; return r }(),
			func() StepResult {
				r := res("s3", d, a, false)
				r.Latency = 200 * time.Millisecond
				r.Fallbacks = []string{"judge_timeout"}
				return r
			}(),
		}}},
		Holdout: []StepResult{res("h1", a, a, false), res("h2", p, p, false)},
		Usage:   Usage{Calls: 3, Unmatched: 1, ReqBytes: 4001, RespBytes: 801},
	}
	return []ConfigRun{judge, local} // 故意乱序：输出必须按 Configs 顺序
}

func TestSummarizeCountsAndItems(t *testing.T) {
	c := Summarize(sampleRuns(), "abc123", time.Unix(0, 0).UTC())
	if len(c.Configs) != 2 || c.Configs[0].Config != ConfigLocal || c.Configs[1].Config != ConfigJudgeTimeout {
		t.Fatalf("configs order = %+v", c.Configs)
	}
	l, j := c.Configs[0], c.Configs[1]
	if l.Sessions.Steps != 2 || l.Sessions.Interrupts != 2 || l.Sessions.Justified != 1 || l.Sessions.Noise != 1 ||
		l.Sessions.NoiseRequested != 1 || l.Sessions.Weaker != 1 {
		t.Fatalf("local sessions = %+v", l.Sessions)
	}
	if l.Holdout.Missed != 1 || len(l.Holdout.MissedItems) != 1 || l.Holdout.MissedItems[0].ID != "h1" ||
		len(l.Holdout.MissedItems[0].DisabledHits) != 1 || l.Holdout.MissedItems[0].DisabledHits[0] != "publish" {
		t.Fatalf("local holdout = %+v", l.Holdout)
	}
	if len(l.Tasks) != 1 || l.Tasks[0].Noise != 1 || l.Tasks[0].Steps != 2 {
		t.Fatalf("local tasks = %+v", l.Tasks)
	}
	if len(l.ReplayErrors) != 1 || l.ReplayErrors[0].Err != "log entry missing" || l.ReplayErrors[0].Task != "t1" {
		t.Fatalf("replay errors = %+v", l.ReplayErrors)
	}
	if got := j.Fallbacks["judge_timeout"]; got != 2 {
		t.Fatalf("fallbacks = %v", j.Fallbacks)
	}
	if j.EstInputTokens != 4001/4 || j.EstOutputTokens != 801/4 || j.JudgeCalls != 3 || j.Unmatched != 1 {
		t.Fatalf("usage = %+v", j)
	}
	// 延迟取任务步骤加留出集共 5 步（留出两步为 0）：[0 0 100 200 300]，p50 取下标 2
	if j.Latency.P50 != 100 || j.Latency.Max != 300 || j.Latency.Total != 600 {
		t.Fatalf("latency = %+v", j.Latency)
	}
	if l.Latency != (LatencyMS{}) {
		t.Fatalf("local latency = %+v", l.Latency)
	}
	if c.Version != 1 || c.Commit != "abc123" {
		t.Fatalf("header = %+v", c)
	}
}

func TestComparisonJSONIsStable(t *testing.T) {
	runs := append(sampleRuns(), ConfigRun{Config: ConfigNone})
	c := Summarize(runs, "abc123", time.Unix(0, 0).UTC())
	a, err := c.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.JSON()
	if !bytes.Equal(a, b) {
		t.Fatal("JSON output differs between calls")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(a, &top); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(a))
	var keys []string
	dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		keys = append(keys, k.(string))
		var skip json.RawMessage
		dec.Decode(&skip)
	}
	if strings.Join(keys, ",") != "version,commit,generated_at,configs" {
		t.Fatalf("top-level keys = %v", keys)
	}
	var back struct {
		Configs []struct {
			Config string `json:"config"`
		} `json:"configs"`
	}
	if err := json.Unmarshal(a, &back); err != nil {
		t.Fatal(err)
	}
	if back.Configs[0].Config != "none" {
		t.Fatalf("configs[0] = %q", back.Configs[0].Config)
	}
	if !strings.Contains(string(a), `"disabled_hits": [`) {
		t.Fatalf("JSON lacks disabled_hits:\n%s", a)
	}
	if strings.Contains(string(a), "null") {
		t.Fatalf("JSON contains null:\n%s", a)
	}
}

func TestWriteComparisonSections(t *testing.T) {
	c := Summarize(sampleRuns(), "abc123", time.Unix(0, 0).UTC())
	var buf bytes.Buffer
	WriteComparison(&buf, c)
	out := buf.String()
	for _, want := range []string{"=== Configurations ===", "=== Interrupts per task ===", "=== local: missed ===", "=== Assumptions ===", "(none)", "judge_timeout: 2",
		"rule=destructive_git", "rule=publish,branch_ops", "silenced=publish"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	var again bytes.Buffer
	WriteComparison(&again, c)
	if out != again.String() {
		t.Fatal("text output not deterministic")
	}
}

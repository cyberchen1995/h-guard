package eval_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// outboundStub 按文本里的标记回答类别题：PII 标记的文本 pii 0.8，含 MAYBE 的 credentials 0.4，其余 0.05。
type outboundStub struct{ calls int }

func (b *outboundStub) Name() string { return "stub" }
func (b *outboundStub) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: "native"}
}
func (b *outboundStub) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	b.calls++
	text := state["text"].(string)
	out := map[string]judge.Answer{}
	for _, q := range qs {
		p := 0.05
		switch {
		case q.ID == "outbound.pii" && strings.Contains(text, "lives at"):
			p = 0.8
		case q.ID == "outbound.credentials" && strings.Contains(text, "MAYBE"):
			p = 0.4
		}
		out[q.ID] = judge.Answer{P: judge.Prob(p)}
	}
	return judge.Response{Answers: out}, nil
}

var filler = strings.Repeat("Notes from the weekly sync about the release schedule and testing. ", 4)

func outboundCases() []eval.OutboundCase {
	return []eval.OutboundCase{
		{Text: "use key sk-abcdefghijklmnop1234 for the deploy", Source: "prompt", Expect: []string{"credentials"}, Split: eval.SplitTune, Note: "local"},
		{Text: filler + "Zhang Wei lives at 12 Xinhua Road, Room 301", Source: "tool_output", Tool: "Bash", Expect: []string{"pii"}, Split: eval.SplitTune, Note: "judge only"},
		{Text: filler + "MAYBE nothing here", Source: "prompt", Split: eval.SplitTune, Note: "clean, judge unsure"},
		{Text: "Zhang Wei lives at 12 Xinhua Road", Source: "prompt", Expect: []string{"pii"}, Split: eval.SplitHoldout, Note: "short, not sent"},
		{Text: filler, Source: "prompt", Split: eval.SplitHoldout, Note: "clean"},
		{Text: filler + "Liu Yang lives at 7 Garden Road", Source: "prompt", Expect: []string{"pii"}, Split: eval.SplitFresh, Note: "fresh"},
	}
}

// TestRunOutbound：每条语料走一遍真实的 outbound 检查：本地识别的类别、模型的概率（门槛 0，全部留下）；本地已经 deny
// 或短于 judge_min_chars 的不发给模型。
func TestRunOutbound(t *testing.T) {
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	b := &outboundStub{}
	outs := eval.RunOutbound(context.Background(), eval.OutboundEnv{Rules: set, Config: config.Defaults(), Backend: b}, outboundCases())
	if len(outs) != 6 || b.calls != 4 {
		t.Fatalf("outcomes %d, calls %d", len(outs), b.calls)
	}
	if o := outs[0]; o.Sent || len(o.Local) != 1 || o.Local[0] != "credentials" {
		t.Errorf("local: %+v", o)
	}
	if o := outs[1]; !o.Sent || o.P["pii"] != 0.8 || o.P["credentials"] != 0.05 || len(o.Local) != 0 {
		t.Errorf("judge only: %+v", o)
	}
	if o := outs[3]; o.Sent || o.P != nil {
		t.Errorf("short: %+v", o)
	}
	// 门槛 0.5：PII 由模型补上；不确定的 0.4 不算
	s := eval.ScoreOutbound(outs, 0.5, "")
	if s.Expected != 4 || s.LocalMissed != 3 || s.Missed != 1 || s.Clean != 2 || s.LocalFP != 0 || s.FP != 0 || s.NotSent != 2 {
		t.Errorf("score at 0.5: %+v", s)
	}
	// 门槛 0.3：0.4 的干净文本被拦下
	if s := eval.ScoreOutbound(outs, 0.3, eval.SplitTune); s.FP != 1 || s.Missed != 0 {
		t.Errorf("score at 0.3: %+v", s)
	}
	rows, best := eval.SweepOutbound(outs, 0.5)
	// 扫描只用 tune：fresh 与 holdout 的语料不影响建议
	if best != 0.5 || len(rows) != 19 || eval.ScoreOutbound(outs, 0.5, eval.SplitTune).Cases != 3 {
		t.Errorf("sweep: best %g, %d rows", best, len(rows))
	}
	var buf bytes.Buffer
	eval.WriteOutboundReport(&buf, outs, 0.5)
	eval.WriteOutboundSweep(&buf, rows)
	for _, want := range []string{"missed, local only", "flagged clean", "holdout", "fresh", "missed pii", "(not sent)", "(current)",
		"=== By category (all splits) ===", "pii ", "=== By source (all splits) ===", "tool_output", "latency of texts sent to the judge: p50"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
	if strings.Contains(buf.String(), "sk-abcdefghijklmnop1234") {
		t.Errorf("report leaks the key:\n%s", buf.String())
	}
}

// TestLoadOutboundCases：语料严格解析：未知字段、缺文本、来源或切分不认识都是错误。
func TestLoadOutboundCases(t *testing.T) {
	dir := t.TempDir()
	for name, line := range map[string]string{
		"unknown field": `{"text":"x","source":"prompt","split":"tune","expect":[],"extra":1}`,
		"no text":       `{"text":"","source":"prompt","split":"tune","expect":[]}`,
		"bad source":    `{"text":"x","source":"file","split":"tune","expect":[]}`,
		"bad split":     `{"text":"x","source":"prompt","split":"train","expect":[]}`,
		"no split":      `{"text":"x","source":"prompt","expect":[]}`,
	} {
		p := filepath.Join(dir, "c.jsonl")
		os.WriteFile(p, []byte(line+"\n"), 0o600)
		if _, err := eval.LoadOutboundCases(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := filepath.Join(dir, "ok.jsonl")
	os.WriteFile(p, []byte(`{"text":"x","source":"tool_output","tool":"Read","split":"holdout","expect":["pii"],"note":"n"}`+"\n"), 0o600)
	if cs, err := eval.LoadOutboundCases(p); err != nil || len(cs) != 1 || cs[0].Expect[0] != "pii" {
		t.Errorf("ok: %+v %v", cs, err)
	}
}

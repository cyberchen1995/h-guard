package prompt

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

var (
	probQ = judge.Question{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{
		Question: "Would it publish?", CountsAsYes: "git push", CountsAsNo: "git status",
		Criteria: map[string]string{"true": "it publishes", "false": "it does not"},
	}}
	scaleQ = judge.Question{ID: "blast_radius", Kind: judge.KindScale,
		Instructions: judge.Instructions{Question: "How much is lost?"}, Levels: []string{"none", "some", "a lot", "everything"}}
)

func TestPrefixIsStableAndQuestionsComeLast(t *testing.T) {
	state := map[string]any{"call": map[string]any{"command": "git push", "cwd": "/w"}, "user_requests": []string{"push it"}}
	a, _ := Prefix(state)
	b, _ := Prefix(state)
	if a != b || !strings.HasPrefix(a, "STATE:\n{") {
		t.Fatalf("prefix not stable: %q", a)
	}
	single := Single(a, probQ)
	if !strings.HasPrefix(single, a) || !strings.HasSuffix(single, "Y for yes, N for no. Do not write anything else.") {
		t.Errorf("single = %q", single)
	}
	for _, want := range []string{"### publish", "Question: Would it publish?", "Counts as yes: git push", "Counts as no: git status", "Yes means: it publishes", "No means: it does not"} {
		if !strings.Contains(single, want) {
			t.Errorf("single lacks %q", want)
		}
	}
	scale := Single(a, scaleQ)
	if !strings.Contains(scale, "Level 3: everything") || !strings.Contains(scale, "single digit from 0 to 3") {
		t.Errorf("scale = %q", scale)
	}
	batch := Batch(a, []judge.Question{probQ, scaleQ})
	if !strings.HasPrefix(batch, a) || !strings.Contains(batch, "array of 4 probabilities") || !strings.Contains(batch, "### blast_radius") {
		t.Errorf("batch = %q", batch)
	}
}

func TestSchemaRequiresEveryQuestion(t *testing.T) {
	s := Schema([]judge.Question{probQ, scaleQ})
	b, _ := json.Marshal(s)
	var got struct {
		Required   []string `json:"required"`
		Properties struct {
			Answers struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
				Additional bool                       `json:"additionalProperties"`
			} `json:"answers"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	a := got.Properties.Answers
	if len(got.Required) != 1 || len(a.Required) != 2 || a.Additional || string(a.Properties["publish"]) != `{"type":"number"}` ||
		string(a.Properties["blast_radius"]) != `{"items":{"type":"number"},"type":"array"}` {
		t.Errorf("schema = %s", b)
	}
}

func TestParseBatchKeepsMissingMissing(t *testing.T) {
	qs := []judge.Question{probQ, scaleQ}
	for raw, want := range map[string]map[string]judge.Answer{
		`{"answers": {"publish": 0.3, "blast_radius": [0.1, 0.2, 0.3, 0.4]}}`: {"publish": {P: judge.Prob(0.3)}, "blast_radius": {Dist: []float64{0.1, 0.2, 0.3, 0.4}}},
		`{"answers": {"publish": 0}}`:                                         {"publish": {P: judge.Prob(0)}},
		`{"answers": {"publish": null, "blast_radius": [0.5, null, 0.5, 0]}}`: {},
		`{"answers": {"publish": "0.3", "blast_radius": 0.5}}`:                {},
		`{"answers": {"other": 0.9}}`:                                         {},
		`{}`:                                                                  {},
	} {
		got, err := ParseBatch([]byte(raw), qs)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if len(got) != len(want) {
			t.Errorf("%s: got %+v, want %+v", raw, got, want)
			continue
		}
		for id, w := range want {
			g := got[id]
			if (w.P == nil) != (g.P == nil) || (w.P != nil && *w.P != *g.P) || len(w.Dist) != len(g.Dist) {
				t.Errorf("%s: %s = %+v, want %+v", raw, id, g, w)
			}
		}
	}
	if _, err := ParseBatch([]byte(`not json`), qs); err == nil {
		t.Error("non-JSON accepted")
	}
}

func TestFromLogprobs(t *testing.T) {
	lp := func(p float64) *float64 { v := math.Log(p); return &v }
	a := FromLogprobs(probQ, []Candidate{{"Y", lp(0.6)}, {" yes", lp(0.1)}, {"N", lp(0.2)}, {"The", lp(0.1)}})
	if a.P == nil || math.Abs(*a.P-0.7/0.9) > 1e-9 {
		t.Errorf("P = %v", a.P)
	}
	if a := FromLogprobs(probQ, []Candidate{{"The", lp(0.9)}}); a.P != nil || a.Dist != nil {
		t.Errorf("no Y/N candidates must give no answer: %+v", a)
	}
	d := FromLogprobs(scaleQ, []Candidate{{"1", lp(0.5)}, {" 2", lp(0.3)}, {"7", lp(0.1)}, {"x", lp(0.1)}})
	if len(d.Dist) != 4 || math.Abs(d.Dist[1]-0.625) > 1e-9 || math.Abs(d.Dist[2]-0.375) > 1e-9 || d.Dist[0] != 0 {
		t.Errorf("Dist = %v", d.Dist)
	}
	if d := FromLogprobs(scaleQ, []Candidate{{"9", lp(1)}}); d.Dist != nil {
		t.Errorf("no level digits must give no answer: %v", d.Dist)
	}
}

// TestFromLogprobsNeedsValidNumbers：答案字符的 logprob 缺失、null 或不合法时整题没有给出，不能变成
// 「明确的否」去否决命中（评审 M2-01）；与答案无关的候选数值无效不影响；合法的 logprob 0 表示概率 1。
func TestFromLogprobsNeedsValidNumbers(t *testing.T) {
	lp := func(v float64) *float64 { return &v }
	for name, cands := range map[string][]Candidate{
		"only N, no number":      {{"N", nil}},
		"Y missing its number":   {{"N", lp(math.Log(0.6))}, {"Y", nil}},
		"positive logprob":       {{"N", lp(0.5)}},
		"NaN":                    {{"N", lp(math.NaN())}},
		"answer mass below half": {{"The", lp(math.Log(0.8))}, {"N", lp(math.Log(0.1))}},
		"level digit, no number": {{"1", nil}},
	} {
		q := probQ
		if name == "level digit, no number" {
			q = scaleQ
		}
		if a := FromLogprobs(q, cands); a.P != nil || a.Dist != nil {
			t.Errorf("%s: %+v, want no answer", name, a)
		}
	}
	if a := FromLogprobs(probQ, []Candidate{{"N", lp(0)}, {"The", nil}}); a.P == nil || *a.P != 0 {
		t.Errorf("a certain N (logprob 0) must be p=0: %+v", a)
	}
	if a := FromLogprobs(probQ, []Candidate{{"Y", lp(0)}}); a.P == nil || *a.P != 1 {
		t.Errorf("a certain Y must be p=1: %+v", a)
	}
}

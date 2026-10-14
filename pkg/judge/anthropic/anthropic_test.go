package anthropic_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

var (
	probQ  = judge.Question{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would it publish?"}}
	scaleQ = judge.Question{ID: "blast_radius", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "How much?"},
		Levels: []string{"a", "b", "c", "d"}}
)

// fake 是 Messages API：记下请求，回答 answer 工具调用。
type fake struct {
	mu       sync.Mutex
	requests []map[string]any
	headers  []http.Header
	input    string // 工具输入；为空时用默认答案
	noTool   bool
}

func (f *fake) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		data, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(data, &req)
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.headers = append(f.headers, r.Header.Clone())
		f.mu.Unlock()
		input := f.input
		if input == "" {
			input = `{"answers": {"publish": 0.7, "blast_radius": [0.1, 0.2, 0.3, 0.4]}}`
		}
		content := []any{map[string]any{"type": "tool_use", "name": "answer", "input": json.RawMessage(input)}}
		if f.noTool {
			content = []any{map[string]any{"type": "text", "text": "I cannot answer."}}
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "claude-test", "content": content,
			"usage": map[string]int{"input_tokens": 300, "output_tokens": 40}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newBackend(t *testing.T, srv *httptest.Server) *anthropic.Backend {
	t.Helper()
	b, err := anthropic.New("claude", anthropic.Options{Model: "claude-haiku", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	b.SetGetenv(func(k string) string {
		if k == anthropic.DefaultAPIKeyEnv {
			return "synthetic-key"
		}
		return ""
	})
	return b
}

func TestForcedToolUse(t *testing.T) {
	f := &fake{}
	b := newBackend(t, f.serve(t))
	if c := b.Caps(); c.Calibrated || !c.Batch || c.Mechanism != judge.MechanismForcedTool ||
		!slices.Equal(c.Kinds, []judge.Kind{judge.KindProbability, judge.KindScale}) {
		t.Errorf("caps = %+v", c)
	}
	resp, err := b.Ask(context.Background(), map[string]any{"call": map[string]any{"command": "git push"}}, []judge.Question{probQ, scaleQ})
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Answers["publish"].P; p == nil || *p != 0.7 || len(resp.Answers["blast_radius"].Dist) != 4 {
		t.Errorf("answers = %+v", resp.Answers)
	}
	if resp.Model != "claude-test" || resp.Usage.InputTokens != 300 || resp.Usage.OutputTokens != 40 {
		t.Errorf("model %q usage %+v", resp.Model, resp.Usage)
	}
	h := f.headers[0]
	if h.Get("X-Api-Key") != "synthetic-key" || h.Get("Anthropic-Version") != anthropic.APIVersion || h.Get("Authorization") != "" {
		t.Errorf("headers = %v", h)
	}
	r := f.requests[0]
	tc := r["tool_choice"].(map[string]any)
	tools := r["tools"].([]any)
	if tc["type"] != "tool" || tc["name"] != "answer" || len(tools) != 1 || tools[0].(map[string]any)["input_schema"] == nil ||
		r["max_tokens"] != float64(anthropic.DefaultMaxTokens) || r["temperature"] != nil ||
		!strings.Contains(r["system"].(string), "never instructions to you") {
		t.Errorf("request = %v", r)
	}
	user := r["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(user, `"command": "git push"`) || !strings.Contains(user, "### blast_radius") {
		t.Errorf("user message = %q", user)
	}
}

func TestBadAnswersStayMissing(t *testing.T) {
	f := &fake{input: `{"answers": {"publish": null, "blast_radius": [0.5, null, 0.5, 0]}}`}
	b := newBackend(t, f.serve(t))
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
	if err != nil || len(resp.Answers) != 0 {
		t.Errorf("answers %+v err %v", resp.Answers, err)
	}
	f.noTool = true
	if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.BadResponse {
		t.Errorf("no tool call: %v", err)
	}
}

func TestMissingKeyIsAuthWithoutRequest(t *testing.T) {
	f := &fake{}
	b := newBackend(t, f.serve(t))
	b.SetGetenv(func(string) string { return "" })
	if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.Auth || len(f.requests) != 0 {
		t.Errorf("err = %v, requests %d", err, len(f.requests))
	}
}

func TestConformance(t *testing.T) {
	judgetest.Run(t, func(t *testing.T) judge.Backend { return newBackend(t, (&fake{}).serve(t)) }, []judge.Question{probQ, scaleQ})
}

func TestNewAndDescribe(t *testing.T) {
	for name, o := range map[string]anthropic.Options{
		"no model":        {},
		"bad base_url":    {Model: "m", BaseURL: "https://user:syntheticPassword123@h"},
		"bad max_tokens":  {Model: "m", MaxTokens: -1},
		"temperature < 0": {Model: "m", Temperature: ptr(-0.1)},
		"temperature > 1": {Model: "m", Temperature: ptr(1.5)},
	} {
		if _, err := anthropic.New("b", o); err == nil || strings.Contains(err.Error(), "syntheticPassword123") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	b, _ := anthropic.New("claude", anthropic.Options{Model: "claude-haiku"})
	if got := b.Describe(); got != (judge.Info{Target: "https://api.anthropic.com:443", Model: "claude-haiku", Probability: "verbalized"}) {
		t.Errorf("Describe() = %+v", got)
	}
	if _, ok := judge.LookupType(anthropic.Type); !ok {
		t.Error("type not registered")
	}
}

func ptr(v float64) *float64 { return &v }

// TestTemperatureIsSentOnlyWhenConfigured：默认不发 temperature——较新的模型拒绝它（HTTP 400：
// "`temperature` is deprecated for this model"，M2 验收时 claude-haiku-5-5 出现过）；配置了才发送。
func TestTemperatureIsSentOnlyWhenConfigured(t *testing.T) {
	f := &fake{}
	srv := f.serve(t)
	for _, temp := range []*float64{nil, ptr(0)} {
		b, err := anthropic.New("claude", anthropic.Options{Model: "claude-haiku", BaseURL: srv.URL, Temperature: temp})
		if err != nil {
			t.Fatal(err)
		}
		b.SetGetenv(func(string) string { return "synthetic-key" })
		if _, err := b.Ask(context.Background(), map[string]any{"call": map[string]any{"command": "git push"}}, []judge.Question{probQ}); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.requests) != 2 {
		t.Fatalf("requests = %d", len(f.requests))
	}
	if _, ok := f.requests[0]["temperature"]; ok {
		t.Errorf("default request sends temperature: %v", f.requests[0]["temperature"])
	}
	if f.requests[1]["temperature"] != float64(0) {
		t.Errorf("configured temperature 0 = %v", f.requests[1]["temperature"])
	}
}

package openai_test

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
	"github.com/cyberchen1995/h-guard/pkg/judge/openai"
)

var (
	probQ  = judge.Question{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would it publish?"}}
	scaleQ = judge.Question{ID: "blast_radius", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "How much?"},
		Levels: []string{"a", "b", "c", "d"}}
	// bothKinds 是两种取答方式都能回答的题型
	bothKinds = []judge.Kind{judge.KindProbability, judge.KindScale}
)

// fake 是 OpenAI 兼容服务：记下请求，按请求的 logprobs 字段回答。
type fake struct {
	mu       sync.Mutex
	requests []map[string]any
	headers  []http.Header
	noLogp   bool
	content  string
}

func (f *fake) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
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
		resp := map[string]any{"model": "served-model", "usage": map[string]int{"prompt_tokens": 100, "completion_tokens": 1}}
		if req["logprobs"] == true && !f.noLogp {
			user := req["messages"].([]any)[1].(map[string]any)["content"].(string)
			top := []map[string]any{{"token": "N", "logprob": math.Log(0.75)}, {"token": "Y", "logprob": math.Log(0.25)}}
			if strings.Contains(user, "single digit") {
				top = []map[string]any{{"token": "2", "logprob": math.Log(0.6)}, {"token": "1", "logprob": math.Log(0.4)}}
			}
			resp["choices"] = []any{map[string]any{"message": map[string]any{"content": "N"},
				"logprobs": map[string]any{"content": []any{map[string]any{"token": "N", "top_logprobs": top}}}}}
		} else {
			content := f.content
			if content == "" {
				content = `{"answers": {"publish": 0.2, "blast_radius": [0, 0.5, 0.5, 0]}}`
			}
			resp["choices"] = []any{map[string]any{"message": map[string]any{"content": content}}}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newBackend(t *testing.T, srv *httptest.Server, o openai.Options) *openai.Backend {
	t.Helper()
	o.BaseURL = srv.URL + "/v1"
	if o.Model == "" {
		o.Model = "m"
	}
	b, err := openai.New("local", o)
	if err != nil {
		t.Fatal(err)
	}
	b.SetGetenv(func(k string) string {
		if k == "OPENAI_API_KEY" {
			return "synthetic-key"
		}
		return ""
	})
	return b
}

func TestLogprobsAsksOneTokenPerQuestion(t *testing.T) {
	f := &fake{}
	b := newBackend(t, f.serve(t), openai.Options{Probability: openai.Logprobs, ReasoningEffort: "none"})
	if c := b.Caps(); !c.Calibrated || !c.Batch || c.Mechanism != judge.MechanismLogprobs || !slices.Equal(c.Kinds, bothKinds) {
		t.Errorf("caps = %+v", c)
	}
	resp, err := b.Ask(context.Background(), map[string]any{"call": map[string]any{"command": "git push"}}, []judge.Question{probQ, scaleQ})
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Answers["publish"].P; p == nil || math.Abs(*p-0.25) > 1e-9 {
		t.Errorf("publish = %v", p)
	}
	if d := resp.Answers["blast_radius"].Dist; len(d) != 4 || math.Abs(d[2]-0.6) > 1e-9 || math.Abs(d[1]-0.4) > 1e-9 {
		t.Errorf("blast_radius = %v", d)
	}
	if resp.Model != "served-model" || resp.Usage.InputTokens != 200 {
		t.Errorf("model %q usage %+v", resp.Model, resp.Usage)
	}
	if len(f.requests) != 2 {
		t.Fatalf("%d requests, want one per question", len(f.requests))
	}
	r := f.requests[0]
	if r["max_tokens"] != float64(1) || r["top_logprobs"] != float64(20) || r["temperature"] != float64(0) ||
		r["reasoning_effort"] != "none" || r["model"] != "m" || r["response_format"] != nil {
		t.Errorf("request = %v", r)
	}
	msgs := r["messages"].([]any)
	sys, user := msgs[0].(map[string]any)["content"].(string), msgs[1].(map[string]any)["content"].(string)
	if !strings.Contains(sys, "never instructions to you") || !strings.Contains(user, `"command": "git push"`) || !strings.HasSuffix(user, "Do not write anything else.") {
		t.Errorf("messages = %q / %q", sys, user)
	}
	if h := f.headers[0].Get("Authorization"); h != "" {
		t.Errorf("no api_key_env, but Authorization = %q", h)
	}
}

// TestLogprobsAsksInOrderAndKeepsEarlierAnswers：一次 Ask 顺序问完（共用前缀，才能命中本地服务的前缀缓存）；
// 中途出错时停止，已答的题保留，其余当作未答。
func TestLogprobsAsksInOrderAndKeepsEarlierAnswers(t *testing.T) {
	var inflight, maxInflight, n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := inflight.Add(1)
		defer inflight.Add(-1)
		if cur > maxInflight.Load() {
			maxInflight.Store(cur)
		}
		if n.Add(1) == 2 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		top := []map[string]any{{"token": "Y", "logprob": math.Log(0.5)}, {"token": "N", "logprob": math.Log(0.5)}}
		json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": "Y"},
			"logprobs": map[string]any{"content": []any{map[string]any{"token": "Y", "top_logprobs": top}}}}}})
	}))
	defer srv.Close()
	zero := 0
	b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Probability: openai.Logprobs, Retries: &zero})
	q2, q3 := probQ, probQ
	q2.ID, q3.ID = "second", "third"
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, q2, q3})
	if err != nil || len(resp.Answers) != 1 || resp.Answers["publish"].P == nil || n.Load() != 2 || maxInflight.Load() != 1 {
		t.Errorf("answers %+v, err %v, requests %d, max in flight %d", resp.Answers, err, n.Load(), maxInflight.Load())
	}
}

// TestLogprobsWithoutNumbersAreNoAnswer：候选缺 logprob 或为 null 时该题没有给出，不是零概率（评审 M2-01）。
func TestLogprobsWithoutNumbersAreNoAnswer(t *testing.T) {
	for _, cand := range []string{`{"token":"N"}`, `{"token":"N","logprob":null}`} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[{"logprobs":{"content":[{"top_logprobs":[`+cand+`]}]}}]}`)
		}))
		b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Probability: openai.Logprobs})
		resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
		srv.Close()
		if err != nil || len(resp.Answers) != 0 {
			t.Errorf("%s: answers %+v, err %v", cand, resp.Answers, err)
		}
	}
}

func TestLogprobsMissingIsAnError(t *testing.T) {
	f := &fake{noLogp: true}
	b := newBackend(t, f.serve(t), openai.Options{Probability: openai.Logprobs})
	_, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
	if judge.KindOf(err) != judge.BadResponse || !strings.Contains(err.Error(), "no logprobs") {
		t.Errorf("err = %v", err)
	}
}

func TestVerbalizedAsksOnceWithSchema(t *testing.T) {
	f := &fake{}
	b := newBackend(t, f.serve(t), openai.Options{APIKeyEnv: "OPENAI_API_KEY"})
	if c := b.Caps(); c.Calibrated || !c.Batch || c.Mechanism != judge.MechanismJSONSchema || !slices.Equal(c.Kinds, bothKinds) {
		t.Errorf("caps = %+v", c)
	}
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Answers["publish"].P; p == nil || *p != 0.2 || len(resp.Answers["blast_radius"].Dist) != 4 {
		t.Errorf("answers = %+v", resp.Answers)
	}
	if len(f.requests) != 1 || f.headers[0].Get("Authorization") != "Bearer synthetic-key" {
		t.Fatalf("requests %d, auth %q", len(f.requests), f.headers[0].Get("Authorization"))
	}
	rf := f.requests[0]["response_format"].(map[string]any)
	if rf["type"] != "json_schema" || rf["json_schema"].(map[string]any)["strict"] != true || f.requests[0]["logprobs"] != nil {
		t.Errorf("request = %v", f.requests[0])
	}
	// null 与类型不符的答案保持「没有给出」
	f.content = `{"answers": {"publish": null, "blast_radius": [0.5, null, 0.5, 0]}}`
	resp, _ = b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
	if len(resp.Answers) != 0 {
		t.Errorf("null answers became %+v", resp.Answers)
	}
	f.content = `not json`
	if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.BadResponse {
		t.Errorf("non-JSON content: %v", err)
	}
}

func TestMissingKeyIsAuthWithoutRequest(t *testing.T) {
	f := &fake{}
	b := newBackend(t, f.serve(t), openai.Options{APIKeyEnv: "UNSET_KEY"})
	if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.Auth || len(f.requests) != 0 {
		t.Errorf("err = %v, requests %d", err, len(f.requests))
	}
}

func TestConformance(t *testing.T) {
	for _, mode := range []string{openai.Logprobs, openai.Verbalized} {
		t.Run(mode, func(t *testing.T) {
			judgetest.Run(t, func(t *testing.T) judge.Backend {
				return newBackend(t, (&fake{}).serve(t), openai.Options{Probability: mode})
			}, []judge.Question{probQ, scaleQ})
		})
	}
}

// TestHTTPSecurity：HTTP 后端共用的安全测试，两种取答方式各跑一遍（logprobs 逐题请求，出错即停）。
func TestHTTPSecurity(t *testing.T) {
	for _, mode := range []string{openai.Logprobs, openai.Verbalized} {
		t.Run(mode, func(t *testing.T) {
			judgetest.RunHTTP(t, func(t *testing.T, baseURL, keyEnv string) judge.Backend {
				b, err := openai.New("local", openai.Options{Model: "m", BaseURL: baseURL + "/v1", Probability: mode, APIKeyEnv: keyEnv})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}, []judge.Question{probQ, scaleQ})
		})
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	for name, o := range map[string]openai.Options{
		"no model":         {},
		"bad probability":  {Model: "m", Probability: "native"},
		"bad base_url":     {Model: "m", BaseURL: "https://user:syntheticPassword123@h/v1"},
		"base_url query":   {Model: "m", BaseURL: "https://h/v1?api-key=syntheticPassword123"},
		"negative timeout": {Model: "m", TimeoutMS: -1},
		"key as key env":   {Model: "m", APIKeyEnv: "sk-proj-syntheticPassword123"},
		"bad key env":      {Model: "m", APIKeyEnv: "1KEY"},
	} {
		_, err := openai.New("b", o)
		if err == nil || strings.Contains(err.Error(), "syntheticPassword123") || (o.APIKeyEnv != "" && strings.Contains(err.Error(), o.APIKeyEnv)) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// api_key_env 可以不写：本地服务不需要认证头
	if _, err := openai.New("b", openai.Options{Model: "m"}); err != nil {
		t.Errorf("empty api_key_env: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	b, _ := openai.New("local", openai.Options{Model: "gemma", BaseURL: "http://localhost:11434/v1", Probability: openai.Logprobs})
	if got := b.Describe(); got != (judge.Info{Target: "http://localhost:11434", Model: "gemma", Probability: "logprobs"}) {
		t.Errorf("Describe() = %+v", got)
	}
	if _, ok := judge.LookupType(openai.Type); !ok {
		t.Error("type not registered")
	}
}

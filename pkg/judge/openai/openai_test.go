package openai_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// fake 是 OpenAI 兼容服务：记下请求，按请求的 logprobs 字段回答。finish 非空时作为 choices[0].finish_reason。
type fake struct {
	mu       sync.Mutex
	requests []map[string]any
	headers  []http.Header
	noLogp   bool
	content  string
	finish   string
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
		if f.finish != "" {
			resp["choices"].([]any)[0].(map[string]any)["finish_reason"] = f.finish
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

// TestLogprobsWithoutNumbersAreNoAnswer：候选缺 logprob 或为 null 时该题没有给出，不是零概率。
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

// TestLogprobsWithoutTopLogprobsIsAnError：服务端给了 logprobs 结构，但 top_logprobs 为空（或缺失、null）时，
// 与完全没有 logprobs 一样是 BadResponse，说明是固定文本；不再静默成为全部未答（那样每次都只能回退到请求确认，
// 而用户看不到原因）。
func TestLogprobsWithoutTopLogprobsIsAnError(t *testing.T) {
	const canary = "HGCanaryReply20481024"
	for name, entry := range map[string]string{
		"empty":   `{"token":"` + canary + `","top_logprobs":[]}`,
		"null":    `{"token":"` + canary + `","top_logprobs":null}`,
		"missing": `{"token":"` + canary + `"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[{"logprobs":{"content":[`+entry+`]}}]}`)
		}))
		b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Probability: openai.Logprobs})
		resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
		srv.Close()
		if judge.KindOf(err) != judge.BadResponse || len(resp.Answers) != 0 {
			t.Errorf("%s: answers %+v, err %v, want bad_response and no answers", name, resp.Answers, err)
			continue
		}
		if !strings.HasSuffix(err.Error(), ": the server returned no logprobs (use probability: verbalized)") || strings.Contains(err.Error(), canary) {
			t.Errorf("%s: err = %q, want the fixed text", name, err)
		}
	}
}

// TestLogprobsEmptyTopLogprobsKeepsEarlierAnswers：中途出现空的 top_logprobs 与其他错误一样——已答的题保留，
// 其余当作未答（不会产生放行）。
func TestLogprobsEmptyTopLogprobsKeepsEarlierAnswers(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		top := `[{"token":"Y","logprob":-0.7},{"token":"N","logprob":-0.7}]`
		if n.Add(1) == 2 {
			top = `[]`
		}
		io.WriteString(w, `{"choices":[{"logprobs":{"content":[{"top_logprobs":`+top+`}]}}]}`)
	}))
	defer srv.Close()
	b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Probability: openai.Logprobs})
	q2, q3 := probQ, probQ
	q2.ID, q3.ID = "second", "third"
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, q2, q3})
	if err != nil || len(resp.Answers) != 1 || resp.Answers["publish"].P == nil || n.Load() != 2 {
		t.Errorf("answers %+v, err %v, requests %d", resp.Answers, err, n.Load())
	}
}

func ptr(v float64) *float64 { return &v }

// TestTemperature：logprobs 方式默认发送 0（与校准内置档案时的请求相同，档案因此仍然有效），verbalized 方式默认不发送
// （OpenAI 的推理模型拒绝 temperature）；配置了就原样发送，logprobs 的每个逐题请求都带它。
func TestTemperature(t *testing.T) {
	for _, tc := range []struct {
		mode string
		temp *float64
		want any // 请求里 temperature 的值；nil 表示不出现
	}{
		{openai.Logprobs, nil, float64(0)},
		{openai.Logprobs, ptr(0), float64(0)},
		{openai.Logprobs, ptr(0.3), 0.3},
		{openai.Logprobs, ptr(1), float64(1)},
		{openai.Verbalized, nil, nil},
		{openai.Verbalized, ptr(0), float64(0)},
		{openai.Verbalized, ptr(0.7), 0.7},
	} {
		name := fmt.Sprintf("%s/%v", tc.mode, tc.temp != nil)
		if tc.temp != nil {
			name = fmt.Sprintf("%s/%v", tc.mode, *tc.temp)
		}
		t.Run(name, func(t *testing.T) {
			f := &fake{}
			b := newBackend(t, f.serve(t), openai.Options{Probability: tc.mode, Temperature: tc.temp})
			if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ}); err != nil {
				t.Fatal(err)
			}
			if len(f.requests) == 0 {
				t.Fatal("no request")
			}
			for i, r := range f.requests {
				got, ok := r["temperature"]
				if (tc.want == nil) == ok || (ok && got != tc.want) {
					t.Errorf("request %d: temperature = %v (present %v), want %v", i, got, ok, tc.want)
				}
			}
		})
	}
}

// TestTemperatureIsPartOfTheFingerprint：实际发送的 temperature 与该方式的默认不同时，Info.Probability 末尾加
// -temperature-<值>（进入校准指纹）。logprobs 的默认是发送 0，所以只有配置了非 0 才加；verbalized 的默认是不发送，
// 所以配置了就加，包括 0。默认（没有配置）的 Probability 不变，现有档案仍然有效。
func TestTemperatureIsPartOfTheFingerprint(t *testing.T) {
	negZero := math.Copysign(0, -1)
	for _, tc := range []struct {
		mode string
		temp *float64
		want string
	}{
		{openai.Logprobs, nil, "logprobs"},
		{openai.Logprobs, ptr(0), "logprobs"},
		{openai.Logprobs, ptr(negZero), "logprobs"},
		{openai.Logprobs, ptr(0.3), "logprobs-temperature-0.3"},
		{openai.Logprobs, ptr(1), "logprobs-temperature-1"},
		{openai.Verbalized, nil, "verbalized"},
		{openai.Verbalized, ptr(0), "verbalized-temperature-0"},
		{openai.Verbalized, ptr(negZero), "verbalized-temperature-0"},
		{openai.Verbalized, ptr(0.25), "verbalized-temperature-0.25"},
		{openai.Verbalized, ptr(1), "verbalized-temperature-1"},
		{"", nil, "verbalized"}, // 默认方式是 verbalized
		{"", ptr(0), "verbalized-temperature-0"},
	} {
		b, err := openai.New("local", openai.Options{Model: "m", Probability: tc.mode, Temperature: tc.temp})
		if err != nil {
			t.Fatal(err)
		}
		if got := b.Describe().Probability; got != tc.want {
			v := "unset"
			if tc.temp != nil {
				v = fmt.Sprint(*tc.temp)
			}
			t.Errorf("probability %q, temperature %s: Describe().Probability = %q, want %q", tc.mode, v, got, tc.want)
		}
	}
}

// TestVerbalizedFingerprintMatchesTheRequest：verbalized 指的是「不发送 temperature」。指纹与实际的请求体一一对应：
// 默认不发送、指纹是 verbalized；显式配置 0 时发送 "temperature":0、指纹是 verbalized-temperature-0。
func TestVerbalizedFingerprintMatchesTheRequest(t *testing.T) {
	for _, tc := range []struct {
		temp        *float64
		sent        string // 请求体里 temperature 的原文；空表示没有这个键
		probability string
	}{
		{nil, "", "verbalized"},
		{ptr(0), "0", "verbalized-temperature-0"},
		{ptr(0.25), "0.25", "verbalized-temperature-0.25"},
	} {
		var body []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ = io.ReadAll(r.Body)
			io.WriteString(w, `{"choices":[{"message":{"content":"{\"answers\": {\"publish\": 0.2}}"}}]}`)
		}))
		b, err := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Temperature: tc.temp})
		if err != nil {
			t.Fatal(err)
		}
		_, err = b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
		srv.Close()
		var req map[string]json.RawMessage
		if err != nil || json.Unmarshal(body, &req) != nil {
			t.Fatalf("%s: err %v, body %.200s", tc.probability, err, body)
		}
		got, present := req["temperature"]
		if present != (tc.sent != "") || (present && string(got) != tc.sent) {
			t.Errorf("%s: request has temperature %s (present %v), want %q", tc.probability, got, present, tc.sent)
		}
		if p := b.Describe().Probability; p != tc.probability {
			t.Errorf("request temperature %q: Describe().Probability = %q, want %q", tc.sent, p, tc.probability)
		}
	}
}

// TestReasoningEffortIsPartOfTheFingerprint：reasoning_effort 改变模型的行为，设置后 Info.Probability 加
// -reasoning-effort-<值>，排在 temperature 后缀之前（与 anthropic 的 effort 一致）；不设置时不变。
func TestReasoningEffortIsPartOfTheFingerprint(t *testing.T) {
	for _, tc := range []struct {
		mode, effort string
		temp         *float64
		want         string
	}{
		{openai.Logprobs, "", nil, "logprobs"},
		{openai.Logprobs, "none", nil, "logprobs-reasoning-effort-none"},
		{openai.Logprobs, "none", ptr(0), "logprobs-reasoning-effort-none"},
		{openai.Logprobs, "none", ptr(0.3), "logprobs-reasoning-effort-none-temperature-0.3"},
		{openai.Verbalized, "", nil, "verbalized"},
		{openai.Verbalized, "low", nil, "verbalized-reasoning-effort-low"},
		{openai.Verbalized, "high", ptr(0), "verbalized-reasoning-effort-high-temperature-0"},
		{"", "minimal", nil, "verbalized-reasoning-effort-minimal"},
	} {
		b, err := openai.New("local", openai.Options{Model: "m", Probability: tc.mode, ReasoningEffort: tc.effort, Temperature: tc.temp})
		if err != nil {
			t.Fatal(err)
		}
		if got := b.Describe().Probability; got != tc.want {
			v := "unset"
			if tc.temp != nil {
				v = fmt.Sprint(*tc.temp)
			}
			t.Errorf("probability %q, reasoning_effort %q, temperature %s: Describe().Probability = %q, want %q",
				tc.mode, tc.effort, v, got, tc.want)
		}
	}
}

// TestVerbalizedFinishReason：verbalized 方式下 finish_reason 为 length（被截断）或 content_filter（被过滤）时，
// 内容不可信，即使是会放行的完整答案也报 BadResponse（固定说明）。logprobs 方式只要一个 token，length 是正常结束。
func TestVerbalizedFinishReason(t *testing.T) {
	const valid = `{"answers": {"publish": 0.01, "blast_radius": [1, 0, 0, 0]}}`
	for finish, want := range map[string]string{
		"length":         "the answer was cut off (finish_reason length)",
		"content_filter": "the content filter withheld the answer (finish_reason content_filter)",
	} {
		f := &fake{content: valid, finish: finish}
		b := newBackend(t, f.serve(t), openai.Options{})
		resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
		if judge.KindOf(err) != judge.BadResponse || len(resp.Answers) != 0 || !strings.HasSuffix(err.Error(), ": "+want) {
			t.Errorf("verbalized %s: answers %+v err %v, want bad_response %q", finish, resp.Answers, err, want)
		}
	}
	for _, finish := range []string{"stop", "tool_calls"} {
		f := &fake{content: valid, finish: finish}
		b := newBackend(t, f.serve(t), openai.Options{})
		if resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ}); err != nil || len(resp.Answers) != 2 {
			t.Errorf("verbalized %s: answers %+v err %v", finish, resp.Answers, err)
		}
	}
	f := &fake{finish: "length"}
	b := newBackend(t, f.serve(t), openai.Options{Probability: openai.Logprobs})
	if resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ}); err != nil || len(resp.Answers) != 2 {
		t.Errorf("logprobs length: answers %+v err %v, want both answers", resp.Answers, err)
	}
}

// TestTemperatureNegativeZeroIsSentAsZero：-0 与 0 是同一个值——请求里发送的是 0，不是 -0。
func TestTemperatureNegativeZeroIsSentAsZero(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		body = string(data)
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Temperature: ptr(math.Copysign(0, -1))})
	b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
	if !strings.Contains(body, `"temperature":0,`) || strings.Contains(body, `"temperature":-0`) {
		t.Errorf("body = %.200s", body)
	}
}

// TestLogprobsRequestKeepsTheCalibratedBytes：logprobs 方式不配置 temperature 时，请求体里的字段顺序与取值和校准时
// 逐字节相同（内置的本地档案依赖它）：temperature 紧跟在 messages 之后，值为 0。
func TestLogprobsRequestKeepsTheCalibratedBytes(t *testing.T) {
	for effort, tail := range map[string]string{
		"":     `],"temperature":0,"max_tokens":1,"logprobs":true,"top_logprobs":20}`,
		"none": `],"temperature":0,"max_tokens":1,"logprobs":true,"top_logprobs":20,"reasoning_effort":"none"}`,
	} {
		var body string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, _ := io.ReadAll(r.Body)
			body = string(data)
			io.WriteString(w, `{"choices":[{"logprobs":{"content":[{"top_logprobs":[{"token":"Y","logprob":-0.1}]}]}}]}`)
		}))
		b, _ := openai.New("local", openai.Options{Model: "m", BaseURL: srv.URL, Probability: openai.Logprobs, ReasoningEffort: effort})
		_, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
		srv.Close()
		if err != nil || !strings.HasPrefix(body, `{"model":"m","messages":[`) || !strings.HasSuffix(body, tail) {
			t.Errorf("effort %q: err %v, body = %.80s … %s", effort, err, body, body[max(0, len(body)-110):])
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
		"temperature < 0":  {Model: "m", Temperature: ptr(-0.1)},
		"temperature > 1":  {Model: "m", Temperature: ptr(1.5)},
		"temperature NaN":  {Model: "m", Temperature: ptr(math.NaN())},
		"temperature +Inf": {Model: "m", Temperature: ptr(math.Inf(1))},
	} {
		_, err := openai.New("b", o)
		if err == nil || strings.Contains(err.Error(), "syntheticPassword123") || (o.APIKeyEnv != "" && strings.Contains(err.Error(), o.APIKeyEnv)) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// temperature 的边界值 0 与 1 有效
	for _, v := range []float64{0, 0.5, 1} {
		if _, err := openai.New("b", openai.Options{Model: "m", Temperature: ptr(v)}); err != nil {
			t.Errorf("temperature %v: %v", v, err)
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

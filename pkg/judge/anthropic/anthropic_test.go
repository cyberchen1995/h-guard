package anthropic_test

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	"github.com/cyberchen1995/h-guard/pkg/judge/internal/prompt"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

var (
	probQ  = judge.Question{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would it publish?"}}
	scaleQ = judge.Question{ID: "blast_radius", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "How much?"},
		Levels: []string{"a", "b", "c", "d"}}
)

// fake 是 Messages API：记下请求并作答。默认按请求的取答方式回答：带 output_config 时回一个 text 块
// （结构化输出），否则回 answer 工具调用。content 非 nil 时原样作为回复内容，stop 是回复的 stop_reason；
// edit 非 nil 时在发出前改写整个回复（例如去掉 stop_reason）。
type fake struct {
	mu       sync.Mutex
	requests []map[string]any
	headers  []http.Header
	input    string // 答案 JSON；为空时用默认答案
	noTool   bool
	content  []any
	stop     string
	edit     func(resp map[string]any)
}

const defaultAnswers = `{"answers": {"publish": 0.7, "blast_radius": [0.1, 0.2, 0.3, 0.4]}}`

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
		input, content, stop, noTool, edit := f.input, f.content, f.stop, f.noTool, f.edit
		f.mu.Unlock()
		if input == "" {
			input = defaultAnswers
		}
		if content == nil {
			_, structured := req["output_config"]
			switch {
			case noTool:
				content = []any{map[string]any{"type": "text", "text": "I cannot answer."}}
			case structured:
				content = []any{map[string]any{"type": "text", "text": input}}
			default:
				content = []any{map[string]any{"type": "tool_use", "id": "toolu_1", "name": "answer", "input": json.RawMessage(input)}}
			}
		}
		if stop == "" {
			stop = "end_turn"
			if _, structured := req["output_config"]; !structured && !noTool {
				stop = "tool_use"
			}
		}
		resp := map[string]any{"model": "claude-test", "content": content, "stop_reason": stop,
			"usage": map[string]int{"input_tokens": 300, "output_tokens": 40}}
		if edit != nil {
			edit(resp)
		}
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newBackend(t *testing.T, srv *httptest.Server) *anthropic.Backend {
	t.Helper()
	return newBackendAnswering(t, srv, "")
}

// newBackendAnswering 创建取答方式为 answer 的后端（空串为默认）。
func newBackendAnswering(t *testing.T, srv *httptest.Server, answer string) *anthropic.Backend {
	t.Helper()
	b, err := anthropic.New("claude", anthropic.Options{Model: "claude-haiku", BaseURL: srv.URL, Answer: answer})
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

// modes 是全部取答方式。
var modes = []string{anthropic.AnswerTool, anthropic.AnswerStructured, anthropic.AnswerAutoTool}

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
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			judgetest.Run(t, func(t *testing.T) judge.Backend { return newBackendAnswering(t, (&fake{}).serve(t), mode) },
				[]judge.Question{probQ, scaleQ})
		})
	}
}

// TestHTTPSecurity：HTTP 后端共用的安全测试（重定向、错误响应、响应上限、Retry-After 与截止时间），三种取答方式各跑一次。
func TestHTTPSecurity(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			judgetest.RunHTTP(t, func(t *testing.T, baseURL, keyEnv string) judge.Backend {
				b, err := anthropic.New("claude", anthropic.Options{Model: "claude-haiku", BaseURL: baseURL, APIKeyEnv: keyEnv, Answer: mode})
				if err != nil {
					t.Fatal(err)
				}
				return b
			}, []judge.Question{probQ, scaleQ})
		})
	}
}

func TestNewAndDescribe(t *testing.T) {
	for name, o := range map[string]anthropic.Options{
		"no model":        {},
		"bad base_url":    {Model: "m", BaseURL: "https://user:syntheticPassword123@h"},
		"base_url anchor": {Model: "m", BaseURL: "https://h#syntheticPassword123"},
		"bad max_tokens":  {Model: "m", MaxTokens: -1},
		"temperature < 0": {Model: "m", Temperature: ptr(-0.1)},
		"temperature > 1": {Model: "m", Temperature: ptr(1.5)},
		"key as key env":  {Model: "m", APIKeyEnv: "sk-ant-api03-syntheticPassword123"},
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

// autoToolInstruction 是 auto_tool 方式加在用户消息末尾的一句（tool_choice auto 不保证调用）。
const autoToolInstruction = "Record the answers by calling the answer tool."

// normalize 把 v 经 JSON 往返成 map[string]any 等通用形式，便于与收到的请求体比较。
func normalize(t *testing.T, v any) any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAnswerModes：三种取答方式各自的能力声明、校准用的 Probability、请求体与答案解析。
func TestAnswerModes(t *testing.T) {
	qs := []judge.Question{probQ, scaleQ}
	schema := normalize(t, prompt.Schema(qs))
	for _, tc := range []struct {
		answer, mode, probability string
		mechanism                 judge.Mechanism
		keys                      []string // 请求体顶层的全部键
	}{
		{"", anthropic.AnswerTool, "verbalized", judge.MechanismForcedTool,
			[]string{"max_tokens", "messages", "model", "system", "tool_choice", "tools"}},
		{anthropic.AnswerTool, anthropic.AnswerTool, "verbalized", judge.MechanismForcedTool,
			[]string{"max_tokens", "messages", "model", "system", "tool_choice", "tools"}},
		{anthropic.AnswerStructured, anthropic.AnswerStructured, "verbalized-structured", judge.MechanismJSONSchema,
			[]string{"max_tokens", "messages", "model", "output_config", "system"}},
		{anthropic.AnswerAutoTool, anthropic.AnswerAutoTool, "verbalized-auto-tool", judge.MechanismAutoTool,
			[]string{"max_tokens", "messages", "model", "system", "tool_choice", "tools"}},
	} {
		t.Run("answer="+tc.answer, func(t *testing.T) {
			f := &fake{}
			b := newBackendAnswering(t, f.serve(t), tc.answer)
			if c := b.Caps(); c.Calibrated || !c.Batch || c.Mechanism != tc.mechanism ||
				!slices.Equal(c.Kinds, []judge.Kind{judge.KindProbability, judge.KindScale}) {
				t.Errorf("caps = %+v", c)
			}
			if got := b.Describe().Probability; got != tc.probability {
				t.Errorf("Describe().Probability = %q, want %q", got, tc.probability)
			}
			resp, err := b.Ask(context.Background(), map[string]any{"call": map[string]any{"command": "git push"}}, qs)
			if err != nil {
				t.Fatal(err)
			}
			if p := resp.Answers["publish"].P; p == nil || *p != 0.7 || len(resp.Answers["blast_radius"].Dist) != 4 {
				t.Errorf("answers = %+v", resp.Answers)
			}
			if resp.Model != "claude-test" || resp.Usage.InputTokens != 300 {
				t.Errorf("model %q usage %+v", resp.Model, resp.Usage)
			}
			r := f.requests[0]
			if keys := slices.Sorted(maps.Keys(r)); !slices.Equal(keys, tc.keys) {
				t.Errorf("request keys = %v, want %v (temperature only when configured)", keys, tc.keys)
			}
			user := r["messages"].([]any)[0].(map[string]any)["content"].(string)
			if !strings.Contains(user, `"command": "git push"`) || !strings.Contains(user, "### blast_radius") {
				t.Errorf("user message = %q", user)
			}
			switch tc.mode {
			case anthropic.AnswerTool:
				tool := r["tools"].([]any)[0].(map[string]any)
				if _, strict := tool["strict"]; strict || tool["name"] != "answer" || !reflect.DeepEqual(tool["input_schema"], schema) ||
					!reflect.DeepEqual(r["tool_choice"], map[string]any{"type": "tool", "name": "answer"}) || len(r["tools"].([]any)) != 1 {
					t.Errorf("tool request: tools %v tool_choice %v", r["tools"], r["tool_choice"])
				}
				if strings.HasSuffix(user, autoToolInstruction) {
					t.Errorf("the forced tool request changed its wording: %q", user)
				}
			case anthropic.AnswerStructured:
				want := map[string]any{"format": map[string]any{"type": "json_schema", "schema": schema}}
				if !reflect.DeepEqual(r["output_config"], want) {
					t.Errorf("output_config = %v, want %v", r["output_config"], want)
				}
				if strings.HasSuffix(user, autoToolInstruction) {
					t.Errorf("the structured request asks for a tool call: %q", user)
				}
			case anthropic.AnswerAutoTool:
				tools := r["tools"].([]any)
				tool := tools[0].(map[string]any)
				if len(tools) != 1 || tool["strict"] != true || tool["name"] != "answer" || !reflect.DeepEqual(tool["input_schema"], schema) ||
					!reflect.DeepEqual(r["tool_choice"], map[string]any{"type": "auto"}) {
					t.Errorf("auto_tool request: tools %v tool_choice %v", r["tools"], r["tool_choice"])
				}
				if !strings.HasSuffix(user, "\n"+autoToolInstruction) {
					t.Errorf("user message does not end with the instruction: %q", user)
				}
			}
		})
	}
}

// TestStopReasonComesFirst：refusal 与 max_tokens 时内容可能不符合 schema 或不完整，即使里面有看似完整的答案也报
// BadResponse（固定说明，不含回复内容）。
func TestStopReasonComesFirst(t *testing.T) {
	const canary = "HGCanaryReply246810"
	valid := `{"answers": {"publish": 0.01, "blast_radius": [1, 0, 0, 0]}, "note": "` + canary + `"}`
	for _, mode := range modes {
		for stop, want := range map[string]string{
			"refusal":    "the model declined to answer (refusal)",
			"max_tokens": "the answer was cut off at max_tokens",
		} {
			t.Run(mode+"/"+stop, func(t *testing.T) {
				f := &fake{input: valid, stop: stop}
				b := newBackendAnswering(t, f.serve(t), mode)
				resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
				if judge.KindOf(err) != judge.BadResponse || len(resp.Answers) != 0 {
					t.Fatalf("answers %+v err %v, want bad_response and no answers", resp.Answers, err)
				}
				if !strings.HasSuffix(err.Error(), ": "+want) || strings.Contains(err.Error(), canary) {
					t.Errorf("err = %q, want the fixed text %q", err, want)
				}
			})
		}
	}
}

// TestStopReasonIsAnAllowList：stop_reason 只接受正常结束的 end_turn、tool_use、stop_sequence。
// 其余取值（被上下文窗口截断、暂停、以后新增的取值）与缺失都报 BadResponse，说明是固定文本、不回显取值，
// 即使内容里有会放行的完整答案。
func TestStopReasonIsAnAllowList(t *testing.T) {
	const canary = "HGCanaryStop802468"
	valid := `{"answers": {"publish": 0.01, "blast_radius": [1, 0, 0, 0]}}`
	const early, none = "the response stopped early", "the response has no stop reason"
	for _, mode := range modes {
		for _, tc := range []struct {
			name string
			edit func(map[string]any)
			want string
		}{
			{"model_context_window_exceeded", func(r map[string]any) { r["stop_reason"] = "model_context_window_exceeded" }, early},
			{"pause_turn", func(r map[string]any) { r["stop_reason"] = "pause_turn" }, early},
			{"unknown", func(r map[string]any) { r["stop_reason"] = canary }, early},
			{"missing", func(r map[string]any) { delete(r, "stop_reason") }, none},
			{"null", func(r map[string]any) { r["stop_reason"] = nil }, none},
			{"empty", func(r map[string]any) { r["stop_reason"] = "" }, none},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				f := &fake{input: valid, edit: tc.edit}
				b := newBackendAnswering(t, f.serve(t), mode)
				resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
				if judge.KindOf(err) != judge.BadResponse || len(resp.Answers) != 0 {
					t.Fatalf("answers %+v err %v, want bad_response and no answers", resp.Answers, err)
				}
				if !strings.HasSuffix(err.Error(), ": "+tc.want) || strings.Contains(err.Error(), canary) {
					t.Errorf("err = %q, want the fixed text %q", err, tc.want)
				}
			})
		}
		for _, stop := range []string{"end_turn", "tool_use", "stop_sequence"} {
			t.Run(mode+"/"+stop, func(t *testing.T) {
				f := &fake{input: valid, stop: stop}
				b := newBackendAnswering(t, f.serve(t), mode)
				resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
				if err != nil || len(resp.Answers) != 2 {
					t.Fatalf("answers %+v err %v, want both answers", resp.Answers, err)
				}
			})
		}
	}
}

// TestMissingAnswerBlock：取不到答案所在的块时报 BadResponse，说明是固定文本。
func TestMissingAnswerBlock(t *testing.T) {
	const canary = "HGCanaryReply135790"
	text := map[string]any{"type": "text", "text": "I will not answer " + canary}
	thinking := map[string]any{"type": "thinking", "thinking": "", "signature": "sig"}
	call := map[string]any{"type": "tool_use", "id": "toolu_1", "name": "answer", "input": json.RawMessage(defaultAnswers)}
	other := map[string]any{"type": "tool_use", "id": "toolu_2", "name": "other", "input": json.RawMessage(defaultAnswers)}
	for _, tc := range []struct {
		mode    string
		content []any
		want    string
	}{
		{anthropic.AnswerTool, []any{text}, "the response has no answer tool call"},
		{anthropic.AnswerTool, []any{other}, "the response has no answer tool call"},
		{anthropic.AnswerAutoTool, []any{thinking, text}, "the response has no answer tool call"},
		{anthropic.AnswerAutoTool, []any{}, "the response has no answer tool call"},
		{anthropic.AnswerStructured, []any{call}, "the response has no text block"},
		{anthropic.AnswerStructured, []any{thinking}, "the response has no text block"},
		{anthropic.AnswerStructured, []any{text}, "answers are not a JSON object"},
	} {
		f := &fake{content: tc.content, stop: "end_turn"}
		b := newBackendAnswering(t, f.serve(t), tc.mode)
		_, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
		if judge.KindOf(err) != judge.BadResponse || !strings.HasSuffix(err.Error(), ": "+tc.want) || strings.Contains(err.Error(), canary) {
			t.Errorf("%s %v: err = %v, want bad_response %q", tc.mode, tc.content, err, tc.want)
		}
	}
}

// TestStructuredReadsTheFirstTextBlock：结构化输出取第一个 text 块（之前可能有 thinking 块），
// 经 prompt.ParseBatch 解析，多包一层 answers 时照常解析。
func TestStructuredReadsTheFirstTextBlock(t *testing.T) {
	thinking := map[string]any{"type": "thinking", "thinking": "", "signature": "sig"}
	for name, content := range map[string][]any{
		"after thinking": {thinking, map[string]any{"type": "text", "text": defaultAnswers}},
		"wrapped twice":  {map[string]any{"type": "text", "text": `{"answers": ` + defaultAnswers + `}`}},
		"first of two": {map[string]any{"type": "text", "text": defaultAnswers},
			map[string]any{"type": "text", "text": `{"answers": {"publish": 0.1}}`}},
	} {
		f := &fake{content: content, stop: "end_turn"}
		b := newBackendAnswering(t, f.serve(t), anthropic.AnswerStructured)
		resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p := resp.Answers["publish"].P; p == nil || *p != 0.7 || len(resp.Answers["blast_radius"].Dist) != 4 {
			t.Errorf("%s: answers = %+v", name, resp.Answers)
		}
	}
}

// TestUnknownAnswerIsAConfigError：answer 只能是 tool、structured、auto_tool；错误说明不回显取值。
func TestUnknownAnswerIsAConfigError(t *testing.T) {
	const canary = "HGCanaryAnswer97531"
	for _, v := range []string{canary, "Tool", "forced_tool", "json_schema", " tool"} {
		_, err := anthropic.New("claude", anthropic.Options{Model: "m", Answer: v})
		if err == nil || !strings.Contains(err.Error(), "answer") || strings.Contains(err.Error(), canary) {
			t.Errorf("answer %q: err = %v", v, err)
		}
	}
}

// TestFailureHint：只在强制工具调用方式、且失败说明正是 HTTP 400 时给出改用 structured 的提示。
func TestFailureHint(t *testing.T) {
	const hint = "If this model rejects forced tool use (Claude Opus 5.5, Sonnet 5.5, Fable 5.1 and newer do), " +
		"set answer: structured for this backend."
	for _, tc := range []struct {
		answer, detail, want string
	}{
		{"", "HTTP 400", hint},
		{anthropic.AnswerTool, "HTTP 400", hint},
		{anthropic.AnswerTool, "HTTP 401", ""},
		{anthropic.AnswerTool, "HTTP 500", ""},
		{anthropic.AnswerTool, "HTTP 4000", ""},
		{anthropic.AnswerTool, "", ""},
		{anthropic.AnswerTool, "the response has no answer tool call", ""},
		{anthropic.AnswerStructured, "HTTP 400", ""},
		{anthropic.AnswerAutoTool, "HTTP 400", ""},
	} {
		b, err := anthropic.New("claude", anthropic.Options{Model: "m", Answer: tc.answer})
		if err != nil {
			t.Fatal(err)
		}
		if got := b.FailureHint(tc.detail); got != tc.want {
			t.Errorf("answer %q detail %q: FailureHint = %q, want %q", tc.answer, tc.detail, got, tc.want)
		}
	}
}

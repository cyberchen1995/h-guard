// Package openai 是 OpenAI 兼容接口的判断后端（spec §8.2），后端类型名 openai。导入本包即注册该类型。
// 覆盖 OpenAI、Ollama、vLLM、LM Studio 等提供 /chat/completions 的服务。
//
// 概率获取方式（probability）：
//   - logprobs：每题一次请求，模型只答一个字符，读该位置候选字符的 logprob 归一化为概率或分布；
//     要求接口返回 logprobs，否则按后端出错处理（不会当作放行）：没有 logprobs、没有第一个 token 的条目、
//     或其 top_logprobs 为空，都是 BadResponse，不会静默成为「全部未答」。一次 Ask 依次问完全部题目（Batch=true）：
//     各题的请求共用同一段前缀（system + state），顺序发送才可能命中服务端的前缀缓存；本地服务通常一次只算一个
//     请求，并发不会更快（Ollama 0.34 MLX 运行器、gemma4 12B 实测：8 题并发约 25 秒，顺序约 14 秒）。
//     Calibrated=true，Mechanism logprobs。
//   - verbalized（默认）：用 json_schema 结构化输出一次问完，模型直接给出概率。Calibrated=false、Batch=true，
//     Mechanism json_schema。finish_reason 为 length（被截断）或 content_filter（被过滤）时内容不可信，按
//     BadResponse 报告（固定说明），即使内容是完整的 JSON。logprobs 方式只要一个 token，length 是正常结束，不检查。
//
// 两种方式都能回答两种题型。
//
// 可选参数 temperature（0 到 1，非法值是配置错误）：logprobs 方式默认发送 0，与校准时的请求逐字节相同
// （内置的本地档案依赖它）；verbalized 方式默认不发送，因为 OpenAI 的推理模型拒绝它，配置了才发送。
// 实际发送的 temperature 与该方式的默认不同时，Info.Probability 末尾加 -temperature-<值>（进入校准指纹，
// 要分别校准）：logprobs 只有配置了非 0 的值才加，verbalized 配置了就加（包括 0）。
//
// reasoning_effort 非空时原样放进请求。它改变模型的行为（思考的多少），所以同样进入校准指纹：Info.Probability
// 末尾加 -reasoning-effort-<值>，排在 temperature 后缀之前（与 anthropic 的 effort 一致），
// 如 logprobs-reasoning-effort-none、verbalized-reasoning-effort-low-temperature-0。
//
// 端点只来自配置（base_url），不读环境变量：同意绑定的主机不会被悄悄改掉（spec §8.5）。
package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/internal/httpx"
	"github.com/cyberchen1995/h-guard/pkg/judge/internal/prompt"
)

// Type 是注册的后端类型名。
const Type = "openai"

const (
	DefaultBaseURL = "https://api.openai.com/v1"
	DefaultTimeout = 8 * time.Second // 单次请求
	DefaultRetries = 1
	topLogprobs    = 20 // OpenAI 允许的上限
)

// 概率获取方式。
const (
	Logprobs   = "logprobs"
	Verbalized = "verbalized"
)

// Options 是 openai 后端的配置项。
type Options struct {
	Model       string `yaml:"model" json:"model"`
	BaseURL     string `yaml:"base_url" json:"base_url"`
	Probability string `yaml:"probability" json:"probability"`
	// APIKeyEnv 是存放 API key 的环境变量名。不写时不发送认证头（本地服务）；写了而变量为空时报认证错误。
	APIKeyEnv string `yaml:"api_key_env" json:"api_key_env"`
	// ReasoningEffort 非空时原样放进请求（如本地思考模型设为 none，让第一个 token 就是答案），
	// 并让 Info.Probability 末尾加 -reasoning-effort-<值>（进入校准指纹）。
	ReasoningEffort string `yaml:"reasoning_effort" json:"reasoning_effort"`
	TimeoutMS       int    `yaml:"timeout_ms" json:"timeout_ms"`
	Retries         *int   `yaml:"retries" json:"retries"`
	// Temperature 取 0 到 1。logprobs 方式默认发送 0（与校准时的请求相同；该方式读的是模型自己的分布，
	// 采样温度不是它要的参数）；verbalized 方式默认不发送——OpenAI 的推理模型拒绝它——配置了才发送。
	// 实际发送的值与默认不同时，Info.Probability 末尾加 -temperature-<值>（进入校准指纹）。
	Temperature *float64 `yaml:"temperature" json:"temperature"`
}

func init() {
	if err := judge.RegisterType(Type, func(name string, decode func(v any) error) (judge.Backend, error) {
		var o Options
		if err := decode(&o); err != nil {
			return nil, err
		}
		return New(name, o)
	}); err != nil {
		panic(err)
	}
}

// Backend 是 openai 后端。创建时不做任何网络操作。
type Backend struct {
	name, model, mode, keyEnv, effort string
	temperature                       *float64 // 已套用方式的默认值；nil 表示不发送
	base                              *url.URL
	endpoint                          string
	client                            *httpx.Client
	getenv                            func(string) string
}

// New 按配置创建后端；配置非法时返回错误（不回显 base_url）。
func New(name string, o Options) (*Backend, error) {
	if o.Model == "" {
		return nil, errors.New("openai: model is required")
	}
	b := &Backend{name: name, model: o.Model, mode: o.Probability, keyEnv: o.APIKeyEnv, effort: o.ReasoningEffort, getenv: os.Getenv}
	switch b.mode {
	case "":
		b.mode = Verbalized
	case Logprobs, Verbalized:
	default:
		return nil, errors.New("openai: probability must be logprobs or verbalized")
	}
	if t := o.Temperature; t != nil && !(*t >= 0 && *t <= 1) { // 不回显取值；NaN 也在此被拒绝
		return nil, errors.New("openai: temperature must be between 0 and 1")
	}
	if t := o.Temperature; t != nil {
		v := *t + 0 // 复制一份，不与调用方共享；加 0 把 -0 变成 0，请求里与指纹里都是 0
		b.temperature = &v
	} else if b.mode == Logprobs {
		zero := 0.0
		b.temperature = &zero
	}
	if b.keyEnv != "" { // 可以不写：不发认证头（本地服务）
		if err := httpx.ValidKeyEnv(Type, b.keyEnv); err != nil { // 不回显：误填进来的可能正是 key
			return nil, err
		}
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := httpx.ParseBase(Type, base)
	if err != nil {
		return nil, err
	}
	b.base, b.endpoint = u, u.JoinPath("chat", "completions").String()
	timeout, retries, err := httpx.Settings(Type, o.TimeoutMS, o.Retries, DefaultTimeout, DefaultRetries)
	if err != nil {
		return nil, err
	}
	b.client = httpx.New(timeout, retries)
	return b, nil
}

func (b *Backend) Name() string { return b.name }

func (b *Backend) Caps() judge.BackendCaps {
	c := judge.BackendCaps{Calibrated: b.mode == Logprobs, Batch: true, Mechanism: judge.MechanismJSONSchema,
		Kinds: []judge.Kind{judge.KindProbability, judge.KindScale}}
	if b.mode == Logprobs {
		c.Mechanism = judge.MechanismLogprobs
	}
	return c
}

// Describe 实现 judge.Describer。Probability 进入校准指纹，必须随请求的形态一起变：同一个 Probability 只对应一种请求。
//
// verbalized 指的是「不发送 temperature」（服务端默认温度）。早先的 verbalized 请求带 "temperature":0；
// 改为默认不发送后，verbalized 的含义随之重新定义，显式配置 0 的请求（即早先的形态）得到 verbalized-temperature-0。
// 这样改而不另起新名字，是因为改动时还没有发布过任何版本，也没有按 openai verbalized 校准的档案。
func (b *Backend) Describe() judge.Info {
	p := b.mode
	if b.effort != "" { // reasoning_effort 改变模型的行为，进入校准指纹；排在 temperature 之前
		p += "-reasoning-effort-" + b.effort
	}
	// 实际发送的 temperature 与该方式的默认不同时进入校准指纹：logprobs 的默认是发送 0，verbalized 的默认是不发送
	if t := b.temperature; t != nil && !(b.mode == Logprobs && *t == 0) {
		p += "-temperature-" + strconv.FormatFloat(*t, 'g', -1, 64)
	}
	return judge.Info{Target: httpx.Target(b.base), Model: b.model, Probability: p}
}

// Endpoint 返回请求地址，供 status 与 check 显示（不含凭据）。
func (b *Backend) Endpoint() string { return b.endpoint }

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type request struct {
	Model           string         `json:"model"`
	Messages        []message      `json:"messages"`
	Temperature     *float64       `json:"temperature,omitempty"`
	MaxTokens       int            `json:"max_tokens,omitempty"`
	Logprobs        bool           `json:"logprobs,omitempty"`
	TopLogprobs     int            `json:"top_logprobs,omitempty"`
	ResponseFormat  map[string]any `json:"response_format,omitempty"`
	ReasoningEffort string         `json:"reasoning_effort,omitempty"`
}

type response struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
		Logprobs     *struct {
			Content []struct {
				TopLogprobs []struct {
					Token   string   `json:"token"`
					Logprob *float64 `json:"logprob"` // 缺失或 null 时为 nil：没有给出，不是 0
				} `json:"top_logprobs"`
			} `json:"content"`
		} `json:"logprobs"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Ask 按 probability 提问。logprobs 时逐题依次请求；某题出错即停止，已答的题保留（其余当作未答，
// 不会产生放行），一题都没答出时返回该错误。
func (b *Backend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	header := http.Header{}
	if b.keyEnv != "" {
		key := b.getenv(b.keyEnv)
		if key == "" {
			return judge.Response{}, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("%s is not set", b.keyEnv)}
		}
		header.Set("Authorization", "Bearer "+key)
	}
	prefix, err := prompt.Prefix(state)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	if b.mode == Verbalized {
		return b.verbalized(ctx, header, prefix, qs)
	}
	out := judge.Response{Answers: map[string]judge.Answer{}}
	for _, q := range qs {
		r, err := b.send(ctx, header, request{
			Model: b.model, Temperature: b.temperature, MaxTokens: 1, Logprobs: true, TopLogprobs: topLogprobs, ReasoningEffort: b.effort,
			Messages: []message{{"system", prompt.System}, {"user", prompt.Single(prefix, q)}},
		})
		// 没有 logprobs、没有第一个 token 的条目、或其 top_logprobs 为空，都是「服务端没有给出」，不是全部未答
		if err == nil && (len(r.Choices) == 0 || r.Choices[0].Logprobs == nil || len(r.Choices[0].Logprobs.Content) == 0 ||
			len(r.Choices[0].Logprobs.Content[0].TopLogprobs) == 0) {
			err = &judge.Error{Kind: judge.BadResponse, Err: errors.New("the server returned no logprobs (use probability: verbalized)")}
		}
		if err != nil {
			if len(out.Answers) == 0 {
				return judge.Response{}, err
			}
			break
		}
		var cands []prompt.Candidate
		for _, c := range r.Choices[0].Logprobs.Content[0].TopLogprobs {
			cands = append(cands, prompt.Candidate{Token: c.Token, Logprob: c.Logprob})
		}
		if a := prompt.FromLogprobs(q, cands); a.P != nil || a.Dist != nil {
			out.Answers[q.ID] = a
		}
		out.Model = r.Model
		out.Usage.InputTokens += r.Usage.PromptTokens
		out.Usage.OutputTokens += r.Usage.CompletionTokens
	}
	return out, nil
}

func (b *Backend) verbalized(ctx context.Context, header http.Header, prefix string, qs []judge.Question) (judge.Response, error) {
	r, err := b.send(ctx, header, request{
		Model: b.model, Temperature: b.temperature, ReasoningEffort: b.effort,
		Messages: []message{{"system", prompt.System}, {"user", prompt.Batch(prefix, qs)}},
		ResponseFormat: map[string]any{
			"type": "json_schema", "json_schema": map[string]any{"name": "answers", "strict": true, "schema": prompt.Schema(qs)},
		},
	})
	if err != nil {
		return judge.Response{}, err
	}
	if len(r.Choices) == 0 {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("no choices in response")}
	}
	// 被截断或被过滤时内容不可信：截断的答案仍可能是合法的 JSON，数字截短后就成了有把握的否决
	switch r.Choices[0].FinishReason {
	case "length":
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("the answer was cut off (finish_reason length)")}
	case "content_filter":
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse,
			Err: errors.New("the content filter withheld the answer (finish_reason content_filter)")}
	}
	answers, err := prompt.ParseBatch([]byte(r.Choices[0].Message.Content), qs)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	return judge.Response{Answers: answers, Model: r.Model,
		Usage: judge.Usage{InputTokens: r.Usage.PromptTokens, OutputTokens: r.Usage.CompletionTokens}}, nil
}

func (b *Backend) send(ctx context.Context, header http.Header, req request) (response, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	data, err := b.client.PostJSON(ctx, b.endpoint, header, body)
	if err != nil {
		return response{}, err
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response is not valid JSON")}
	}
	return r, nil
}

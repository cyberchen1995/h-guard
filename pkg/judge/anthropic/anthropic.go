// Package anthropic 是 Anthropic Messages API 的判断后端（spec §8.2），后端类型名 anthropic。导入本包即注册该类型。
//
// Messages API 不提供 logprobs，模型一次答完全部题目、直接给出概率（verbalized）：Calibrated=false、Batch=true，
// 两种题型都能回答。三种取答方式（配置项 answer）请求形态不同，给出的概率也不同，所以 Info.Probability 各不相同，
// 要分别校准：
//   - tool（默认）：强制调用 answer 工具（tool_choice {type: tool}），工具的输入就是答案。Mechanism forced_tool，
//     Probability verbalized。较新的模型（Claude Opus 5.5、Sonnet 5.5、Fable 5.1 等）拒绝强制工具调用（HTTP 400）。
//   - structured：原生结构化输出（output_config.format 的 json_schema），不发 tools；答案是第一个 text 块里的 JSON。
//     Mechanism json_schema，Probability verbalized-structured。
//   - auto_tool：answer 工具带 strict: true（参数符合 schema），tool_choice {type: auto}，用户消息末尾要求调用该工具。
//     模型仍可能不调用，这时按没有答案报错。Mechanism auto_tool，Probability verbalized-auto-tool。
//
// 不探测模型支持哪种方式，也不在 HTTP 400 后自动换一种：换了方式，概率分布随之改变，按原方式校准的阈值不再适用，
// 同一份配置也会在不同时刻用不同的方式作答。方式只来自配置；tool 方式收到 HTTP 400 时，FailureHint 提示改用 structured。
//
// 读答案前先看 stop_reason，只接受正常结束的 end_turn、tool_use、stop_sequence。refusal（安全分类器拒答，内容可能
// 不符合 schema）、max_tokens（被截断）、其余取值（如被上下文窗口截断、暂停、以后新增的取值）与缺失都按 BadResponse
// 报告，即使内容里有看似完整的答案：被截断的答案仍可能是合法的 JSON，数字截短后就成了有把握的否决。
// 错误说明一律是固定文本，不含回复内容，也不回显 stop_reason 的取值。
//
// 端点只来自配置（base_url），同意绑定的主机不会被环境变量改掉（spec §8.5）。
package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/internal/httpx"
	"github.com/cyberchen1995/h-guard/pkg/judge/internal/prompt"
)

// Type 是注册的后端类型名。
const Type = "anthropic"

const (
	DefaultBaseURL   = "https://api.anthropic.com"
	DefaultAPIKeyEnv = "ANTHROPIC_API_KEY"
	DefaultMaxTokens = 1024
	DefaultTimeout   = 12 * time.Second // 单次请求
	DefaultRetries   = 1
	APIVersion       = "2023-06-01"
	toolName         = "answer"
	// autoToolInstruction 加在 auto_tool 方式的用户消息末尾：tool_choice auto 不保证调用
	autoToolInstruction = "Record the answers by calling the answer tool."
	// forcedToolHint 是 tool 方式收到 HTTP 400 时的提示（FailureHint）
	forcedToolHint = "If this model rejects forced tool use (Claude Opus 5.5, Sonnet 5.5, Fable 5.1 and newer do), " +
		"set answer: structured for this backend."
)

// 取答方式（配置项 answer）。
const (
	AnswerTool       = "tool"       // 强制调用 answer 工具（默认）
	AnswerStructured = "structured" // output_config.format 的 json_schema
	AnswerAutoTool   = "auto_tool"  // strict 工具 + tool_choice auto
)

// Options 是 anthropic 后端的配置项。
type Options struct {
	Model     string `yaml:"model" json:"model"`
	BaseURL   string `yaml:"base_url" json:"base_url"`
	APIKeyEnv string `yaml:"api_key_env" json:"api_key_env"`
	MaxTokens int    `yaml:"max_tokens" json:"max_tokens"`
	TimeoutMS int    `yaml:"timeout_ms" json:"timeout_ms"`
	Retries   *int   `yaml:"retries" json:"retries"`
	// Temperature 默认不发送：较新的模型拒绝它（HTTP 400，"temperature is deprecated for this model"）。
	// 仍接受它的模型可以设为 0，使答案更稳定。
	Temperature *float64 `yaml:"temperature" json:"temperature"`
	// Answer 是取答方式：tool（默认）、structured 或 auto_tool，见包注释。
	Answer string `yaml:"answer" json:"answer"`
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

// Backend 是 anthropic 后端。创建时不做任何网络操作。
type Backend struct {
	name, model, keyEnv string
	answer              string
	maxTokens           int
	temperature         *float64
	base                *url.URL
	endpoint            string
	client              *httpx.Client
	getenv              func(string) string
}

// New 按配置创建后端；配置非法时返回错误（不回显 base_url）。
func New(name string, o Options) (*Backend, error) {
	if o.Model == "" {
		return nil, errors.New("anthropic: model is required")
	}
	b := &Backend{name: name, model: o.Model, keyEnv: o.APIKeyEnv, answer: o.Answer, maxTokens: o.MaxTokens,
		temperature: o.Temperature, getenv: os.Getenv}
	switch b.answer {
	case "":
		b.answer = AnswerTool
	case AnswerTool, AnswerStructured, AnswerAutoTool:
	default: // 不回显取值
		return nil, errors.New("anthropic: answer must be tool, structured or auto_tool")
	}
	if b.keyEnv == "" {
		b.keyEnv = DefaultAPIKeyEnv
	}
	if err := httpx.ValidKeyEnv(Type, b.keyEnv); err != nil { // 不回显：误填进来的可能正是 key
		return nil, err
	}
	switch {
	case b.maxTokens < 0:
		return nil, errors.New("anthropic: max_tokens must not be negative")
	case b.maxTokens == 0:
		b.maxTokens = DefaultMaxTokens
	}
	if t := b.temperature; t != nil && !(*t >= 0 && *t <= 1) {
		return nil, errors.New("anthropic: temperature must be between 0 and 1")
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := httpx.ParseBase(Type, base)
	if err != nil {
		return nil, err
	}
	b.base, b.endpoint = u, u.JoinPath("v1", "messages").String()
	timeout, retries, err := httpx.Settings(Type, o.TimeoutMS, o.Retries, DefaultTimeout, DefaultRetries)
	if err != nil {
		return nil, err
	}
	b.client = httpx.New(timeout, retries)
	return b, nil
}

func (b *Backend) Name() string { return b.name }

func (b *Backend) Caps() judge.BackendCaps {
	m := judge.MechanismForcedTool
	switch b.answer {
	case AnswerStructured:
		m = judge.MechanismJSONSchema
	case AnswerAutoTool:
		m = judge.MechanismAutoTool
	}
	return judge.BackendCaps{Batch: true, Mechanism: m, Kinds: []judge.Kind{judge.KindProbability, judge.KindScale}}
}

// Describe 实现 judge.Describer。Probability 区分取答方式（进入校准指纹）：tool 仍是 verbalized，
// 与之前的校准档案一致。
func (b *Backend) Describe() judge.Info {
	p := "verbalized"
	switch b.answer {
	case AnswerStructured:
		p = "verbalized-structured"
	case AnswerAutoTool:
		p = "verbalized-auto-tool"
	}
	return judge.Info{Target: httpx.Target(b.base), Model: b.model, Probability: p}
}

// FailureHint 返回调用失败时给用户的提示：tool 方式下失败说明正是 HTTP 400 时，提示改用 structured
// （较新的模型拒绝强制工具调用）；其余情况为空串。只看状态码与取答方式，不回显 detail。
func (b *Backend) FailureHint(detail string) string {
	if b.answer == AnswerTool && detail == "HTTP 400" {
		return forcedToolHint
	}
	return ""
}

// Endpoint 返回请求地址，供 status 与 check 显示（不含凭据）。
func (b *Backend) Endpoint() string { return b.endpoint }

type request struct {
	Model        string           `json:"model"`
	MaxTokens    int              `json:"max_tokens"`
	Temperature  *float64         `json:"temperature,omitempty"`
	System       string           `json:"system"`
	Messages     []map[string]any `json:"messages"`
	Tools        []map[string]any `json:"tools,omitempty"`
	ToolChoice   map[string]any   `json:"tool_choice,omitempty"`
	OutputConfig map[string]any   `json:"output_config,omitempty"`
}

type response struct {
	Model      string `json:"model"`
	StopReason string `json:"stop_reason"`
	Content    []struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
		Text  string          `json:"text"`
	} `json:"content"`
	Usage judge.Usage `json:"usage"`
}

// build 按取答方式构造请求。tool 方式的请求与引入取答方式之前逐字节相同（校准档案依赖它）。
func (b *Backend) build(prefix string, qs []judge.Question) request {
	user := prompt.Batch(prefix, qs)
	req := request{Model: b.model, MaxTokens: b.maxTokens, Temperature: b.temperature, System: prompt.System}
	tool := map[string]any{"name": toolName, "description": "Record the answer to every question.", "input_schema": prompt.Schema(qs)}
	switch b.answer {
	case AnswerStructured:
		req.OutputConfig = map[string]any{"format": map[string]any{"type": "json_schema", "schema": prompt.Schema(qs)}}
	case AnswerAutoTool:
		tool["strict"] = true
		req.Tools, req.ToolChoice = []map[string]any{tool}, map[string]any{"type": "auto"}
		user += "\n" + autoToolInstruction
	default:
		req.Tools, req.ToolChoice = []map[string]any{tool}, map[string]any{"type": "tool", "name": toolName}
	}
	req.Messages = []map[string]any{{"role": "user", "content": user}}
	return req
}

// Ask 一次问完 qs，按取答方式取答案（见包注释）。
func (b *Backend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	key := b.getenv(b.keyEnv)
	if key == "" {
		return judge.Response{}, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("%s is not set", b.keyEnv)}
	}
	prefix, err := prompt.Prefix(state)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	body, err := json.Marshal(b.build(prefix, qs))
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	header := http.Header{"X-Api-Key": {key}, "Anthropic-Version": {APIVersion}}
	data, err := b.client.PostJSON(ctx, b.endpoint, header, body)
	if err != nil {
		return judge.Response{}, err
	}
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response is not valid JSON")}
	}
	raw, err := b.answerOf(r)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	answers, err := prompt.ParseBatch(raw, qs)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	return judge.Response{Answers: answers, Model: r.Model, Usage: r.Usage}, nil
}

// answerOf 取出回复里的答案 JSON。先看 stop_reason（允许列表）：只有正常结束时内容才可信，拒答、截断、
// 其余取值与缺失时即使看似完整也不用。错误说明都是固定文本，不含回复内容，也不回显 stop_reason。
func (b *Backend) answerOf(r response) ([]byte, error) {
	switch r.StopReason {
	case "end_turn", "tool_use", "stop_sequence":
	case "refusal":
		return nil, errors.New("the model declined to answer (refusal)")
	case "max_tokens":
		return nil, errors.New("the answer was cut off at max_tokens")
	case "": // 缺失或为 null（有的代理不转发）：无法确认答案完整
		return nil, errors.New("the response has no stop reason")
	default:
		return nil, errors.New("the response stopped early")
	}
	if b.answer == AnswerStructured {
		for _, c := range r.Content {
			if c.Type == "text" {
				return []byte(c.Text), nil
			}
		}
		return nil, errors.New("the response has no text block")
	}
	// auto_tool 时模型没有调用同样按错误报告（eval 能显示原因），结论照样不放行
	for _, c := range r.Content {
		if c.Type == "tool_use" && c.Name == toolName {
			return c.Input, nil
		}
	}
	return nil, errors.New("the response has no answer tool call")
}

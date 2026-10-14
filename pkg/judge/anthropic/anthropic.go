// Package anthropic 是 Anthropic Messages API 的判断后端（spec §8.2），后端类型名 anthropic。导入本包即注册该类型。
//
// 用强制 tool use 让模型按 JSON schema 一次答完全部题目，模型直接给出概率（verbalized）：
// Calibrated=false、Batch=true，Mechanism forced_tool，两种题型都能回答。端点只来自配置（base_url），同意绑定的主机不会被环境变量改掉（spec §8.5）。
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
	b := &Backend{name: name, model: o.Model, keyEnv: o.APIKeyEnv, maxTokens: o.MaxTokens, temperature: o.Temperature, getenv: os.Getenv}
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
	return judge.BackendCaps{Batch: true, Mechanism: judge.MechanismForcedTool,
		Kinds: []judge.Kind{judge.KindProbability, judge.KindScale}}
}

// Describe 实现 judge.Describer。
func (b *Backend) Describe() judge.Info {
	return judge.Info{Target: httpx.Target(b.base), Model: b.model, Probability: "verbalized"}
}

// Endpoint 返回请求地址，供 status 与 check 显示（不含凭据）。
func (b *Backend) Endpoint() string { return b.endpoint }

type request struct {
	Model       string           `json:"model"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature *float64         `json:"temperature,omitempty"`
	System      string           `json:"system"`
	Messages    []map[string]any `json:"messages"`
	Tools       []map[string]any `json:"tools"`
	ToolChoice  map[string]any   `json:"tool_choice"`
}

type response struct {
	Model   string `json:"model"`
	Content []struct {
		Type  string          `json:"type"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	Usage judge.Usage `json:"usage"`
}

// Ask 一次问完 qs：强制调用 answer 工具，工具的输入就是答案。
func (b *Backend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	key := b.getenv(b.keyEnv)
	if key == "" {
		return judge.Response{}, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("%s is not set", b.keyEnv)}
	}
	prefix, err := prompt.Prefix(state)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	body, err := json.Marshal(request{
		Model: b.model, MaxTokens: b.maxTokens, Temperature: b.temperature, System: prompt.System,
		Messages: []map[string]any{{"role": "user", "content": prompt.Batch(prefix, qs)}},
		Tools: []map[string]any{{"name": toolName, "description": "Record the answer to every question.",
			"input_schema": prompt.Schema(qs)}},
		ToolChoice: map[string]any{"type": "tool", "name": toolName},
	})
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
	for _, c := range r.Content {
		if c.Type == "tool_use" && c.Name == toolName {
			answers, err := prompt.ParseBatch(c.Input, qs)
			if err != nil {
				return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
			}
			return judge.Response{Answers: answers, Model: r.Model, Usage: r.Usage}, nil
		}
	}
	return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("the response has no answer tool call")}
}

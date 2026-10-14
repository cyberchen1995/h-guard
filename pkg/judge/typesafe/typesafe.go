// Package typesafe 是 TypeSafe /v1/systemone 判断后端（spec §8.2），后端类型名 typesafe。
// 导入本包即注册该类型。原生概率（Mechanism native），Calibrated=true；一次请求问完全部题目，
// 两种题型都能回答。
//
// 与 Python 版（typesafe_sdk）的线上格式一致：题型 noul 对应 Probability，score 对应 Scale。
// 不读 TYPESAFE_BASE_URL：端点只来自配置，同意绑定的主机才不会被环境变量悄悄改掉（spec §8.5）。
package typesafe

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
)

// Type 是注册的后端类型名。
const Type = "typesafe"

const (
	DefaultBaseURL   = "https://api.typesafe.ai"
	DefaultModel     = "jev-latest"
	DefaultAPIKeyEnv = "TYPESAFE_API_KEY"
	DefaultTimeout   = 6 * time.Second // 单次请求，与 Python 版一致
	DefaultRetries   = 1
)

// Options 是 typesafe 后端的配置项（spec §8.3 backends.<name>）。
type Options struct {
	Model     string `yaml:"model" json:"model"`
	BaseURL   string `yaml:"base_url" json:"base_url"`
	APIKeyEnv string `yaml:"api_key_env" json:"api_key_env"`
	TimeoutMS int    `yaml:"timeout_ms" json:"timeout_ms"`
	Retries   *int   `yaml:"retries" json:"retries"`
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

// Backend 是 typesafe 后端。创建时不做任何网络或文件操作，配置校验可以放心创建。
type Backend struct {
	name     string
	model    string
	base     *url.URL
	endpoint *url.URL
	keyEnv   string
	client   *httpx.Client
	getenv   func(string) string
}

// New 按配置创建后端；配置非法时返回错误。
func New(name string, o Options) (*Backend, error) {
	b := &Backend{name: name, model: o.Model, keyEnv: o.APIKeyEnv, getenv: os.Getenv}
	if b.model == "" {
		b.model = DefaultModel
	}
	if b.keyEnv == "" {
		b.keyEnv = DefaultAPIKeyEnv
	}
	if err := httpx.ValidKeyEnv(Type, b.keyEnv); err != nil { // 不回显：误填进来的可能正是 key
		return nil, err
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := httpx.ParseBase(Type, base) // 不回显 base_url：写错的地址里可能带着凭据
	if err != nil {
		return nil, err
	}
	b.base, b.endpoint = u, u.JoinPath("v1", "systemone")
	timeout, retries, err := httpx.Settings(Type, o.TimeoutMS, o.Retries, DefaultTimeout, DefaultRetries)
	if err != nil {
		return nil, err
	}
	b.client = httpx.New(timeout, retries)
	return b, nil
}

// Endpoint 返回请求地址，供 status 与 check 显示（不含凭据）。
func (b *Backend) Endpoint() string { return b.endpoint.String() }

// Describe 实现 judge.Describer：同意绑定 scheme、主机与端口，指纹绑定模型与原生概率。
func (b *Backend) Describe() judge.Info {
	return judge.Info{Target: httpx.Target(b.base), Model: b.model, Probability: "native"}
}

func (b *Backend) Name() string { return b.name }

func (b *Backend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Calibrated: true, Batch: true, Mechanism: judge.MechanismNative,
		Kinds: []judge.Kind{judge.KindProbability, judge.KindScale}}
}

type wireInstructions struct {
	Question    string `json:"question"`
	CountsAsYes string `json:"counts_as_yes,omitempty"`
	CountsAsNo  string `json:"counts_as_no,omitempty"`
}

type wireQuestion struct {
	Type         string `json:"type"`
	Instructions any    `json:"instructions"`
	Criteria     any    `json:"criteria"`
}

type wireRequest struct {
	State     map[string]any          `json:"state"`
	Model     string                  `json:"model"`
	Questions map[string]wireQuestion `json:"questions"`
}

type wireAnswer struct {
	Type          string              `json:"type"`
	Noul          *float64            `json:"noul"`
	Probabilities map[string]*float64 `json:"probabilities"` // 指针保留 null：null 是「没有给出」，不是 0
}

type wireResponse struct {
	Model   string                `json:"model"`
	Answers map[string]wireAnswer `json:"answers"`
	Usage   judge.Usage           `json:"usage"`
}

func encodeQuestion(q judge.Question) (wireQuestion, error) {
	switch q.Kind {
	case judge.KindProbability:
		return wireQuestion{
			Type: "noul",
			Instructions: wireInstructions{
				Question: q.Instructions.Question, CountsAsYes: q.Instructions.CountsAsYes, CountsAsNo: q.Instructions.CountsAsNo,
			},
			Criteria: q.Instructions.Criteria,
		}, nil
	case judge.KindScale:
		return wireQuestion{Type: "score", Instructions: q.Instructions.Question, Criteria: q.Levels}, nil
	}
	return wireQuestion{}, fmt.Errorf("typesafe: unsupported question kind %q", q.Kind)
}

// decodeAnswer 把线上答案转成 judge.Answer，保留「没有给出」：noul 为 null 时 P 为 nil；
// score 的 probabilities 必须恰好覆盖 0..n-1 且都不为 null，否则 Dist 为 nil（交给框架判无效）。
func decodeAnswer(q judge.Question, w wireAnswer) judge.Answer {
	switch w.Type {
	case "noul":
		return judge.Answer{P: w.Noul}
	case "score":
		if len(w.Probabilities) != len(q.Levels) {
			return judge.Answer{}
		}
		dist := make([]float64, len(q.Levels))
		for i := range dist {
			p, ok := w.Probabilities[strconv.Itoa(i)]
			if !ok || p == nil {
				return judge.Answer{}
			}
			dist[i] = *p
		}
		return judge.Answer{Dist: dist}
	}
	return judge.Answer{}
}

// Ask 一次请求问完 qs。重试与错误分类见 httpx.Client.PostJSON；总时长受 ctx 截止时间约束。
func (b *Backend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	key := b.getenv(b.keyEnv)
	if key == "" {
		return judge.Response{}, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("%s is not set", b.keyEnv)}
	}
	req := wireRequest{State: state, Model: b.model, Questions: make(map[string]wireQuestion, len(qs))}
	for _, q := range qs {
		w, err := encodeQuestion(q)
		if err != nil {
			return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
		}
		req.Questions[q.ID] = w
	}
	body, err := json.Marshal(req)
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	data, err := b.client.PostJSON(ctx, b.endpoint.String(), http.Header{"Authorization": {"Bearer " + key}}, body)
	if err != nil {
		return judge.Response{}, err
	}
	var w wireResponse
	if err := json.Unmarshal(data, &w); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response is not valid JSON")}
	}
	return b.convert(w, qs), nil
}

func (b *Backend) convert(w wireResponse, qs []judge.Question) judge.Response {
	out := judge.Response{Answers: make(map[string]judge.Answer, len(qs)), Model: w.Model, Usage: w.Usage}
	for _, q := range qs {
		if a, ok := w.Answers[q.ID]; ok {
			out.Answers[q.ID] = decodeAnswer(q, a)
		}
	}
	return out
}

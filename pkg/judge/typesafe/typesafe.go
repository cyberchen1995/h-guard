// Package typesafe 是 TypeSafe /v1/systemone 判断后端（spec §8.2），后端类型名 typesafe。
// 导入本包即注册该类型。原生概率，Calibrated=true；一次请求问完全部题目。
//
// 与 Python 版（typesafe_sdk）的线上格式一致：题型 noul 对应 Probability，score 对应 Scale。
// 不读 TYPESAFE_BASE_URL：端点只来自配置，同意绑定的主机才不会被环境变量悄悄改掉（spec §8.5）。
package typesafe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Type 是注册的后端类型名。
const Type = "typesafe"

const (
	DefaultBaseURL   = "https://api.typesafe.ai"
	DefaultModel     = "jev-latest"
	DefaultAPIKeyEnv = "TYPESAFE_API_KEY"
	DefaultTimeout   = 6 * time.Second // 单次请求，与 Python 版一致
	DefaultRetries   = 1
	maxResponseBytes = 1 << 20
	retryBackoff     = 300 * time.Millisecond
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
	endpoint *url.URL
	keyEnv   string
	timeout  time.Duration
	retries  int
	client   *http.Client
	getenv   func(string) string
}

// New 按配置创建后端；配置非法时返回错误。
func New(name string, o Options) (*Backend, error) {
	b := &Backend{
		name: name, model: o.Model, keyEnv: o.APIKeyEnv,
		timeout: DefaultTimeout, retries: DefaultRetries, getenv: os.Getenv,
	}
	if b.model == "" {
		b.model = DefaultModel
	}
	if b.keyEnv == "" {
		b.keyEnv = DefaultAPIKeyEnv
	}
	base := o.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		// 不回显 base_url：写错的地址里可能带着凭据
		return nil, errors.New("typesafe: base_url must be an http(s) URL without user info")
	}
	b.endpoint = u.JoinPath("v1", "systemone")
	switch {
	case o.TimeoutMS < 0:
		return nil, errors.New("typesafe: timeout_ms must not be negative")
	case o.TimeoutMS > 0:
		b.timeout = time.Duration(o.TimeoutMS) * time.Millisecond
	}
	if o.Retries != nil {
		if *o.Retries < 0 || *o.Retries > 5 {
			return nil, fmt.Errorf("typesafe: retries = %d, want 0..5", *o.Retries)
		}
		b.retries = *o.Retries
	}
	b.client = &http.Client{CheckRedirect: sameOrigin}
	return b, nil
}

// sameOrigin 只允许同 scheme、主机、端口的重定向（spec §8.5）。
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	first := via[0].URL
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return fmt.Errorf("refusing cross-origin redirect to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// Endpoint 返回请求地址，供同意与 status 显示（不含凭据）。
func (b *Backend) Endpoint() string { return b.endpoint.String() }

func (b *Backend) Name() string { return b.name }

func (b *Backend) Caps() judge.BackendCaps { return judge.BackendCaps{Calibrated: true, Batch: true} }

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

// Ask 一次请求问完 qs。重试 Unavailable、Timeout（单次请求超时）、RateLimit，
// 总时长受 ctx 截止时间约束；Auth、BadResponse 不重试。
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
	var lastErr error
	for attempt := 0; attempt <= b.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
			case <-time.After(retryBackoff):
			}
		}
		w, err := b.post(ctx, key, body)
		if err == nil {
			return b.convert(w, qs), nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		switch judge.KindOf(err) {
		case judge.Auth, judge.BadResponse:
			return judge.Response{}, err
		}
	}
	return judge.Response{}, lastErr
}

func (b *Backend) post(ctx context.Context, key string, body []byte) (wireResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return wireResponse{}, &judge.Error{Kind: judge.Unavailable, Err: err}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return wireResponse{}, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		return wireResponse{}, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return wireResponse{}, &judge.Error{Kind: judge.Unavailable, Err: err}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return wireResponse{}, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode == http.StatusTooManyRequests:
		return wireResponse{}, &judge.Error{Kind: judge.RateLimit, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode >= 500:
		return wireResponse{}, &judge.Error{Kind: judge.Unavailable, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode != http.StatusOK:
		return wireResponse{}, &judge.Error{Kind: judge.BadResponse, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	if len(data) > maxResponseBytes {
		return wireResponse{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response larger than 1 MiB")}
	}
	var w wireResponse
	if err := json.Unmarshal(data, &w); err != nil {
		return wireResponse{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response is not valid JSON")}
	}
	return w, nil
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

// redactURLError 去掉 *url.Error 里的 URL（避免把查询串等写进日志），只留操作与原因。
func redactURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// Package httpx 是 HTTP 判断后端（typesafe、openai、anthropic）共用的请求逻辑（spec §8.5、§8.6）：
// 只跟随同源重定向，单次请求有超时，按错误分类重试，响应上限 1 MiB，错误说明里不带 URL 与原值。
package httpx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// MaxResponseBytes 是响应体的上限。
const MaxResponseBytes = 1 << 20

const retryBackoff = 300 * time.Millisecond

// ParseBase 解析配置的 base_url：必须是 http(s)、有主机、不带用户信息。错误说明不回显原值
// （写错的地址里可能带着凭据，spec §9）。
func ParseBase(backend, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%s: base_url must be an http(s) URL without user info", backend)
	}
	return u, nil
}

// Target 返回 u 的 scheme://host:port（没写端口时补上默认端口），用作同意身份（spec §8.5）。
func Target(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(u.Hostname(), port)
}

// Settings 校验并返回单次请求超时与重试次数：timeoutMS 为 0 时用 def，负数是配置错误；
// retries 为 nil 时用 defRetries，须在 0..5。
func Settings(backend string, timeoutMS int, retries *int, def time.Duration, defRetries int) (time.Duration, int, error) {
	timeout, n := def, defRetries
	switch {
	case timeoutMS < 0:
		return 0, 0, fmt.Errorf("%s: timeout_ms must not be negative", backend)
	case timeoutMS > 0:
		timeout = time.Duration(timeoutMS) * time.Millisecond
	}
	if retries != nil {
		if *retries < 0 || *retries > 5 {
			return 0, 0, fmt.Errorf("%s: retries = %d, want 0..5", backend, *retries)
		}
		n = *retries
	}
	return timeout, n, nil
}

// Client 发送 JSON 请求。字段在构造后只读，可并发使用。
type Client struct {
	timeout time.Duration
	retries int
	http    *http.Client
}

// New 返回单次请求超时为 timeout、最多重试 retries 次的客户端。
func New(timeout time.Duration, retries int) *Client {
	return &Client{timeout: timeout, retries: retries, http: &http.Client{CheckRedirect: sameOrigin}}
}

var (
	errCrossOrigin = errors.New("cross-origin redirect refused")
	errRedirects   = errors.New("too many redirects")
)

// sameOrigin 只允许同 scheme、主机、端口的重定向（spec §8.5）。
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errRedirects
	}
	if Target(req.URL) != Target(via[0].URL) {
		return errCrossOrigin
	}
	return nil
}

// PostJSON 把 body POST 到 endpoint，返回 2xx 的响应体。重试 Unavailable、Timeout（单次请求超时）、
// RateLimit，两次之间等待 300ms，总时长受 ctx 截止时间约束；Auth、BadResponse 不重试（501 也算 BadResponse）。
func (c *Client) PostJSON(ctx context.Context, endpoint string, header http.Header, body []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
			case <-time.After(retryBackoff):
			}
		}
		data, err := c.post(ctx, endpoint, header, body)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		switch judge.KindOf(err) {
		case judge.Auth, judge.BadResponse:
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) post(ctx context.Context, endpoint string, header http.Header, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		return nil, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, &judge.Error{Kind: judge.Auth, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, &judge.Error{Kind: judge.RateLimit, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode == http.StatusNotImplemented:
		// 服务端不支持这种请求（如 Ollama 的 MLX 运行器不支持结构化输出），重试也没用
		return nil, &judge.Error{Kind: judge.BadResponse, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode >= 500:
		return nil, &judge.Error{Kind: judge.Unavailable, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, &judge.Error{Kind: judge.BadResponse, Err: fmt.Errorf("HTTP %d", resp.StatusCode)}
	}
	if len(data) > MaxResponseBytes {
		return nil, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response larger than 1 MiB")}
	}
	return data, nil
}

// redactURLError 把网络与重定向错误换成固定说明：内层错误也可能带着 URL（如解析不了的 Location 头，
// 评审 M2-09），所以不回显任何原始错误字符串，只保留类别。
func redactURLError(err error) error {
	var dns *net.DNSError
	var ue *url.Error
	switch {
	case errors.Is(err, errCrossOrigin):
		return errCrossOrigin
	case errors.Is(err, errRedirects):
		return errRedirects
	case errors.As(err, &ue) && ue.Timeout():
		return errors.New("request timed out")
	case errors.Is(err, syscall.ECONNREFUSED):
		return errors.New("connection refused")
	case errors.As(err, &dns):
		return errors.New("host lookup failed")
	}
	return errors.New("request failed")
}

// Package httpx 是 HTTP 判断后端（typesafe、openai、anthropic）共用的请求逻辑：
// 只跟随同源重定向，单次请求有超时，按错误分类重试且只在剩余时间够完成一次请求时重试，
// 响应上限 1 MiB，错误说明里不带 URL、响应体与配置的原值。
package httpx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// MaxResponseBytes 是响应体的上限。
const MaxResponseBytes = 1 << 20

const (
	// retryBackoff 是两次请求之间的最短等待。
	retryBackoff = 300 * time.Millisecond
	// minAttempt 是值得发起一次请求的最少剩余时间：ctx 有截止时间时，剩余时间不够「等待 + minAttempt」
	// 就不再重试，直接返回这次的错误。
	minAttempt = 500 * time.Millisecond
	// maxKeyEnv 是 api_key_env 的最大长度。
	maxKeyEnv = 128
)

// noRetryAfter 表示响应没有可用的 Retry-After（没有、不是秒数或者不是 429/503）。
const noRetryAfter time.Duration = -1

// ParseBase 解析配置的 base_url：必须是 http(s)、有主机名、不带用户信息、query 与 fragment
// （拼端点时它们会被带走或丢掉，写在那里的多半是误填的 key）。错误说明不回显原值
// （写错的地址里可能带着凭据）。
func ParseBase(backend, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	// url.Parse 从第一个 '#' 起切出 fragment，所以原值里有 '#' 就是带了 fragment（包括空的 "#"）
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s: base_url must be an http(s) URL with a host name and without user info, query or fragment", backend)
	}
	return u, nil
}

// ValidKeyEnv 校验 api_key_env 是环境变量名：字母、数字、下划线，不以数字开头，不超过 128 个字符。
// 错误说明不回显原值：误填进来的可能正是 key 本身。
func ValidKeyEnv(backend, name string) error {
	ok := name != "" && len(name) <= maxKeyEnv
	for i := 0; ok && i < len(name); i++ {
		c := name[i]
		ok = c == '_' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || i > 0 && '0' <= c && c <= '9'
	}
	if !ok {
		return fmt.Errorf("%s: api_key_env must be an environment variable name "+
			"(letters, digits and underscores, not starting with a digit, at most %d characters)", backend, maxKeyEnv)
	}
	return nil
}

// Target 返回 u 的 scheme://host:port（没写端口时补上默认端口），用作同意身份。
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

// sameOrigin 只允许同 scheme、主机、端口的重定向。
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
// RateLimit，Auth、BadResponse 不重试（501 也算 BadResponse）。两次之间等待 retryBackoff；ctx 有截止时间时，
// 429 与 503 的 Retry-After（秒数）比它长就等 Retry-After，剩余时间不够「等待 + minAttempt」就不再重试、
// 直接返回这次的错误（Retry-After 超过剩余时间时同样立即返回）。ctx 没有截止时间时只等 retryBackoff。
func (c *Client) PostJSON(ctx context.Context, endpoint string, header http.Header, body []byte) ([]byte, error) {
	var wait time.Duration
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
			case <-time.After(wait):
			}
		}
		data, retryAfter, err := c.post(ctx, endpoint, header, body)
		if err == nil {
			return data, nil
		}
		if ctx.Err() != nil {
			return nil, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		switch judge.KindOf(err) {
		case judge.Auth, judge.BadResponse:
			return nil, err
		}
		if attempt >= c.retries {
			return nil, err
		}
		var ok bool
		if wait, ok = retryWait(ctx, retryAfter); !ok {
			return nil, err
		}
	}
}

// retryWait 返回下一次请求前要等多久；剩余时间不够等完再做一次请求（minAttempt）时返回 false。
// retryAfter 为 noRetryAfter 时只等 retryBackoff。ctx 没有截止时间时照旧只等 retryBackoff。
func retryWait(ctx context.Context, retryAfter time.Duration) (time.Duration, bool) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return retryBackoff, true
	}
	wait := max(retryBackoff, retryAfter)
	// 用减法比较：retryAfter 可能接近 math.MaxInt64，wait+minAttempt 会溢出
	if wait > time.Until(deadline)-minAttempt {
		return 0, false
	}
	return wait, true
}

// parseRetryAfter 解析 Retry-After 的秒数形式。HTTP 日期以及其他不是纯数字的值按无法解析处理，
// 返回 noRetryAfter；秒数大到 Duration 放不下时返回 math.MaxInt64（一定超过剩余时间）。
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return noRetryAfter
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return noRetryAfter
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n > math.MaxInt64/int64(time.Second) { // 全是数字时只可能是溢出
		return math.MaxInt64
	}
	return time.Duration(n) * time.Second
}

// post 发送一次请求。第二个返回值是 429 与 503 响应的 Retry-After，其余情况为 noRetryAfter。
func (c *Client) post(ctx context.Context, endpoint string, header http.Header, body []byte) ([]byte, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, noRetryAfter, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, noRetryAfter, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		return nil, noRetryAfter, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, noRetryAfter, &judge.Error{Kind: judge.Unavailable, Err: redactURLError(err)}
	}
	retryAfter := noRetryAfter
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	// 错误说明只有状态码：响应体里可能回显请求内容或 key
	status := fmt.Errorf("HTTP %d", resp.StatusCode)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, noRetryAfter, &judge.Error{Kind: judge.Auth, Err: status}
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, retryAfter, &judge.Error{Kind: judge.RateLimit, Err: status}
	case resp.StatusCode == http.StatusNotImplemented:
		// 服务端不支持这种请求（如 Ollama 的 MLX 运行器不支持结构化输出），重试也没用
		return nil, noRetryAfter, &judge.Error{Kind: judge.BadResponse, Err: status}
	case resp.StatusCode >= 500:
		return nil, retryAfter, &judge.Error{Kind: judge.Unavailable, Err: status}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, noRetryAfter, &judge.Error{Kind: judge.BadResponse, Err: status}
	}
	if len(data) > MaxResponseBytes {
		return nil, noRetryAfter, &judge.Error{Kind: judge.BadResponse, Err: errors.New("response larger than 1 MiB")}
	}
	return data, noRetryAfter, nil
}

// redactURLError 把网络与重定向错误换成固定说明：内层错误也可能带着 URL（如解析不了的 Location 头），
// 所以不回显任何原始错误字符串，只保留类别。
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

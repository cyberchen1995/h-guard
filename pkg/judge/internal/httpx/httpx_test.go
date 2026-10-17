package httpx

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

func TestParseBaseDoesNotEchoTheValue(t *testing.T) {
	for _, raw := range []string{
		"ftp://h", "https://user:syntheticPassword123@h", "not a url", "https://",
		// query 与 fragment：拼端点时会被带走或丢掉，写在这里的多半是误填的 key
		"https://h/v1?key=syntheticPassword123", "https://h/v1?", "https://h/v1#syntheticPassword123", "https://h/v1#",
		// 空主机名
		"https://:443", "https://:443/v1",
	} {
		_, err := ParseBase("openai", raw)
		if err == nil {
			t.Errorf("%q accepted", raw)
			continue
		}
		if strings.Contains(err.Error(), "syntheticPassword123") || strings.Contains(err.Error(), "ftp") ||
			strings.Contains(err.Error(), "://") {
			t.Errorf("error echoes the value: %v", err)
		}
	}
	for _, raw := range []string{"http://localhost:11434/v1", "https://api.openai.com/v1", "https://[::1]:8443", "http://127.0.0.1:8080/"} {
		if _, err := ParseBase("openai", raw); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestValidKeyEnv(t *testing.T) {
	for _, name := range []string{"OPENAI_API_KEY", "_X", "a1", "HG_TEST_KEY", strings.Repeat("K", 128)} {
		if err := ValidKeyEnv("openai", name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	const canary = "syntheticKey123"
	for _, name := range []string{
		"", "1KEY", "MY KEY", "KEY=VALUE", "$KEY", "ÄKEY", "KEY\n", strings.Repeat("K", 129),
		"sk-ant-api03-" + canary, // 误把 key 本身填进了 api_key_env
		"sk_" + canary + "-x",
	} {
		err := ValidKeyEnv("anthropic", name)
		if err == nil {
			t.Errorf("%q accepted", name)
			continue
		}
		if strings.Contains(err.Error(), canary) || (name != "" && strings.Contains(err.Error(), name)) {
			t.Errorf("error echoes the value: %v", err)
		}
		if !strings.HasPrefix(err.Error(), "anthropic: api_key_env") {
			t.Errorf("error does not name the backend and field: %v", err)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	for v, want := range map[string]time.Duration{
		"30":                            30 * time.Second,
		"0":                             0,
		" 2 ":                           2 * time.Second,
		"":                              noRetryAfter,
		"-1":                            noRetryAfter,
		"+5":                            noRetryAfter,
		"1.5":                           noRetryAfter,
		"Fri, 31 Dec 1999 23:59:59 GMT": noRetryAfter,  // HTTP 日期按无法解析处理
		"99999999999999999999":          math.MaxInt64, // 溢出：按「很久」处理，一定超过剩余时间
		"9223372036854775807":           math.MaxInt64,
	} {
		if got := parseRetryAfter(v); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestRetryRespectsTheDeadline：重试只在剩余时间足够完成一次请求时进行。429/503 的 Retry-After（秒）超过
// 剩余时间时立即返回该错误；剩余时间不够「等待 + minAttempt」时不再重试；没有截止时间的 ctx 照旧。
func TestRetryRespectsTheDeadline(t *testing.T) {
	const s = time.Second
	tests := []struct {
		name       string
		status     int    // 第一次的状态码
		then       int    // 之后的状态码；0 表示同 status
		retryAfter string // 每个响应都带的 Retry-After；空表示不带
		deadline   time.Duration
		retries    int
		calls      int32
		kind       judge.ErrorKind // 空表示成功
		min, max   time.Duration   // 耗时范围
	}{
		{"429 Retry-After beyond the deadline", 429, 0, "30", 2 * s, 3, 1, judge.RateLimit, 0, s},
		{"503 Retry-After beyond the deadline", 503, 0, "30", 2 * s, 3, 1, judge.Unavailable, 0, s},
		{"huge Retry-After", 429, 0, "99999999999999999999", 2 * s, 3, 1, judge.RateLimit, 0, s},
		{"Retry-After leaves no time for the next request", 429, 0, "2", 2200 * time.Millisecond, 3, 1, judge.RateLimit, 0, s},
		{"Retry-After within the deadline is honoured", 429, 200, "1", 2 * s, 1, 2, "", s, 1800 * time.Millisecond},
		{"Retry-After shorter than the backoff", 503, 200, "0", 2 * s, 1, 2, "", retryBackoff, s},
		{"Retry-After on other statuses is ignored", 500, 200, "30", 2 * s, 1, 2, "", retryBackoff, s},
		{"HTTP-date Retry-After is ignored", 429, 200, "Fri, 31 Dec 1999 23:59:59 GMT", 2 * s, 1, 2, "", retryBackoff, s},
		// 截止时间只比 retryBackoff+minAttempt 少一点：不重试、立即返回。上限 500ms 给 -race 全量测试留出余量，
		// 同时远低于截止时间，等到截止时间才返回的实现仍会被判失败。
		{"no time left for backoff and a request", 503, 0, "", 790 * time.Millisecond, 3, 1, judge.Unavailable, 0, 500 * time.Millisecond},
		{"enough time for every retry", 503, 0, "", 2 * s, 2, 3, judge.Unavailable, 2 * retryBackoff, 1500 * time.Millisecond},
		{"no deadline keeps the plain backoff", 429, 200, "30", 0, 1, 2, "", retryBackoff, s},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				code := tt.status
				if calls.Add(1) > 1 && tt.then != 0 {
					code = tt.then
				}
				if tt.retryAfter != "" {
					w.Header().Set("Retry-After", tt.retryAfter)
				}
				w.WriteHeader(code)
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			ctx := context.Background()
			if tt.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.deadline)
				defer cancel()
			}
			start := time.Now()
			_, err := New(5*time.Second, tt.retries).PostJSON(ctx, srv.URL, nil, []byte(`{}`))
			elapsed := time.Since(start)
			if judge.KindOf(err) != tt.kind || calls.Load() != tt.calls {
				t.Errorf("err = %v (kind %q), calls = %d; want kind %q, calls %d", err, judge.KindOf(err), calls.Load(), tt.kind, tt.calls)
			}
			if elapsed < tt.min || elapsed > tt.max {
				t.Errorf("took %v, want %v..%v", elapsed, tt.min, tt.max)
			}
		})
	}
}

func TestTargetAddsDefaultPorts(t *testing.T) {
	for raw, want := range map[string]string{
		"https://api.openai.com/v1":  "https://api.openai.com:443",
		"http://localhost:11434/v1":  "http://localhost:11434",
		"http://example.com":         "http://example.com:80",
		"https://[::1]:8443/x":       "https://[::1]:8443",
		"https://API.Example.com/v1": "https://API.Example.com:443",
	} {
		u, _ := url.Parse(raw)
		if got := Target(u); got != want {
			t.Errorf("Target(%s) = %s, want %s", raw, got, want)
		}
	}
}

func TestSettings(t *testing.T) {
	neg, six := -1, 6
	for _, tc := range []struct {
		ms      int
		retries *int
		ok      bool
	}{{0, nil, true}, {-1, nil, false}, {1500, nil, true}, {0, &neg, false}, {0, &six, false}} {
		_, _, err := Settings("b", tc.ms, tc.retries, time.Second, 1)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: err = %v", tc, err)
		}
	}
	d, n, _ := Settings("b", 1500, nil, time.Second, 2)
	if d != 1500*time.Millisecond || n != 2 {
		t.Errorf("got %v %d", d, n)
	}
}

func TestPostJSONRetriesAndClassifies(t *testing.T) {
	var calls atomic.Int32
	codes := []int{503, 200}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := int(calls.Add(1)) - 1
		if r.Header.Get("X-Key") != "k" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		w.WriteHeader(codes[min(i, len(codes)-1)])
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New(time.Second, 1)
	data, err := c.PostJSON(context.Background(), srv.URL, http.Header{"X-Key": {"k"}}, []byte(`{}`))
	if err != nil || string(data) != `{"ok":true}` || calls.Load() != 2 {
		t.Fatalf("data %q err %v calls %d", data, err, calls.Load())
	}
	for code, kind := range map[int]judge.ErrorKind{401: judge.Auth, 403: judge.Auth, 429: judge.RateLimit, 500: judge.Unavailable, 400: judge.BadResponse, 501: judge.BadResponse} {
		calls.Store(0)
		codes = []int{code}
		_, err := New(time.Second, 2).PostJSON(context.Background(), srv.URL, http.Header{"X-Key": {"k"}}, nil)
		if judge.KindOf(err) != kind {
			t.Errorf("HTTP %d: kind %s, want %s", code, judge.KindOf(err), kind)
		}
		wantCalls := int32(3)
		if kind == judge.Auth || kind == judge.BadResponse {
			wantCalls = 1
		}
		if calls.Load() != wantCalls {
			t.Errorf("HTTP %d: %d calls, want %d", code, calls.Load(), wantCalls)
		}
	}
}

func TestPostJSONLimitsAndTimeouts(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", MaxResponseBytes+1)))
	}))
	defer big.Close()
	if _, err := New(time.Second, 0).PostJSON(context.Background(), big.URL, nil, nil); judge.KindOf(err) != judge.BadResponse {
		t.Errorf("oversized response: %v", err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	start := time.Now()
	_, err := New(100*time.Millisecond, 0).PostJSON(context.Background(), slow.URL, nil, nil)
	if judge.KindOf(err) != judge.Timeout || time.Since(start) > time.Second {
		t.Errorf("slow server: %v after %v", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(time.Second, 3).PostJSON(ctx, slow.URL, nil, nil); judge.KindOf(err) != judge.Timeout {
		t.Errorf("canceled ctx: %v", err)
	}
}

func TestPostJSONRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer other.Close()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, srv.URL+"/done", http.StatusTemporaryRedirect)
		case "/cross":
			http.Redirect(w, r, other.URL+"/done?token=secret", http.StatusTemporaryRedirect)
		default:
			w.Write([]byte(`{"done":true}`))
		}
	}))
	defer srv.Close()
	c := New(time.Second, 0)
	if data, err := c.PostJSON(context.Background(), srv.URL+"/same", nil, []byte(`{}`)); err != nil || string(data) != `{"done":true}` {
		t.Errorf("same-origin redirect: %q %v", data, err)
	}
	_, err := c.PostJSON(context.Background(), srv.URL+"/cross", nil, []byte(`{}`))
	if err == nil || strings.Contains(err.Error(), "token=secret") || !strings.Contains(err.Error(), "cross-origin redirect refused") {
		t.Errorf("cross-origin redirect: %v", err)
	}
}

// TestNetworkErrorsCarryNoURL：网络与重定向错误只保留类别，不回显 URL——包括内层错误里的地址，
// 如解析不了的 Location 头。
func TestNetworkErrorsCarryNoURL(t *testing.T) {
	const canary = "PRIVATE_ROUTE_CANARY"
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://%zz/"+canary+"?token="+canary)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer bad.Close()
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()
	for name, endpoint := range map[string]string{
		"malformed Location": bad.URL + "/" + canary + "?q=" + canary,
		"connection refused": closedURL + "/" + canary + "?q=" + canary,
	} {
		_, err := New(time.Second, 0).PostJSON(context.Background(), endpoint, nil, []byte(`{}`))
		if err == nil || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s: %v", name, err)
		}
		if judge.KindOf(err) != judge.Unavailable {
			t.Errorf("%s: kind %v, want unavailable", name, judge.KindOf(err))
		}
	}
}

package httpx

import (
	"context"
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
	for _, raw := range []string{"ftp://h", "https://user:syntheticPassword123@h", "not a url", "https://"} {
		_, err := ParseBase("openai", raw)
		if err == nil {
			t.Errorf("%q accepted", raw)
			continue
		}
		if strings.Contains(err.Error(), "syntheticPassword123") || strings.Contains(err.Error(), "ftp") {
			t.Errorf("error echoes the value: %v", err)
		}
	}
	if _, err := ParseBase("openai", "http://localhost:11434/v1"); err != nil {
		t.Error(err)
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
// 如解析不了的 Location 头（评审 M2-09）。
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

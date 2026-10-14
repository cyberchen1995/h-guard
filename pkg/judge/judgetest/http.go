package judgetest

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// RunHTTP 使用的环境变量与合成值。canary 不是真的 key，只用来确认它没有出现在错误说明里。
const (
	httpKeyEnv = "HG_JUDGETEST_API_KEY"
	keyCanary  = "hg-judgetest-key-CANARY-7f3a9c2e"
	bodyCanary = "hg-judgetest-body-CANARY-51d2e8b4"
)

// RunHTTP 是 HTTP 判断后端共用的安全测试，检查凭据、响应内容与地址不会经错误说明泄露，响应有上限，
// 重试不会拖过截止时间。内置的 typesafe、openai、anthropic 都调用它；第三方 HTTP 后端应在自己的测试里调用：
//
//	func TestHTTPSecurity(t *testing.T) {
//		judgetest.RunHTTP(t, func(t *testing.T, baseURL, keyEnv string) judge.Backend {
//			b, err := mybackend.New("mine", mybackend.Options{BaseURL: baseURL, APIKeyEnv: keyEnv})
//			if err != nil {
//				t.Fatal(err)
//			}
//			return b
//		}, qs)
//	}
//
// 每台测试服务器调用一次工厂（error-body 场景有三台），t 是当前子测试，创建失败时用 t.Fatal。工厂收到：
//   - baseURL：这台 httptest 服务器的根地址（http://127.0.0.1:端口，不带路径）。服务器对任何路径、
//     任何请求体都按场景作答，工厂可以在后面接上后端需要的路径前缀（如 baseURL+"/v1"）。
//   - keyEnv：环境变量名，RunHTTP 已用 t.Setenv 把它设成一个合成的 canary key。后端必须在 Ask 时从这个
//     变量读 key 并随请求发送（请求头、URL 或请求体均可）。每个场景都断言服务器收到了请求、请求里带着这个
//     key，否则「错误说明不含 key」的断言会落空。
//
// 工厂应保留后端默认的重试次数与单次请求超时：关掉重试时，第 4 个场景（不重试）恒过，证明不了什么。
// RunHTTP 调用 t.Setenv，所以不能在 t.Parallel 的测试（或其子测试）里调用。qs 是传给 Ask 的题目；
// 不能批量的后端（Caps().Batch 为假）只问第一题。
//
// 场景（子测试名）：
//  1. cross-host-redirect：服务器以 307 把请求重定向到另一台服务器（两台只差端口：同源按 scheme、主机、端口判断，
//     与同意绑定的目标一致），Location 带 canary 查询参数。第二台服务器一个请求都收不到，Ask 返回错误。
//  2. error-body：400、401、500 的响应体里写着 canary 与 key（有的服务会在错误里回显 key）。Ask 返回错误。
//  3. oversized-response：200 的响应体超过 1 MiB。Ask 返回 judge.BadResponse。
//  4. retry-after-beyond-deadline：429 带 Retry-After: 30，ctx 的截止时间是 2 秒。Ask 在 1.5 秒内返回
//     judge.RateLimit，服务器只收到 1 个请求（等不到 Retry-After 就不重试，立即报错）。
//  5. non-json-200：200 的响应体不是 JSON。Ask 返回 judge.BadResponse。
//
// 所有场景的错误说明都不能含 key、响应体里的 canary、服务器的 URL 或主机地址。
//
// 场景只用每个 HTTP 后端无论响应格式如何都必须拒绝的状态码与响应体，不需要知道后端成功时的响应格式
// （前提是后端使用 JSON 接口）。代价：第 3 个场景的响应体是不含任何后端字段的合法 JSON，没有大小上限、
// 但按自己的格式也会拒绝它的后端同样能过，所以这一条只检查结果（BadResponse、不泄露），上限本身应由后端
// 自己的测试覆盖（内置后端由共用的 HTTP 客户端负责并单独测试）。
func RunHTTP(t *testing.T, newBackend func(t *testing.T, baseURL, keyEnv string) judge.Backend, qs []judge.Question) {
	t.Helper()
	if len(qs) == 0 {
		t.Fatal("judgetest: at least one question is required")
	}
	t.Setenv(httpKeyEnv, keyCanary)
	ask := func(ctx context.Context, b judge.Backend) error {
		_, err := b.Ask(ctx, map[string]any{}, batches(b, qs)[0])
		return err
	}
	// 非计时的场景也给截止时间：出问题的后端不至于让测试挂住
	generous := func(t *testing.T) context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		return ctx
	}

	t.Run("cross-host-redirect", func(t *testing.T) {
		other := serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{}`)
		})
		var first *httpServer
		first = serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+r.URL.Path+"?token="+bodyCanary, http.StatusTemporaryRedirect)
		})
		err := ask(generous(t), newBackend(t, first.URL, httpKeyEnv))
		if err == nil {
			t.Error("Ask succeeded after a cross-host redirect")
		}
		if n := other.calls.Load(); n != 0 {
			t.Errorf("the second server received %d request(s): a cross-host redirect was followed", n)
		}
		first.checkKey(t)
		checkError(t, err, first, other)
	})

	t.Run("error-body", func(t *testing.T) {
		for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusInternalServerError} {
			s := serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				io.WriteString(w, `{"error":{"message":"`+bodyCanary+` (key `+keyCanary+`)"}}`)
			})
			err := ask(generous(t), newBackend(t, s.URL, httpKeyEnv))
			if err == nil {
				t.Errorf("HTTP %d: Ask succeeded", code)
			}
			s.checkKey(t)
			checkError(t, err, s)
		}
	})

	t.Run("oversized-response", func(t *testing.T) {
		s := serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"padding":"`+bodyCanary+strings.Repeat("x", 1<<20)+`"}`)
		})
		err := ask(generous(t), newBackend(t, s.URL, httpKeyEnv))
		checkKind(t, err, judge.BadResponse)
		s.checkKey(t)
		checkError(t, err, s)
	})

	t.Run("retry-after-beyond-deadline", func(t *testing.T) {
		s := serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"error":{"message":"rate limited `+bodyCanary+`"}}`)
		})
		b := newBackend(t, s.URL, httpKeyEnv)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		start := time.Now()
		err := ask(ctx, b)
		if d := time.Since(start); d >= 1500*time.Millisecond {
			t.Errorf("Ask took %v; with Retry-After beyond the deadline it should return at once", d.Round(time.Millisecond))
		}
		checkKind(t, err, judge.RateLimit)
		if n := s.calls.Load(); n != 1 {
			t.Errorf("the server received %d requests, want 1 (Retry-After is beyond the deadline, so no retry)", n)
		}
		s.checkKey(t)
		checkError(t, err, s)
	})

	t.Run("non-json-200", func(t *testing.T) {
		s := serveHTTP(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<html><body>"+bodyCanary+" "+keyCanary+"</body></html>")
		})
		err := ask(generous(t), newBackend(t, s.URL, httpKeyEnv))
		checkKind(t, err, judge.BadResponse)
		s.checkKey(t)
		checkError(t, err, s)
	})
}

// httpServer 是记录请求数、以及请求里是否带着 canary key 的 httptest 服务器。
type httpServer struct {
	*httptest.Server
	calls  atomic.Int32
	sawKey atomic.Bool
}

func serveHTTP(t *testing.T, h http.HandlerFunc) *httpServer {
	t.Helper()
	s := &httpServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		if bytes.Contains(body, []byte(keyCanary)) || strings.Contains(r.URL.String(), keyCanary) {
			s.sawKey.Store(true)
		}
		for _, vs := range r.Header {
			for _, v := range vs {
				if strings.Contains(v, keyCanary) {
					s.sawKey.Store(true)
				}
			}
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// checkKey 断言后端把 keyEnv 里的 key 发到了服务器（工厂接上了 keyEnv）。
func (s *httpServer) checkKey(t *testing.T) {
	t.Helper()
	if s.calls.Load() > 0 && !s.sawKey.Load() {
		t.Error("the API key from keyEnv never reached the server: the factory must make the backend read its key from keyEnv")
	}
	if s.calls.Load() == 0 {
		t.Error("the backend sent no request to baseURL")
	}
}

// checkError 断言错误说明不含 key、响应体里的 canary、各服务器的 URL 与主机地址；有问题时一条说明列出全部。
func checkError(t *testing.T, err error, servers ...*httpServer) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	var leaks []string
	if strings.Contains(msg, keyCanary) {
		leaks = append(leaks, "the API key")
	}
	if strings.Contains(msg, bodyCanary) {
		leaks = append(leaks, "the response body or the redirect target")
	}
	for _, s := range servers {
		u, _ := url.Parse(s.URL)
		if strings.Contains(msg, u.Host) || strings.Contains(msg, u.Hostname()) {
			leaks = append(leaks, "the server address "+u.Host)
		}
	}
	if len(leaks) > 0 {
		t.Errorf("the error text contains %s: %s", strings.Join(leaks, ", "), msg)
	}
}

func checkKind(t *testing.T, err error, want judge.ErrorKind) {
	t.Helper()
	if got := judge.KindOf(err); got != want {
		t.Errorf("err = %v (kind %q), want %s", err, got, want)
	}
}

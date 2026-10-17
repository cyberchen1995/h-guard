package judgetest_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
	"github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

type constBackend struct{ p float64 }

func (constBackend) Name() string { return "const" }
func (constBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram}
}

func (b constBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: make(map[string]judge.Answer, len(qs))}
	for _, q := range qs {
		resp.Answers[q.ID] = judge.Answer{P: judge.Prob(b.p)}
	}
	return resp, nil
}

// singleBackend 不支持批量：一次只接受一题。
type singleBackend struct{}

func (singleBackend) Name() string { return "single" }
func (singleBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Mechanism: judge.MechanismProgram}
}

func (singleBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	if len(qs) != 1 {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("one question per call")}
	}
	return judge.Response{Answers: map[string]judge.Answer{qs[0].ID: {P: judge.Prob(0.5)}}}, nil
}

// kindsBackend 声明只能回答 kinds 中的题型；honest 为真时只回答这些题型，否则收到什么答什么；
// strict 为真时收到不支持的题型就报错（契约允许这样做）。caps 可以整体替换，用来构造违反契约的声明。
type kindsBackend struct {
	caps   judge.BackendCaps
	honest bool
	strict bool
}

func (kindsBackend) Name() string              { return "kinds" }
func (b kindsBackend) Caps() judge.BackendCaps { return b.caps }

func (b kindsBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: map[string]judge.Answer{}}
	for _, q := range qs {
		switch {
		case b.strict && !b.caps.Supports(q.Kind):
			return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("unsupported question kind")}
		case b.honest && !b.caps.Supports(q.Kind):
		case q.Kind == judge.KindScale:
			resp.Answers[q.ID] = judge.Answer{Dist: []float64{0.5, 0.5, 0}}
		default:
			resp.Answers[q.ID] = judge.Answer{P: judge.Prob(0.5)}
		}
	}
	return resp, nil
}

var mixed = []judge.Question{
	{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would this publish?"}},
	{ID: "blast_radius", Kind: judge.KindScale, Levels: []string{"0", "1", "2"}, Instructions: judge.Instructions{Question: "How wide?"}},
}

func TestRunSingleQuestionBackend(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return singleBackend{} }, []judge.Question{
		{ID: "first", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
		{ID: "second", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
	})
}

func TestRun(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return constBackend{p: 0.1} }, mixed)
}

// TestRunBackendWithFewerKinds：只能回答概率题、也只回答概率题的后端满足契约。
func TestRunBackendWithFewerKinds(t *testing.T) {
	for _, batch := range []bool{true, false} {
		judgetest.Run(t, func(*testing.T) judge.Backend {
			return kindsBackend{caps: judge.BackendCaps{Batch: batch, Mechanism: judge.MechanismProgram,
				Kinds: []judge.Kind{judge.KindProbability}}, honest: true}
		}, mixed)
	}
}

// TestRunBackendThatRejectsUnsupportedKinds：收到不支持的题型就报错的后端同样满足契约。
// 只有 caps 子测试会把不支持的题型直接发给它，其余子测试只问它支持的题。
func TestRunBackendThatRejectsUnsupportedKinds(t *testing.T) {
	for name, kinds := range map[string][]judge.Kind{"probability": {judge.KindProbability}, "none": {}} {
		for mode, batch := range map[string]bool{"batch": true, "single": false} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				judgetest.Run(t, func(*testing.T) judge.Backend {
					return kindsBackend{caps: judge.BackendCaps{Batch: batch, Mechanism: judge.MechanismProgram,
						Kinds: kinds}, strict: true}
				}, mixed)
			})
		}
	}
}

// badBackends 是违反 caps 契约的后端，以及 caps 子测试应当给出的说明。
var badBackends = map[string]struct {
	b    judge.Backend
	want string
}{
	"no-mechanism": {kindsBackend{caps: judge.BackendCaps{Batch: true}, honest: true}, "Mechanism is empty"},
	"unknown-kind": {kindsBackend{caps: judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram,
		Kinds: []judge.Kind{judge.KindProbability, "choice"}}, honest: true}, `unknown kind "choice"`},
	"answers-unsupported": {kindsBackend{caps: judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram,
		Kinds: []judge.Kind{judge.KindProbability}}}, `"blast_radius" (scale), which it does not support`},
}

// badEnv 让测试二进制在子进程里对一个违反契约的后端运行 judgetest.Run。
const badEnv = "HG_JUDGETEST_BAD"

// TestCapsCatchesBadBackends：caps 子测试确实会失败。在子进程里运行（失败的子测试会让本测试失败），
// 断言子进程失败并给出对应说明。
func TestCapsCatchesBadBackends(t *testing.T) {
	if name := os.Getenv(badEnv); name != "" {
		bad := badBackends[name]
		judgetest.Run(t, func(*testing.T) judge.Backend { return bad.b }, mixed)
		return
	}
	for name, bad := range badBackends {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCapsCatchesBadBackends$", "-test.count=1")
		cmd.Env = append(os.Environ(), badEnv+"="+name)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "--- FAIL: TestCapsCatchesBadBackends/caps") ||
			!strings.Contains(string(out), bad.want) {
			t.Errorf("%s: err = %v, want the caps subtest to fail with %q; output:\n%s", name, err, bad.want, out)
		}
	}
}

// naiveBackend 是不加防护的 HTTP 后端：用默认客户端（跟随任何重定向）、不限响应大小、把响应体写进错误、
// 收到 429 与 5xx 立即重试一次。RunHTTP 的每个场景都应当判它失败。
type naiveBackend struct{ base, keyEnv string }

func (naiveBackend) Name() string { return "naive" }
func (naiveBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: judge.MechanismJSONSchema}
}

func (b naiveBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.base+"/v1/ask", strings.NewReader(`{}`))
		if err != nil {
			return judge.Response{}, err
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv(b.keyEnv))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return judge.Response{}, err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return judge.Response{}, fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, req.URL, data)
		}
		var out struct{ Answers map[string]float64 }
		if err := json.Unmarshal(data, &out); err != nil {
			return judge.Response{}, fmt.Errorf("bad JSON %q", data)
		}
		resp2 := judge.Response{Answers: map[string]judge.Answer{}}
		for _, q := range qs {
			if p, ok := out.Answers[q.ID]; ok {
				resp2.Answers[q.ID] = judge.Answer{P: judge.Prob(p)}
			}
		}
		return resp2, nil
	}
}

// httpSubtests 是 RunHTTP 的全部场景。
var httpSubtests = []string{"cross-host-redirect", "error-body", "oversized-response", "retry-after-beyond-deadline", "non-json-200"}

// noKey 是工厂没有让后端用 keyEnv 时 RunHTTP 的说明。
const noKey = "the API key from keyEnv never reached the server"

// badHTTPEnv 让测试二进制在子进程里对一个不合格的 HTTP 后端运行 judgetest.RunHTTP。
const badHTTPEnv = "HG_JUDGETEST_BAD_HTTP"

// TestRunHTTPCatchesBadBackends：RunHTTP 的每个场景确实会失败——对不加防护的后端，以及没有按 keyEnv
// 读 key 的工厂（否则关于 key 的断言会落空）。在子进程里运行，断言子进程失败并给出对应说明。
func TestRunHTTPCatchesBadBackends(t *testing.T) {
	switch os.Getenv(badHTTPEnv) {
	case "naive":
		judgetest.RunHTTP(t, func(_ *testing.T, baseURL, keyEnv string) judge.Backend {
			return naiveBackend{base: baseURL, keyEnv: keyEnv}
		}, mixed)
		return
	case "wrong-key":
		// 后端本身合格（typesafe），只是工厂没有用 keyEnv：唯一的失败应当是 key 没有送到
		judgetest.RunHTTP(t, func(t *testing.T, baseURL, _ string) judge.Backend {
			t.Setenv("HG_JUDGETEST_OTHER_KEY", "not-the-key-from-keyEnv")
			b, err := typesafe.New("x", typesafe.Options{BaseURL: baseURL, APIKeyEnv: "HG_JUDGETEST_OTHER_KEY"})
			if err != nil {
				t.Fatal(err)
			}
			return b
		}, mixed)
		return
	}
	for name, want := range map[string][]string{
		"naive": {
			"the second server received", "contains the API key", "contains the response body",
			"want bad_response", "want rate_limit", "server received 2 requests", "the server address",
		},
		"wrong-key": {noKey},
	} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestRunHTTPCatchesBadBackends$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), badHTTPEnv+"="+name)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: RunHTTP passed; output:\n%s", name, out)
			continue
		}
		for _, sub := range httpSubtests {
			if !strings.Contains(string(out), "--- FAIL: TestRunHTTPCatchesBadBackends/"+sub+" ") {
				t.Errorf("%s: subtest %s did not fail; output:\n%s", name, sub, out)
			}
		}
		for _, w := range want {
			if !strings.Contains(string(out), w) {
				t.Errorf("%s: output lacks %q; output:\n%s", name, w, out)
			}
		}
		if name == "wrong-key" {
			// 后端合格，每个场景失败都只能是因为 key：至少每个场景报一次
			if n := strings.Count(string(out), noKey); n < len(httpSubtests) {
				t.Errorf("wrong-key: %q reported %d times, want at least once per subtest; output:\n%s", noKey, n, out)
			}
		}
	}
}

package typesafe_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
	"github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

const testKey = "test-key-not-a-secret"

var questions = []judge.Question{
	{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{
		Question: "Q?", CountsAsYes: "yes", CountsAsNo: "no",
		Criteria: map[string]string{"true": "T", "false": "F"},
	}},
	{ID: "blast_radius", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "How bad?"},
		Levels: []string{"l0", "l1", "l2", "l3"}},
}

func newBackend(t *testing.T, url string, o typesafe.Options) *typesafe.Backend {
	t.Helper()
	o.BaseURL = url
	b, err := typesafe.New("jev", o)
	if err != nil {
		t.Fatal(err)
	}
	b.SetGetenv(func(k string) string {
		if k == typesafe.DefaultAPIKeyEnv {
			return testKey
		}
		return ""
	})
	return b
}

const okBody = `{"model":"jev-1","answers":{
  "publish":{"type":"noul","noul":0.83},
  "blast_radius":{"type":"score","score":2,"confidence":0.7,"legend":{"0":"l0"},
                  "probabilities":{"0":0.1,"1":0.2,"2":0.6,"3":0.1}},
  "extra":{"type":"noul","noul":1}},
  "usage":{"input_tokens":120,"output_tokens":7}}`

func TestRequestShapeAndAnswers(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/systemone" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("headers = %v", r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Error(err)
		}
		io.WriteString(w, okBody)
	}))
	defer srv.Close()
	b := newBackend(t, srv.URL, typesafe.Options{})
	resp, err := b.Ask(context.Background(), map[string]any{"call": map[string]any{"command": "git push"}}, questions)
	if err != nil {
		t.Fatal(err)
	}
	if got["model"] != typesafe.DefaultModel || got["state"].(map[string]any)["call"] == nil {
		t.Errorf("request = %v", got)
	}
	qs := got["questions"].(map[string]any)
	pub := qs["publish"].(map[string]any)
	if pub["type"] != "noul" || pub["instructions"].(map[string]any)["counts_as_yes"] != "yes" ||
		pub["criteria"].(map[string]any)["true"] != "T" {
		t.Errorf("noul question = %v", pub)
	}
	br := qs["blast_radius"].(map[string]any)
	if br["type"] != "score" || br["instructions"] != "How bad?" || len(br["criteria"].([]any)) != 4 {
		t.Errorf("score question = %v", br)
	}
	if p := resp.Answers["publish"].P; p == nil || *p != 0.83 {
		t.Errorf("publish = %+v", resp.Answers["publish"])
	}
	if d := resp.Answers["blast_radius"].Dist; len(d) != 4 || d[2] != 0.6 {
		t.Errorf("blast_radius = %+v", resp.Answers["blast_radius"])
	}
	if _, ok := resp.Answers["extra"]; ok {
		t.Error("kept an answer to a question that was not asked")
	}
	if resp.Model != "jev-1" || resp.Usage.InputTokens != 120 {
		t.Errorf("model/usage = %q %+v", resp.Model, resp.Usage)
	}
}

func TestMissingValuesStayMissing(t *testing.T) {
	for _, body := range []string{
		`{"answers":{"publish":{"type":"noul","noul":null},"blast_radius":{"type":"score","probabilities":{"0":0.5,"1":0.5}}}}`,
		`{"answers":{"publish":{"type":"noul"},"blast_radius":{"type":"score","probabilities":{"0":1,"1":null,"2":null,"3":null}}}}`,
		`{"answers":{"publish":{"type":"score","probabilities":{"0":1}},"blast_radius":{"type":"score","probabilities":{"0":0,"1":0,"2":null,"3":1}}}}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body) }))
		resp, err := newBackend(t, srv.URL, typesafe.Options{}).Ask(context.Background(), nil, questions)
		srv.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.Answers["publish"].P != nil || resp.Answers["blast_radius"].Dist != nil {
			t.Errorf("%s: answers = %+v; null and incomplete answers must not become zeros", body, resp.Answers)
		}
		if v := judge.Validate(questions, resp); len(v) != 0 {
			t.Errorf("%s: validated = %+v, want none", body, v)
		}
	}
}

func TestErrorKindsAndRetries(t *testing.T) {
	tests := []struct {
		name     string
		statuses []int
		body     string
		kind     judge.ErrorKind
		calls    int32
	}{
		{"auth is not retried", []int{401}, "", judge.Auth, 1},
		{"forbidden", []int{403}, "", judge.Auth, 1},
		{"bad request is not retried", []int{400}, "", judge.BadResponse, 1},
		{"server error retried once", []int{500, 502}, "", judge.Unavailable, 2},
		{"rate limit retried", []int{429, 429}, "", judge.RateLimit, 2},
		{"recovers on retry", []int{503, 200}, okBody, "", 2},
		{"invalid json", []int{200}, "{not json", judge.BadResponse, 1},
		{"too large", []int{200}, `{"model":"` + strings.Repeat("x", 1<<20) + `"}`, judge.BadResponse, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				w.WriteHeader(tt.statuses[min(int(n), len(tt.statuses))-1])
				io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			_, err := newBackend(t, srv.URL, typesafe.Options{}).Ask(context.Background(), nil, questions)
			if judge.KindOf(err) != tt.kind || calls.Load() != tt.calls {
				t.Errorf("err = %v (kind %q), calls = %d; want kind %q, calls %d", err, judge.KindOf(err), calls.Load(), tt.kind, tt.calls)
			}
		})
	}
}

func TestMissingKeyIsAuthWithoutRequest(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer srv.Close()
	b := newBackend(t, srv.URL, typesafe.Options{})
	b.SetGetenv(func(string) string { return "" })
	_, err := b.Ask(context.Background(), nil, questions)
	if judge.KindOf(err) != judge.Auth || calls.Load() != 0 || !strings.Contains(err.Error(), "TYPESAFE_API_KEY") {
		t.Errorf("err = %v, calls = %d", err, calls.Load())
	}
}

func TestRequestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	zero := 0
	b := newBackend(t, srv.URL, typesafe.Options{TimeoutMS: 50, Retries: &zero})
	start := time.Now()
	_, err := b.Ask(context.Background(), nil, questions)
	if judge.KindOf(err) != judge.Timeout || time.Since(start) > time.Second {
		t.Errorf("err = %v after %v", err, time.Since(start))
	}
}

func TestRedirects(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("followed a cross-origin redirect")
	}))
	defer other.Close()
	redirectTo := func(target func(r *http.Request) string) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("/v1/systemone", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target(r), http.StatusTemporaryRedirect)
		})
		mux.HandleFunc("/moved", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, okBody) })
		return httptest.NewServer(mux)
	}

	// 同主机重定向允许
	same := redirectTo(func(*http.Request) string { return "/moved" })
	defer same.Close()
	if _, err := newBackend(t, same.URL, typesafe.Options{}).Ask(context.Background(), nil, questions); err != nil {
		t.Errorf("same-origin redirect: %v", err)
	}

	// 跨主机（这里是跨端口）重定向拒绝
	cross := redirectTo(func(*http.Request) string { return other.URL + "/v1/systemone" })
	defer cross.Close()
	zero := 0
	_, err := newBackend(t, cross.URL, typesafe.Options{Retries: &zero}).Ask(context.Background(), nil, questions)
	if judge.KindOf(err) != judge.Unavailable || !strings.Contains(err.Error(), "cross-origin") {
		t.Errorf("cross-origin redirect: err = %v", err)
	}
}

func TestNewRejectsBadOptions(t *testing.T) {
	neg := -1
	for _, o := range []typesafe.Options{
		{BaseURL: "ftp://example.com"},
		{BaseURL: "https://user:syntheticPassword123@example.com"},
		{BaseURL: "not a url"},
		{TimeoutMS: -1},
		{Retries: &neg},
	} {
		_, err := typesafe.New("x", o)
		if err == nil {
			t.Errorf("New(%+v) accepted", o)
		} else if strings.Contains(err.Error(), "syntheticPassword123") || (o.BaseURL != "" && strings.Contains(err.Error(), o.BaseURL)) {
			t.Errorf("error echoes the configured URL: %v", err)
		}
	}
	b, err := typesafe.New("x", typesafe.Options{})
	if err != nil || b.Endpoint() != "https://api.typesafe.ai/v1/systemone" {
		t.Errorf("default endpoint = %v, %v", b, err)
	}
}

func TestRegistered(t *testing.T) {
	f, ok := judge.LookupType(typesafe.Type)
	if !ok {
		t.Fatal("typesafe is not registered")
	}
	b, err := f("jev", func(v any) error {
		v.(*typesafe.Options).Model = "jev-2"
		return nil
	})
	if err != nil || b.Name() != "jev" {
		t.Fatalf("factory = %v, %v", b, err)
	}
	if c := b.Caps(); !c.Calibrated || !c.Batch || c.Mechanism != judge.MechanismNative ||
		!slices.Equal(c.Kinds, []judge.Kind{judge.KindProbability, judge.KindScale}) {
		t.Errorf("caps = %+v", c)
	}
}

func TestConformance(t *testing.T) {
	judgetest.Run(t, func(t *testing.T) judge.Backend {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, okBody) }))
		t.Cleanup(srv.Close)
		return newBackend(t, srv.URL, typesafe.Options{})
	}, questions)
}

// TestDescribe：同意绑定 scheme、主机与端口（不含路径与凭据），指纹绑定模型与原生概率（spec §8.3、§8.5）。
func TestDescribe(t *testing.T) {
	b, err := typesafe.New("jev", typesafe.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var d judge.Describer = b
	if got := d.Describe(); got != (judge.Info{Target: "https://api.typesafe.ai:443", Model: "jev-latest", Probability: "native"}) {
		t.Errorf("Describe() = %+v", got)
	}
	b, _ = typesafe.New("jev", typesafe.Options{BaseURL: "http://localhost:8080/proxy", Model: "jev-1"})
	if got := b.Describe(); got.Target != "http://localhost:8080" || got.Model != "jev-1" {
		t.Errorf("Describe() = %+v", got)
	}
}

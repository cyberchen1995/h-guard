package eval

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"
)

// StubMode 决定替身如何回应请求。
type StubMode int

const (
	StubAnswer  StubMode = iota // 按标注正常作答
	StubTimeout                 // 先睡一段时间再作答，让后端自己超时
	StubError                   // 一律返回 HTTP 500
)

// Stub 是进程内的 judge 替身：监听本机回环地址，说 typesafe 的线上格式，
// 答案完全由步骤标注决定，不依赖任何外部模型。
// 请求字节数按 state.call.cwd 换成固定占位符 stubCwdPlaceholder 之后计：cwd 是每次运行随机的临时目录，
// 不归一化的话输入 token 的估算会随机器与运行次数变化。
type Stub struct {
	srv   *httptest.Server
	steps map[string][]Step // 命令文本 -> 带这条命令的步骤，按出现顺序
	mode  StubMode
	sleep time.Duration

	mu    sync.Mutex // 后端将来可能并发重试，计数要加锁
	usage Usage
}

// stubQuestion 与 stubRequest 只解析替身需要的字段，和 typesafe 的 wireRequest 对应。
type stubQuestion struct {
	Type string `json:"type"`
}

type stubRequest struct {
	State struct {
		Call struct {
			Command string `json:"command"`
			Cwd     string `json:"cwd"`
		} `json:"call"`
		UserRequests []string `json:"user_requests"`
	} `json:"state"`
	Questions map[string]stubQuestion `json:"questions"`
}

type stubAnswer struct {
	Type          string             `json:"type"`
	Noul          *float64           `json:"noul,omitempty"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
}

type stubUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type stubResponse struct {
	Model   string                `json:"model"`
	Answers map[string]stubAnswer `json:"answers"`
	Usage   stubUsage             `json:"usage"`
}

// NewStub 以 steps 的标注建立替身并开始监听 127.0.0.1；任意路径都由同一个处理器应答。
// 只有执行命令的步骤进入查找表，以命令文本为键；同一命令出现多次时见 lookup。
func NewStub(steps []Step, mode StubMode, sleep time.Duration) *Stub {
	s := &Stub{steps: map[string][]Step{}, mode: mode, sleep: sleep}
	for _, st := range steps {
		if !st.IsExec() {
			continue
		}
		key := strings.TrimSpace(st.Text())
		s.steps[key] = append(s.steps[key], st)
	}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL 返回替身的根地址，可直接作为后端的 base_url。
func (s *Stub) URL() string { return s.srv.URL }

// Close 停止监听，并等仍在处理的请求结束（超时模式下睡眠中的回复也会写完并计入用量）；可重复调用。
func (s *Stub) Close() { s.srv.Close() }

// Usage 返回迄今累计的调用量。
func (s *Stub) Usage() Usage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

func (s *Stub) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req stubRequest
	_ = json.Unmarshal(body, &req) // 解析失败按未匹配处理
	s.mu.Lock()
	s.usage.Calls++
	s.usage.ReqBytes += int64(normalizedLen(body, req.State.Call.Cwd))
	s.mu.Unlock()

	if s.mode == StubError {
		s.write(w, http.StatusInternalServerError, []byte(`{"error":"stub failure"}`))
		return
	}
	if s.mode == StubTimeout {
		time.Sleep(s.sleep)
	}

	step, ok := s.lookup(strings.TrimSpace(req.State.Call.Command), req.State.UserRequests)
	if !ok {
		s.mu.Lock()
		s.usage.Unmatched++
		s.mu.Unlock()
	}
	resp := stubResponse{Model: "stub", Answers: make(map[string]stubAnswer, len(req.Questions))}
	for id, q := range req.Questions {
		resp.Answers[id] = stubAnswerFor(id, q, step)
	}
	resp.Usage.InputTokens = normalizedLen(body, req.State.Call.Cwd) / 4
	// 输出 token 按未含 usage 的响应长度估算
	pre, _ := json.Marshal(resp)
	resp.Usage.OutputTokens = len(pre) / 4
	out, _ := json.Marshal(resp)
	s.write(w, http.StatusOK, out)
}

// stubCwdPlaceholder 是计算请求字节数时代替 cwd 的固定文本。
const stubCwdPlaceholder = "<sandbox>"

// normalizedLen 返回把 body 里 cwd 的 JSON 转义形式全部换成 stubCwdPlaceholder 之后的长度；cwd 为空时就是 len(body)。
func normalizedLen(body []byte, cwd string) int {
	if cwd == "" {
		return len(body)
	}
	esc, _ := json.Marshal(cwd) // 与后端一样用 encoding/json 转义，结果带引号
	esc = esc[1 : len(esc)-1]
	return len(bytes.ReplaceAll(body, esc, []byte(stubCwdPlaceholder)))
}

// lookup 找命令对应的步骤。同一命令可能先未经要求、后经用户要求各出现一次（标注不同），
// 所以只考虑自身的 user_requests 全部出现在请求里的步骤，其中取指令最多的，一样多取先出现的。
// 指令在会话里累积：要求过之后再出现的同一命令也会取到「要求了」的标注。
func (s *Stub) lookup(command string, requests []string) (Step, bool) {
	var best Step
	found := false
	for _, st := range s.steps[command] {
		sent := true
		for _, r := range st.UserRequests {
			sent = sent && slices.Contains(requests, r)
		}
		if sent && (!found || len(st.UserRequests) > len(best.UserRequests)) {
			best, found = st, true
		}
	}
	return best, found
}

func (s *Stub) write(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	n, _ := w.Write(b)
	s.mu.Lock()
	s.usage.RespBytes += int64(n)
	s.mu.Unlock()
}

// stubAnswerFor 按步骤标注回答一道题；未匹配的步骤传零值 Step（无 harm、未 requested）。
func stubAnswerFor(id string, q stubQuestion, step Step) stubAnswer {
	if q.Type == "score" {
		// blast_radius 共 4 级：有 harm 记 2 级，否则 0 级；四个键必须齐全，缺键后端判无效
		p := map[string]float64{"0": 0, "1": 0, "2": 0, "3": 0}
		if len(step.Harm) > 0 {
			p["2"] = 1
		} else {
			p["0"] = 1
		}
		return stubAnswer{Type: "score", Probabilities: p}
	}
	v := 0.02
	switch {
	case id == "explicitly_requested":
		v = 0.05
		if step.Requested {
			v = 0.9
		}
	case slices.Contains(step.Harm, id):
		v = 0.95
	}
	return stubAnswer{Type: "noul", Noul: &v}
}

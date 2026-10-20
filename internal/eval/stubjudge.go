package eval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
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
	steps map[string]Step // caseKey(命令, 线上指令) -> 步骤
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

// StubCase 是替身查找表的一项：一步，加上重放时 action 检查会随这一步发给 judge 的用户指令
// （按时间先后，旧的在前，重复的照样保留），由重放器按会话里实际发过的指令推算。
type StubCase struct {
	Step     Step
	Requests []string
}

// NewStub 以 cases 的标注建立替身并开始监听 127.0.0.1；任意路径都由同一个处理器应答。
// 只有执行命令的步骤进入查找表，以 caseKey(命令, Requests) 为键；同一个键出现多次时先出现的那项作答，
// 调用方应先用 AmbiguousCases 校验，否则标注不同的后一项悄悄失效。
func NewStub(cases []StubCase, mode StubMode, sleep time.Duration) *Stub {
	s := &Stub{steps: map[string]Step{}, mode: mode, sleep: sleep}
	for _, c := range cases {
		if !c.Step.IsExec() {
			continue
		}
		key := caseKey(c.Step.Text(), c.Requests)
		if _, dup := s.steps[key]; !dup {
			s.steps[key] = c.Step
		}
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

	step, ok := s.lookup(req.State.Call.Command, req.State.UserRequests)
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

// stubKey 把命令或指令文本换成替身比较用的形式：先 secrets.Redact 再去掉首尾空白，与线上状态一致。
// BuildState（internal/check/action/state.go）送出的命令与指令都已遮蔽凭据，按原文建表的话，
// 命令里带凭据的步骤永远匹配不上。线上状态在超过 policy.max_command_chars / max_request_chars
// （默认 8000 / 2000 字符）时还会做中间截断，替身不重现截断；validateStep 拒收超长的命令与指令，
// 这个差别不会悄悄生效。
func stubKey(text string) string { return strings.TrimSpace(secrets.Redact(text)) }

// caseKey 是替身查找表的键：命令与每条指令各自按 stubKey 归一化，指令保持原有顺序与重复，
// 编码成 JSON 数组，命令或指令里出现什么字符都不会让两个不同的组合撞成同一个键。
func caseKey(command string, requests []string) string {
	parts := make([]string, 0, len(requests)+1)
	parts = append(parts, stubKey(command))
	for _, r := range requests {
		parts = append(parts, stubKey(r))
	}
	b, _ := json.Marshal(parts) // 字符串数组的编码不会失败
	return string(b)
}

// lookup 按命令与请求里的指令列表精确查找步骤：同一命令在会话里出现多次时，各次带的指令列表不同，
// 靠它分开；查不到的按未匹配处理。
func (s *Stub) lookup(command string, requests []string) (Step, bool) {
	st, ok := s.steps[caseKey(command, requests)]
	return st, ok
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

// AmbiguousCases 找出替身分不开、标注却不同的两项：都执行命令，caseKey 相同（judge 看到的命令与指令完全一样），
// 而 harm（不计顺序）、requested 或 expect 不同。替身遇到同一个键只会让先出现的那项作答，
// 后一项的标注悄悄失效，所以重放之前就报错；键相同、标注也相同的两项没有问题。
// 错误只写两步的 id，不写命令：命令可能带凭据。
func AmbiguousCases(cases []StubCase) error {
	seen := map[string]Step{}
	for _, c := range cases {
		if !c.Step.IsExec() {
			continue
		}
		key := caseKey(c.Step.Text(), c.Requests)
		prev, ok := seen[key]
		if !ok {
			seen[key] = c.Step
			continue
		}
		if !sameLabel(prev, c.Step) {
			return fmt.Errorf("steps %q and %q send the judge the same command and user requests but have different labels (harm, requested or expect); the judge stand-in cannot tell them apart", prev.ID, c.Step.ID)
		}
	}
	return nil
}

// sameLabel 报告两步的 harm（不计顺序）、requested 与 expect 是否都相同。
func sameLabel(a, b Step) bool {
	ha, hb := slices.Clone(a.Harm), slices.Clone(b.Harm)
	slices.Sort(ha)
	slices.Sort(hb)
	return a.Requested == b.Requested && a.Expect == b.Expect && slices.Equal(slices.Compact(ha), slices.Compact(hb))
}

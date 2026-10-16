package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/cache"
	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/consent"
	hglog "github.com/cyberchen1995/h-guard/internal/log"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

const testKey = "sk-abcdefghijklmnop1234"

// TestOutboundPromptBlocked：提示词里有凭据时 Claude Code 的 mod 收到 deny（drop），说明里没有原文；被拦的提示词
// 不写入指令缓存（spec §5.4、§6.3），之后正常的提示词照常写入。
func TestOutboundPromptBlocked(t *testing.T) {
	e := newEnv(t)
	out, _, code := e.run(promptReq("here is my key "+testKey+" please use it", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	r, err := extproto.ParseReply([]byte(out))
	if err != nil || code != 0 || r.Action != extproto.ActionDeny || !strings.Contains(r.Message, "credentials") || strings.Contains(out, testKey) {
		t.Fatalf("reply %q, exit %d, %v", out, code, err)
	}
	p := &cache.Prompts{Dir: filepath.Join(e.cache, "prompts")}
	if got := p.Recent("claudecode", "s1", 10); len(got) != 0 {
		t.Errorf("blocked prompt cached: %+v", got)
	}
	e.run(promptReq("push it to origin", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if got := p.Recent("claudecode", "s1", 10); len(got) != 1 || got[0].Text != "push it to origin" {
		t.Errorf("cache = %+v", got)
	}
}

// TestOutboundToolOutput：第 2 档扫描文件内容的工具输出：Read 的结果里有私钥时 mod 扣下结果（deny）；第 1 档不扫。
func TestOutboundToolOutput(t *testing.T) {
	result := ext("tool.result", map[string]any{"tool": "Read", "file_path": "/w/id_rsa", "tool_use_id": "t1"},
		map[string]any{"text": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"})
	e := newEnv(t)
	if out, _, _ := e.run(result, "hook", "claudecode", "--event", "tool.result"); !strings.Contains(out, `"action":"pass"`) {
		t.Errorf("tier 1: %s", out)
	}
	e.config("version: 1\noutbound: {tier: 2}\n")
	out, _, _ := e.run(result, "hook", "claudecode", "--event", "tool.result")
	if r, err := extproto.ParseReply([]byte(out)); err != nil || r.Action != extproto.ActionDeny || !strings.Contains(r.Message, "private key") {
		t.Errorf("tier 2: %s", out)
	}
}

// TestOutboundCodexPrompt：Codex 上被拦的提示词用 block；它不进缓存，会话记录回退时也跳过它（指纹）与 h-guard 自己
// 的拦截说明，不会重新成为授权依据（spec §5.4、§13 安全性质）。
func TestOutboundCodexPrompt(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	blocked := "deploy with token " + testKey
	out, _, _ := e.run(codexHook("UserPromptSubmit", map[string]any{"prompt": blocked}), "hook", "codex", "--event", "UserPromptSubmit")
	if !strings.Contains(out, `"decision":"block"`) || strings.Contains(out, testKey) {
		t.Fatalf("output %s", out)
	}
	tr := filepath.Join(t.TempDir(), "rollout-s1.jsonl")
	msg := func(text string) string {
		return `{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"` + text + `"}]}}` + "\n"
	}
	os.WriteFile(tr, []byte(msg(blocked)+msg("h-guard: Contains credentials (1 found, line 1).")+msg("clean the build dir")), 0o600)
	e.run(codexHook("PreToolUse", map[string]any{"transcript_path": tr, "tool_name": "Bash", "tool_input": map[string]any{"command": "rm -rf build"},
		"tool_use_id": "exec-1"}), "hook", "codex", "--event", "PreToolUse")
	var action string // 动作事件那一条：参与判断的用户指令
	for _, line := range strings.Split(e.files("logs"), "\n") {
		if strings.Contains(line, `"event":"action"`) {
			action = line
		}
	}
	if !strings.Contains(action, `"text":"clean the build dir"`) || strings.Contains(action, "deploy with token") || strings.Contains(action, "Contains credentials") {
		t.Errorf("action entry = %s", action)
	}
}

// TestOutboundDecisionLog：决策日志记命中（规则、类别、行号）与命中行前后各 2 行的摘录，凭据值遮蔽、不记整段文本；
// 健康记录不含任何内容（spec §10.2、§10.3）。
func TestOutboundDecisionLog(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	lines := []string{"marker-one", "marker-two", "marker-three", "marker-four", "key " + testKey, "marker-six", "marker-seven", "marker-eight", "marker-nine"}
	e.run(promptReq(strings.Join(lines, "\n"), "composer"), "hook", "claudecode", "--event", "prompt.submit")
	logs := e.files("logs")
	for _, want := range []string{`"rule":"credentials.prefixed_token"`, `"category":"credentials"`, `"line":5`, "marker-three", "marker-seven", "[secret:"} {
		if !strings.Contains(logs, want) {
			t.Errorf("decision log lacks %q: %s", want, logs)
		}
	}
	for _, absent := range []string{testKey, "marker-two", "marker-eight"} {
		if strings.Contains(logs, absent) {
			t.Errorf("decision log has %q: %s", absent, logs)
		}
	}
	if h := e.files("health"); strings.Contains(h, "marker") || strings.Contains(h, testKey) {
		t.Errorf("health = %s", h)
	}
}

// TestOutboundLogPEMExcerpt：摘录先遮蔽再按行截取：命中行前后各 2 行只切到私钥的一部分时，私钥正文也不进决策日志，
// 行号不变（M4a 计划评审 C1）。
func TestOutboundLogPEMExcerpt(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	body := []string{"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ", "AAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACDm9z", "QyNTUxOQAAACDm9zLbW1hc2tlZC1ib2R5LWxpbmUtMw", "ZWQyNTUxOQAAAEBtYXNrZWQtYm9keS1saW5lLTQAAAA"}
	text := "line-one\nline-two\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(body, "\n") + "\n-----END OPENSSH PRIVATE KEY-----\nline-after"
	e.run(promptReq(text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	logs := e.files("logs")
	if !strings.Contains(logs, `"line":3`) || !strings.Contains(logs, "line-one") {
		t.Errorf("decision log = %s", logs)
	}
	for _, b := range body {
		if strings.Contains(logs, b[:16]) {
			t.Errorf("decision log has key body %q: %s", b[:16], logs)
		}
	}
	// 被截断的私钥（没有 END 行），前一行另有一处命中：正文同样不进日志（M4a 终审 I-1）
	e = newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	e.run(promptReq("deploy key "+testKey+"\n-----BEGIN OPENSSH PRIVATE KEY-----\n"+strings.Join(body[:2], "\n"), "composer"), "hook", "claudecode", "--event", "prompt.submit")
	logs = e.files("logs")
	for _, b := range body[:2] {
		if strings.Contains(logs, b[:16]) || !strings.Contains(logs, "[secret:private_key.pem") {
			t.Errorf("truncated key in decision log: %s", logs)
		}
	}
}

// TestOutboundLogToolOutput：工具输出的决策日志同样只记命中行前后各 2 行的摘录，不记整段输出（spec §10.3）。
func TestOutboundLogToolOutput(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\noutbound: {tier: 3}\nlog: {decisions: true}\n")
	lines := []string{"marker-one", "marker-two", "marker-three", "token " + testKey, "marker-five", "marker-six", "marker-seven"}
	e.run(ext("tool.result", map[string]any{"tool": "Bash", "command": "env", "tool_use_id": "t1"}, map[string]any{"text": strings.Join(lines, "\n")}),
		"hook", "claudecode", "--event", "tool.result")
	logs := e.files("logs")
	for _, want := range []string{`"event":"tool_output"`, `"line":4`, "marker-two", "marker-six"} {
		if !strings.Contains(logs, want) {
			t.Errorf("decision log lacks %q: %s", want, logs)
		}
	}
	for _, absent := range []string{testKey, "marker-one", "marker-seven"} {
		if strings.Contains(logs, absent) {
			t.Errorf("decision log has %q: %s", absent, logs)
		}
	}
}

// TestOutboundLogContextShapes：依赖上下文的凭据（关键词与值隔着几行）被拦下后，摘录窗口里只有值、没有关键词，
// 值也不进决策日志（M4a Codex 评审 M4A-01）。
func TestOutboundLogContextShapes(t *testing.T) {
	for _, prefix := range []string{"password:\n\n\n\n", "Bearer\n\n\n\n"} {
		e := newEnv(t)
		e.config("version: 1\nlog: {decisions: true}\n")
		value := "Ab3dEf6hIj9kLm2nOp5q"
		out, _, _ := e.run(promptReq(prefix+value, "composer"), "hook", "claudecode", "--event", "prompt.submit")
		if logs := e.files("logs"); !strings.Contains(out, `"action":"deny"`) || strings.Contains(logs, value) || !strings.Contains(logs, "[secret:") {
			t.Errorf("%q: reply %s, logs %s", prefix, out, logs)
		}
	}
}

// TestOutboundLogCustomCredential：用户正则认出的 credentials、private_key 类别的值同样遮蔽后再进决策日志，包括跨行的
// 值与超过命中位置上限（100 处）的命中；其他自定义类别按 spec §10.3 原样记录（M4a Codex 评审 M4A-02）。
func TestOutboundLogCustomCredential(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	rules := filepath.Join(e.configDir, "rules")
	os.MkdirAll(rules, 0o700)
	os.WriteFile(filepath.Join(rules, "key.yaml"), []byte("schema: 1\nid: acme.key\ncategory: credentials\non: [prompt]\nmatch: {regex: ['ACME-[0-9]{12}']}\n"), 0o600)
	os.WriteFile(filepath.Join(rules, "blob.yaml"), []byte("schema: 1\nid: acme.blob\ncategory: private_key\non: [prompt]\nmatch: {regex: ['BLOB<[^>]*>']}\n"), 0o600)
	os.WriteFile(filepath.Join(rules, "falcon.yaml"), []byte("schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\nmatch: {regex: [falcon]}\n"), 0o600)
	var lines []string
	for i := range 150 { // 前 100 处之后的命中也在摘录窗口里
		lines = append(lines, fmt.Sprintf("ACME-%012d", i))
	}
	lines = append(lines, "BLOB<zq81Tsecretpart1", "zq81Tsecretpart2>", "project falcon")
	e.run(promptReq(strings.Join(lines, "\n"), "composer"), "hook", "claudecode", "--event", "prompt.submit")
	logs := e.files("logs")
	for _, absent := range []string{"ACME-000000000000", "ACME-000000000149", "zq81Tsecretpart"} {
		if strings.Contains(logs, absent) {
			t.Errorf("decision log has %q", absent)
		}
	}
	if !strings.Contains(logs, "[secret:custom len=17") || !strings.Contains(logs, "project falcon") {
		t.Errorf("decision log = %s", logs)
	}
}

// cancelOnSecondErr 在第二次 Err 调用时取消（第一处匹配之后），之后照实报告取消。
type cancelOnSecondErr struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *cancelOnSecondErr) Err() error {
	if c.calls++; c.calls == 2 {
		c.cancel()
	}
	return c.Context.Err()
}

// TestOutboundLogPartialScan：决策日志的摘录用 outbound 这一次扫出的区间遮蔽（M4b，不再重扫）。扫描途中截止时间到了
// （第一处匹配之后）时区间不全：不记摘录，同一行里没扫到的凭据不会落盘；结论与命中照常记录（M4a Codex 第二轮
// R2-01）。正常扫完时两处都遮蔽；没有扫描（outbound 没有运行）时也不记摘录。
func TestOutboundLogPartialScan(t *testing.T) {
	for _, mode := range []string{"complete", "cancelled", "no scan"} {
		e := newEnv(t)
		e.config("version: 1\nlog: {decisions: true}\n")
		dir := filepath.Join(e.configDir, "rules")
		os.MkdirAll(dir, 0o700)
		os.WriteFile(filepath.Join(dir, "k.yaml"), []byte("schema: 1\nid: acme.key\ncategory: credentials\non: [prompt]\nmatch: {regex: ['ACME-[0-9]{12}']}\n"), 0o600)
		o := Options{ConfigDir: e.configDir, CacheDir: e.cache, Home: e.home, Getenv: func(string) string { return "" }, Now: time.Now}
		o.fill()
		s, err := load(o, "")
		if err != nil {
			t.Fatal(err)
		}
		ev := guard.Event{Kind: guard.EventPrompt, Harness: "claudecode", SessionID: "s1", Text: "ACME-111111111111 ACME-222222222222"}
		v, err := (&outbound.Check{Rules: s.rules, Config: s.cfg}).Evaluate(context.Background(), ev, func(guard.Verdict) {})
		if err != nil || v.Decision != guard.DecisionDeny {
			t.Fatalf("evaluate: %+v %v", v, err)
		}
		h := &hookRun{o: o, start: time.Now(), logs: &hglog.Writer{Dir: e.cache, Now: time.Now, Decisions: true, RetentionDays: 14}}
		if mode != "no scan" {
			var ctx context.Context = context.Background()
			if mode == "cancelled" {
				c, cancel := context.WithCancel(ctx)
				defer cancel()
				ctx = &cancelOnSecondErr{Context: c, cancel: cancel}
			}
			(&outbound.Check{Rules: s.rules, Config: s.cfg, Scanned: func(sc outbound.Scan) { h.scan = &sc }}).Evaluate(ctx, ev, func(guard.Verdict) {})
		}
		h.decision(s, judgeState{}, ev, guard.Outcome{Verdict: v, Raw: guard.DecisionDeny})
		logs := e.files("logs")
		if strings.Contains(logs, "ACME-1111") || strings.Contains(logs, "ACME-2222") || !strings.Contains(logs, `"rule":"acme.key"`) ||
			strings.Contains(logs, `"excerpts"`) != (mode == "complete") {
			t.Errorf("%s: %s", mode, logs)
		}
	}
}

// TestOutboundReaderOptions：第 2 档按读文件的命令扫描工具输出；xargs、git 带参数的选项不影响识别，Claude Code 与
// Codex 都是（M4a Codex 评审 M4A-04）。
func TestOutboundReaderOptions(t *testing.T) {
	for _, cmd := range []string{"xargs -I {} cat {}", "git -C /repo show HEAD:secrets.txt", "cat secrets.txt"} {
		e := newEnv(t)
		e.config("version: 1\noutbound: {tier: 2}\n")
		out, _, _ := e.run(ext("tool.result", map[string]any{"tool": "Bash", "command": cmd, "tool_use_id": "t1"}, map[string]any{"text": testKey}),
			"hook", "claudecode", "--event", "tool.result")
		if !strings.Contains(out, `"action":"deny"`) {
			t.Errorf("claudecode %q: %s", cmd, out)
		}
		out, _, _ = e.run(codexHook("PostToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": cmd},
			"tool_response": testKey, "tool_use_id": "exec-1"}), "hook", "codex", "--event", "PostToolUse")
		if !strings.Contains(out, `"decision":"block"`) {
			t.Errorf("codex %q: %s", cmd, out)
		}
	}
}

// ext 是 Claude Code mod 发来的扩展请求（hook、data、result）。
func ext(hook string, data, result map[string]any) []byte {
	b, _ := json.Marshal(map[string]any{"protocol": extproto.Protocol, "harness": "claudecode", "harness_version": "2.1.296",
		"hook": hook, "session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data, "result": result})
	return b
}

// outboundServer 是假的 typesafe 服务，回答 outbound 类别题：credentials 为 p，其余 0.02。
type outboundServer struct {
	*httptest.Server
	calls int
	body  string
}

func newOutboundServer(t *testing.T, p float64) *outboundServer {
	s := &outboundServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls++
		b, _ := io.ReadAll(r.Body)
		s.body = string(b)
		low := `{"type":"noul","noul":0.02}`
		fmt.Fprintf(w, `{"answers":{"outbound.credentials":{"type":"noul","noul":%g},"outbound.private_key":%s,"outbound.pii":%s}}`, p, low, low)
	}))
	t.Cleanup(s.Close)
	return s
}

// outboundJudgeConfig 开启模型、把 jev 指向 srv；extra 追加在后面（如开启 PII）。
func (e *env) outboundJudgeConfig(srv *outboundServer, extra string) {
	e.t.Setenv("HG_TEST_KEY", "test-key-not-a-secret")
	e.config("version: 1\njudge: {enabled: true, backend: jev}\n" +
		"backends: {jev: {type: typesafe, model: jev-latest, profile: jev, base_url: '" + srv.URL + "', api_key_env: HG_TEST_KEY}}\n" + extra)
}

// TestBackendEnableGrantsOutbound：backend enable 一次说明并同意 action 与 outbound 两个范围；PII 类别开启时加上 pii
// 范围并写明本地识别不了的个人信息会原样发送（M4b 已定决策，spec §8.5）。
func TestBackendEnableGrantsOutbound(t *testing.T) {
	srv := newOutboundServer(t, 0.9)
	id := func(e *env) consent.Identity {
		return consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}
	}
	for pii, scopes := range map[bool][]consent.Scope{false: {consent.ScopeAction, consent.ScopeOutbound}, true: {consent.ScopeAction, consent.ScopeOutbound, consent.ScopePII}} {
		e := newEnv(t)
		e.tty = true
		extra := ""
		if pii {
			extra = "outbound: {categories: {pii: {enabled: true}}}\n"
		}
		e.outboundJudgeConfig(srv, extra)
		out, _, code := e.run([]byte("y\n"), "backend", "enable", "jev")
		if code != 0 || !strings.Contains(out, "prompts") || strings.Contains(out, "personal information that h-guard does not recognize") != pii {
			t.Errorf("pii=%v: exit %d, out %q", pii, code, out)
		}
		store := consent.Store{Dir: e.configDir}
		if !store.Covers(id(e), scopes...) || !pii && store.Covers(id(e), consent.ScopePII) {
			t.Errorf("pii=%v: scopes not recorded", pii)
		}
		if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "scopes: "+strings.Join(func() []string {
			var s []string
			for _, sc := range scopes {
				s = append(s, string(sc))
			}
			return s
		}(), ", ")) || !strings.Contains(out, "outbound calibration: uncalibrated") {
			t.Errorf("pii=%v: status %q", pii, out)
		}
	}
}

// TestHookOutboundJudge：模型开启、同意含 outbound 时，够长的提示词本地没有命中也发给模型，模型报出凭据时提示（warn，
// 模型的命中不拦，M4b 计划评审 I-3）；
// 同意只有 action 范围时不调用（judge_consent_missing），状态里写明要重新同意（spec §8.5）。
func TestHookOutboundJudge(t *testing.T) {
	text := strings.Repeat("Here is the staging setup we discussed yesterday with the team. ", 4) + "admin pw Tr0ub4dor and3"
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.outboundJudgeConfig(srv, "")
	store := consent.Store{Dir: e.configDir}
	id := consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}
	store.Grant(id, []consent.Scope{consent.ScopeAction}, time.Now())
	out, _, _ := e.run(promptReq(text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if !strings.Contains(out, `"action":"pass"`) || srv.calls != 0 || !strings.Contains(e.files("health"), "judge_consent_missing") {
		t.Errorf("action-only consent: %s, calls %d", out, srv.calls)
	}
	if st, _, _ := e.run(nil, "status"); !strings.Contains(st, "does not cover outbound") {
		t.Errorf("status = %q", st)
	}
	store.Grant(id, []consent.Scope{consent.ScopeAction, consent.ScopeOutbound}, time.Now())
	out, _, _ = e.run(promptReq(text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	r, err := extproto.ParseReply([]byte(out))
	if err != nil || r.Action != extproto.ActionWarn || !strings.Contains(r.Message, "judge model reports credentials") || srv.calls != 1 ||
		!strings.Contains(srv.body, "outbound.credentials") || strings.Contains(srv.body, "outbound.pii") {
		t.Errorf("with consent: %s, calls %d, body %s", out, srv.calls, srv.body)
	}
}

// TestOutboundJudgeOff：outbound.judge: false 时只用 action 判断：backend enable 只说明并同意 action，提示词不发给模型，
// 也不记 judge_consent_missing（M4b 计划评审 I-4，维护者决定）。
func TestOutboundJudgeOff(t *testing.T) {
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.tty = true
	e.outboundJudgeConfig(srv, "outbound: {judge: false}\n")
	out, _, code := e.run([]byte("y\n"), "backend", "enable", "jev")
	store := consent.Store{Dir: e.configDir}
	id := consent.Identity{Backend: "jev", Type: "typesafe", Target: srv.URL}
	if code != 0 || strings.Contains(out, "tool output that h-guard scans") || !store.Covers(id, consent.ScopeAction) || store.Covers(id, consent.ScopeOutbound) {
		t.Errorf("enable: exit %d, %s", code, out)
	}
	text := strings.Repeat("Here is the staging setup we discussed yesterday with the team. ", 4)
	e.run(promptReq(text, "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if srv.calls != 0 || strings.Contains(e.files("health"), "judge_consent_missing") {
		t.Errorf("calls %d, health %s", srv.calls, e.files("health"))
	}
	if st, _, _ := e.run(nil, "status"); !strings.Contains(st, "outbound judge: off (outbound.judge: false)") || strings.Contains(st, "does not cover outbound") {
		t.Errorf("status = %s", st)
	}
}

// TestConsentPIILater：同意之后才开启 PII 类别时，status 写明同意不含 pii 并给出命令（spec §8.5：扩大范围要重新同意，
// M4b 计划评审 M-4）；backend enable 的说明写明之后改档位与分块不再询问（M-5）。
func TestConsentPIILater(t *testing.T) {
	srv := newOutboundServer(t, 0.9)
	e := newEnv(t)
	e.tty = true
	e.outboundJudgeConfig(srv, "")
	if out, _, _ := e.run([]byte("y\n"), "backend", "enable", "jev"); !strings.Contains(out, "does not ask again") {
		t.Errorf("enable text = %s", out)
	}
	e.outboundJudgeConfig(srv, "outbound: {categories: {pii: {enabled: true}}}\n")
	if st, _, _ := e.run(nil, "status"); !strings.Contains(st, "does not cover pii") {
		t.Errorf("status = %s", st)
	}
}

// TestOutboundClaudeTranscript：claude -p 下被 drop 的提示词仍写进 Claude Code 的会话记录（spec §6.3 的 M0 实测）。
// 它不进缓存，transcript 回退读到它时按指纹跳过，h-guard 自己的说明同样跳过，不会成为授权依据（spec §5.4，M4a 计划
// 评审 M1）。会话记录里的写法与 hook 收到的空白不同（换行、首尾空白）也认得出。
func TestOutboundClaudeTranscript(t *testing.T) {
	e := newEnv(t)
	e.config("version: 1\nlog: {decisions: true}\n")
	blocked := "deploy with token " + testKey + "\nthen   restart"
	if out, _, _ := e.run(promptReq(blocked, "sdk"), "hook", "claudecode", "--event", "prompt.submit"); !strings.Contains(out, `"action":"deny"`) {
		t.Fatalf("not blocked: %s", out)
	}
	rec := func(text, kind string) string {
		b, _ := json.Marshal(map[string]any{"type": "user", "message": map[string]any{"content": text}, "origin": map[string]string{"kind": kind}})
		return string(b) + "\n"
	}
	tr := filepath.Join(t.TempDir(), "s1.jsonl")
	os.WriteFile(tr, []byte(rec("clean the build dir", "human")+rec(" deploy with token "+testKey+"\r\nthen restart ", "sdk")+
		rec("h-guard: Contains credentials (1 found, line 1).", "human")), 0o600)
	e.run(pre("Bash", map[string]any{"command": "rm -rf build"}, tr), "hook", "claudecode", "--event", "PreToolUse")
	var action string
	for _, line := range strings.Split(e.files("logs"), "\n") {
		if strings.Contains(line, `"event":"action"`) {
			action = line
		}
	}
	if !strings.Contains(action, `"text":"clean the build dir"`) || strings.Contains(action, "deploy with token") || strings.Contains(action, "Contains credentials") {
		t.Errorf("action entry = %s", action)
	}
}

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/cache"
	"github.com/cyberchen1995/h-guard/internal/check/outbound"
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

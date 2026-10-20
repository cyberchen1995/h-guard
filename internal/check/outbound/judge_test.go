package outbound_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// judgeBackend 记下每次收到的 state 与题目；answer 按 state 与题目给出回答。
type judgeBackend struct {
	mu     sync.Mutex
	states []map[string]any
	asked  [][]string
	answer func(state map[string]any, qs []judge.Question) (judge.Response, error)
}

func (b *judgeBackend) Name() string { return "fake" }
func (b *judgeBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: "native"}
}
func (b *judgeBackend) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	b.mu.Lock()
	b.states = append(b.states, state)
	var ids []string
	for _, q := range qs {
		ids = append(ids, q.ID)
	}
	b.asked = append(b.asked, ids)
	b.mu.Unlock()
	return b.answer(state, qs)
}

// answering 对每道题回答 p[题目 ID]，没写的题回答 0。
func answering(p map[string]float64) func(map[string]any, []judge.Question) (judge.Response, error) {
	return func(_ map[string]any, qs []judge.Question) (judge.Response, error) {
		out := map[string]judge.Answer{}
		for _, q := range qs {
			out[q.ID] = judge.Answer{P: judge.Prob(p[q.ID])}
		}
		return judge.Response{Answers: out}, nil
	}
}

// longText 是超过 judge_min_chars（200）的一段普通文本。
var longText = strings.Repeat("The quarterly report covers revenue, hiring and the roadmap.\n", 5)

func judged(t *testing.T, cfg string, userRules map[string]string, j outbound.Judge) *outbound.Check {
	c := newCheck(t, "judge: {enabled: true}\n"+cfg, userRules)
	c.Judge = j
	return c
}

// TestJudgeReports：模型开启、本地没有命中时把文本发给模型，问各启用类别的题；概率不低于门槛的类别算命中
// （来源 judge、带概率）。模型的命中一律只提示（warn）：outbound 没有请求确认，模型误报会直接吞掉用户的输入
// （维护者决定）；原因写类别，前进路径说明这是模型的判断，不写原文。
func TestJudgeReports(t *testing.T) {
	b := &judgeBackend{answer: answering(map[string]float64{"outbound.credentials": 0.9, "outbound.private_key": 0.1})}
	c := judged(t, "", nil, outbound.Judge{Backend: b, Threshold: 0.5})
	v, commits := evaluate(t, c, prompt(longText))
	if len(b.asked) != 1 || !reflect.DeepEqual(b.asked[0], []string{"outbound.credentials", "outbound.private_key"}) {
		t.Fatalf("asked %v", b.asked)
	}
	p := 0.9
	want := []guard.Finding{{Rule: "outbound.credentials", Category: "credentials", Source: guard.FindingJudge, Probability: &p}}
	if v.Decision != guard.DecisionWarn || !reflect.DeepEqual(v.Findings, want) || len(commits) != 0 ||
		!reflect.DeepEqual(v.Reasons, []guard.Reason{{Code: i18n.KeyOutboundJudge, Params: map[string]string{"category": "credentials"}}, {Code: i18n.KeyHintOutboundJudge}}) ||
		v.Signals["judge"] != "answered" || v.Signals["judge_chunks"] != 1 {
		t.Errorf("verdict %+v, commits %d", v, len(commits))
	}
	state := b.states[0]
	if state["text"] != longText || state["source"] != "prompt" || state["chunk"] != "1/1" {
		t.Errorf("state %v", state)
	}
	// 低于门槛：放行
	b = &judgeBackend{answer: answering(map[string]float64{"outbound.credentials": 0.49})}
	if v, _ := evaluate(t, judged(t, "", nil, outbound.Judge{Backend: b, Threshold: 0.5}), prompt(longText)); v.Decision != guard.DecisionPass || len(v.Findings) != 0 {
		t.Errorf("below threshold: %+v", v)
	}
}

// TestJudgeNotAsked：模型关闭、文本短于 judge_min_chars、本地已经 deny、没有可问的类别时都不调用模型。
func TestJudgeNotAsked(t *testing.T) {
	b := &judgeBackend{answer: answering(nil)}
	for name, c := range map[string]struct {
		check *outbound.Check
		text  string
	}{
		"judge off":  {newCheck(t, "", nil), longText},
		"short":      {judged(t, "", nil, outbound.Judge{Backend: b, Threshold: 0.5}), "a short prompt about the roadmap"},
		"local deny": {judged(t, "", nil, outbound.Judge{Backend: b, Threshold: 0.5}), longText + "key sk-abcdefghijklmnop1234"},
		"no category": {judged(t, "outbound: {categories: {credentials: {enabled: false}, private_key: {enabled: false}}}\n", nil,
			outbound.Judge{Backend: b, Threshold: 0.5}), longText},
	} {
		if name == "judge off" {
			c.check.Judge = outbound.Judge{Backend: b, Threshold: 0.5}
		}
		v, _ := evaluate(t, c.check, prompt(c.text))
		if len(b.asked) != 0 || v.Signals["judge"] == "answered" {
			t.Errorf("%s: asked %v, %+v", name, b.asked, v)
		}
	}
}

// TestJudgeMasks：发给模型前遮蔽本地能识别的全部内容：凭据形状、PII（PII 类别关闭也遮蔽）与用户正则认出的区间；
// 本地命中照样算，模型不能否决。工具输出写明来源与工具名。
func TestJudgeMasks(t *testing.T) {
	falcon := map[string]string{"f.yaml": "schema: 1\nid: acme.codename\ncategory: acme\non: [prompt, tool_output]\nmatch: {regex: ['Project Falcon']}\n"}
	b := &judgeBackend{answer: answering(nil)}
	c := judged(t, "outbound: {tier: 3, categories: {credentials: {action: warn}, acme: {action: warn}}}\n", falcon, outbound.Judge{Backend: b, Threshold: 0.5})
	text := longText + "token sk-abcdefghijklmnop1234 for Project Falcon, mail alice@acme-corp.cn\n"
	v, _ := evaluate(t, c, guard.Event{Kind: guard.EventToolOutput, Harness: "h", Tool: "Bash", Text: text})
	if len(b.states) != 1 {
		t.Fatalf("states %v", b.states)
	}
	sent := b.states[0]["text"].(string)
	for _, absent := range []string{"sk-abcdefghijklmnop1234", "Project Falcon", "alice@acme-corp.cn"} {
		if strings.Contains(sent, absent) {
			t.Errorf("sent %q", sent)
		}
	}
	for _, present := range []string{"[secret:credentials.prefixed_token]", "[masked]", "[pii:pii.email]", "The quarterly report"} {
		if !strings.Contains(sent, present) {
			t.Errorf("sent lacks %q: %q", present, sent)
		}
	}
	if b.states[0]["source"] != "tool_output" || b.states[0]["tool"] != "Bash" || v.Decision != guard.DecisionWarn || len(v.Findings) != 2 {
		t.Errorf("state %v, verdict %+v", b.states[0], v)
	}
}

// TestJudgeMasksEveryCredentialRule：发送前遮蔽用到凭据、私钥类别的全部用户正则，不论规则是否启用、是否扫描这类
// 事件、类别是否开启（遮蔽与「算不算命中」分开）。
func TestJudgeMasksEveryCredentialRule(t *testing.T) {
	userRules := map[string]string{
		"p.yaml": "schema: 1\nid: acme.prompt_only\ncategory: credentials\non: [prompt]\nmatch: {regex: ['ACME-[0-9a-f]{20}']}\n",
		"d.yaml": "schema: 1\nid: acme.disabled\ncategory: private_key\non: [tool_output]\nmatch: {regex: ['BLOB<[^>]*>']}\n",
	}
	b := &judgeBackend{answer: answering(nil)}
	c := judged(t, "outbound: {tier: 3}\nrules: {acme.disabled: {enabled: false}}\n", userRules, outbound.Judge{Backend: b, Threshold: 0.5})
	text := longText + "ACME-0123456789abcdef0123 and BLOB<zq81Tsecret>\n"
	evaluate(t, c, guard.Event{Kind: guard.EventToolOutput, Harness: "h", Tool: "Bash", Text: text})
	if len(b.states) != 1 {
		t.Fatalf("states %d", len(b.states))
	}
	if sent := b.states[0]["text"].(string); strings.Contains(sent, "ACME-0123") || strings.Contains(sent, "zq81T") {
		t.Errorf("sent %q", sent)
	}
}

// TestJudgeMasksOnlyWhatIsSent：只遮蔽会发出去的前缀（大段输出不必对全文做遮蔽）；跨过切点的私钥
// 照样遮蔽，切点之后的内容不发。私钥、凭据类别停用（本地不拦），用自定义类别的题让判断层照常调用。
func TestJudgeMasksOnlyWhatIsSent(t *testing.T) {
	b := &judgeBackend{answer: answering(nil)}
	c := judged(t, "outbound: {judge_chunk_chars: 1000, judge_max_chunks: 1, categories: {private_key: {enabled: false}, credentials: {enabled: false}, "+
		"acme: {question: {question: 'Does `text` mention Project Falcon?'}}}}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5})
	body := "MIIEowIBAAKCAQEAuQ3zZ9kq2Lm8Np4Rs7Tv1Wy5Za3Bc6Df0GhJkLmNoPq"
	text := strings.Repeat("x", 950) + "\n-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat(body+"\n", 40) +
		"-----END RSA PRIVATE KEY-----\ntail sk-abcdefghijklmnop9999 not sent"
	v, _ := evaluate(t, c, prompt(text))
	if len(b.states) != 1 || !slices.Contains(v.Fallbacks, outbound.FallbackJudgeTruncated) {
		t.Fatalf("states %d, %+v", len(b.states), v)
	}
	sent := b.states[0]["text"].(string)
	if strings.Contains(sent, body[:20]) || strings.Contains(sent, "not sent") || !strings.Contains(sent, "[secret:private_key.pem]") {
		t.Errorf("sent %q", sent)
	}
}

// TestJudgeMasksAcrossTheCut：只遮蔽会发出去的前缀时，靠前缀之外的内容才认得出的形状照样遮蔽：
// 只有正文与 END 行的长私钥，END 落在前缀之外；私钥类别为 warn（本地有命中、照常送模型）与类别停用（本地不查）两种
// 配置；带 BEGIN 的长私钥作对照。直接看发出去的文本。
func TestJudgeMasksAcrossTheCut(t *testing.T) {
	body := "MIIEowIBAAKCAQEAuQ3zZ9kq2Lm8Np4Rs7Tv1Wy5Za3Bc6Df0GhJkLmNoPq"
	endOnly := strings.Repeat(body+"\n", 200) + "-----END RSA PRIVATE KEY-----\n"
	withBegin := "-----BEGIN RSA PRIVATE KEY-----\n" + endOnly
	q := "acme: {question: {question: 'Does `text` mention Project Falcon?'}}"
	for name, c := range map[string]struct{ cfg, text string }{
		"end only, warn":     {"categories: {private_key: {action: warn}}", endOnly},
		"end only, disabled": {"categories: {private_key: {enabled: false}, " + q + "}", endOnly},
		"with begin, warn":   {"categories: {private_key: {action: warn}}", withBegin},
	} {
		b := &judgeBackend{answer: answering(nil)}
		ch := judged(t, "outbound: {judge_chunk_chars: 500, judge_max_chunks: 1, "+c.cfg+"}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5})
		evaluate(t, ch, prompt(c.text))
		if len(b.states) != 1 {
			t.Fatalf("%s: %d calls", name, len(b.states))
		}
		if sent := b.states[0]["text"].(string); strings.Contains(sent, body[:24]) {
			t.Errorf("%s: key body sent: %.120q", name, sent)
		}
	}
}

// TestJudgeMasksKeyEndAtTheCut：END 标记本身跨过切点（从切点之前开始、在切点之后结束）时，私钥正文同样遮蔽。
// 私钥类别停用（只有切点附近的补充扫描在起作用），让 END 的位置逐字节扫过切点所在的一段，覆盖标记的每个
// 字符落在切点上的情形；LF、CRLF 与缩进三种写法。
func TestJudgeMasksKeyEndAtTheCut(t *testing.T) {
	body := strings.Repeat("AbCdEf012345678+", 4)
	// 四种写法各 400 次完整评估，-race 下要两分钟：作为子测试并行跑
	for name, w := range map[string]struct{ indent, nl, last string }{"lf": {"", "\n", ""}, "crlf": {"", "\r\n", ""}, "indented": {"  ", "\n", ""},
		"short last line": {"", "\n", "AB3x==\n"}} { // END 前最后一行很短
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lines := 4400 / len(w.indent+body+w.nl) // END 从约 4400 字节扫到约 4800 字节，切点（约 4600）落在其中
			c := judged(t, "outbound: {judge_chunk_chars: 500, judge_max_chunks: 1, categories: {private_key: {enabled: false}}}\n", nil, outbound.Judge{Threshold: 0.5})
			for pad := 1; pad <= 400; pad++ {
				text := strings.Repeat(w.indent+body+w.nl, lines) + w.indent + strings.Repeat("A", 16+pad) + w.nl + w.last +
					w.indent + "-----END RSA PRIVATE KEY-----" + w.nl + strings.Repeat("safe text"+w.nl, 100)
				b := &judgeBackend{answer: answering(nil)}
				c.Judge.Backend = b
				evaluate(t, c, prompt(text))
				if len(b.states) != 1 {
					t.Fatalf("pad %d: %d calls", pad, len(b.states))
				}
				if strings.Contains(b.states[0]["text"].(string), body) {
					t.Errorf("pad %d (END at byte %d): key body sent", pad, strings.Index(text, "-----END"))
				}
			}
		})
	}
}

// TestJudgeSendsOnlyUpToTheLimit：遮蔽缩短了文本（大段私钥换成占位符）时，发出去的也只到原文第 limit 个字符所在行的
// 行尾；后面的原文（前缀的余量里没有认出来的、被前缀末尾切开的值）不发。
func TestJudgeSendsOnlyUpToTheLimit(t *testing.T) {
	b := &judgeBackend{answer: answering(nil)}
	c := judged(t, "outbound: {judge_chunk_chars: 500, judge_max_chunks: 1, categories: {private_key: {action: warn}}}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5})
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("MIIEowIBAAKCAQEAuQ3zZ9kq2Lm8Np4Rs7Tv1Wy5Za3Bc6Df0GhJkLmNoPq\n", 35) + "-----END RSA PRIVATE KEY-----\n"
	text := key + key + strings.Repeat("ordinary log line number ten\n", 10) + "ZZMARKERZZ beyond the limit\n" + strings.Repeat("y", 2000)
	evaluate(t, c, prompt(text))
	if len(b.states) != 1 {
		t.Fatalf("%d calls", len(b.states))
	}
	// 第 500 个字符落在第一段私钥里：那一行之后的原文（第二段私钥、日志行）都不该发
	if sent := b.states[0]["text"].(string); strings.Contains(sent, "ordinary log line") || strings.Contains(sent, "ZZMARKERZZ") {
		t.Errorf("sent text goes past the limit: %q", sent)
	}
}

// TestHintOrderWithJudgeHits：本地命中与模型命中同时出现时，模型的前进路径在前（Engine 只取第一条 hint）。
func TestHintOrderWithJudgeHits(t *testing.T) {
	falcon := map[string]string{"f.yaml": "schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\nmatch: {regex: ['Project Falcon']}\n"}
	b := &judgeBackend{answer: answering(map[string]float64{"outbound.credentials": 0.9})}
	c := judged(t, "outbound: {categories: {acme: {action: warn}}}\n", falcon, outbound.Judge{Backend: b, Threshold: 0.5})
	v, _ := evaluate(t, c, prompt(longText+"Project Falcon\n"))
	var hints []string
	for _, r := range v.Reasons {
		if strings.HasPrefix(r.Code, "hint.") {
			hints = append(hints, r.Code)
		}
	}
	if !reflect.DeepEqual(hints, []string{i18n.KeyHintOutboundJudge, i18n.KeyHintOutbound}) {
		t.Errorf("hints = %v", hints)
	}
}

// TestJudgeChunks：长文本按行切块，每块不超过 judge_chunk_chars 个字符，至多 judge_max_chunks 块，多出的部分只由本地层
// 覆盖并带 judge_truncated；类别的概率取各块的最大值。
func TestJudgeChunks(t *testing.T) {
	line := strings.Repeat("x", 99) + "\n" // 100 个字符一行
	text := strings.Repeat(line, 30)       // 3000 个字符
	b := &judgeBackend{}
	b.answer = func(state map[string]any, qs []judge.Question) (judge.Response, error) {
		p := map[string]float64{}
		if state["chunk"] == "2/2" {
			p["outbound.credentials"] = 0.8
		}
		return answering(p)(state, qs)
	}
	c := judged(t, "outbound: {judge_chunk_chars: 1000, judge_max_chunks: 2}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5})
	v, _ := evaluate(t, c, prompt(text))
	if len(b.states) != 2 || v.Decision != guard.DecisionWarn || !slices.Contains(v.Fallbacks, outbound.FallbackJudgeTruncated) || v.Signals["judge_chunks"] != 2 {
		t.Fatalf("states %d, verdict %+v", len(b.states), v)
	}
	for _, s := range b.states {
		if n := utf8.RuneCountInString(s["text"].(string)); n > 1000 || n < 900 {
			t.Errorf("chunk of %d chars", n)
		}
	}
	// 一行比一块还长：按字符切开
	b = &judgeBackend{answer: answering(nil)}
	c = judged(t, "outbound: {judge_chunk_chars: 1000, judge_max_chunks: 4}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5})
	if v, _ := evaluate(t, c, prompt(strings.Repeat("长", 2500))); len(b.states) != 3 || slices.Contains(v.Fallbacks, outbound.FallbackJudgeTruncated) {
		t.Errorf("long line: %d chunks, %+v", len(b.states), v)
	}
}

// TestJudgeFailures：模型不可用、超时、答案无效、同意缺失或本地扫描不完整时只用本地结论，带对应的原因码；
// 都不会产生放行之外的变宽。
func TestJudgeFailures(t *testing.T) {
	warn := "outbound: {categories: {acme: {action: warn}}}\n"
	falcon := map[string]string{"f.yaml": "schema: 1\nid: acme.codename\ncategory: acme\non: [prompt]\nmatch: {regex: ['Project Falcon']}\n"}
	text := longText + "Project Falcon\n"
	for name, c := range map[string]struct {
		j        outbound.Judge
		ctx      context.Context
		fallback string
	}{
		"unavailable": {outbound.Judge{Threshold: 0.5, Backend: &judgeBackend{answer: func(map[string]any, []judge.Question) (judge.Response, error) {
			return judge.Response{}, errors.New("down")
		}}}, context.Background(), outbound.FallbackJudgeUnavailable},
		"timeout": {outbound.Judge{Threshold: 0.5, Backend: &judgeBackend{answer: func(map[string]any, []judge.Question) (judge.Response, error) {
			return judge.Response{}, &judge.Error{Kind: judge.Timeout}
		}}}, context.Background(), outbound.FallbackJudgeTimeout},
		"invalid": {outbound.Judge{Threshold: 0.5, Backend: &judgeBackend{answer: func(map[string]any, []judge.Question) (judge.Response, error) {
			return judge.Response{Answers: map[string]judge.Answer{"outbound.credentials": {P: judge.Prob(2)}}}, nil
		}}}, context.Background(), outbound.FallbackAnswerInvalid},
		"consent":    {outbound.Judge{Unavailable: outbound.FallbackConsentMissing}, context.Background(), outbound.FallbackConsentMissing},
		"no backend": {outbound.Judge{Threshold: 0.5}, context.Background(), outbound.FallbackJudgeUnavailable},
		"incomplete scan": {outbound.Judge{Threshold: 0.5, Backend: &judgeBackend{answer: answering(map[string]float64{"outbound.credentials": 1})}},
			&cancelCtx{faultCtx: &faultCtx{Context: context.Background(), n: -1, at: func() {}}, from: 3}, outbound.FallbackBudget}, // 第一处匹配之后取消
	} {
		ch := judged(t, warn, falcon, c.j)
		v, err := ch.Evaluate(c.ctx, prompt(text), func(guard.Verdict) {})
		if err != nil || v.Decision != guard.DecisionWarn || !slices.Contains(v.Fallbacks, c.fallback) || len(v.Findings) != 1 || v.Findings[0].Source != guard.FindingLocal {
			t.Errorf("%s: %+v %v", name, v, err)
		}
	}
}

// TestJudgeCategories：PII 题只在 PII 类别开启且同意含 pii 范围时问；自定义类别写了题目才问，类别停用不问。
func TestJudgeCategories(t *testing.T) {
	cfg := "outbound: {categories: {pii: {enabled: true}, acme: {question: {question: 'Does `text` mention Project Falcon?'}}, off: {enabled: false, question: {question: 'Off?'}}}}\n"
	for pii, want := range map[bool][]string{
		false: {"outbound.acme", "outbound.credentials", "outbound.private_key"},
		true:  {"outbound.acme", "outbound.credentials", "outbound.pii", "outbound.private_key"},
	} {
		b := &judgeBackend{answer: answering(map[string]float64{"outbound.acme": 0.7})}
		v, _ := evaluate(t, judged(t, cfg, nil, outbound.Judge{Backend: b, Threshold: 0.5, PII: pii}), prompt(longText))
		got := slices.Clone(b.asked[0])
		slices.Sort(got)
		if !reflect.DeepEqual(got, want) || v.Decision != guard.DecisionWarn || v.Findings[0].Category != "acme" {
			t.Errorf("pii=%v: asked %v, %+v", pii, got, v)
		}
	}
}

// TestJudgeMasksDevText：本地对开发文本的写法不拦（所以照常送模型），发送前的遮蔽不做这些排除：数量位置上的手机号、
// 版本词后面的公网 IP、本地部分为 git 的邮箱都换成占位符。
func TestJudgeMasksDevText(t *testing.T) {
	b := &judgeBackend{answer: answering(nil)}
	c := judged(t, "outbound: {categories: {pii: {enabled: true}}}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5, PII: true})
	text := longText + "memory: 13800138000, build 8.8.4.4, ssh -T git@github.com\n"
	v, _ := evaluate(t, c, prompt(text))
	if len(b.states) != 1 {
		t.Fatalf("states %d, %+v", len(b.states), v)
	}
	sent := b.states[0]["text"].(string)
	for _, absent := range []string{"13800138000", "8.8.4.4", "git@github.com"} {
		if strings.Contains(sent, absent) {
			t.Errorf("sent %q", sent)
		}
	}
	for _, present := range []string{"[pii:pii.phone_cn]", "[pii:pii.ip]", "[pii:pii.email]"} {
		if !strings.Contains(sent, present) {
			t.Errorf("sent lacks %q: %q", present, sent)
		}
	}
}

// TestJudgeMasksEmailBeforeColon：邮箱后面紧跟冒号与空白时是普通的联系邮箱：PII 类别关闭时遮蔽后送模型，
// 开启时本地按 pii.email 拦下、不调用模型。
func TestJudgeMasksEmailBeforeColon(t *testing.T) {
	text := longText + "Contact alice.wang@acme-corp.cn: call later\n"
	b := &judgeBackend{answer: answering(nil)}
	evaluate(t, judged(t, "", nil, outbound.Judge{Backend: b, Threshold: 0.5}), prompt(text))
	if len(b.states) != 1 {
		t.Fatalf("pii off: states %d", len(b.states))
	}
	if sent := b.states[0]["text"].(string); strings.Contains(sent, "alice.wang@acme-corp.cn") || !strings.Contains(sent, "[pii:pii.email]") {
		t.Errorf("pii off: sent %q", sent)
	}
	b = &judgeBackend{answer: answering(nil)}
	v, _ := evaluate(t, judged(t, "outbound: {categories: {pii: {enabled: true}}}\n", nil, outbound.Judge{Backend: b, Threshold: 0.5, PII: true}), prompt(text))
	if len(b.states) != 0 || v.Decision != guard.DecisionDeny || len(v.Findings) != 1 || v.Findings[0].Rule != "pii.email" {
		t.Errorf("pii on: states %d, %+v", len(b.states), v)
	}
}

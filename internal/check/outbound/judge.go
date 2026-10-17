package outbound

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/cyberchen1995/h-guard/pkg/detect/pii"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// 判断层的降级原因码（与 action 检查同名同义）。
const (
	FallbackJudgeUnavailable = "judge_unavailable"
	FallbackJudgeTimeout     = "judge_timeout"
	FallbackConsentMissing   = "judge_consent_missing"
	FallbackAnswerInvalid    = "judge_answer_invalid"
	FallbackKindUnsupported  = "judge_kind_unsupported"
	FallbackJudgeTruncated   = "judge_truncated" // 文本超过 judge_max_chunks 块，多出的部分只由本地层覆盖
)

// Judge 描述判断层在这次调用中能否使用。
type Judge struct {
	Backend     judge.Backend // 可调用的后端
	Unavailable string        // 模型已开启但不能调用的原因码（如 judge_consent_missing）；非空时不调用
	Threshold   float64       // 类别题的门槛：概率不低于它时算命中（校准档案的 thresholds.outbound）
	PII         bool          // 同意含 pii 范围：可以问 PII 类别题
	// Skip 为真时这一次不调用：模型的命中只提示，harness 在这类事件上显示不了提示时（Codex 的提示词与工具输出）发出去
	// 也送不到用户面前，白白外发、多等。
	Skip bool
}

// judgeHit 是判断层报告的一个类别。
type judgeHit struct {
	category, question string
	p                  float64
}

// judgeResult 是一次判断层调用的结果。
type judgeResult struct {
	state    string // off（没有调用）、failed、answered；模型关闭时为空
	hits     []judgeHit
	fallback []string
	chunks   int
}

// askJudge 在本地层之后补报本地规则覆盖不到的内容：模型开启、本地没有得出 deny、文本不短于
// judge_min_chars、至少有一个启用的类别有题时，把遮蔽了本地命中的文本按块发给模型，问各类别题；类别的概率取各块的
// 最大值，不低于门槛即算命中。模型只能补报，不能否决本地命中（泄露不可逆）。不可用、超时、答案无效、同意缺失或本地
// 扫描不完整时只用本地结论，带原因码。
func (c *Check) askJudge(ctx context.Context, ev guard.Event, local guard.Decision, scan Scan) judgeResult {
	if !c.Config.Judge.Enabled || !c.Config.OutboundJudge() || c.Judge.Skip {
		return judgeResult{}
	}
	qs := c.judgeQuestions()
	if local == guard.DecisionDeny || utf8.RuneCountInString(ev.Text) < c.Config.Outbound.JudgeMinChars || len(qs) == 0 {
		return judgeResult{state: "off"}
	}
	failed := func(code string) judgeResult { return judgeResult{state: "failed", fallback: []string{code}} }
	switch {
	case c.Judge.Unavailable != "":
		return failed(c.Judge.Unavailable)
	case c.Judge.Backend == nil:
		return failed(FallbackJudgeUnavailable)
	case !c.Judge.Backend.Caps().Supports(judge.KindProbability):
		return failed(FallbackKindUnsupported)
	case !scan.Complete:
		// 用户正则认出的区间不全，遮蔽不了：不能把文本发出去
		return failed(FallbackBudget)
	}
	if ctx.Err() != nil {
		return failed(FallbackBudget)
	}
	text, sendEnd, cut := sendable(ev.Text, c.Config.Outbound.JudgeMaxChunks*c.Config.Outbound.JudgeChunkChars)
	prefix := clip(scan, len(text))
	if cut {
		// 跨过切点的私钥正文：END 行在前缀之外，前缀里只剩 base64 行，在前缀上认不出（类别停用时检测器也没跑）
		if l, ok := keyTailAcross(ev.Text, len(text)); ok {
			prefix.Builtin = append(prefix.Builtin, secrets.Hit{Rule: secrets.RulePrivateKey, Start: l[0], End: l[1]})
		}
	}
	parts, truncated := chunk(maskForJudge(text, prefix, sendEnd), c.Config.Outbound.JudgeChunkChars, c.Config.Outbound.JudgeMaxChunks)
	res := judgeResult{state: "answered", chunks: len(parts)}
	if truncated || cut {
		res.fallback = append(res.fallback, FallbackJudgeTruncated)
	}
	best := map[string]float64{}
	invalid := false
	for i, part := range parts {
		state := map[string]any{"text": part, "source": string(ev.Kind), "chunk": fmt.Sprintf("%d/%d", i+1, len(parts))}
		if ev.Kind == guard.EventToolOutput {
			state["tool"] = secrets.Redact(ev.Tool)
		}
		resp, err := judge.AskAll(ctx, c.Judge.Backend, state, qs)
		if err != nil {
			// 已经答完的块照样算：补报只会让结论更严
			res.state = "failed"
			code := FallbackJudgeUnavailable
			if judge.KindOf(err) == judge.Timeout {
				code = FallbackJudgeTimeout
			}
			res.fallback = append(res.fallback, code)
			break
		}
		answers := judge.Validate(qs, resp)
		for _, q := range qs {
			a, ok := answers[q.ID]
			if !ok {
				invalid = true
				continue
			}
			if p, seen := best[q.ID]; !seen || *a.P > p {
				best[q.ID] = *a.P
			}
		}
	}
	if invalid {
		res.fallback = append(res.fallback, FallbackAnswerInvalid)
	}
	for _, q := range qs {
		if p, ok := best[q.ID]; ok && p >= c.Judge.Threshold {
			res.hits = append(res.hits, judgeHit{category: strings.TrimPrefix(q.ID, QuestionPrefix), question: q.ID, p: p})
		}
	}
	return res
}

// sendMargin 是会发出去的前缀之后多留的字节：跨过切点的形状（被切开的赋值、私钥块的开头）在前缀里照样能认出、遮蔽。
const sendMargin = 4096

// sendable 返回 text 中用来遮蔽的前缀与会发出去的终点 sendEnd：发出去的只到前 limit 个字符所在行的行尾（遮蔽缩短了
// 文本时也不越过它）；前缀再多留 sendMargin 字节，跨过 sendEnd 的形状在前缀里照样能认出。cut 报告
// sendEnd 之后还有内容。遮蔽只对前缀做：大段工具输出不必对全文做遮蔽（对全文遮蔽时，16 MiB 输入多出约 8 秒）。
func sendable(text string, limit int) (prefix string, sendEnd int, cut bool) {
	n := 0
	end := len(text)
	for i := range text {
		if n == limit {
			end = i
			break
		}
		n++
	}
	if end == len(text) {
		return text, len(text), false
	}
	if nl := strings.IndexByte(text[end:], '\n'); nl >= 0 {
		end += nl + 1
	} else {
		end = len(text)
	}
	sendEnd = end
	end = min(len(text), end+sendMargin)
	for end < len(text) && !utf8.RuneStart(text[end]) {
		end++
	}
	return text[:end], sendEnd, sendEnd < len(text)
}

// clip 只留下 scan 中落在前 n 个字节里的区间（跨过 n 的截到 n）。
func clip(scan Scan, n int) Scan {
	keep := func(spans [][2]int) [][2]int {
		var out [][2]int
		for _, s := range spans {
			if s[0] < n {
				out = append(out, [2]int{s[0], min(s[1], n)})
			}
		}
		return out
	}
	var builtin []secrets.Hit
	for _, h := range scan.Builtin {
		if h.Start < n {
			builtin = append(builtin, secrets.Hit{Rule: h.Rule, Start: h.Start, End: min(h.End, n)})
		}
	}
	return Scan{Secret: keep(scan.Secret), Other: keep(scan.Other), Builtin: builtin, Complete: scan.Complete}
}

// keyTailAcross 找跨过切点 cut 的私钥正文：从 cut 所在那一行的行首往后找第一行 -----END … PRIVATE KEY-----，它前面连着的
// base64 行（每行至少 16 个字符，可以缩进）从 cut 之前开始时，返回 [起点, cut)。从行首找，END 标记本身跨过切点时也找得到。
// 只看第一行 END：正文是连续的，跨过切点的那一段一定在它前面。只用 strings 查找，大段输出上
// 也很快。
func keyTailAcross(text string, cut int) ([2]int, bool) {
	from := strings.LastIndexByte(text[:cut], '\n') + 1
	i := strings.Index(text[from:], "-----END ")
	if i < 0 {
		return [2]int{}, false
	}
	end := from + i
	line := text[end:]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	if !strings.Contains(line, "PRIVATE KEY-----") {
		return [2]int{}, false
	}
	start := strings.LastIndexByte(text[:end], '\n') + 1 // END 行的行首
	if strings.TrimSpace(text[start:end]) != "" {
		return [2]int{}, false
	}
	for minLen := 2; start > 0; minLen = 16 { // END 前最后一行正文可以很短（AB3x==）
		prev := strings.LastIndexByte(text[:start-1], '\n') + 1
		if !base64Line(text[prev:start-1], minLen) {
			break
		}
		start = prev
	}
	if start >= cut {
		return [2]int{}, false
	}
	return [2]int{start, cut}, true
}

// base64Line 报告一行（去掉首尾空白）是至少 minLen 个字符的 base64。
func base64Line(line string, minLen int) bool {
	line = strings.TrimSpace(line)
	if len(line) < minLen {
		return false
	}
	for i := 0; i < len(line); i++ {
		if c := line[i]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '=') {
			return false
		}
	}
	return true
}

// judgeQuestions 返回这次要问的类别题：启用、有题的类别，内置类别在前（credentials、private_key、pii），
// 自定义类别按名字排序；PII 题只在同意含 pii 范围时问。
func (c *Check) judgeQuestions() []judge.Question {
	names := []string{"credentials", "private_key", "pii"}
	for _, name := range slices.Sorted(maps.Keys(c.Config.Outbound.Categories)) {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	var qs []judge.Question
	for _, name := range names {
		if !c.Config.Category(name).Enabled || name == "pii" && !c.Judge.PII {
			continue
		}
		if q, ok := c.Question(name); ok {
			qs = append(qs, q)
		}
	}
	return qs
}

// maskForJudge 遮蔽本地能识别的全部内容（发送前遮蔽所有本地命中）：凭据形状（宽的，含停用的高熵规则）、
// PII（不论 PII 类别是否开启，也不做开发文本写法的排除）、用户正则认出的区间。占位符只写规则名或类别，不写长度与形状：模型不需要它们。
// 重叠的区间合并，标签取先开始的那个；占位符之后补上原值里的换行，切块按行进行。只输出到 upto（会发出去的终点），跨过
// upto 的区间整段换成占位符。
func maskForJudge(text string, scan Scan, upto int) string {
	type span struct {
		start, end int
		label      string
	}
	var spans []span
	for _, h := range secrets.Find(text) {
		spans = append(spans, span{h.Start, h.End, "[secret:" + h.Rule + "]"})
	}
	for _, h := range scan.Builtin { // 全文上的内置检测结果（截到前缀）
		kind := "secret"
		if strings.HasPrefix(h.Rule, "pii.") {
			kind = "pii"
		}
		spans = append(spans, span{h.Start, h.End, "[" + kind + ":" + h.Rule + "]"})
	}
	for _, h := range pii.FindForMask(text) {
		spans = append(spans, span{h.Start, h.End, "[pii:" + h.Rule + "]"})
	}
	for _, l := range scan.Secret {
		spans = append(spans, span{l[0], l[1], "[secret:" + secrets.RuleCustom + "]"})
	}
	for _, l := range scan.Other {
		spans = append(spans, span{l[0], l[1], "[masked]"})
	}
	if len(spans) == 0 {
		return text[:upto]
	}
	slices.SortStableFunc(spans, func(a, b span) int { return a.start - b.start })
	merged := spans[:1]
	for _, s := range spans[1:] {
		if last := &merged[len(merged)-1]; s.start < last.end {
			last.end = max(last.end, s.end)
		} else {
			merged = append(merged, s)
		}
	}
	var b strings.Builder
	last := 0
	for _, s := range merged {
		if s.start >= upto {
			break
		}
		b.WriteString(text[last:s.start])
		b.WriteString(s.label)
		b.WriteString(strings.Repeat("\n", strings.Count(text[s.start:min(s.end, upto)], "\n")))
		last = s.end
	}
	if last < upto {
		b.WriteString(text[last:upto])
	}
	return b.String()
}

// chunk 把 text 按行切成每块不超过 size 个字符的块，至多 limit 块；一行比一块还长时按字符切开。还有没放进去的内容时
// truncated 为真。
func chunk(text string, size, limit int) (parts []string, truncated bool) {
	var cur strings.Builder
	n := 0
	flush := func() bool {
		if n == 0 {
			return true
		}
		if len(parts) == limit {
			return false
		}
		parts = append(parts, cur.String())
		cur.Reset()
		n = 0
		return true
	}
	for line := range strings.SplitAfterSeq(text, "\n") {
		for line != "" {
			r := utf8.RuneCountInString(line)
			if n+r <= size {
				cur.WriteString(line)
				n += r
				break
			}
			if n > 0 {
				if !flush() {
					return parts, true
				}
				continue
			}
			// 一行比一块还长：取前 size 个字符
			cut, k := len(line), 0
			for i := range line {
				if k == size {
					cut = i
					break
				}
				k++
			}
			cur.WriteString(line[:cut])
			n = size
			line = line[cut:]
		}
	}
	if !flush() {
		return parts, true
	}
	return parts, false
}

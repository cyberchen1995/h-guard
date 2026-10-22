package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"

	"github.com/cyberchen1995/h-guard/pkg/detect/pii"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/dlclark/regexp2"
	"go.yaml.in/yaml/v3"
)

// OutboundRule 是一条 outbound 规则：扫描提示词与工具输出，命中归到它的类别。动作、忽略列表与发给
// 模型的题目都在类别的配置里（outbound.categories），规则只管本地检测：内置的凭据、私钥、PII 形状引用检测器
// （match.detector），用户的规则写正则（match.regex，regexp2，不区分大小写，每次匹配有超时）。
//
// 与 action 规则共用 id 与配置里的开关（rules.<id>.enabled）；同 id 是配置错误。没有锁定、没有题目、没有影响范围。
type OutboundRule struct {
	Schema     int               `yaml:"schema"`
	ID         string            `yaml:"id"`
	EnabledRaw *bool             `yaml:"enabled"`
	Category   string            `yaml:"category"`
	On         []guard.EventKind `yaml:"on"`
	Match      OutboundMatch     `yaml:"match"`
	Examples   OutboundExamples  `yaml:"examples"`

	Builtin bool   `yaml:"-"`
	Origin  string `yaml:"-"`
	enabled bool
	regex   []*regexp2.Regexp
}

// OutboundMatch 是 outbound 规则的本地检测：正则或内置检测器，二选一。
type OutboundMatch struct {
	Regex    []string `yaml:"regex"`
	Detector string   `yaml:"detector"`
}

// OutboundExamples 是 outbound 规则的样例文本：hit 必须命中，miss 必须不命中。
type OutboundExamples struct {
	Hit  []string `yaml:"hit"`
	Miss []string `yaml:"miss"`
}

// Detectors 返回 match.detector 可用的检测器 id：pkg/detect/secrets 的凭据与私钥形状、pkg/detect/pii 的个人信息。
func Detectors() []string {
	return append([]string{secrets.RulePrefixedToken, secrets.RuleBearer, secrets.RuleAssignment, secrets.RuleAWSAccessKey,
		secrets.RuleURLPassword, secrets.RuleHighEntropy, secrets.RulePrivateKey}, pii.Rules()...)
}

// Enabled 报告规则在配置覆盖之后是否启用（类别的开关另算）。
func (r *OutboundRule) Enabled() bool { return r.enabled }

// AppliesTo 报告规则是否扫描该类事件。
func (r *OutboundRule) AppliesTo(kind guard.EventKind) bool { return slices.Contains(r.On, kind) }

// Find 返回规则在 text 中的命中区间（字节，按起点排序）。正则规则每次匹配有 MatchTimeout，超时的正则跳过、
// timedOut 为真（outbound 规则超时按未命中处理）；ctx 结束时返回它的错误，连同已经找到的命中（不完整）。检测器规则单独查时只用
// 这一条；同一段文本里几条检测器一起查用 FindDetectors（重叠时只报最具体的一条）。
func (r *OutboundRule) Find(ctx context.Context, text string) (locs [][2]int, timedOut bool, err error) {
	if r.Match.Detector != "" {
		return FindDetectors(text, []string{r.Match.Detector})[r.Match.Detector], false, nil
	}
	for _, re := range r.regex {
		cur := runeCursor{text: text} // regexp2 按字符计位置；同一个正则的命中位置递增，边走边换算成字节偏移
		if err := ctx.Err(); err != nil {
			return locs, timedOut, err
		}
		m, err := re.FindStringMatch(text)
		for ; m != nil && err == nil; m, err = re.FindNextMatch(m) {
			if m.Length == 0 {
				continue
			}
			start := cur.at(m.Index)
			locs = append(locs, [2]int{start, cur.at(m.Index + m.Length)})
			if cerr := ctx.Err(); cerr != nil {
				// 没扫完：已找到的命中照样返回（可以收紧结论），同时报告取消，调用方不能当成完整结果
				slices.SortFunc(locs, func(a, b [2]int) int { return a[0] - b[0] })
				return locs, timedOut, cerr
			}
		}
		if err != nil {
			timedOut = true
		}
	}
	slices.SortFunc(locs, func(a, b [2]int) int { return a[0] - b[0] })
	return locs, timedOut, nil
}

// runeCursor 把字符位置换成字节偏移：从上一次的位置往后走，位置递增时整体是线性的，也不像预先
// 建表那样按字节分配内存（16 MiB 的输入要约 128 MB）。位置回退时从头再走。无效的 UTF-8 字节各算
// 一个字符，与 regexp2（[]rune 转换）一致。
type runeCursor struct {
	text       string
	rune, byte int
}

func (c *runeCursor) at(r int) int {
	if r < c.rune {
		c.rune, c.byte = 0, 0
	}
	for c.rune < r && c.byte < len(c.text) {
		_, size := utf8.DecodeRuneInString(c.text[c.byte:])
		c.byte += size
		c.rune++
	}
	return c.byte
}

// FindDetectors 用 ids 里的检测器扫描 text，返回各检测器的命中区间。凭据与私钥一起查（只在这些规则之间合并区间、
// 标签取最具体的，见 secrets.FindRules；值还要通过 secrets.Confirmed），个人信息一起查（重叠时只报最具体的，
// 见 pii.Find），所以同一片段只归到一条规则。
func FindDetectors(text string, ids []string) map[string][][2]int {
	out := map[string][][2]int{}
	var piiIDs []string
	for _, id := range ids {
		if slices.Contains(pii.Rules(), id) {
			piiIDs = append(piiIDs, id)
		}
	}
	var credIDs []string
	for _, id := range ids {
		if !slices.Contains(pii.Rules(), id) {
			credIDs = append(credIDs, id)
		}
	}
	if len(credIDs) > 0 {
		// 只用启用的规则合并（停用一条不会吞掉其他规则的命中），再确认值像真的凭据：遮蔽用宽的形状，拦截不能拦下
		// 占位符、代码表达式与单词（维护者决定 2026-10-16）
		for _, h := range secrets.FindRules(text, credIDs...) {
			if secrets.Confirmed(h.Rule, text[h.Start:h.End]) {
				out[h.Rule] = append(out[h.Rule], [2]int{h.Start, h.End})
			}
		}
	}
	if len(piiIDs) > 0 {
		for _, h := range pii.Find(text, piiIDs...) {
			out[h.Rule] = append(out[h.Rule], [2]int{h.Start, h.End})
		}
	}
	return out
}

// isOutbound 报告规则文件写的是不是 outbound 规则（有 category 字段）。
func isOutbound(data []byte) bool {
	var head struct {
		Category *string `yaml:"category"`
	}
	return yaml.Unmarshal(data, &head) == nil && head.Category != nil
}

// parseOutbound 严格解析一条 outbound 规则（只接受一个 YAML 文档）并编译正则。
func parseOutbound(data []byte, origin string, builtin bool) (*OutboundRule, error) {
	// 先按带 action 字段规则的写法检查一遍：outbound 规则写了 action、question、locked 时给出明确的错误，
	// 而不是「未知字段」
	var misplaced struct {
		Action   *yaml.Node `yaml:"action"`
		Question *yaml.Node `yaml:"question"`
		Locked   *yaml.Node `yaml:"locked"`
	}
	_ = yaml.Unmarshal(data, &misplaced)
	r := &OutboundRule{}
	fail := func(path string, err error) (*OutboundRule, error) {
		return nil, &Error{File: origin, Rule: r.ID, Path: path, Err: err}
	}
	switch {
	case misplaced.Action != nil:
		_ = yaml.Unmarshal(data, r)
		return fail("action", errors.New("outbound actions are set on the category (outbound.categories.<name>.action)"))
	case misplaced.Question != nil:
		_ = yaml.Unmarshal(data, r)
		return fail("question", errors.New("outbound questions are set on the category (outbound.categories.<name>.question)"))
	case misplaced.Locked != nil:
		_ = yaml.Unmarshal(data, r)
		return fail("locked", errors.New("outbound rules cannot be locked"))
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(r); err != nil && !errors.Is(err, io.EOF) {
		path := "yaml"
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			path = "line " + m[1]
		}
		return fail(path, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return fail("document", errors.New("multiple YAML documents are not supported"))
	}
	r.Builtin, r.Origin = builtin, origin
	r.enabled = r.EnabledRaw == nil || *r.EnabledRaw
	if err := r.validate(); err != nil {
		var re *Error
		if !errors.As(err, &re) {
			re = &Error{Err: err}
		}
		re.File, re.Rule = origin, r.ID
		return nil, re
	}
	return r, nil
}

func (r *OutboundRule) validate() error {
	switch {
	case r.Schema != SchemaVersion:
		return fieldErr("schema", "got %d, want %d", r.Schema, SchemaVersion)
	case !guard.ValidName(r.ID):
		return fieldErr("id", "invalid")
	case slices.Contains(ReservedIDs, r.ID):
		return fieldErr("id", "reserved for a signal question")
	case !guard.ValidName(r.Category):
		return fieldErr("category", "invalid (lowercase letters, digits, '.', '_' and '-')")
	case len(r.On) == 0:
		return fieldErr("on", "missing")
	}
	for _, k := range r.On {
		if k != guard.EventPrompt && k != guard.EventToolOutput {
			return fieldErr("on", "outbound rules scan prompt and tool_output")
		}
	}
	m := r.Match
	switch {
	case len(m.Regex) == 0 && m.Detector == "":
		return fieldErr("match", "missing (regex or detector)")
	case len(m.Regex) > 0 && m.Detector != "":
		return fieldErr("match", "regex and detector are mutually exclusive")
	case m.Detector != "" && !slices.Contains(Detectors(), m.Detector):
		return fieldErr("match.detector", "unknown detector")
	}
	for i, p := range m.Regex {
		re, err := regexp2.Compile(p, regexp2.IgnoreCase)
		if err != nil {
			// regexp2 的错误里带着整条正则；只留错误类型，原文不回显
			return fieldErr(fmt.Sprintf("match.regex[%d]", i), "%s", quotedSpan.ReplaceAllString(err.Error(), "…"))
		}
		re.MatchTimeout = currentMatchTimeout()
		r.regex = append(r.regex, re)
	}
	return nil
}

// InactiveCategory 表示 outbound 规则所属的类别停用了（类别与规则的 enabled 同时为真才启用）。
const InactiveCategory = "category_disabled"

// OutboundTierCovers 报告 outbound 档位是否扫描该类事件：提示词任何档位都扫；工具输出从第 2 档起
// （第 2 档只扫文件内容，第 3 档扫全部）。
func OutboundTierCovers(tier int, kind guard.EventKind) bool {
	switch kind {
	case guard.EventPrompt:
		return tier >= 1
	case guard.EventToolOutput:
		return tier >= 2
	}
	return false
}

// OutboundStateOf 计算 outbound 规则的状态：规则停用、类别停用、档位不覆盖它扫描的任何一类事件时不生效。
func OutboundStateOf(r *OutboundRule, tier int, categoryEnabled bool) State {
	st := State{Enabled: r.enabled && categoryEnabled}
	switch {
	case !r.enabled:
		st.Inactive = InactiveDisabled
	case !categoryEnabled:
		st.Inactive = InactiveCategory
	case !slices.ContainsFunc(r.On, func(k guard.EventKind) bool { return OutboundTierCovers(tier, k) }):
		st.Inactive = InactiveTier
	default:
		st.Effective = true
	}
	return st
}

// CheckExamples 运行样例：hit 必须命中，miss 必须不命中；超时算失败。
func (r *OutboundRule) CheckExamples(ctx context.Context) error {
	var errs []error
	for _, set := range []struct {
		want bool
		list []string
	}{{true, r.Examples.Hit}, {false, r.Examples.Miss}} {
		for _, text := range set.list {
			locs, timedOut, err := r.Find(ctx, text)
			switch {
			case err != nil:
				return err
			case timedOut:
				errs = append(errs, fmt.Errorf("rule %q: example %q timed out", r.ID, text))
			case (len(locs) > 0) != set.want:
				errs = append(errs, fmt.Errorf("rule %q: example %q: hit = %v, want %v", r.ID, text, len(locs) > 0, set.want))
			}
		}
	}
	return errors.Join(errs...)
}

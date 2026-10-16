// Package outbound 是 outbound 检查（spec §6）：扫描用户提示词与工具输出里的凭据、私钥、个人信息与用户自定义
// 类别的内容，动作只有 deny 与 warn（harness 在提示词与工具输出上不支持请求确认）。本包只有本地层：规则包里
// 每种形状一条规则（rules.OutboundRule），类别的配置管启用、动作与忽略列表（config.Category）；判断层随 M4b。
//
// 隐私性质（spec §6.3）：结论里的原因只有类别、命中数与行号，命中写明规则、类别与位置，都不含原文。
package outbound

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/pii"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// 降级原因码（spec §10.2）。
const (
	FallbackRegexTimeout = "regex_timeout"         // 用户正则超时，按未命中处理
	FallbackBudget       = "local_budget_exceeded" // 截止时间到了，没扫完的规则不算
)

// Check 是 outbound 检查。Rules 已按配置覆盖了开关；Config 给出档位与类别。
type Check struct {
	Rules  *rules.Set
	Config *config.Config
	// Scanned 不为 nil 时，Evaluate 扫完之后用这次的 Scan 调用它（hook 的决策日志用它遮蔽摘录）。
	Scanned func(Scan)
}

// Name 返回 Check 的名字。
func (c *Check) Name() string { return "outbound" }

// Applies 按档位决定扫描范围（spec §4）：第 1 档扫用户提示词；第 2 档加上文件内容的工具输出（读文件的工具与
// 命令，guard.Event.FileContent）；第 3 档扫全部工具输出。
func (c *Check) Applies(ev guard.Event) bool {
	tier := c.Config.Outbound.Tier
	switch ev.Kind {
	case guard.EventPrompt:
		return tier >= 1
	case guard.EventToolOutput:
		return tier >= 3 || tier >= 2 && ev.FileContent
	}
	return false
}

// hit 是一条规则在文本里的命中。
type hit struct {
	rule, category string
	locs           [][2]int
}

// Evaluate 扫描 ev.Text。检测器规则（凭据、私钥、PII）一起查，同一片段只归到最具体的一条；用户正则逐条查，超时的
// 按未命中处理；截止时间到了还没查完的规则跳过（已查到的照样算）。命中值在类别的 ignore 里时不算。结论取命中类别
// 中最严的动作；本地得出的 deny 立即提交（不会被后续任何结果撤销，spec §3.3）：检测器或某条用户正则第一次得出
// deny 时，在开始下一条规则之前就提交，之后的规则慢、超时或 panic 都不会丢掉它（M4a 计划评审、Codex 评审 M4A-03）；
// 只提前提交这一次，之后的命中在最终结论里补全，不会每条规则都重新整理一遍。
func (c *Check) Evaluate(ctx context.Context, ev guard.Event, commit func(guard.Verdict)) (guard.Verdict, error) {
	var detectors, regexRules, maskOnly []*rules.OutboundRule
	for _, r := range c.Rules.Outbound() {
		switch {
		case !r.Enabled() || !r.AppliesTo(ev.Kind):
		case !c.Config.Category(r.Category).Enabled:
			if r.Match.Detector == "" && secretCategories[r.Category] {
				maskOnly = append(maskOnly, r) // 类别停用的凭据规则：不算命中，只为遮蔽
			}
		case r.Match.Detector != "":
			detectors = append(detectors, r)
		default:
			regexRules = append(regexRules, r)
		}
	}
	scan := Scan{Complete: true}
	record := func(r *rules.OutboundRule, locs [][2]int, timedOut bool, err error) {
		if timedOut || err != nil {
			scan.Complete = false
		}
		if secretCategories[r.Category] {
			scan.Secret = append(scan.Secret, locs...)
		} else {
			scan.Other = append(scan.Other, locs...)
		}
	}
	var v guard.Verdict
	var hits []hit
	if len(detectors) > 0 {
		ids := make([]string, len(detectors))
		for i, r := range detectors {
			ids[i] = r.Match.Detector
		}
		found := rules.FindDetectors(ev.Text, ids)
		for _, r := range detectors {
			if locs := c.keep(r, ev.Text, found[r.Match.Detector]); len(locs) > 0 {
				hits = append(hits, hit{r.ID, r.Category, locs})
			}
		}
	}
	committed := -1 // 提前提交时的命中条数；-1 表示还没有提交
	early := func(from int) {
		if committed >= 0 || !slices.ContainsFunc(hits[from:], func(h hit) bool { return c.Config.Category(h.category).Action == guard.DecisionDeny }) {
			return
		}
		var partial guard.Verdict
		c.render(&partial, ev.Text, slices.Clone(hits))
		commit(partial)
		committed = len(hits)
	}
	if len(regexRules) > 0 {
		early(0)
	}
	for i, r := range regexRules {
		if ctx.Err() != nil {
			v.Fallbacks = appendOnce(v.Fallbacks, FallbackBudget)
			break
		}
		locs, timedOut, err := r.Find(ctx, ev.Text)
		record(r, locs, timedOut, err)
		if timedOut {
			v.Fallbacks = appendOnce(v.Fallbacks, FallbackRegexTimeout)
		}
		if err != nil {
			v.Fallbacks = appendOnce(v.Fallbacks, FallbackBudget)
		}
		if locs = c.keep(r, ev.Text, locs); len(locs) > 0 {
			hits = append(hits, hit{r.ID, r.Category, locs})
			if i+1 < len(regexRules) {
				early(len(hits) - 1)
			}
		}
	}
	c.render(&v, ev.Text, hits)
	if v.Decision == guard.DecisionDeny && len(hits) != committed {
		commit(v)
	}
	for _, r := range maskOnly {
		if ctx.Err() != nil {
			break
		}
		locs, timedOut, err := r.Find(ctx, ev.Text)
		record(r, locs, timedOut, err)
	}
	if ctx.Err() != nil { // 有规则没扫（或没扫完）
		scan.Complete = false
	}
	if c.Scanned != nil {
		c.Scanned(scan)
	}
	return v, nil
}

// secretCategories 是值本身就是秘密的类别：决策日志里它们的命中一律遮蔽（spec §10.3 只遮蔽凭据值；私钥同理）。
// 其他类别（PII、用户自定义的代号等）按 spec §10.3 原样记录。
var secretCategories = map[string]bool{"credentials": true, "private_key": true}

// Scan 是一次 Evaluate 中用户正则认出的区间（字节偏移，按 ignore 过滤之前，不受命中位置上限限制），供决策日志与
// 判断层发送前遮蔽（M4b，取代 M4a 决策日志的重扫）。内置检测器的区间不在这里：遮蔽时由 secrets、pii 自己找。
type Scan struct {
	// Secret 是 credentials、private_key 类别的区间：决策日志里遮蔽。类别停用时这些规则也扫（只为遮蔽）。
	Secret [][2]int
	// Other 是其余类别的区间：只在发给模型前遮蔽。
	Other [][2]int
	// Complete 报告该扫的用户正则都扫完了：没有超时、出错，截止时间也没到。不完整时这些区间不能当作全部，调用方
	// 不能据此记录或发送正文（M4a Codex 第二轮 R2-01）。
	Complete bool
}

// keep 去掉类别 ignore 里的命中值（比较前去掉首尾空白；邮箱不区分大小写，spec §6.1）。
func (c *Check) keep(r *rules.OutboundRule, text string, locs [][2]int) [][2]int {
	ignore := c.Config.Category(r.Category).Ignore
	if len(ignore) == 0 {
		return locs
	}
	var out [][2]int
	for _, l := range locs {
		value := strings.TrimSpace(text[l[0]:l[1]])
		ignored := slices.ContainsFunc(ignore, func(v string) bool {
			v = strings.TrimSpace(v)
			if r.Match.Detector == pii.RuleEmail {
				return strings.EqualFold(v, value)
			}
			return v == value
		})
		if !ignored {
			out = append(out, l)
		}
	}
	return out
}

// render 写出结论：命中（规则、类别、位置）、按类别的原因（命中数与行号）与前进路径。
func (c *Check) render(v *guard.Verdict, text string, hits []hit) {
	if len(hits) == 0 {
		v.Decision = guard.DecisionPass
		return
	}
	slices.SortFunc(hits, func(a, b hit) int { return strings.Compare(a.rule, b.rule) })
	type tally struct {
		count int
		lines map[int]bool
	}
	newlines := newlineIndex(text)
	byCategory := map[string]*tally{}
	var categories []string
	v.Decision = guard.DecisionPass
	for _, h := range hits {
		f := guard.Finding{Rule: h.rule, Category: h.category, Source: guard.FindingLocal}
		t := byCategory[h.category]
		if t == nil {
			t = &tally{lines: map[int]bool{}}
			byCategory[h.category] = t
			categories = append(categories, h.category)
		}
		for _, l := range h.locs {
			line := lineOf(newlines, l[0])
			if len(f.Locations) < maxLocations {
				f.Locations = append(f.Locations, guard.Location{Line: line, Start: l[0], End: l[1]})
			}
			t.count++
			t.lines[line] = true
		}
		v.Findings = append(v.Findings, f)
		if guard.Stricter(v.Decision, c.Config.Category(h.category).Action) != v.Decision {
			v.Decision = c.Config.Category(h.category).Action
		}
	}
	slices.Sort(categories)
	for _, name := range categories {
		t := byCategory[name]
		params := map[string]string{"count": strconv.Itoa(t.count), "lines": joinLines(slices.Sorted(maps.Keys(t.lines)))}
		code := map[string]string{"credentials": i18n.KeyOutboundCredentials, "private_key": i18n.KeyOutboundPrivateKey, "pii": i18n.KeyOutboundPII}[name]
		if code == "" {
			code = i18n.KeyOutboundCustom
			params["category"] = name
		}
		v.Reasons = append(v.Reasons, guard.Reason{Code: code, Params: params})
	}
	v.Reasons = append(v.Reasons, guard.Reason{Code: i18n.KeyHintOutbound})
}

// maxLines 是原因里列出的行号上限，其余写作省略号。
const maxLines = 10

// maxLocations 是一条命中记下的位置上限：大段日志里可能有几十万处，结论与决策日志只需要前面一部分；命中数照常
// 全部计入（M4a 计划评审 I3）。
const maxLocations = 100

func joinLines(lines []int) string {
	parts := make([]string, 0, min(len(lines), maxLines)+1)
	for i, l := range lines {
		if i == maxLines {
			parts = append(parts, "…")
			break
		}
		parts = append(parts, strconv.Itoa(l))
	}
	return strings.Join(parts, ", ")
}

// newlineIndex 返回 text 中各换行符的字节偏移（升序）。命中多时逐个数换行是平方级的（M4a 计划评审）。
func newlineIndex(text string) []int {
	var idx []int
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			idx = append(idx, i)
		}
	}
	return idx
}

// lineOf 返回字节偏移 off 所在的行号（从 1 开始）；newlines 来自 newlineIndex。
func lineOf(newlines []int, off int) int {
	n, _ := slices.BinarySearch(newlines, off)
	return n + 1
}

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

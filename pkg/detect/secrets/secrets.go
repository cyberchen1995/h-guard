// Package secrets 识别文本中的凭据形状。它是 h-guard 中凭据检测的唯一来源（spec §6.2、§10.3）：
// 发给判断后端的内容、写入指令缓存的指令、决策日志都用它遮蔽凭据值。只认形状、不认语义——
// 认错了顶多少看几个字符，认漏了就是把 key 发出去。
//
// M1 覆盖带前缀的 token、Bearer、key=value 赋值（沿用 Python 版，另支持成对引号与 JSON 写法）、
// AWS access key、带密码的连接串与 PEM 私钥；高熵检测在 M4 随 outbound 加入。
package secrets

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// 规则 id，与规则包的 id 命名一致（spec §5.2）。
const (
	RulePrefixedToken = "credentials.prefixed_token"
	RuleBearer        = "credentials.bearer"
	RuleAssignment    = "credentials.assignment"
	RuleAWSAccessKey  = "credentials.aws_access_key"
	RuleURLPassword   = "credentials.url_password"
	RulePrivateKey    = "private_key.pem"
)

// Hit 是一处凭据值在文本中的字节区间 [Start, End)。只覆盖值本身，不含键名、引号或 Bearer 前缀。
type Hit struct {
	Rule       string
	Start, End int
}

type rule struct {
	id     string
	re     *regexp.Regexp
	groups []int // 值所在的捕获组，取第一个匹配到的；为空表示整个匹配
}

// assignmentValue 是赋值右侧的值：成对的双引号（允许转义）、成对的单引号，或不带引号的值
// （含只有开引号的写法）。键名后允许紧跟引号，覆盖 JSON 的 "api_key": "…"。
const assignmentValue = `(?:"((?:[^"\\\n]|\\.){6,})"|'([^'\n]{6,})'|["']?([^\s'"]{6,}))`

// rules 按具体程度排序：区间重叠时合并为并集，标签取靠前的规则。
var rules = []rule{
	{RulePrivateKey, regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`), nil},
	{RulePrefixedToken, regexp.MustCompile(`\b(?:sk|pk|ghp|gho|ghs|ghu|ghr|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b`), nil},
	{RuleAWSAccessKey, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), nil},
	{RuleURLPassword, regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@`), []int{1}},
	{RuleBearer, regexp.MustCompile(`\bBearer\s+([A-Za-z0-9._~+/-]{12,}=*)`), []int{1}},
	{RuleAssignment, regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|token|secret|password|passwd|pwd)["']?\s*[=:]\s*` + assignmentValue), []int{1, 2, 3}},
}

// placeholder 是本包生成的占位符（[redacted] 与 MaskForLog 的 [secret:…]）。规则名、charset 只认本包的取值，
// 其余字段只含数字与 shape 的字符（x 与白名单分隔符），占位符里放不下凭据。
var placeholder = regexp.MustCompile(`\[redacted\]|\[secret:(?:` + strings.Join([]string{
	regexp.QuoteMeta(RulePrefixedToken), regexp.QuoteMeta(RuleBearer), regexp.QuoteMeta(RuleAssignment),
	regexp.QuoteMeta(RuleAWSAccessKey), regexp.QuoteMeta(RuleURLPassword), regexp.QuoteMeta(RulePrivateKey),
}, "|") + `) len=\d+ charset=(?:digits|hex|alnum|base64url|base64|mixed)(?: shape=[x` +
	strings.ReplaceAll(regexp.QuoteMeta(shapeSeparators), "-", "") + `-]*)?\]`) // 字符类里 - 放在最后

// Find 返回 text 中全部凭据值的区间，按起点排序、互不重叠。不同规则的区间重叠或相接时合并为并集
// （只遮蔽较小的一段会让其余部分原样留下），标签取其中最具体的规则。
//
// 完全落在已有占位符里的命中不算，所以遮蔽过的文本再遮蔽一次，占位符本身不会被当作凭据。只排除
// 「完全落在里面」的：原文也可能含占位符的写法，与占位符部分重叠的命中照常遮蔽（连同重叠的占位符）。
// 占位符里有空格，会截断赋值等写法的值，所以另用一个把占位符换成等长 x 的视图再匹配一遍，两边的命中
// 取并集：紧挨在占位符前后、或被占位符夹在中间的原始凭据都不会因此漏掉（评审 R3-01）。
func Find(text string) []Hit {
	type span struct {
		Hit
		prio int
	}
	protected := placeholder.FindAllStringIndex(text, -1)
	views := []string{text}
	if len(protected) > 0 {
		b := []byte(text)
		for _, p := range protected {
			for i := p[0]; i < p[1]; i++ {
				b[i] = 'x' // 等长替换，命中区间在原文中仍然有效
			}
		}
		views = append(views, string(b))
	}
	// insidePlaceholders 报告 [start, end) 是否被占位符完全覆盖（可以跨几个相邻的占位符）。
	insidePlaceholders := func(start, end int) bool {
		for _, p := range protected {
			if p[0] <= start && start < p[1] {
				start = p[1]
			}
		}
		return start >= end
	}
	var all []span
	for _, view := range views {
		for prio, r := range rules {
			for _, m := range r.re.FindAllStringSubmatchIndex(view, -1) {
				start, end := m[0], m[1]
				if len(r.groups) > 0 {
					start = -1
					for _, g := range r.groups {
						if m[2*g] >= 0 {
							start, end = m[2*g], m[2*g+1]
							break
						}
					}
					if start < 0 {
						continue
					}
				}
				if insidePlaceholders(start, end) {
					continue
				}
				all = append(all, span{Hit{Rule: r.id, Start: start, End: end}, prio})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Start < all[j].Start })
	var out []Hit
	var cur span
	for i, s := range all {
		switch {
		case i == 0:
			cur = s
		case s.Start <= cur.End:
			cur.End = max(cur.End, s.End)
			if s.prio < cur.prio {
				cur.prio, cur.Rule = s.prio, s.Rule
			}
		default:
			out = append(out, cur.Hit)
			cur = s
		}
	}
	if len(all) > 0 {
		out = append(out, cur.Hit)
	}
	return out
}

// Redact 把凭据值换成 [redacted]，保留键名与 Bearer 前缀。用于发给判断后端的内容与指令缓存，
// 与 Python 版的写法一致（阈值在这种写法上校准）。
func Redact(text string) string {
	return replace(text, func(Hit, string) string { return "[redacted]" })
}

// MaskForLog 把凭据值换成描述形状的占位符（spec §10.3），例如
// [secret:credentials.assignment len=36 charset=hex shape=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]。
// len 为字符数；shape 只保留白名单中的分隔符，其余任何字符（含各种文字与符号）都换成 x。
// 值超过 64 个字符、或实际被换成 x 的字符不到一半时省略 shape（否则分隔符为主的值会被 shape 重放），
// shape 也绝不会等于原值。
func MaskForLog(text string) string {
	return replace(text, func(h Hit, value string) string {
		var b strings.Builder
		b.WriteString("[secret:")
		b.WriteString(h.Rule)
		b.WriteString(" len=")
		n := utf8.RuneCountInString(value)
		b.WriteString(strconv.Itoa(n))
		b.WriteString(" charset=")
		b.WriteString(charset(value))
		if sh, replaced := shape(value); n <= 64 && replaced*2 >= n && sh != value {
			b.WriteString(" shape=")
			b.WriteString(sh)
		}
		b.WriteString("]")
		return b.String()
	})
}

func replace(text string, with func(Hit, string) string) string {
	hits := Find(text)
	if len(hits) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, h := range hits {
		b.WriteString(text[last:h.Start])
		b.WriteString(with(h, text[h.Start:h.End]))
		last = h.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// charset 描述值用到的字符：digits、hex、alnum、base64url、base64 或 mixed（含非 ASCII 字符时一律为 mixed）。
// 只要没有 _ + / =，连字符就当作分隔符（如 UUID），不影响判断。
func charset(v string) string {
	alnum := strings.Map(func(r rune) rune {
		if r == '-' && !strings.ContainsAny(v, "_+/=") {
			return -1
		}
		return r
	}, v)
	all := func(pred func(rune) bool) bool {
		for _, r := range alnum {
			if !pred(r) {
				return false
			}
		}
		return true
	}
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	isHex := func(r rune) bool { return isDigit(r) || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') }
	isAlnum := func(r rune) bool { return isDigit(r) || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
	switch {
	case all(isDigit):
		return "digits"
	case all(isHex):
		return "hex"
	case all(isAlnum):
		return "alnum"
	case all(func(r rune) bool { return isAlnum(r) || r == '-' || r == '_' }):
		return "base64url"
	case all(func(r rune) bool { return isAlnum(r) || r == '+' || r == '/' || r == '=' }):
		return "base64"
	}
	return "mixed"
}

// shapeSeparators 是 shape 中原样保留的分隔符。
const shapeSeparators = "-_.:/+=@~"

// shape 把白名单分隔符以外的字符都换成 x，返回结果与实际替换的字符数（原来就是 x 的也算替换）。
func shape(v string) (string, int) {
	replaced := 0
	out := strings.Map(func(r rune) rune {
		if strings.ContainsRune(shapeSeparators, r) {
			return r
		}
		replaced++
		return 'x'
	}, v)
	return out, replaced
}

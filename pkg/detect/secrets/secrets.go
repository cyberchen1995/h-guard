// Package secrets 识别文本中的凭据形状。它是 h-guard 中凭据检测的唯一来源：
// 发给判断后端的内容、写入指令缓存的指令、决策日志都用它遮蔽凭据值。只认形状、不认语义——
// 认错了顶多少看几个字符，认漏了就是把 key 发出去。
//
// 识别带前缀的 token、Bearer、key=value 赋值（沿用 Python 版，另支持成对引号与 JSON 写法）、
// AWS access key、带密码的连接串与 PEM 私钥，以及关键词上下文里的高熵值（credentials.high_entropy）。
package secrets

import (
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 规则 id，与规则包的 id 命名一致。
const (
	RulePrefixedToken = "credentials.prefixed_token"
	RuleBearer        = "credentials.bearer"
	RuleAssignment    = "credentials.assignment"
	RuleAWSAccessKey  = "credentials.aws_access_key"
	RuleURLPassword   = "credentials.url_password"
	RulePrivateKey    = "private_key.pem"
	// RuleHighEntropy 是关键词（token、secret、password、api key……）之后不远处的高熵值（高熵检测只在
	// 赋值或关键词上下文中生效）。
	RuleHighEntropy = "credentials.high_entropy"
	// RuleCustom 是 MaskKeepLines 给调用方另外给出的区间用的标签（不是检测规则）。占位符只认固定的标签：
	// 让任意名字进占位符，伪造的占位符就能把真的凭据挡在遮蔽之外。
	RuleCustom = "custom"
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
	// check 不为空时，值还要通过它才算命中（正则找候选、代码里校验）
	check func(value string) bool
}

// assignmentValue 是赋值右侧的值：成对的双引号（允许转义）、成对的单引号，或不带引号的值
// （含只有开引号的写法）。键名后允许紧跟引号，覆盖 JSON 的 "api_key": "…"。
const assignmentValue = `(?:"((?:[^"\\\n]|\\.){6,})"|'([^'\n]{6,})'|["']?([^\s'"]{6,}))`

// rules 按具体程度排序：区间重叠时合并为并集，标签取靠前的规则。
var rules = []rule{
	{RulePrivateKey, regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`), nil, nil},
	// 被截断的私钥：head、带 limit 的读取或只粘贴了一部分时只有 BEGIN 行与之后的正文（可带
	// Proc-Type 这类头部行），或者只有正文与 END 行。正文行是整行至少 16 个 base64 字符，可以缩进（YAML 块）。
	{RulePrivateKey, regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:[ \t]*\r?\n[ \t]*(?:[A-Za-z0-9+/=]{16,}|[A-Za-z-]+: [^\n]*)[ \t]*)+`), nil, nil},
	// END 前最后一行正文可以很短（PEM 的最后一行长度不定，常是 AB3x== 这样几个字符）
	{RulePrivateKey, regexp.MustCompile(`(?m)(?:^[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*\r?\n)+(?:^[ \t]*[A-Za-z0-9+/=]{2,15}[ \t]*\r?\n)?[ \t]*-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----`), nil, nil},
	{RulePrefixedToken, regexp.MustCompile(`\b(?:sk|pk|ghp|gho|ghs|ghu|ghr|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b`), nil, nil},
	{RuleAWSAccessKey, regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), nil, nil},
	{RuleURLPassword, regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@`), []int{1}, nil},
	{RuleBearer, regexp.MustCompile(`\bBearer\s+([A-Za-z0-9._~+/-]{12,}=*)`), []int{1}, nil},
	{RuleAssignment, regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?key|secret[_-]?key|token|secret|password|passwd|pwd)["']?\s*[=:]\s*` + assignmentValue), []int{1, 2, 3}, nil},
	// 关键词之后至多 3 个词、经 is、was、:、=、->、=> 连接的一段值：至少 24 个字符，大小写数字都有、每字符熵 ≥ 4.0，
	// 不是由单词拼成的标识符或路径（OAuth2TokenService、src/…/HandlerV2 不算）
	{RuleHighEntropy, regexp.MustCompile(`(?i)\b(?:token|secret|password|passwd|pwd|api[_ -]?key|access[_ -]?key|credential|auth(?:orization)?)s?\b(?:[ \t]+[\w.-]+){0,3}?[ \t]*(?:\bis\b|\bwas\b|:|=|->|=>)[ \t]*["'` + "`" + `]?([A-Za-z0-9+/_=-]{24,})`),
		[]int{1}, randomValue},
}

// 关键词上下文里的高熵值：最短长度、每字符熵的下限，与「单词占比」的上限（超过即视为由单词拼成的标识符或路径）。
const (
	minContextLen     = 24
	minContextEntropy = 4.0
	maxWordShare      = 0.35
)

// wordRun 是标识符里的一个单词：可带一个大写开头的至少 3 个小写字母。
var wordRun = regexp.MustCompile(`[A-Z]?[a-z]{3,}`)

// wordShare 返回 v 中属于单词（wordRun）的字符占比。随机生成的值几乎没有长串小写字母，标识符与路径几乎全是。
func wordShare(v string) float64 {
	n := 0
	for _, loc := range wordRun.FindAllStringIndex(v, -1) {
		n += loc[1] - loc[0]
	}
	return float64(n) / float64(len(v))
}

// randomValue 报告 v 像随机生成的值：够长、大小写数字都有、熵够高、不是由单词拼成的。
func randomValue(v string) bool {
	return HighEntropy(v, minContextLen) && Entropy(v) >= minContextEntropy && wordShare(v) < maxWordShare
}

// placeholder 是本包生成的占位符（[redacted] 与 MaskForLog 的 [secret:…]）。规则名、charset 只认本包的取值，
// 其余字段只含数字与 shape 的字符（x 与白名单分隔符），占位符里放不下凭据。
var placeholder = regexp.MustCompile(`\[redacted\]|\[secret:(?:` + strings.Join([]string{
	regexp.QuoteMeta(RulePrefixedToken), regexp.QuoteMeta(RuleBearer), regexp.QuoteMeta(RuleAssignment),
	regexp.QuoteMeta(RuleAWSAccessKey), regexp.QuoteMeta(RuleURLPassword), regexp.QuoteMeta(RulePrivateKey),
	regexp.QuoteMeta(RuleHighEntropy), regexp.QuoteMeta(RuleCustom),
}, "|") + `) len=\d+ charset=(?:digits|hex|alnum|base64url|base64|mixed)(?: shape=[x` +
	strings.ReplaceAll(regexp.QuoteMeta(shapeSeparators), "-", "") + `-]*)?\]`) // 字符类里 - 放在最后

// Find 返回 text 中全部凭据值的区间，按起点排序、互不重叠。不同规则的区间重叠或相接时合并为并集
// （只遮蔽较小的一段会让其余部分原样留下），标签取其中最具体的规则。
//
// 完全落在已有占位符里的命中不算，所以遮蔽过的文本再遮蔽一次，占位符本身不会被当作凭据。只排除
// 「完全落在里面」的：原文也可能含占位符的写法，与占位符部分重叠的命中照常遮蔽（连同重叠的占位符）。
// 占位符里有空格，会截断赋值等写法的值，所以另用一个把占位符换成等长 x 的视图再匹配一遍，两边的命中
// 取并集：紧挨在占位符前后、或被占位符夹在中间的原始凭据都不会因此漏掉。
func Find(text string) []Hit { return FindRules(text) }

// FindRules 同 Find，但只用 ids 里的规则（为空时用全部）；合并与标签只在这些规则之间进行，所以停用一条规则不会
// 连带吞掉其他规则的命中。
func FindRules(text string, ids ...string) []Hit {
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
			if len(ids) > 0 && !slices.Contains(ids, r.id) {
				continue
			}
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
				if insidePlaceholders(start, end) || r.check != nil && !r.check(view[start:end]) {
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

// MaskForLog 把凭据值换成描述形状的占位符，例如
// [secret:credentials.assignment len=36 charset=hex shape=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx]。
// len 为字符数；shape 只保留白名单中的分隔符，其余任何字符（含各种文字与符号）都换成 x。
// 值超过 64 个字符、或实际被换成 x 的字符不到一半时省略 shape（否则分隔符为主的值会被 shape 重放），
// shape 也绝不会等于原值。
func MaskForLog(text string) string { return replace(text, logPlaceholder) }

// logPlaceholder 是 MaskForLog 给一个已经找到的命中生成的占位符。
func logPlaceholder(h Hit, value string) string {
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

// HighEntropy 报告 v 是否像一段编码或随机生成的内容：至少 minLen 个字符；字符集是 base64 一类（base64、base64url
// 或字母数字），且大写、小写、数字都有（只有 / 的路径不算）；每字符的香农熵至少 minHighEntropy 比特。只看形状：单词、路径、
// UUID、hex（git 哈希）、重复字符都不算。detect/encoded 用它判断交给解释器的内容是否经过编码；outbound 的
// 高熵凭据检测复用它。
func HighEntropy(v string, minLen int) bool {
	if len(v) < minLen {
		return false
	}
	switch charset(v) {
	case "base64", "base64url", "alnum":
	default:
		return false
	}
	var upper, lower, digit bool
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	if !(upper && lower && digit) {
		return false
	}
	return Entropy(v) >= minHighEntropy
}

// minHighEntropy 是 HighEntropy 要求的每字符熵（比特）。英文单词拼成的标识符约 3.5–4.2，base64 编码的命令约 4.0
// 以上，PowerShell 的 UTF-16LE base64 约 3.9–4.1；长度下限与「大小写数字混合」排除了大部分标识符。
const minHighEntropy = 3.5

// Entropy 返回 v 的每字符香农熵（比特，按字节计）。
func Entropy(v string) float64 {
	if v == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(v); i++ {
		counts[v[i]]++
	}
	n := float64(len(v))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// MaskKeepLines 同 MaskForLog，但保持行数：值里的每个换行在占位符之后照样保留，按行截取的摘录与行号都不受影响，
// 跨行的私钥也不会被切成看不出是私钥的几段。占位符直接按找到的命中生成，不再单独识别裸值：
// 依赖上下文的形状（赋值、Bearer）单看值认不出来。
//
// extra 是调用方另外认出的敏感区间（如用户正则认出的凭据，[起点, 终点) 字节偏移），与内置命中一起遮蔽，标签为
// RuleCustom；重叠的区间合并，标签取先开始的那个。越界或空的区间忽略。
func MaskKeepLines(text string, extra ...[2]int) string {
	hits := Find(text)
	for _, e := range extra {
		if 0 <= e[0] && e[0] < e[1] && e[1] <= len(text) {
			hits = append(hits, Hit{Rule: RuleCustom, Start: e[0], End: e[1]})
		}
	}
	if len(hits) == 0 {
		return text
	}
	slices.SortStableFunc(hits, func(a, b Hit) int { return a.Start - b.Start })
	merged := hits[:1]
	for _, h := range hits[1:] {
		if last := &merged[len(merged)-1]; h.Start < last.End {
			last.End = max(last.End, h.End)
		} else {
			merged = append(merged, h)
		}
	}
	var b strings.Builder
	last := 0
	for _, h := range merged {
		value := text[h.Start:h.End]
		b.WriteString(text[last:h.Start])
		b.WriteString(logPlaceholder(h, value))
		b.WriteString(strings.Repeat("\n", strings.Count(value, "\n")))
		last = h.End
	}
	b.WriteString(text[last:])
	return b.String()
}

// placeholderValue 是文档与示例里常见的占位值（比较前去掉引号、转成小写）。
var placeholderValue = regexp.MustCompile(`^(?:your[-_ ].*|<.*|\[.*|\{\{.*|x{3,}|\*{3,}|\.{3,}|changeme|change[-_]?me|example.*|.*[-_]?example|placeholder.*|redacted|todo|tbd|none|null|nil|undefined|secret|password|pass|test|dummy|sample|postgres|guest|root|admin|mysql|redis|user|demo)$`)

// codeLike 是代码表达式：函数调用、下标、成员访问链（a.b.c）。
var codeLike = regexp.MustCompile(`[()\[\]<>|]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$`)

// passwdEntry 是 /etc/passwd 的一行（name:x:uid:gid:…），grep 输出里常见。
var passwdEntry = regexp.MustCompile(`^[^:\s]+:[^:]*:\d+:\d+:`)

// Confirmed 报告 rule 命中的值像真的凭据（用于拦截；遮蔽仍用宽的形状，维护者决定 2026-10-16）。遮蔽为了不漏
// 宁可宽：认错了顶多多遮几个字符；拦截认错了就吞掉用户的输入，所以再排除占位符、代码表达式、变量引用与由单词
// 拼成的写法。
func Confirmed(rule, value string) bool {
	v := strings.Trim(strings.TrimSpace(value), "\"'`")
	switch rule {
	case RulePrefixedToken:
		// 前缀之后全是用 _、- 连起来的小写单词（sk-learn-preprocessing、pk_feature_branch）不算
		_, rest, _ := strings.Cut(strings.ReplaceAll(v, "_", "-"), "-")
		for _, seg := range strings.FieldsFunc(rest, func(r rune) bool { return r == '-' }) {
			if strings.ToLower(seg) != seg || strings.ContainsAny(seg, "0123456789") {
				return true
			}
		}
		return false
	case RuleBearer:
		// 至少有数字，或大小写都有且不是由单词拼成的
		hasDigit := strings.ContainsAny(v, "0123456789")
		return hasDigit || strings.ToLower(v) != v && strings.ToUpper(v) != v && wordShare(v) < maxWordShare
	case RuleAssignment, RuleURLPassword:
		v = strings.TrimRight(v, ";,.") // 代码里的 token: string; 、对象里的 password: hashedPassword, 与句末的句号
		switch {
		case placeholderValue.MatchString(strings.ToLower(v)),
			strings.ContainsAny(v, "$%") && !strings.ContainsAny(v, "0123456789"), // ${VAR}、$VAR、%VAR%
			strings.HasPrefix(v, "${"), strings.HasPrefix(v, "$") && len(v) > 1 && (v[1] == '_' || unicode.IsLetter(rune(v[1]))), // ${TOKEN:-default123}
			codeLike.MatchString(v),
			v == strings.ToUpper(v) && strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") == "", // DB_PASSWORD 这类变量名
			// 只由字母与下划线组成：类型名（string、String）、标识符（hashedPassword、accessToken）、配置取值
			// （required、enabled）。纯字母的真口令只遮蔽、不拦截
			strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_") == "",
			strings.ContainsAny(v[:1], "&*!"), // YAML 锚点、别名与标签（&secret、!vault）
			// 路径：粘贴的环境变量（PWD=/Users/…、OLDPWD=…），关键词没有左边界，遮蔽照宽、拦截时排除
			strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~/") || len(v) > 2 && unicode.IsLetter(rune(v[0])) && v[1] == ':' && (v[2] == '\\' || v[2] == '/'),
			passwdEntry.MatchString(v):
			return false
		}
		return true
	case RuleAWSAccessKey:
		return !strings.HasSuffix(v, "EXAMPLE") // AWS 文档里的示例 key（AKIAIOSFODNN7EXAMPLE）
	}
	return true
}

// Package pii 识别文本中的个人信息：邮箱、中国大陆手机号、国际号码、中国居民身份证号、美国 SSN、
// 公网 IP。每个检测器先用正则找候选，再在代码里校验（校验位、日期、地址段），排除开发场景里常见的误报
// （保留域名、noreply、SSH 地址、内网 IP、版本号）。只认形状、不认语义；姓名、地址这类本地识别不了的留给判断层。
// Find 排除开发文本里的常见写法；FindForMask 不做这些排除，用于发送前的遮蔽：多遮蔽只是少发一点上下文，漏遮蔽会外发个人信息。
// 正则用标准库 regexp（RE2，线性时间）。
package pii

import (
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// 规则 id，与规则包的 id 一致（rules/outbound）。
const (
	RuleEmail     = "pii.email"
	RulePhoneCN   = "pii.phone_cn"
	RulePhoneIntl = "pii.phone_intl"
	RuleCNID      = "pii.cn_id"
	RuleUSSSN     = "pii.us_ssn"
	RuleIP        = "pii.ip"
)

// Hit 是一处个人信息在文本中的字节区间 [Start, End)。
type Hit struct {
	Rule       string
	Start, End int
}

// detector 找出一种个人信息的候选并校验，返回通过校验的区间。dev 为 true 时另外排除开发文本里的常见写法
// （SSH 用户、数量、版本号前缀、diff 新增行这类值本身可能是个人信息形状、只是所在的位置说明它不是的情形）；
// 值本身就不是个人信息的排除（保留域名、内网地址、校验失败）不论 dev 都做。
type detector struct {
	id   string
	find func(text string, dev bool) [][2]int
}

// detectors 按具体程度排序：区间重叠时取靠前的规则。
var detectors = []detector{
	{RuleCNID, findCNID},
	{RuleUSSSN, findSSN},
	{RulePhoneCN, findPhoneCN},
	{RulePhoneIntl, findPhoneIntl},
	{RuleEmail, findEmail},
	{RuleIP, findIP},
}

// Rules 返回全部规则 id，按固定顺序。
func Rules() []string {
	return []string{RuleEmail, RulePhoneCN, RulePhoneIntl, RuleCNID, RuleUSSSN, RuleIP}
}

// Find 返回 text 中的个人信息，按起点排序、互不重叠；同一片段被几条规则命中时只报最具体的一条。rules 不为空时
// 只用这些规则（在其中取最具体的，所以 phone_cn 停用时带 +86 的号码报 phone_intl）。
func Find(text string, rules ...string) []Hit {
	return find(text, true, rules)
}

// FindForMask 返回发送前要遮蔽的个人信息，约定与 Find(text) 相同（按起点排序、互不重叠、同一片段只报最具体的规则），
// 但不排除开发文本里的写法；Find(text) 的每个区间都落在 FindForMask(text) 的某个区间内。
func FindForMask(text string) []Hit {
	return find(text, false, nil)
}

func find(text string, dev bool, rules []string) []Hit {
	var all []Hit
	prio := map[string]int{}
	for i, d := range detectors {
		if len(rules) > 0 && !contains(rules, d.id) {
			continue
		}
		prio[d.id] = i
		for _, loc := range d.find(text, dev) {
			all = append(all, Hit{Rule: d.id, Start: loc[0], End: loc[1]})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Start != all[j].Start {
			return all[i].Start < all[j].Start
		}
		return prio[all[i].Rule] < prio[all[j].Rule]
	})
	var out []Hit
	for _, h := range all {
		n := len(out)
		if n > 0 && h.Start < out[n-1].End {
			// 重叠：保留更具体的一条，区间取并集（只报一次，也不会漏掉一部分）
			last := &out[n-1]
			if prio[h.Rule] < prio[last.Rule] {
				last.Rule = h.Rule
			}
			last.End = max(last.End, h.End)
			continue
		}
		out = append(out, h)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// digitBounded 报告 [start, end) 前后都不紧邻数字。
func digitBounded(text string, start, end int) bool {
	return (start == 0 || !isDigit(text[start-1])) && (end == len(text) || !isDigit(text[end]))
}

var (
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
	// 保留给文档与测试的域名（RFC 2606、RFC 6761）
	reservedDomains = []string{"example.com", "example.net", "example.org"}
	reservedTLDs    = []string{"test", "example", "invalid", "localhost"}
)

func findEmail(text string, dev bool) [][2]int {
	var out [][2]int
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		addr := text[loc[0]:loc[1]]
		at := strings.LastIndexByte(addr, '@')
		local, domain := strings.ToLower(addr[:at]), strings.ToLower(addr[at+1:])
		switch {
		case dev && hostPath(text, loc[1]):
			continue // git@github.com:org/repo、bob@host:repo.git 是 SSH 与 scp 的 host:path 写法
		case dev && local == "git":
			continue // ssh -T git@github.com：git 是代码托管的 SSH 用户，不是人
		case reservedDomain(domain):
			continue
		case noreply(local) || strings.Contains("."+domain+".", ".noreply."):
			continue
		}
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
}

// hostPath 报告 text[end:] 以冒号开头、冒号之后紧跟的既不是空白也不是文本末尾（user@host:path）。
// 「Contact alice@acme.cn: call later」里冒号后是空白，是普通的标点。
func hostPath(text string, end int) bool {
	if end+1 >= len(text) || text[end] != ':' {
		return false
	}
	r, _ := utf8.DecodeRuneInString(text[end+1:])
	return !unicode.IsSpace(r)
}

func reservedDomain(domain string) bool {
	for _, d := range reservedDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	for _, t := range reservedTLDs {
		if tld == t {
			return true
		}
	}
	return false
}

func noreply(local string) bool {
	l := strings.NewReplacer("-", "", "_", "", ".", "").Replace(local)
	return strings.HasPrefix(l, "noreply") || strings.HasPrefix(l, "donotreply")
}

var phoneCNRe = regexp.MustCompile(`(?:\+?86[\s-]?)?1[3-9]\d[\s-]?\d{4}[\s-]?\d{4}`)

func findPhoneCN(text string, dev bool) [][2]int {
	var out [][2]int
	for _, loc := range phoneCNRe.FindAllStringIndex(text, -1) {
		if digitBounded(text, loc[0], loc[1]) && !(dev && quantity(text, loc[0], loc[1])) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

var (
	phoneIntlRe = regexp.MustCompile(`\+[1-9][\d\s().-]{6,22}\d`)
	dateAfter   = regexp.MustCompile(`^\+\d{4}-\d{2}-\d{2}`)
)

func findPhoneIntl(text string, dev bool) [][2]int {
	var out [][2]int
	var hunks [][2]int
	scanned := false
	inHunk := func(pos int) bool { // 只在有行首候选时才扫一遍 diff 结构
		if !scanned {
			hunks, scanned = hunkBodies(text), true
		}
		return inSpans(hunks, pos)
	}
	for _, loc := range phoneIntlRe.FindAllStringIndex(text, -1) {
		switch {
		case loc[1] < len(text) && isDigit(text[loc[1]]):
			continue
		case !dev: // 以下是开发文本里的写法，只在 Find 里排除
		case loc[0] > 0 && (isWord(text[loc[0]-1]) || text[loc[0]-1] == '.'), // 1.2.3+20231015.1 的构建元数据
			dateAfter.MatchString(text[loc[0]:]),                      // +2026-10-16：diff 里的时间戳
			(loc[0] == 0 || text[loc[0]-1] == '\n') && inHunk(loc[0]): // diff 新增行的标记
			continue
		}
		n := 0
		for i := loc[0]; i < loc[1]; i++ {
			if isDigit(text[i]) {
				n++
			}
		}
		if n >= 8 && n <= 15 {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

// hunkHeader 是 unified diff 的块头 @@ -a[,b] +c[,d] @@；hunkStart 是读不出行数时也认的块头开头。
var (
	hunkHeader = regexp.MustCompile(`^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@`)
	hunkStart  = regexp.MustCompile(`^@@ -\d`)
)

// hunkBodies 一次扫描算出 unified diff 各个 hunk 正文的字节区间：hunk 正文里行首的 + 是新增行的标记，不是国际号码的开头。
// 块头写明旧侧与新侧的行数（省略时为 1），之后逐行消耗：以空格开头或空行算上下文（两侧各减 1；粘贴时行尾空格被去掉的
// 上下文行就是空行），- 减旧侧，+ 减新侧，\ 不计数；两侧都减到 0 时 hunk 结束，中途遇到别的行提前结束。块头读不出行数时
// 正文是其后连续的、以空格、+、-、\ 开头的行。结束 hunk 的那一行是下一个块头时，从它开始下一个 hunk。
func hunkBodies(text string) [][2]int {
	var out [][2]int
	in, counted := false, false
	var oldN, newN, start, end int
	closeHunk := func() {
		if in && end > start {
			out = append(out, [2]int{start, end})
		}
		in = false
	}
	for pos := 0; pos < len(text); {
		lineEnd := strings.IndexByte(text[pos:], '\n')
		next := len(text)
		if lineEnd < 0 {
			lineEnd = len(text)
		} else {
			lineEnd += pos
			next = lineEnd + 1
		}
		line := text[pos:lineEnd]
		if in {
			blank := line == "" || line == "\r"
			c := byte(0)
			if !blank {
				c = line[0]
			}
			switch {
			case counted && (blank || c == ' '):
				oldN--
				newN--
			case counted && c == '-':
				oldN--
			case counted && c == '+':
				newN--
			case c == '\\', !counted && (c == ' ' || c == '-' || c == '+'):
			default:
				closeHunk()
			}
			if in {
				end = lineEnd
				if counted && oldN <= 0 && newN <= 0 {
					closeHunk()
				}
				pos = next
				continue
			}
		}
		if m := hunkHeader.FindStringSubmatch(line); m != nil {
			oldN, newN = hunkCount(m[1]), hunkCount(m[2])
			in, counted, start, end = oldN > 0 || newN > 0, true, next, next
		} else if hunkStart.MatchString(line) {
			in, counted, start, end = true, false, next, next
		}
		pos = next
	}
	closeHunk()
	return out
}

// hunkCount 读块头里的行数：省略时为 1。
func hunkCount(s string) int {
	if s == "" {
		return 1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 1 << 30 // 超出 int 的行数：按到 hunk 遇到别的行为止处理
	}
	return n
}

// inSpans 报告 pos 落在某个区间 [start, end) 内。spans 按起点排序、互不重叠。
func inSpans(spans [][2]int, pos int) bool {
	i := sort.Search(len(spans), func(i int) bool { return spans[i][1] > pos })
	return i < len(spans) && spans[i][0] <= pos
}

var (
	cnIDRe = regexp.MustCompile(`\d{17}[\dXx]`)
	// 省级行政区划代码的前两位
	provinces = map[string]bool{
		"11": true, "12": true, "13": true, "14": true, "15": true, "21": true, "22": true, "23": true, "31": true, "32": true,
		"33": true, "34": true, "35": true, "36": true, "37": true, "41": true, "42": true, "43": true, "44": true, "45": true,
		"46": true, "50": true, "51": true, "52": true, "53": true, "54": true, "61": true, "62": true, "63": true, "64": true,
		"65": true, "71": true, "81": true, "82": true,
	}
	// now 是校验出生日期用的当前时间（测试可替换）。
	now = time.Now
)

func findCNID(text string, _ bool) [][2]int {
	var out [][2]int
	for _, loc := range cnIDRe.FindAllStringIndex(text, -1) {
		id := text[loc[0]:loc[1]]
		if digitBounded(text, loc[0], loc[1]) && validCNID(id) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

func validCNID(id string) bool {
	if !provinces[id[:2]] {
		return false
	}
	birth, err := time.Parse("20060102", id[6:14])
	if err != nil || birth.Year() < 1900 || birth.After(now()) {
		return false
	}
	// ISO 7064 MOD 11-2
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	sum := 0
	for i, w := range weights {
		sum += int(id[i]-'0') * w
	}
	return "10X98765432"[sum%11] == strings.ToUpper(id[17:])[0]
}

var ssnRe = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)

func findSSN(text string, _ bool) [][2]int {
	var out [][2]int
	for _, m := range ssnRe.FindAllStringSubmatchIndex(text, -1) {
		area, group, serial := text[m[2]:m[3]], text[m[4]:m[5]], text[m[6]:m[7]]
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			continue
		}
		if !digitBounded(text, m[0], m[1]) || (m[0] > 0 && text[m[0]-1] == '-') || (m[1] < len(text) && text[m[1]] == '-') {
			continue
		}
		out = append(out, [2]int{m[0], m[1]})
	}
	return out
}

var (
	ipv4Re = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6Re = regexp.MustCompile(`(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	// 文档保留段（RFC 5737、RFC 3849）与运营商级 NAT（RFC 6598）
	excluded = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
)

// versionWord 是写在版本号前面的词：build 2.0.0.1 是版本号，不是地址。
var versionWord = regexp.MustCompile(`(?i)\b(?:version|ver|build|release|rev|revision)\s*$`)

func findIP(text string, dev bool) [][2]int {
	var out [][2]int
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
		if dev && versionWord.MatchString(text[max(0, loc[0]-12):loc[0]]) {
			continue
		}
		// 版本号形态：前面紧邻字母、数字或点（v1.2.3.4、1.2.3.4.5 的后四段），后面还有 .数字
		if loc[0] > 0 && (isWord(text[loc[0]-1]) || text[loc[0]-1] == '.') {
			continue
		}
		if loc[1] < len(text) && (isDigit(text[loc[1]]) || loc[1]+1 < len(text) && text[loc[1]] == '.' && isDigit(text[loc[1]+1])) {
			continue
		}
		if public(text[loc[0]:loc[1]]) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	for _, loc := range ipv6Re.FindAllStringIndex(text, -1) {
		if loc[0] > 0 && (isWord(text[loc[0]-1]) || text[loc[0]-1] == ':') || loc[1] < len(text) && (isWord(text[loc[1]]) || text[loc[1]] == ':') {
			continue
		}
		if strings.Count(text[loc[0]:loc[1]], ":") < 2 {
			continue
		}
		if public(text[loc[0]:loc[1]]) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

// quantityKey、quantityUnit 是数量的写法：size=13421772800、17179869184 bytes 是字节数，不是手机号。
var (
	quantityKey = regexp.MustCompile(`(?i)\b(?:size|bytes|memory|mem|length|len|count|total|offset|timestamp|ts|ms|elapsed)\s*[=:]\s*$`)
	// 单位紧跟数字（至多隔一个空格）：长单位后面可以接词（bytes free）；短单位（b、s、us、ms、ns、sec）后面不能再是
	// 字母或「空格加字母」（B座、us office 不是单位）
	quantityUnit      = regexp.MustCompile(`(?i)^ ?(?:bytes?|seconds?|[kmgt]i?b)(?:$|[^\p{L}])`)
	quantityUnitShort = regexp.MustCompile(`(?i)^ ?(?:b|s|us|µs|ns|ms|sec)(?:$|[^\p{L}\s]|\s+[^\p{L}\s]|\s*$)`)
)

// quantity 报告 [start, end) 写在数量的位置上：前面是 size=、memory: 这类键，或后面跟着单位。
func quantity(text string, start, end int) bool {
	after := text[end:min(len(text), end+16)]
	return quantityKey.MatchString(text[max(0, start-16):start]) || quantityUnit.MatchString(after) || quantityUnitShort.MatchString(after)
}

func isWord(b byte) bool {
	return isDigit(b) || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_'
}

// public 报告 s 是不是公网地址：排除私有（含 ULA）、回环、链路本地、组播、未指定与文档保留段。
func public(s string) bool {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range excluded {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Package pii 识别文本中的个人信息（spec §6.2）：邮箱、中国大陆手机号、国际号码、中国居民身份证号、美国 SSN、
// 公网 IP。每个检测器先用正则找候选，再在代码里校验（校验位、日期、地址段），排除开发场景里常见的误报
// （保留域名、noreply、SSH 地址、内网 IP、版本号）。只认形状、不认语义；姓名、地址这类本地识别不了的留给判断层。
// 正则用标准库 regexp（RE2，线性时间）。
package pii

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
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

// detector 找出一种个人信息的候选并校验，返回通过校验的区间。
type detector struct {
	id   string
	find func(text string) [][2]int
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

// Rules 返回全部规则 id（spec §6.2 的顺序）。
func Rules() []string {
	return []string{RuleEmail, RulePhoneCN, RulePhoneIntl, RuleCNID, RuleUSSSN, RuleIP}
}

// Find 返回 text 中的个人信息，按起点排序、互不重叠；同一片段被几条规则命中时只报最具体的一条。rules 不为空时
// 只用这些规则（在其中取最具体的，所以 phone_cn 停用时带 +86 的号码报 phone_intl）。
func Find(text string, rules ...string) []Hit {
	var all []Hit
	prio := map[string]int{}
	for i, d := range detectors {
		if len(rules) > 0 && !contains(rules, d.id) {
			continue
		}
		prio[d.id] = i
		for _, loc := range d.find(text) {
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

func findEmail(text string) [][2]int {
	var out [][2]int
	for _, loc := range emailRe.FindAllStringIndex(text, -1) {
		addr := text[loc[0]:loc[1]]
		at := strings.LastIndexByte(addr, '@')
		local, domain := strings.ToLower(addr[:at]), strings.ToLower(addr[at+1:])
		switch {
		case loc[1] < len(text) && text[loc[1]] == ':':
			continue // git@github.com:org/repo 是 SSH 地址
		case reservedDomain(domain):
			continue
		case noreply(local) || strings.Contains("."+domain+".", ".noreply."):
			continue
		}
		out = append(out, [2]int{loc[0], loc[1]})
	}
	return out
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

func findPhoneCN(text string) [][2]int {
	var out [][2]int
	for _, loc := range phoneCNRe.FindAllStringIndex(text, -1) {
		if digitBounded(text, loc[0], loc[1]) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

var phoneIntlRe = regexp.MustCompile(`\+[1-9][\d\s().-]{6,22}\d`)

func findPhoneIntl(text string) [][2]int {
	var out [][2]int
	for _, loc := range phoneIntlRe.FindAllStringIndex(text, -1) {
		if loc[1] < len(text) && isDigit(text[loc[1]]) {
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

func findCNID(text string) [][2]int {
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

func findSSN(text string) [][2]int {
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

func findIP(text string) [][2]int {
	var out [][2]int
	for _, loc := range ipv4Re.FindAllStringIndex(text, -1) {
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

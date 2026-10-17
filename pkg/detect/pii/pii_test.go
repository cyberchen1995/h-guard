package pii_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/pii"
)

// found 返回 text 中命中的规则与原文，便于比较。
func found(text string, rules ...string) [][2]string {
	var out [][2]string
	for _, h := range pii.Find(text, rules...) {
		out = append(out, [2]string{h.Rule, text[h.Start:h.End]})
	}
	return out
}

// detectorCases 是每条规则的正例与反例（各自的校验与排除）。
var detectorCases = []struct {
	text string
	want [][2]string
}{
	// 邮箱：保留域名、保留顶级域、noreply 类、SSH 地址不算
	{"contact alice.wang@acme-corp.cn today", [][2]string{{pii.RuleEmail, "alice.wang@acme-corp.cn"}}},
	{"Bob <bob+tag@mail.example.com>, carol@example.org, dan@site.test, eve@host.invalid, x@y.localhost, z@w.example", nil},
	{"noreply@github.com no-reply@acme.com 12345+octocat@users.noreply.github.com", nil},
	{"git clone git@github.com:acme/repo.git", nil},
	// 开发文本里的误报：SSH 命令的 git@ 用户、mDNS 的 .local、字节数、diff 里的时间戳与
	// 行首 +、semver 的构建元数据、带 version、build 字样的四段版本号
	{"ssh -T git@github.com", nil},
	// 单位只在紧跟数字、后面不再是字母时才算；短单位（b、s、us、ms）后面跟着词时不算；.local 是 AD 域里人的邮箱
	{"联系人 张伟 13800138000 B座1201", [][2]string{{pii.RulePhoneCN, "13800138000"}}},
	{"call 13800138000 us office hours", [][2]string{{pii.RulePhoneCN, "13800138000"}}},
	{"mail jane.doe@contoso.local", [][2]string{{pii.RuleEmail, "jane.doe@contoso.local"}}},
	{"took 13800138000 ms, 13900139000 bytes free", nil},
	{"memory 17179869184 bytes, size=13421772800", nil},
	{"+2026-10-16 12:00:00 started", nil},
	{"@@ -1,3 +1,4 @@\n+1234567890 rows affected", nil},
	{"tag 1.2.3+20231015.1", nil},
	{"build 2.0.0.1 and version 8.8.4.4", nil},
	{"call 13800138000 or +44 20 7946 0958", [][2]string{{pii.RulePhoneCN, "13800138000"}, {pii.RulePhoneIntl, "+44 20 7946 0958"}}},
	// 中国大陆手机号：1[3-9] 开头 11 位，可带 +86、86 与空格连字符；前后不能紧邻数字
	{"call 13800138000 or +86 139-1234-5678", [][2]string{{pii.RulePhoneCN, "13800138000"}, {pii.RulePhoneCN, "+86 139-1234-5678"}}},
	{"id 913800138000 and 1380013800012 and 12345678901", nil},
	// 国际号码：带 +，去掉分隔符后 8–15 位，国家码首位非 0
	{"ring +1 (415) 555-0132 or +44 20 7946 0958", [][2]string{{pii.RulePhoneIntl, "+1 (415) 555-0132"}, {pii.RulePhoneIntl, "+44 20 7946 0958"}}},
	{"+0 123 456 789, +12 34, v+1234567", nil},
	// 身份证号：省级代码、日期、校验位
	{"身份证 11010519491231002X 已登记", [][2]string{{pii.RuleCNID, "11010519491231002X"}}},
	{"110105194912310021 990105194912310025 110105194913310023 110105299912310029", nil},
	// SSN：只认带连字符的格式，排除无效区号、组号、序号
	{"ssn 123-45-6789 on file", [][2]string{{pii.RuleUSSSN, "123-45-6789"}}},
	{"000-12-3456 666-12-3456 912-34-5678 123-00-4567 123-45-0000 123456789", nil},
	// IP：只算公网地址
	{"server 8.8.8.8 and 2606:4700:4700::1111", [][2]string{{pii.RuleIP, "8.8.8.8"}, {pii.RuleIP, "2606:4700:4700::1111"}}},
	{"10.0.0.1 192.168.1.1 172.16.0.5 127.0.0.1 100.64.0.1 169.254.1.1 224.0.0.1 0.0.0.0 255.255.255.255", nil},
	{"192.0.2.1 198.51.100.7 203.0.113.9 ::1 fe80::1 fd00::1 2001:db8::1 ff02::1", nil},
	{"version v1.2.3.4, build 1.2.3.4.5, at 12:30:45", nil},
}

// TestDetectors：每条规则的正例与反例（各自的校验与排除）。
func TestDetectors(t *testing.T) {
	for _, c := range detectorCases {
		if got := found(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.text, got, c.want)
		}
	}
}

// TestMostSpecific：同一片段被几条规则命中时只报一次，取更具体的（带 +86 的号码报 pii.phone_cn）。
func TestMostSpecific(t *testing.T) {
	if got := found("+86 13800138000"); !reflect.DeepEqual(got, [][2]string{{pii.RulePhoneCN, "+86 13800138000"}}) {
		t.Errorf("got %q", got)
	}
	// 只启用部分规则时，在启用的规则里取：phone_cn 停用时报 phone_intl
	if got := found("+86 13800138000", pii.RulePhoneIntl); !reflect.DeepEqual(got, [][2]string{{pii.RulePhoneIntl, "+86 13800138000"}}) {
		t.Errorf("phone_intl only: got %q", got)
	}
	if got := found("alice.wang@acme-corp.cn 8.8.8.8", pii.RuleIP); !reflect.DeepEqual(got, [][2]string{{pii.RuleIP, "8.8.8.8"}}) {
		t.Errorf("ip only: got %q", got)
	}
}

// TestRules：规则 id 与它们的固定顺序。
func TestRules(t *testing.T) {
	want := []string{"pii.email", "pii.phone_cn", "pii.phone_intl", "pii.cn_id", "pii.us_ssn", "pii.ip"}
	if got := pii.Rules(); !reflect.DeepEqual(got, want) {
		t.Errorf("rules = %v", got)
	}
}

// FuzzFind：任何输入都不 panic，命中区间合法、按起点排序、互不重叠。
func FuzzFind(f *testing.F) {
	for _, s := range []string{"alice@acme.cn +86 138-0013-8000", "11010519491231002X 123-45-6789", "8.8.8.8 2606:4700::1",
		strings.Repeat("1", 40), "+1 (415) 555-0132"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		for _, find := range []func(string) []pii.Hit{func(s string) []pii.Hit { return pii.Find(s) }, pii.FindForMask} {
			prev := 0
			for _, h := range find(text) {
				if h.Start < prev || h.End <= h.Start || h.End > len(text) {
					t.Fatalf("%q: bad hit %+v", text, h)
				}
				prev = h.End
			}
		}
		// 遮蔽的范围包含本地命中的范围
		mask := pii.FindForMask(text)
		for _, h := range pii.Find(text) {
			if !covers(mask, h.Start, h.End) {
				t.Fatalf("%q: hit %+v not covered by %+v", text, h, mask)
			}
		}
	})
}

// covers 报告 hits 中有一个区间包含 [start, end)。
func covers(hits []pii.Hit, start, end int) bool {
	for _, h := range hits {
		if h.Start <= start && end <= h.End {
			return true
		}
	}
	return false
}

// TestFindForMaskKeepsDevText：Find 排除的开发文本写法，FindForMask 照样报（发送前遮蔽宁多勿漏）。
func TestFindForMaskKeepsDevText(t *testing.T) {
	for _, tt := range []struct{ text, value string }{
		{"ssh -T git@github.com", "git@github.com"},                         // 本地部分为 git
		{"memory: 13800138000", "13800138000"},                              // 数量位置上的手机号
		{"build 8.8.4.4", "8.8.4.4"},                                        // 版本词后面的公网 IP
		{"@@ -1,2 +1,2 @@\n+44 20 7946 0958\n", "+44 20 7946 0958"},         // hunk 正文行首的号码
		{"clone bob@build.acme-corp.cn:repo.git", "bob@build.acme-corp.cn"}, // host:path 写法
		{"tag 1.2.3+20231015.1", "+20231015.1"},                             // 前面紧邻数字或点
		{"+2026-10-16 12:00:00 started", "+2026-10-16"},                     // + 后是日期
	} {
		start := strings.Index(tt.text, tt.value)
		end := start + len(tt.value)
		for _, h := range pii.Find(tt.text) {
			if h.Start < end && start < h.End {
				t.Errorf("Find(%q) reports %+v", tt.text, h)
			}
		}
		if mask := pii.FindForMask(tt.text); !covers(mask, start, end) {
			t.Errorf("FindForMask(%q) = %+v, want %q covered", tt.text, mask, tt.value)
		}
	}
}

// TestFindForMaskKeepsOldExclusions：值本身不是个人信息的排除（保留域名、noreply、内网与文档保留地址、版本号形态、
// 校验失败的身份证号）在 FindForMask 里同样生效。
func TestFindForMaskKeepsOldExclusions(t *testing.T) {
	for _, text := range []string{"a@example.com", "noreply@x.io", "10.0.0.1", "192.0.2.1", "v1.2.3.4", "110105194912310021"} {
		if got := pii.FindForMask(text); len(got) != 0 {
			t.Errorf("FindForMask(%q) = %+v", text, got)
		}
	}
}

// TestEmailFollowedByColon：邮箱后的冒号接空白或在结尾时是普通的标点，照样算邮箱；接着路径时是 host:path 写法，
// 只有 Find 排除。
func TestEmailFollowedByColon(t *testing.T) {
	const addr = "alice.wang@acme-corp.cn"
	for _, text := range []string{"Contact alice.wang@acme-corp.cn: call later", "mail alice.wang@acme-corp.cn:"} {
		start := strings.Index(text, addr)
		for name, hits := range map[string][]pii.Hit{"Find": pii.Find(text), "FindForMask": pii.FindForMask(text)} {
			if want := []pii.Hit{{Rule: pii.RuleEmail, Start: start, End: start + len(addr)}}; !reflect.DeepEqual(hits, want) {
				t.Errorf("%s(%q) = %+v", name, text, hits)
			}
		}
	}
	text := "clone bob@build.acme-corp.cn:repo.git"
	if got := pii.Find(text); len(got) != 0 {
		t.Errorf("Find(%q) = %+v", text, got)
	}
	if got := pii.FindForMask(text); !reflect.DeepEqual(got, []pii.Hit{{Rule: pii.RuleEmail, Start: 6, End: 28}}) {
		t.Errorf("FindForMask(%q) = %+v", text, got)
	}
}

// TestFindForMaskCoversFind：已有的正例与反例文本里，Find 的每个区间都落在 FindForMask 的某个区间内。
func TestFindForMaskCoversFind(t *testing.T) {
	texts := []string{"+86 13800138000", "alice.wang@acme-corp.cn 8.8.8.8"}
	for _, c := range detectorCases {
		texts = append(texts, c.text)
	}
	for _, text := range texts {
		mask := pii.FindForMask(text)
		for _, h := range pii.Find(text) {
			if !covers(mask, h.Start, h.End) {
				t.Errorf("%q: hit %+v not covered by %+v", text, h, mask)
			}
		}
	}
}

// TestPhoneIntlDiffOnlyInsideHunk：行首 + 只在 hunk 正文里当作新增行的标记；hunk 结束后行首的 + 是号码。
func TestPhoneIntlDiffOnlyInsideHunk(t *testing.T) {
	text := "@@ -1,2 +1,2 @@\n+44 20 7946 0958\n context\n\nContacts:\n+44 20 7946 0959\n"
	if got := found(text, pii.RulePhoneIntl); !reflect.DeepEqual(got, [][2]string{{pii.RulePhoneIntl, "+44 20 7946 0959"}}) {
		t.Errorf("got %q", got)
	}
}

// TestPhoneIntlHunkEndsAtNonDiffLine：块头的行数还没用完，但遇到不是 diff 行的行时 hunk 提前结束。
func TestPhoneIntlHunkEndsAtNonDiffLine(t *testing.T) {
	text := "@@ -1,3 +1,4 @@\n context\n+44 20 7946 0958\nNote:\n+44 20 7946 0959\n"
	if got := found(text, pii.RulePhoneIntl); !reflect.DeepEqual(got, [][2]string{{pii.RulePhoneIntl, "+44 20 7946 0959"}}) {
		t.Errorf("got %q", got)
	}
}

// TestPhoneIntlHunkWithBlankContextLine：粘贴时行尾空格被去掉的上下文行是空行，仍在 hunk 里（块头的行数还没用完）。
func TestPhoneIntlHunkWithBlankContextLine(t *testing.T) {
	text := "@@ -1,3 +1,4 @@\n a\n\n b\n+44 20 7946 0958\n"
	if got := found(text, pii.RulePhoneIntl); got != nil {
		t.Errorf("got %q", got)
	}
}

// TestPhoneIntlHunkEndsByLineCount：块头的行数用完后 hunk 结束，其后的空行与行首 + 号码不在 hunk 里。
func TestPhoneIntlHunkEndsByLineCount(t *testing.T) {
	text := "@@ -1 +1 @@\n-a\n+b\n\n+44 20 7946 0959\n"
	if got := found(text, pii.RulePhoneIntl); !reflect.DeepEqual(got, [][2]string{{pii.RulePhoneIntl, "+44 20 7946 0959"}}) {
		t.Errorf("got %q", got)
	}
}

// TestPhoneIntlConsecutiveHunks：一个 hunk 结束于下一个块头，第二个 hunk 里行首的号码同样不报。
func TestPhoneIntlConsecutiveHunks(t *testing.T) {
	text := "@@ -1 +1 @@\n-a\n+b\n@@ -9 +9,2 @@\n c\n+44 20 7946 0958\n"
	if got := found(text, pii.RulePhoneIntl); got != nil {
		t.Errorf("got %q", got)
	}
}

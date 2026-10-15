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

// TestDetectors：每条规则的正例与反例（spec §6.2 的校验与排除）。
func TestDetectors(t *testing.T) {
	for _, c := range []struct {
		text string
		want [][2]string
	}{
		// 邮箱：保留域名、保留顶级域、noreply 类、SSH 地址不算
		{"contact alice.wang@acme-corp.cn today", [][2]string{{pii.RuleEmail, "alice.wang@acme-corp.cn"}}},
		{"Bob <bob+tag@mail.example.com>, carol@example.org, dan@site.test, eve@host.invalid, x@y.localhost, z@w.example", nil},
		{"noreply@github.com no-reply@acme.com 12345+octocat@users.noreply.github.com", nil},
		{"git clone git@github.com:acme/repo.git", nil},
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
	} {
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

// TestRules：规则 id 与 spec §6.2 一致。
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
		prev := 0
		for _, h := range pii.Find(text) {
			if h.Start < prev || h.End <= h.Start || h.End > len(text) {
				t.Fatalf("%q: bad hit %+v", text, h)
			}
			prev = h.End
		}
	})
}

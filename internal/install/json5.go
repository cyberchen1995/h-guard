package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// parseJSON5 解析 JSON5（OpenClaw 读 openclaw.json 与 $include 引入的文件用的写法）：注释、单引号字符串、不带引号的键、
// 结尾多余的逗号、十六进制与带 + 号的数字、Infinity 与 NaN、字符串里的续行。普通 JSON 是它的子集。对象是
// map[string]any（重复的键取后一个），数组是 []any，数字是 float64，只用于读取配置，不写回。
func parseJSON5(b []byte) (any, error) {
	p := &json5Parser{s: string(b)}
	p.skip()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.i < len(p.s) {
		return nil, p.errorf("unexpected %q after the value", p.s[p.i])
	}
	if p.open {
		return nil, p.errorf("unterminated /* comment")
	}
	return v, nil
}

// json5MaxDepth 是嵌套的上限，防止恶意或损坏的文件让解析栈溢出。
const json5MaxDepth = 512

type json5Parser struct {
	s    string
	i    int
	open bool // 有没有结束的 /* 注释（它吞掉了文件其余的部分）
}

func (p *json5Parser) errorf(format string, args ...any) error {
	line := 1 + strings.Count(p.s[:min(p.i, len(p.s))], "\n")
	return fmt.Errorf("line %d: %s", line, fmt.Sprintf(format, args...))
}

// skip 跳过空白与注释。
func (p *json5Parser) skip() {
	for p.i < len(p.s) {
		switch c := p.s[p.i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f':
			p.i++
		case strings.HasPrefix(p.s[p.i:], "//"):
			if j := strings.IndexAny(p.s[p.i:], "\n\r"); j >= 0 {
				p.i += j
			} else {
				p.i = len(p.s)
			}
		case strings.HasPrefix(p.s[p.i:], "/*"):
			if j := strings.Index(p.s[p.i+2:], "*/"); j >= 0 {
				p.i += j + 4
			} else {
				p.i, p.open = len(p.s), true
			}
		case c >= utf8.RuneSelf:
			r, n := utf8.DecodeRuneInString(p.s[p.i:])
			if r != '\u00a0' && r != '\ufeff' && r != '\u2028' && r != '\u2029' {
				return
			}
			p.i += n
		default:
			return
		}
	}
}

func (p *json5Parser) value(depth int) (any, error) {
	if depth > json5MaxDepth {
		return nil, p.errorf("nested too deeply")
	}
	if p.i >= len(p.s) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"' || c == '\'':
		return p.str()
	case c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		id := p.ident()
		switch id {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		case "Infinity":
			return math.Inf(1), nil
		case "NaN":
			return math.NaN(), nil
		}
		return nil, p.errorf("unexpected %q", c)
	}
}

func (p *json5Parser) object(depth int) (any, error) {
	p.i++ // {
	m := map[string]any{}
	for {
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return m, nil
		}
		var key string
		if p.i < len(p.s) && (p.s[p.i] == '"' || p.s[p.i] == '\'') {
			k, err := p.str()
			if err != nil {
				return nil, err
			}
			key = k
		} else if key = p.ident(); key == "" {
			return nil, p.errorf("expected a key")
		}
		p.skip()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errorf("expected ':' after key %q", key)
		}
		p.i++
		p.skip()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		m[key] = v
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			return m, nil
		}
		return nil, p.errorf("expected ',' or '}'")
	}
}

func (p *json5Parser) array(depth int) (any, error) {
	p.i++ // [
	a := []any{}
	for {
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.skip()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			return a, nil
		}
		return nil, p.errorf("expected ',' or ']'")
	}
}

// ident 读一个标识符（不带引号的键与 true、null 等字面量），可以含 \uXXXX 转义；不是标识符时返回空。与 json5 包一样
// 按 ES5 的规则：第一个字符是字母（Unicode 的 L 类与 Nl）、$ 或 _，其后另可以是组合记号（Mn、Mc）、数字（Nd）、连接
// 标点（Pc）与 ZWNJ、ZWJ；转义出的字符同样要符合。遇到不符合的字符就停下，由调用方报错。
func (p *json5Parser) ident() string {
	var b strings.Builder
	for p.i < len(p.s) {
		r, n := utf8.DecodeRuneInString(p.s[p.i:])
		if r == '\\' {
			if !strings.HasPrefix(p.s[p.i:], `\u`) || p.i+6 > len(p.s) {
				break
			}
			v, err := strconv.ParseUint(p.s[p.i+2:p.i+6], 16, 16)
			if err != nil {
				break
			}
			r, n = rune(v), 6
		}
		if !identRune(r, b.Len() == 0) {
			break
		}
		b.WriteRune(r)
		p.i += n
	}
	return b.String()
}

// identRune 报告 r 能不能出现在标识符里（first 为真时是第一个字符）。
func identRune(r rune, first bool) bool {
	if r == '$' || r == '_' || unicode.In(r, unicode.Lu, unicode.Ll, unicode.Lt, unicode.Lm, unicode.Lo, unicode.Nl) {
		return true
	}
	return !first && (r == '\u200c' || r == '\u200d' || unicode.In(r, unicode.Mn, unicode.Mc, unicode.Nd, unicode.Pc))
}

func (p *json5Parser) str() (string, error) {
	q := p.s[p.i]
	p.i++
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch c {
		case q:
			p.i++
			return b.String(), nil
		case '\n', '\r':
			return "", p.errorf("unterminated string")
		case '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", p.errorf("unterminated string")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'v':
				b.WriteByte('\v')
			case '0':
				if p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
					return "", p.errorf("octal escape")
				}
				b.WriteByte(0)
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				return "", p.errorf("octal escape")
			case '\n': // 续行
			case '\r':
				if p.i < len(p.s) && p.s[p.i] == '\n' {
					p.i++
				}
			case 'x', 'u':
				n := 2
				if e == 'u' {
					n = 4
				}
				if p.i+n > len(p.s) {
					return "", p.errorf("bad escape")
				}
				r, ok := hexRune(p.s[p.i : p.i+n])
				if !ok {
					return "", p.errorf("bad escape")
				}
				p.i += n
				if e == 'u' && r >= 0xd800 && r < 0xdc00 && strings.HasPrefix(p.s[p.i:], `\u`) && p.i+6 <= len(p.s) {
					if lo, ok := hexRune(p.s[p.i+2 : p.i+6]); ok && lo >= 0xdc00 && lo < 0xe000 {
						r = (r-0xd800)<<10 + (lo - 0xdc00) + 0x10000
						p.i += 6
					}
				}
				b.WriteRune(r)
			default:
				b.WriteByte(e) // \' \" \\ \/ 与其余字符原样
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", p.errorf("unterminated string")
}

func (p *json5Parser) number() (any, error) {
	start := p.i
	sign := 1.0
	if c := p.s[p.i]; c == '+' || c == '-' {
		if c == '-' {
			sign = -1
		}
		p.i++
	}
	rest := p.s[p.i:]
	switch {
	case strings.HasPrefix(rest, "Infinity"):
		p.i += len("Infinity")
		return math.Inf(int(sign)), nil
	case strings.HasPrefix(rest, "NaN"):
		p.i += len("NaN")
		return math.NaN(), nil
	case strings.HasPrefix(rest, "0x") || strings.HasPrefix(rest, "0X"):
		p.i += 2
		h := p.i
		for p.i < len(p.s) && strings.IndexByte("0123456789abcdefABCDEF", p.s[p.i]) >= 0 {
			p.i++
		}
		v, err := strconv.ParseUint(p.s[h:p.i], 16, 64)
		if err != nil {
			return nil, p.errorf("bad number %q", p.s[start:p.i])
		}
		return sign * float64(v), nil
	case len(rest) > 1 && rest[0] == '0' && rest[1] >= '0' && rest[1] <= '9':
		return nil, p.errorf("number with a leading zero")
	}
	for p.i < len(p.s) && strings.IndexByte("0123456789.eE+-", p.s[p.i]) >= 0 {
		if (p.s[p.i] == '+' || p.s[p.i] == '-') && p.s[p.i-1] != 'e' && p.s[p.i-1] != 'E' {
			break
		}
		p.i++
	}
	v, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil {
		return nil, p.errorf("bad number %q", p.s[start:p.i])
	}
	return v, nil
}

// errNotObject 表示配置的根不是对象。
var errNotObject = errors.New("the configuration is not an object")

// toJSON 把 parseJSON5 的结果编码成 JSON（Infinity 与 NaN 变成 null），供按结构体读取。
func toJSON(v any) ([]byte, error) {
	return json.Marshal(finite(v))
}

func finite(v any) any {
	switch x := v.(type) {
	case float64:
		if math.IsInf(x, 0) || math.IsNaN(x) {
			return nil
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = finite(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = finite(e)
		}
		return out
	}
	return v
}

// hexRune 把 2 或 4 位十六进制数字读成 rune。
func hexRune(h string) (rune, bool) {
	var r rune
	for i := 0; i < len(h); i++ {
		c := h[i]
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, false
		}
		r = r<<4 | d
	}
	return r, true
}

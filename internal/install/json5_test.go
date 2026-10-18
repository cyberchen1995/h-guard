package install

import (
	"encoding/json"
	"testing"
)

// TestParseJSON5：JSON5 的写法（注释、单引号、不带引号的键、多余的逗号、十六进制与 + 号、Infinity、续行）解析成与
// 对应 JSON 相同的值；错误的写法报错。
func TestParseJSON5(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{`{"a": [1, 2.5, -3e2], "b": {"c": null, "d": true}}`, `{"a":[1,2.5,-300],"b":{"c":null,"d":true}}`},
		{"// head\n{\n  /* block */ a: 'x\\'y', $b_1: \"z\\u0041\",\n  c: [1, 2,],\n}\n", `{"$b_1":"zA","a":"x'y","c":[1,2]}`},
		{`{n: 0x1F, p: +5, q: .5, r: 5., s: -Infinity, t: NaN}`, `{"n":31,"p":5,"q":0.5,"r":5,"s":null,"t":null}`},
		{"{s: 'line \\\n continued', u: '\\x41\\n'}", `{"s":"line  continued","u":"A\n"}`},
		{`{"dup": 1, "dup": 2}`, `{"dup":2}`},
		{"\ufeff{}", `{}`},
		{`"just a string"`, `"just a string"`},
	} {
		v, err := parseJSON5([]byte(tt.in))
		if err != nil {
			t.Errorf("%q: %v", tt.in, err)
			continue
		}
		b, _ := toJSON(v)
		var got, want any
		json.Unmarshal(b, &got)
		json.Unmarshal([]byte(tt.want), &want)
		gb, _ := json.Marshal(got)
		wb, _ := json.Marshal(want)
		if string(gb) != string(wb) {
			t.Errorf("%q: %s, want %s", tt.in, gb, wb)
		}
	}
	for _, in := range []string{`{a: }`, `{a: 1`, `[1 2]`, `{'a': 'unterminated}`, `{a: 1} x`, `{a: undefined}`, ``, `{"a": "new` + "\n" + `line"}`} {
		if _, err := parseJSON5([]byte(in)); err == nil {
			t.Errorf("%q: no error", in)
		}
	}
}

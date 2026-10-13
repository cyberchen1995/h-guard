package command

import (
	"path"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Redirections 返回该单元各段的重定向（见 Redirections 函数）；非 POSIX 单元没有（PowerShell 在 M3）。
func (u Unit) Redirections() []string {
	if u.Shell != guard.ShellPOSIX {
		return nil
	}
	return Redirections(u.Text)
}

// Redirections 返回 cmd 各段的重定向，每个写成「命令词 + 空格 + 文件描述符 + 运算符 + 目标词」，
// 例如 `dd if=x 2>"/dev/sda"` → "dd 2>/dev/sda"（评审 R3-01：重定向的判断交给词法分析，不从原文猜）：
//   - 命令词与 NormalizedPositions 一样取去引号后路径的最后一段；段里没有命令词时为空
//     （组合命令的 `( … ) >/dev/sda`，以及 bash 的 `&>` 被切成后台运算符之后的那一段）；
//   - 文件描述符是紧贴运算符的数字；
//   - 目标词取去掉引号与转义后的完整值，不做展开（2>"/dev/null"b0 的目标是 /dev/nullb0）。
//
// 运算符、词与注释由词法分析区分：注释与引号里的 > 不是重定向，转义的空格不会让后面的 # 变成注释。
// heredoc（<<）不算重定向。
func Redirections(cmd string) []string {
	lx := lex(cmd)
	var out []string
	for _, seg := range lx.segments() {
		words, k := commandStart(lx, seg)
		name := ""
		if k < len(words) && words[k].value != "" {
			name = path.Base(words[k].value)
		}
		for i, t := range seg.tokens {
			if t.kind != tokRedir {
				continue
			}
			fd := ""
			if p := i - 1; p >= 0 && seg.tokens[p].kind == tokWord && seg.tokens[p].end == t.start && isDigits(seg.tokens[p].value) {
				fd = seg.tokens[p].value
			}
			target := ""
			if n := i + 1; n < len(seg.tokens) && seg.tokens[n].kind == tokWord {
				target = seg.tokens[n].value
			}
			out = append(out, name+" "+fd+t.op+target)
		}
	}
	return out
}

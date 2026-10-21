// Package command 把一条命令展开成需要逐一检查的文本单元：原命令本身（剥离数据 heredoc），
// 以及从中提取出的内层命令——命令替换 $(…)、反引号与进程替换、不带引号的数据 heredoc 中的命令替换、
// 交给解释器的 heredoc 正文、bash -c 等嵌套调用的脚本；PowerShell 的对应写法见 pwsh_expand.go。
// 内层命令可以换 shell（POSIX 里的 pwsh -c、PowerShell 里的 bash -c 与 wsl），每个单元记下自己的 shell。
// 每个单元再提供三种视图：全文、命令位置、去引号。
// 切段、去前缀、去引号与 heredoc 识别共用同一个 POSIX 词法分析（lex.go）。
//
// 只做展开，不做匹配；规则匹配在规则包中完成。POSIX shell 的词法在 lex.go，PowerShell 的在 pwsh.go。
package command

import (
	"context"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// MaxDepth 是内层命令的最大递归深度。更深的内容不再展开，按原文匹配。
const MaxDepth = 3

// Unit 是一段要按命令检查的文本。
type Unit struct {
	Text  string      // 剥离数据 heredoc 后的全文；超过深度的单元为原文
	Depth int         // 0 为原命令
	Shell guard.Shell // 该单元所用的 shell
	// Encoded 为真表示单元来自 -EncodedCommand 解码出的内容（含其中再展开的单元），规则 obfuscated_exec 据此识别
	Encoded bool
	joined  string // 去掉续行后的全文（没有续行时为空）
}

// FullTexts 返回全文匹配用的文本：原文，以及去掉续行后的版本（rm -r\ 换行 f 与 rm -rf 等价）。
// 哪些反斜杠换行是续行由词法分析按上下文确认：单引号、$'…'、注释与带引号定界符的 heredoc 正文里的不是。
func (u Unit) FullTexts() []string {
	if u.joined == "" {
		return []string{u.Text}
	}
	return []string{u.Text, u.joined}
}

// Positions 返回该单元各段处于命令位置的文本（POSIX 见 CommandPositions，PowerShell 见 pwsh.go）。
func (u Unit) Positions() []string {
	if u.Shell == guard.ShellPowerShell {
		return pwshPositions(pwshLex(u.Text))
	}
	return CommandPositions(u.Text)
}

// NormalizedPositions 返回该单元各段命令位置的规范写法（POSIX 见 NormalizedPositions，PowerShell 见 pwsh.go）。
func (u Unit) NormalizedPositions() []string {
	if u.Shell == guard.ShellPowerShell {
		return pwshNormalized(pwshLex(u.Text))
	}
	return NormalizedPositions(u.Text)
}

// Unquoted 返回抹掉引号内容后的文本（POSIX 见 StripQuoted，PowerShell 见 pwsh.go）。
func (u Unit) Unquoted() string {
	if u.Shell == guard.ShellPowerShell {
		return pwshUnquoted(pwshLex(u.Text))
	}
	return StripQuoted(u.Text)
}

// Expansion 是一条命令展开的结果。
type Expansion struct {
	Units []Unit
	// Limited 为真表示有内容因超过 MaxDepth 未再展开、按原文检查（只用于记录，不影响结论）。
	Limited bool
}

// Expand 展开 cmd。每展开一个单元前检查 ctx，预算耗尽时返回 ctx 的错误与已展开的部分。单元数不设上限：
// 同一深度的单元是互不重叠的原文片段，总量与命令长度成线性（至多 MaxDepth+1 层）；数量再多也不丢弃内容，
// 耗时由截止时间约束。
func Expand(ctx context.Context, cmd string, shell guard.Shell) (Expansion, error) {
	var e Expansion
	err := e.expand(ctx, cmd, shell, 0, 0)
	return e, err
}

// maxBlocks 限制 PowerShell 脚本块、括号与子表达式的嵌套层数（它们不消耗 MaxDepth）。
const maxBlocks = 64

func (e *Expansion) expand(ctx context.Context, text string, shell guard.Shell, depth, blocks int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > MaxDepth || blocks > maxBlocks {
		e.Limited = true
		e.Units = append(e.Units, Unit{Text: text, Depth: depth, Shell: shell})
		return nil
	}
	var inner []nested
	if shell == guard.ShellPowerShell {
		text = pwshNormalize(text) // Unicode 破折号与中文引号换成 ASCII 写法
		stripped, sub := pwshExpand(text)
		u := Unit{Text: stripped, Depth: depth, Shell: shell}
		if lx := pwshLex(stripped); len(lx.conts) > 0 {
			u.joined = lx.join(0, len(stripped)) // 反引号续行与代码里的转义反引号
		}
		e.Units = append(e.Units, u)
		inner = sub
	} else {
		stripped, expandable, executed := stripHeredocs(text)
		u := Unit{Text: stripped, Depth: depth, Shell: shell}
		if lx := lex(stripped); len(lx.conts) > 0 {
			u.joined = lx.join(0, len(stripped)) // 续行由词法分析按上下文确认
		}
		e.Units = append(e.Units, u)
		for _, b := range expandable {
			for _, s := range substitutions(b) {
				inner = append(inner, nested{text: s, shell: shell})
			}
		}
		inner = append(inner, executed...) // 交给解释器的正文：全文已在本单元里，另按命令切段检查
		for _, s := range codeSubstitutions(stripped) {
			inner = append(inner, nested{text: s, shell: shell})
		}
		inner = append(inner, nestedScripts(stripped)...)
		if r := rewritten(stripped); r != "" {
			inner = append(inner, nested{text: r, shell: shell})
		}
	}
	for _, n := range inner {
		if strings.TrimSpace(n.text) == "" {
			continue
		}
		d, b := depth+1, 0
		if n.block {
			d, b = depth, blocks+1
		}
		start := len(e.Units)
		err := e.expand(ctx, n.text, n.shell, d, b)
		if n.encoded {
			for i := start; i < len(e.Units); i++ {
				e.Units[i].Encoded = true
			}
		}
		if err != nil {
			return err
		}
	}
	return nil
}

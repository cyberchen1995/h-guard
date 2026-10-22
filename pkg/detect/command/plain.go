package command

import "strings"

// 去引号与转义的视图（plain）：把每个「简单词」换成 shell 去掉引号与转义之后的值，其余原文不动（只去掉续行）。
// rm /opt/\p\i/x 删的是 /opt/pi/x，hermes 'plugins' disable 与 hermes plugins disable 等价，
// PowerShell 的 R`emove-Item、'plugins' 同理；规则按原文写的模式在这个视图上同样命中（只收紧）。
//
// 简单词是去掉引号与转义之后不含空白、换行、运算符、引号、反引号与 # 的词：换成值之后词的边界不变，
// 引号里的数据（echo "rm -rf ~"）不会被拆成几个词、也不会露出分段符。命令替换、子表达式、脚本块
// 保留原文，所以含它们的词不是简单词，原样保留。POSIX 的值里有反斜杠（$'…'、"\\"）时同样原样保留。

// plainPOSIX 返回 POSIX 单元的去引号与转义视图；与 join 之后的全文相同时返回空串。
func plainPOSIX(lx lexed) string {
	changed := false
	for _, t := range lx.tokens {
		if t.kind == tokWord && t.quoted && plainWord(t.value, false) {
			changed = true
			break
		}
	}
	if !changed {
		return ""
	}
	var sb strings.Builder
	last := 0
	for _, t := range lx.tokens {
		if t.kind != tokWord || !t.quoted || !plainWord(t.value, false) {
			continue
		}
		sb.WriteString(lx.join(last, t.start))
		sb.WriteString(t.value)
		last = t.end
	}
	sb.WriteString(lx.join(last, len(lx.src)))
	return sb.String()
}

// plainPwsh 返回 PowerShell 单元的去引号与转义视图；与 join 之后的全文相同时返回空串。
// 代码里的转义反引号已由 join 去掉，这里只多换掉带引号的简单词。
func plainPwsh(lx pwLexed) string {
	quoted := func(t pwToken) bool {
		return t.kind == tokWord && strings.ContainsAny(lx.src[t.start:t.end], `'"`) && plainWord(t.value, true)
	}
	changed := false
	for _, t := range lx.tokens {
		if quoted(t) {
			changed = true
			break
		}
	}
	if !changed {
		return ""
	}
	var sb strings.Builder
	last := 0
	for _, t := range lx.tokens {
		if !quoted(t) {
			continue
		}
		sb.WriteString(lx.join(last, t.start))
		sb.WriteString(t.value)
		last = t.end
	}
	sb.WriteString(lx.join(last, len(lx.src)))
	return sb.String()
}

// plainWord 报告去引号后的值 v 能否原样代替原词：不含空白、换行、运算符、引号、反引号与 #；
// POSIX（pwsh 为假）另不能含反斜杠；PowerShell 另不能含花括号、逗号与 @（脚本块、数组与 here-string 的写法）。
func plainWord(v string, pwsh bool) bool {
	bad := " \t\r\f\v\n;&|()<>'\"`#"
	if pwsh {
		bad += "{},@"
	} else {
		bad += `\`
	}
	return !strings.ContainsAny(v, bad)
}

// distinct 返回 v；v 与 others 中任一相同时返回空串（不多匹配一遍相同的文本）。
func distinct(v string, others ...string) string {
	for _, o := range others {
		if v == o {
			return ""
		}
	}
	return v
}

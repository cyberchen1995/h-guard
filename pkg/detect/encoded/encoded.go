// Package encoded 识别把编码过的内容交给解释器执行的命令（规则 obfuscated_exec）。只判断有没有，不解码：
// 编码的方式很多（base64、hex、printf 转义、[char] 拼接……），逐一解码既复杂又覆盖不全；编码本身就说明看不出
// 实际执行的是什么，交给人确认。
//
// 三种情形算编码执行：
//   - 解码的写法与执行的写法出现在同一段命令里（echo … | base64 -d | sh、iex (… FromBase64String …)）；
//   - PowerShell 的 -EncodedCommand（含前缀写法 -enc、-e、-ec）；
//   - 一段高熵内容（secrets.HighEntropy，40 个字符起，凭据形状除外）直接交给 eval、sh -c、iex 这类执行写法。
//
// 只解码不执行（base64 -d 写进文件）、只执行不编码（curl … | sh）、哈希与 UUID 都不算。
package encoded

import (
	"regexp"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// minBlob 是直接交给执行写法的内容算作编码所需的最短长度。
const minBlob = 40

var (
	// encodedCommand 是 pwsh / powershell 的 -EncodedCommand 及其前缀写法（-e、-ec、-enc…），POSIX 里调用同样算。
	encodedCommand = regexp.MustCompile(`(?i)\b(?:pwsh|powershell)(?:\.exe)?\b[^\n|;]*?\s-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?:\s|:|$)`)

	// POSIX：解码的写法与执行的写法
	posixDecode = regexp.MustCompile(`(?i)\b(?:g?base64|base32|basenc)\b[^|;&\n]*\s(?:-d|--decode)\b|\bbase64\b[^|;&\n]*\s-D\b|\bxxd\b[^|;&\n]*\s-r|\bopenssl\b[^|;&\n]*\s-d\b|\bprintf\b[^|;&\n]*(?:\\x[0-9a-f]{2}.?){4}|\bprintf\b[^|;&\n]*(?:\\[0-7]{3}.?){4}|\buudecode\b`)
	posixExec   = regexp.MustCompile(`\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:sh|bash|zsh|dash|ksh|python[0-9.]*|perl|ruby|node|php)\b|\b(?:eval|source)\b|(?:^|[;&|(]\s*)\.\s|\b(?:sh|bash|zsh|dash|ksh)\s+-c\b`)
	// 直接执行一段文本的写法（高熵内容交给它们算编码执行）
	posixRun = regexp.MustCompile(`\b(?:eval|source)\b|\b(?:sh|bash|zsh|dash|ksh)\s+-c\b|\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*/)?(?:sh|bash|zsh|dash|ksh)\b`)

	// 内联解释器：解码函数与执行函数同时出现
	inline       = regexp.MustCompile(`\b(?:python[0-9.]*|perl|ruby|node|php)\b[^\n]*?\s-[cer]\b`)
	inlineDecode = regexp.MustCompile(`(?i)b64decode|b32decode|a85decode|unhexlify|fromhex|atob\s*\(|Buffer\.from\([^)]*['"](?:base64|hex)['"]|decode_base64|MIME::Base64|unpack\(\s*['"][mH]|codecs\.decode|\.decode\(\s*['"](?:base64|hex|rot.?13)`)
	inlineExec   = regexp.MustCompile(`\b(?:exec|eval|system|popen|subprocess|spawn|spawnSync|execSync|execFileSync|child_process|passthru|shell_exec)\b`)

	// PowerShell：解码的写法与执行的写法
	psDecode = regexp.MustCompile(`(?i)FromBase64String|FromHexString|\[char\]\s*\d+\s*\+|-bxor\b|\[char\[\]\]|-join\s*\(?\s*\[char`)
	psExec   = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b|\[scriptblock\]::create|\.invokescript\s*\(`)

	// token 是可能编码过的一段内容
	token = regexp.MustCompile(`[A-Za-z0-9+/=_-]{40,}`)
)

// Find 报告 text（一段命令，按 shell 的写法）是否把编码过的内容交给解释器执行。
func Find(text string, shell guard.Shell) bool {
	if encodedCommand.MatchString(text) {
		return true
	}
	if shell == guard.ShellPowerShell {
		return psExec.MatchString(text) && (psDecode.MatchString(text) || hasBlob(text))
	}
	switch {
	case posixDecode.MatchString(text) && posixExec.MatchString(text):
		return true
	case inline.MatchString(text) && inlineDecode.MatchString(text) && inlineExec.MatchString(text):
		return true
	}
	return posixRun.MatchString(text) && hasBlob(text)
}

// hasBlob 报告 text 里有没有一段高熵内容；凭据形状（token、key）是另一回事，不算。
func hasBlob(text string) bool {
	creds := secrets.Find(text)
	for _, loc := range token.FindAllStringIndex(text, -1) {
		overlaps := false
		for _, h := range creds {
			if h.Start < loc[1] && loc[0] < h.End {
				overlaps = true
				break
			}
		}
		if !overlaps && secrets.HighEntropy(text[loc[0]:loc[1]], minBlob) {
			return true
		}
	}
	return false
}

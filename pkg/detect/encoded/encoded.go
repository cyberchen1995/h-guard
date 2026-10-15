// Package encoded 识别把编码过的内容交给解释器执行的命令（规则 obfuscated_exec）。只判断有没有，不解码：
// 编码的方式很多（base64、hex、printf 转义、[char] 拼接……），逐一解码既复杂又覆盖不全；编码本身就说明看不出
// 实际执行的是什么，交给人确认。PowerShell 的 -EncodedCommand 由命令展开标出（command.Unit.Encoded），不在这里。
//
// 只认结构，不认文本里出现的词：
//   - POSIX：同一条管道里解码的一段（base64 -d、xxd -r、openssl -d、printf 转义……）之后有一段从标准输入读程序的
//     shell 或解释器（sh、bash -s、python3、python3 -；python3 -m json.tool、jq、bash script.sh 读的是数据）；
//     shell 读进程替换或命令替换（bash <(…)、source <(…)、eval "$(…)"）而其中有解码的一段；内联解释器
//     （python -c、node -e…）的代码里既有解码函数又有执行函数；
//   - PowerShell：解码的写法（FromBase64String、[char] 拼接、-bxor）与执行的写法（iex、ScriptBlock::Create、经
//     Get-Command 或 [char] 拼出的调用）同时出现；
//   - 一段高熵内容（secrets.HighEntropy，40 个字符起；路径与凭据形状除外）就是被执行的那段：eval 的参数、sh -c 的
//     命令、iex 的参数、ScriptBlock::Create 的字符串。
package encoded

import (
	"path"
	"regexp"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// minBlob 是直接被执行的内容算作编码所需的最短长度。
const minBlob = 40

var (
	// 进程替换或命令替换交给 shell 执行：bash <(…)、bash < <(…)、source <(…)、. <(…)、eval "$(…)"、bash -c "$(…)"
	substitutionRun = regexp.MustCompile(`(?i)(?:\beval|\b(?:sh|bash|zsh|dash|ksh|mksh|ash)(?:\s+-c)?|\bsource|(?:^|[;&|(]\s*)\.)\s+(?:<\s*)?["']?(?:\$\(|<\()`)

	inlineDecode = regexp.MustCompile(`(?i)b64decode|b32decode|a85decode|unhexlify|fromhex|atob\s*\(|Buffer\.from\([^)]*['"](?:base64|hex)['"]|decode_base64|MIME::Base64|unpack\(\s*['"][mH]|codecs\.decode|\.decode\(\s*['"](?:base64|hex|rot.?13)`)
	inlineExec   = regexp.MustCompile(`\b(?:exec|eval|system|popen|subprocess|spawn|spawnSync|execSync|execFileSync|child_process|passthru|shell_exec)\b`)

	psDecode = regexp.MustCompile(`(?i)FromBase64String|FromHexString|\[char\]\s*\d+\s*\+|-bxor\b|\[char\[\]\]|-join\s*\(?\s*\[char`)
	psExec   = regexp.MustCompile(`(?i)\b(?:iex|invoke-expression)\b|\[scriptblock\]::create|\.invokescript\s*\(|[&.]\s*\(\s*(?:gcm|get-command|\[char\])`)
	// 直接交给 iex、ScriptBlock::Create 的一段内容
	psRunArg = regexp.MustCompile(`(?i)(?:\b(?:iex|invoke-expression)\s+|\[scriptblock\]::create\(\s*)(?:'([^']+)'|"([^"]+)"|([^\s;|)'"]+))`)

	escapes = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}).*(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}).*(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}).*(?:\\x[0-9a-fA-F]{2}|\\[0-7]{3})`)
)

var (
	shells       = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "ash": true, "$shell": true, "${shell}": true}
	interpreters = []string{"python", "perl", "ruby", "node", "php"}
)

// Find 报告 text（一个命令单元，按 shell 的写法）是否把编码过的内容交给解释器执行。
func Find(text string, shell guard.Shell) bool {
	if shell == guard.ShellPowerShell {
		if psExec.MatchString(text) && psDecode.MatchString(text) {
			return true
		}
		for _, m := range psRunArg.FindAllStringSubmatch(text, -1) {
			if blob(m[1] + m[2] + m[3]) {
				return true
			}
		}
		return false
	}
	text = strings.NewReplacer("${IFS}", " ", "$IFS", " ").Replace(text)
	pipes := command.Pipelines(text)
	for _, p := range pipes {
		decoded := false
		for _, stage := range p {
			switch {
			case decoded && stdinProgram(stage):
				return true
			case decoder(stage):
				decoded = true
			}
			if direct(stage) || inline(stage) {
				return true
			}
		}
	}
	// 交给 shell 的进程替换、命令替换里有解码的一段
	for _, loc := range substitutionRun.FindAllStringIndex(text, -1) {
		for _, p := range command.Pipelines(text[loc[1]:]) {
			for _, stage := range p {
				if decoder(stage) {
					return true
				}
			}
		}
	}
	return false
}

// name 返回一段命令的命令名（小写、取路径最后一段、去掉 .exe）与参数；busybox 之后的才是命令。
func name(stage []string) (string, []string) {
	if len(stage) == 0 {
		return "", nil
	}
	n := strings.TrimSuffix(strings.ToLower(path.Base(stage[0])), ".exe")
	if n == "busybox" && len(stage) > 1 {
		return name(stage[1:])
	}
	return n, stage[1:]
}

// decoder 报告这一段是否在解码：base64 -d（含 -di、-D、--dec 等写法）、base32、basenc、xxd -r、openssl -d、
// uudecode，或带四个以上 \x、\NNN 转义的 printf、echo -e。
func decoder(stage []string) bool {
	n, args := name(stage)
	switch n {
	case "base64", "gbase64", "base32", "gbase32", "basenc":
		for _, a := range args {
			if shortFlags(a) && strings.ContainsAny(a, "dD") || len(a) >= 3 && strings.HasPrefix("--decode", a) {
				return true
			}
		}
	case "xxd":
		for _, a := range args {
			if shortFlags(a) && len(a) <= 4 && strings.Contains(a, "r") || len(a) >= 3 && strings.HasPrefix("-revert", a) {
				return true
			}
		}
	case "openssl":
		return contains(args, "-d")
	case "uudecode":
		return true
	case "printf", "echo":
		for _, a := range args {
			if escapes.MatchString(a) {
				return true
			}
		}
	}
	return false
}

// stdinProgram 报告这一段是否从标准输入读程序：shell 不带脚本文件（可以带 -s 等选项），解释器不带参数或只有 -。
// 带 -c、-e、-m 等的解释器与 jq、cat 这类程序读的是数据。
func stdinProgram(stage []string) bool {
	n, args := name(stage)
	if shells[n] {
		for _, a := range args {
			if a == "-c" || !isFlag(a) && a != "-" {
				return false
			}
		}
		return true
	}
	if !isInterpreter(n) {
		return false
	}
	for _, a := range args {
		if a == "-" {
			continue
		}
		if !isFlag(a) || strings.ContainsAny(strings.TrimLeft(a, "-"), "cemprnEil") {
			return false
		}
	}
	return true
}

// direct 报告一段高熵内容是否就是被执行的那段：eval 的参数、sh -c 的命令。
func direct(stage []string) bool {
	n, args := name(stage)
	switch {
	case n == "eval":
		return len(args) == 1 && blob(args[0])
	case shells[n]:
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				return blob(args[i+1])
			}
		}
	}
	return false
}

// inline 报告内联解释器（python -c、perl -e、node -e、ruby -e、php -r）的代码里是否既解码又执行。
func inline(stage []string) bool {
	n, args := name(stage)
	if !isInterpreter(n) {
		return false
	}
	for i, a := range args {
		if (a == "-c" || a == "-e" || a == "-r" || a == "-E") && i+1 < len(args) {
			return inlineDecode.MatchString(args[i+1]) && inlineExec.MatchString(args[i+1])
		}
	}
	return false
}

// blob 报告 v 整体是一段编码过的内容：高熵（secrets.HighEntropy），不是路径或 URL，也不是凭据形状。
func blob(v string) bool {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") ||
		strings.Contains(v, "://") || strings.Count(v, "/") >= 3 || strings.ContainsAny(v, " \t\n") {
		return false
	}
	return secrets.HighEntropy(v, minBlob) && len(secrets.Find(v)) == 0
}

// isFlag 报告 a 是选项（- 或 -- 开头；单独的 - 是标准输入，不算）。
func isFlag(a string) bool { return strings.HasPrefix(a, "-") && a != "-" }

// shortFlags 报告 a 是一组短选项（-d、-di），不是长选项。
func shortFlags(a string) bool { return isFlag(a) && !strings.HasPrefix(a, "--") }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// isInterpreter 报告 n 是否是解释器（python3、python3.12 这类带版本的也算）。
func isInterpreter(n string) bool {
	for _, p := range interpreters {
		if n == p || strings.HasPrefix(n, p) && strings.Trim(n[len(p):], "0123456789.") == "" {
			return true
		}
	}
	return false
}

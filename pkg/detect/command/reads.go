package command

import (
	"context"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// posixReaders 是输出文件内容的 POSIX 命令（读文件、按行筛选或转换文件内容）。
var posixReaders = map[string]bool{
	"cat": true, "tac": true, "nl": true, "head": true, "tail": true, "less": true, "more": true, "bat": true, "batcat": true,
	"sed": true, "awk": true, "gawk": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true,
	"cut": true, "sort": true, "uniq": true, "strings": true, "xxd": true, "hexdump": true, "od": true, "jq": true, "yq": true,
	"base64": true, "diff": true, "column": true,
	"zcat": true, "gzcat": true, "xzcat": true, "bzcat": true, "zstdcat": true, "lz4cat": true, "zless": true, "zmore": true, "zgrep": true,
}

// gitReaders 是输出文件内容的 git 子命令。
var gitReaders = map[string]bool{"show": true, "diff": true, "blame": true, "grep": true, "cat-file": true}

// pwshReaders 是输出文件内容的 PowerShell 命令与别名（不区分大小写）。
var pwshReaders = map[string]bool{
	"get-content": true, "gc": true, "cat": true, "type": true, "select-string": true, "sls": true,
	"import-csv": true, "ipcsv": true, "format-hex": true, "fhx": true,
}

// xargsArgOptions、gitArgOptions 是带一个独立参数的选项（参数写在下一个词里；写成 -n1、--opt=v 时不占下一个词）。
var (
	xargsArgOptions = map[string]bool{"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-a": true,
		"-J": true, "-R": true, "-S": true, "--arg-file": true, "--delimiter": true, "--max-args": true, "--max-procs": true,
		"--max-chars": true, "--process-slot-var": true}
	gitArgOptions = map[string]bool{"-C": true, "-c": true, "--git-dir": true, "--work-tree": true, "--namespace": true,
		"--config-env": true, "--super-prefix": true}
	// docker、podman exec 与 compose exec 带参数的选项
	containerArgOptions = map[string]bool{"-e": true, "--env": true, "--env-file": true, "-u": true, "--user": true, "-w": true,
		"--workdir": true, "--detach-keys": true, "--index": true}
	sshArgOptions = map[string]bool{"-p": true, "-i": true, "-l": true, "-o": true, "-F": true, "-J": true, "-L": true, "-R": true,
		"-D": true, "-E": true, "-b": true, "-c": true, "-m": true, "-O": true, "-Q": true, "-S": true, "-W": true, "-w": true, "-B": true}
	posixShells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true}
)

// afterOptions 跳过 args 开头的选项（argOptions 里的选项连同它的参数），在 -- 处结束，返回其后第一个词的下标；
// 没有时返回 len(args)。
func afterOptions(args []string, argOptions map[string]bool) int {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--":
			return i + 1
		case !strings.HasPrefix(a, "-") || a == "-":
			return i
		case argOptions[a]:
			i++
		}
	}
	return len(args)
}

// readerStage 报告一段命令是否读文件；xargs 与 find -exec 调用的命令也算。xargs 与 git 前面的选项
// （含带参数的，如 xargs -I {}、git -C <dir>）先跳过。
func readerStage(stage []string) bool {
	name := strings.ToLower(path.Base(stage[0]))
	switch {
	case posixReaders[name]:
		return true
	case name == "git":
		i := 1 + afterOptions(stage[1:], gitArgOptions)
		switch {
		case i >= len(stage):
			return false
		case stage[i] == "log", stage[i] == "whatchanged": // 带补丁的提交记录：git log -p
			return slices.ContainsFunc(stage[i+1:], func(a string) bool { return a == "-p" || a == "-u" || a == "--patch" })
		}
		return gitReaders[stage[i]]
	case posixShells[name]: // 容器、远程主机里的 sh -c '…'
		for i := 1; i+1 < len(stage); i++ {
			if stage[i] == "-c" {
				return ReadsFiles(stage[i+1], guard.ShellPOSIX)
			}
		}
	case name == "docker" || name == "podman": // docker exec [选项] 容器 命令…；docker compose exec 服务 命令…
		rest := stage[1:]
		if len(rest) > 0 && rest[0] == "compose" {
			rest = rest[1:]
		}
		if len(rest) == 0 || rest[0] != "exec" {
			return false
		}
		if i := 1 + afterOptions(rest[1:], containerArgOptions); i+1 < len(rest) {
			return readerStage(rest[i+1:])
		}
	case name == "kubectl" || name == "oc": // kubectl exec … -- 命令…
		if i := slices.Index(stage, "--"); i > 0 && slices.Contains(stage[1:i], "exec") && i+1 < len(stage) {
			return readerStage(stage[i+1:])
		}
	case name == "ssh": // ssh [选项] 主机 命令…：命令交给远端的 shell
		if i := 1 + afterOptions(stage[1:], sshArgOptions); i+1 < len(stage) {
			return ReadsFiles(strings.Join(stage[i+1:], " "), guard.ShellPOSIX)
		}
	case name == "xargs":
		if i := 1 + afterOptions(stage[1:], xargsArgOptions); i < len(stage) {
			return readerStage(stage[i:])
		}
	case name == "find":
		for i := 1; i+1 < len(stage); i++ {
			if stage[i] == "-exec" || stage[i] == "-execdir" || stage[i] == "-ok" {
				return readerStage(stage[i+1:])
			}
		}
	}
	return false
}

// pwshFileRead 是 PowerShell 里经 .NET 读文件的写法（[IO.File]::ReadAllText 等）。
var pwshFileRead = regexp.MustCompile(`(?i)\[(?:System\.)?IO\.File\]::Read(?:AllText|AllLines|AllBytes|Lines)\b`)

// ReadsFiles 报告命令是否把文件内容输出出来：任何一段（含嵌套的内层命令）是读文件的命令时为真。只按命令名认，
// 多认只会多扫描（outbound 第 2 档扫描这类工具输出，维护者决定 2026-10-15）。
//
// 认不出的（已知限制，第 3 档覆盖）：输入重定向读文件（tr a b < .env、while read … done < .env）、解释器读文件、
// cp X /dev/stdout，以及不在上面这些包装里的远程或容器命令。
func ReadsFiles(cmd string, shell guard.Shell) bool {
	e, _ := Expand(context.Background(), cmd, shell) // 没有截止时间，不会出错
	for _, u := range e.Units {
		if u.Shell == guard.ShellPowerShell {
			if pwshFileRead.MatchString(u.Text) {
				return true
			}
			for _, p := range u.NormalizedPositions() {
				name, rest, _ := strings.Cut(strings.ToLower(p), " ")
				name = strings.TrimSuffix(name, ".exe")
				if pwshReaders[name] {
					return true
				}
				// cmd /c type .env：cmd 的内层命令
				if f := strings.Fields(rest); name == "cmd" && len(f) > 1 && f[0] == "/c" && (f[1] == "type" || f[1] == "more") {
					return true
				}
			}
			continue
		}
		for _, pipe := range Pipelines(u.Text) {
			for _, stage := range pipe {
				if readerStage(stage) {
					return true
				}
			}
		}
	}
	return false
}

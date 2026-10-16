package command

import (
	"context"
	"path"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// posixReaders 是输出文件内容的 POSIX 命令（读文件、按行筛选或转换文件内容）。
var posixReaders = map[string]bool{
	"cat": true, "tac": true, "nl": true, "head": true, "tail": true, "less": true, "more": true, "bat": true, "batcat": true,
	"sed": true, "awk": true, "gawk": true, "grep": true, "egrep": true, "fgrep": true, "rg": true, "ag": true, "ack": true,
	"cut": true, "sort": true, "uniq": true, "strings": true, "xxd": true, "hexdump": true, "od": true, "jq": true, "yq": true,
	"base64": true, "diff": true,
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

// readerStage 报告一段命令是否读文件；xargs 与 find -exec 调用的命令也算（M4a 计划评审）。xargs 与 git 前面的选项
// （含带参数的，如 xargs -I {}、git -C <dir>）先跳过（M4a Codex 评审 M4A-04）。
func readerStage(stage []string) bool {
	name := strings.ToLower(path.Base(stage[0]))
	switch {
	case posixReaders[name]:
		return true
	case name == "git":
		i := 1 + afterOptions(stage[1:], gitArgOptions)
		return i < len(stage) && gitReaders[stage[i]]
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

// ReadsFiles 报告命令是否把文件内容输出出来：任何一段（含嵌套的内层命令）是读文件的命令时为真。只按命令名认，
// 多认只会多扫描（outbound 第 2 档扫描这类工具输出，维护者决定 2026-10-15）。
func ReadsFiles(cmd string, shell guard.Shell) bool {
	e, _ := Expand(context.Background(), cmd, shell) // 没有截止时间，不会出错
	for _, u := range e.Units {
		if u.Shell == guard.ShellPowerShell {
			for _, p := range u.NormalizedPositions() {
				name, _, _ := strings.Cut(strings.ToLower(p), " ")
				if pwshReaders[strings.TrimSuffix(name, ".exe")] {
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

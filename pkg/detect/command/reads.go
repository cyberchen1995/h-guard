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
				if inner := cmdInner(strings.Fields(rest)); name == "cmd" && len(inner) > 0 && (inner[0] == "type" || inner[0] == "more") {
					return true
				}
			}
			continue
		}
		if len(xargsArgFiles(u.Text)) > 0 {
			return true
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

// patternFirst 是第一个位置参数是模式或脚本、其后才是文件的读文件命令（用 -e、-f 给出模式时没有这个参数）。
var patternFirst = map[string]bool{
	"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "rg": true, "ag": true, "ack": true,
	"sed": true, "awk": true, "gawk": true, "jq": true, "yq": true,
}

// patternOptions 是给出模式或脚本的选项：有它们时第一个位置参数就是文件。
var patternOptions = map[string]bool{"-e": true, "-f": true, "--regexp": true, "--file": true, "--expression": true, "--from-file": true}

// patternFiles 是从文件读模式或脚本的选项：它们的值是一个被读取的文件（grep -f .env）。
var patternFiles = map[string]bool{"-f": true, "--file": true, "--from-file": true}

// readerArgOptions 是读文件命令带一个独立参数的常见选项（参数不是要读的文件），按命令分开：同一个选项在
// 不同命令里意思不同（head -n 5 与 sed -n）。
var readerArgOptions = func() map[string]map[string]bool {
	set := func(opts ...string) map[string]bool {
		m := map[string]bool{}
		for _, o := range opts {
			m[o] = true
		}
		return m
	}
	grep := set("-A", "-B", "-C", "-m", "--max-count", "-g", "--glob", "-t", "--type")
	return map[string]map[string]bool{
		"head": set("-n", "-c", "--lines", "--bytes"), "tail": set("-n", "-c", "--lines", "--bytes"),
		"cut": set("-d", "-f", "-c", "-b", "--delimiter", "--fields"), "sort": set("-k", "-t", "-o", "-S", "-T"),
		"grep": grep, "egrep": grep, "fgrep": grep, "zgrep": grep, "rg": grep, "ag": grep, "ack": grep,
		"awk": set("-F", "-v"), "gawk": set("-F", "-v"), "jq": set("--arg", "--argjson"), "yq": set("--arg"),
		"xxd": set("-l", "-s", "-c"), "od": set("-N", "-j", "-t"), "column": set("-s"),
	}
}()

// pwshPathOptions 是 Get-Content 等给出路径的参数；pwshSwitches 是不带值的开关，其余参数都带一个值。
var (
	pwshPathOptions = map[string]bool{"-path": true, "-literalpath": true, "-pspath": true, "-lp": true}
	pwshSwitches    = map[string]bool{"-raw": true, "-wait": true, "-force": true, "-asbytestream": true, "-simplematch": true,
		"-casesensitive": true, "-list": true, "-notmatch": true, "-quiet": true, "-allmatches": true, "-noemphasis": true,
		"-useculture": true, "-verbose": true, "-vb": true, "-debug": true, "-db": true, "-whatif": true, "-wi": true, "-confirm": true, "-cf": true}
	pwshReadAll = regexp.MustCompile(`(?i)\[(?:System\.)?IO\.File\]::Read(?:AllText|AllLines|AllBytes|Lines)\s*\(\s*['"]([^'"]+)['"]`)
)

// ReadTargets 返回命令在本机读取的文件：读文件命令（见 ReadsFiles）的文件参数、输入重定向（< 文件）的目标，
// 以及 PowerShell 的 Get-Content 等的路径参数。只按常见写法认（尽力而为，不是完整的隔离）：模式参数、
// 带值的常见选项会跳过；容器、远程主机里的命令与 xargs、find 交给的文件认不出。
func ReadTargets(cmd string, shell guard.Shell) []string {
	e, _ := Expand(context.Background(), cmd, shell) // 没有截止时间，不会出错
	var out []string
	add := func(p string) {
		p = homeVar.ReplaceAllString(p, "~/")
		if p != "" && p != "-" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, u := range e.Units {
		if u.Shell == guard.ShellPowerShell {
			for _, t := range pwshReadTargets(u.Text) {
				add(t)
			}
			continue
		}
		dir := ""         // 此前 cd 进入的目录：相对的 cd 接在它后面
		var dirs []string // 单元里 cd 进入过的全部目录：其后的相对路径与重定向另按每个解析（cd ~/.ssh && cat config）
		for _, pipe := range Pipelines(u.Text) {
			for _, stage := range pipe {
				if d, ok := cdTarget(stage, false); ok {
					dir = joinDir(dir, d)
					dirs = append(dirs, dir)
					continue
				}
				for _, t := range stageTargets(stage) {
					add(t)
					// 子 shell 里的 cd 不影响外面：不跟踪作用域，相对路径按进入过的每个目录都查一遍（只收紧）
					for _, d := range dirs {
						if isRelative(t) {
							add(joinDir(d, t))
						}
					}
				}
			}
		}
		for _, t := range xargsArgFiles(u.Text) {
			add(t)
		}
		for _, r := range u.Redirections() {
			// 「命令词 运算符目标」：只要读入的重定向（< 与 n<，不含 heredoc、here-string 与复制描述符）
			_, op, ok := strings.Cut(r, " ")
			op = strings.TrimLeft(op, "0123456789")
			if ok && strings.HasPrefix(op, "<") && !strings.HasPrefix(op, "<<") && !strings.HasPrefix(op, "<&") {
				t := strings.TrimPrefix(strings.TrimPrefix(op, "<"), ">")
				add(t)
				for _, d := range dirs {
					if isRelative(t) {
						add(joinDir(d, t))
					}
				}
			}
		}
	}
	return out
}

// homeVar 是路径开头的主目录变量（$HOME/、${HOME}/、PowerShell 的 $HOME\、$env:USERPROFILE\）：换成 ~/，
// 路径规则按配置的主目录判断，而不是当成工作目录下名为 $HOME 的目录。
var homeVar = regexp.MustCompile(`(?i)^(?:\$HOME|\$\{HOME\}|\$env:USERPROFILE|\$env:HOME)[/\\]`)

// pwshReadTargets 是 PowerShell 一个单元里读取的文件：按词法单元取参数（引号里带空格的路径是一个参数），
// .NET 的读文件调用只在代码里算（字符串、注释里提到的不算）。
func pwshReadTargets(text string) []string {
	lx := pwshLex(text)
	var out, items []string // items：上一段 Get-Item 等给出的路径，管道交给读文件命令（Get-Item .env | Get-Content）
	dir := ""
	prevEnd := -1
	for _, seg := range lx.segments() {
		if prevEnd >= 0 && strings.TrimSpace(text[prevEnd:seg.start]) != "|" {
			items = nil // 只有管道把上一段的输出交给这一段；; 与 && 不交
		}
		prevEnd = seg.end
		words, k, _ := lx.commandStart(seg)
		if k < len(words) {
			vals := make([]string, 0, len(words)-k)
			for _, w := range words[k:] {
				vals = append(vals, strings.Trim(w.value, `'"`))
			}
			if d, ok := cdTarget(vals, true); ok {
				dir = joinDir(dir, d)
				continue
			}
		}
		for _, w := range words {
			if pwshFileRead.MatchString(w.bare) {
				for _, m := range pwshReadAll.FindAllStringSubmatch(w.value, -1) {
					out = append(out, m[1])
				}
			}
		}
		if k < len(words) {
			vals := make([]string, 0, len(words)-k)
			for _, w := range words[k:] {
				if !strings.Contains(w.bare, ",") {
					vals = append(vals, w.value)
					continue
				}
				// 代码里的逗号分隔数组的元素（Get-Content README.md,.env），引号里的逗号不算
				for _, p := range strings.Split(w.value, ",") {
					if p != "" {
						vals = append(vals, p)
					}
				}
			}
			targets := pwshTargets(vals)
			name := pwshName(vals[0])
			if len(targets) == 0 && pwshReaders[name] {
				targets = items
			}
			items = nil
			if pwshItems[name] {
				vals[0] = "get-content" // 路径参数的写法相同
				items = pwshTargets(vals)
			}
			for _, t := range targets {
				out = append(out, t)
				if dir != "" && isRelative(t) {
					out = append(out, joinDir(dir, t))
				}
			}
		}
	}
	return out
}

// pwshPathOption 报告 opt 是不是给出路径的参数：全名、别名，或 PowerShell 接受的前缀写法（-Pa、-Lit）。
func pwshPathOption(opt string) bool {
	return pwshPathOptions[opt] || (len(opt) >= 3 && strings.HasPrefix("-path", opt)) ||
		(len(opt) >= 4 && strings.HasPrefix("-literalpath", opt))
}

// pwshName 是 PowerShell 命令词的小写名字：去掉模块限定（Microsoft.PowerShell.Management\Get-Content）与 .exe。
func pwshName(w string) string {
	w = strings.ToLower(w)
	w = w[strings.LastIndex(w, `\`)+1:]
	return strings.TrimSuffix(w, ".exe")
}

// xargsArgFiles 是 xargs -a FILE / --arg-file=FILE 读取参数的文件。xargs 是前缀词，命令段里看不到它的选项，
// 这里按原文的各段找。
func xargsArgFiles(text string) []string {
	var out []string
	lx := lex(text)
	for _, seg := range lx.segments() {
		var f []string // 词的值（引号已去掉，带空格的路径是一个词）
		for _, t := range seg.tokens {
			if t.kind == tokWord {
				f = append(f, t.value)
			}
		}
		for i := 0; i < len(f); i++ {
			if path.Base(f[i]) != "xargs" {
				continue
			}
			for j := i + 1; j < len(f) && strings.HasPrefix(f[j], "-"); j++ {
				switch {
				case (f[j] == "-a" || f[j] == "--arg-file") && j+1 < len(f):
					out = append(out, f[j+1])
					j++
				case strings.HasPrefix(f[j], "--arg-file="):
					out = append(out, strings.TrimPrefix(f[j], "--arg-file="))
				case strings.HasPrefix(f[j], "-a") && len(f[j]) > 2:
					out = append(out, f[j][2:])
				case xargsArgOptions[f[j]] && j+1 < len(f):
					j++
				}
			}
		}
	}
	return out
}

// cmdInner 返回 cmd 的 /c 或 /k 之后的内层命令（之前的 /d、/s、/q 等选项跳过）；没有时为空。
func cmdInner(args []string) []string {
	for i, a := range args {
		switch strings.ToLower(a) {
		case "/c", "/k":
			return args[i+1:]
		}
		if !strings.HasPrefix(a, "/") {
			return nil
		}
	}
	return nil
}

// gitNoIndexTargets 是 git diff --no-index 比较的两个文件系统路径；其他 git 命令读的是仓库内容，不算。
func gitNoIndexTargets(stage []string) []string {
	i := 1 + afterOptions(stage[1:], gitArgOptions)
	if i >= len(stage) || stage[i] != "diff" || !slices.Contains(stage[i+1:], "--no-index") {
		return nil
	}
	var out []string
	for _, a := range stage[i+1:] {
		if a != "--" && !strings.HasPrefix(a, "-") {
			out = append(out, a)
		}
	}
	return out
}

// pwshItems 是输出文件对象、可以经管道交给 Get-Content 的命令。
var pwshItems = map[string]bool{"get-item": true, "gi": true, "get-childitem": true, "gci": true, "dir": true, "ls": true}

// cdTarget 报告一段命令是不是切换目录（cd，PowerShell 另有 Set-Location 等），是时返回目标目录。
func cdTarget(words []string, pwsh bool) (string, bool) {
	if len(words) == 0 {
		return "", false
	}
	switch strings.ToLower(words[0]) {
	case "cd", "pushd":
	case "set-location", "sl", "chdir", "push-location":
		if !pwsh {
			return "", false
		}
	default:
		return "", false
	}
	for i := 1; i < len(words); i++ {
		w := strings.ToLower(words[i])
		if pwsh && (w == "-path" || w == "-literalpath") && i+1 < len(words) {
			return words[i+1], true
		}
		if !strings.HasPrefix(w, "-") {
			return words[i], true
		}
	}
	return "~", true // 不带参数的 cd 回到主目录
}

// isRelative 报告路径是否相对于工作目录（不以 /、~、盘符或主目录变量开头）。
func isRelative(p string) bool {
	return p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, `\`) && !strings.HasPrefix(p, "~") &&
		!strings.HasPrefix(p, "$") && !(len(p) > 1 && p[1] == ':')
}

// joinDir 把 p 接在目录 dir 后面；p 不是相对路径或 dir 为空时就是 p。
func joinDir(dir, p string) string {
	p = homeVar.ReplaceAllString(p, "~/")
	if dir == "" || !isRelative(p) {
		return p
	}
	return strings.TrimSuffix(dir, "/") + "/" + p
}

// stageTargets 是一段读文件命令的文件参数（不是读文件的命令时为空）。
func stageTargets(stage []string) []string {
	name := strings.ToLower(path.Base(stage[0]))
	if name == "git" {
		return gitNoIndexTargets(stage)
	}
	if !posixReaders[name] {
		return nil
	}
	var pos []string
	skipPattern := patternFirst[name]
	for i := 1; i < len(stage); i++ {
		a := stage[i]
		switch {
		case a == "--":
			pos = append(pos, stage[i+1:]...)
			i = len(stage)
		case patternOptions[a]:
			skipPattern = false
			if patternFiles[a] && i+1 < len(stage) {
				pos = append(pos, stage[i+1]) // -f FILE：模式从文件里读，这个文件同样被读取
			}
			i++
		case readerArgOptions[name][a]:
			i++
		case strings.HasPrefix(a, "-") && a != "-":
			if strings.HasPrefix(a, "--regexp=") || strings.HasPrefix(a, "--file=") || strings.HasPrefix(a, "--expression=") ||
				strings.HasPrefix(a, "--from-file=") {
				skipPattern = false
			}
			if opt, v, ok := strings.Cut(a, "="); ok && patternFiles[opt] && v != "" {
				pos = append(pos, v)
			}
			if skipPattern && !strings.HasPrefix(a, "--") {
				// 短选项组里的 -e、-f：在末尾时下一个参数是模式（-ie PATTERN），否则其后是模式本身（-ePATTERN）
				for j := 1; j < len(a); j++ {
					if patternOptions["-"+a[j:j+1]] {
						skipPattern = false
						file := patternFiles["-"+a[j:j+1]]
						switch {
						case j < len(a)-1 && file:
							pos = append(pos, a[j+1:]) // -fFILE
						case j == len(a)-1 && file && i+1 < len(stage):
							pos = append(pos, stage[i+1])
						}
						if j == len(a)-1 {
							i++
						}
						break
					}
				}
			}
		default:
			pos = append(pos, a)
		}
	}
	if skipPattern && len(pos) > 0 {
		pos = pos[1:]
	}
	return pos
}

// pwshTargets 是 PowerShell 一段读文件命令的路径参数。
func pwshTargets(words []string) []string {
	if len(words) == 0 {
		return nil
	}
	name := pwshName(words[0])
	if name == "cmd" {
		if inner := cmdInner(words[1:]); len(inner) > 0 {
			if n := strings.ToLower(inner[0]); n == "type" || n == "more" {
				return unquoteAll(inner[1:])
			}
		}
		return nil
	}
	if !pwshReaders[name] {
		return nil
	}
	// Select-String 的第一个位置参数是模式（用 -Pattern 给出时没有这个参数），其后才是路径
	skipPattern := name == "select-string" || name == "sls"
	var out, pos []string
	for i := 1; i < len(words); i++ {
		w := strings.ToLower(words[i])
		opt, val, bound := strings.Cut(w, ":")
		if opt == "-pattern" {
			skipPattern = false
		}
		switch {
		case strings.HasPrefix(w, "-") && bound && val != "":
			// -Path:.env：值跟在冒号后面，同一个词
			if pwshPathOption(opt) {
				out = append(out, words[i][len(opt)+1:])
			}
		case pwshPathOption(opt) && i+1 < len(words):
			out = append(out, words[i+1])
			i++
		case pwshSwitches[w]:
		case strings.HasPrefix(w, "-"):
			i++ // 其余参数带一个值（-TotalCount 5、-Encoding utf8）
		default:
			pos = append(pos, words[i])
		}
	}
	if skipPattern && len(pos) > 0 {
		pos = pos[1:]
	}
	return unquoteAll(append(out, pos...))
}

func unquoteAll(ws []string) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, strings.Trim(w, `'"`))
	}
	return out
}

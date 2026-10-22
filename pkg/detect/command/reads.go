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
				// cmd /c type .env：cmd 的内层命令（cmd /c "type .env" 里的同样按 cmd 的写法切开）
				if name == "cmd" && slices.ContainsFunc(cmdCommands(rest), func(c []string) bool { return cmdReaders[strings.ToLower(c[0])] }) {
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
	search := []string{"-A", "-B", "-C", "-m", "--max-count", "-g", "--glob", "-t", "--type"}
	grep := set(append(search, "-d", "--directories", "-D", "--devices", "--include", "--exclude", "--exclude-dir",
		"--exclude-from", "--label")...)
	// rg 的 -r 是替换文本（不是递归）
	rg := set(append(search, "-r", "--replace", "-T", "--type-not", "-j", "--threads", "-M", "--max-columns", "-E",
		"--encoding", "-d", "--max-depth", "--iglob", "--ignore-file", "--type-add", "--sort", "--sortr", "--pre",
		"--pre-glob", "--context-separator", "--path-separator")...)
	ag := set(append(search, "-G", "--file-search-regex", "--ignore", "--ignore-dir", "--depth", "-p", "--path-to-ignore")...)
	ack := set(append(search, "--ignore-dir", "--noignore-dir", "--ignore-file", "--type-set", "--type-add")...)
	return map[string]map[string]bool{
		"head": set("-n", "-c", "--lines", "--bytes"), "tail": set("-n", "-c", "--lines", "--bytes"),
		"cut": set("-d", "-f", "-c", "-b", "--delimiter", "--fields"), "sort": set("-k", "-t", "-o", "-S", "-T"),
		"grep": grep, "egrep": grep, "fgrep": grep, "zgrep": grep, "rg": rg, "ag": ag, "ack": ack,
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

// ReadTarget 是命令读取的一个文件参数，以及在磁盘上展开它要知道的写法（见 ReadTargetList）。
type ReadTarget struct {
	// Path 是参数的值：引号与转义已去掉，开头的主目录变量写作 ~/。
	Path string
	// Shell 是展开这个参数的 shell（cmd /c 里的算 PowerShell）。
	Shell guard.Shell
	// Glob 为真表示通配符（* ? [）在运行时生效：POSIX 里参数在引号与转义之外有通配符；PowerShell 里不是
	// -LiteralPath 与 .NET 的读文件调用。为假时 Path 按字面就是要读的文件（cat '.env*' 读名为 .env* 的文件）。
	Glob bool
	// Brace 为真表示花括号展开（{a,b}、{a..z}）生效：只有 POSIX shell 有，且花括号在引号与转义之外。
	Brace bool
	// Walk 不为空表示 Path 是目录时递归读取其中的文件（grep -r、rg）。
	Walk *Walk
}

// Walk 是递归读取目录的方式。命令行上给出的目录本身总是读取，下面几项只管其中的文件与子目录。
type Walk struct {
	Hidden     bool     // 也读以点开头的文件与目录（grep -r 读；rg、ag 默认跳过）
	Follow     bool     // 跟随目录里的符号链接（grep -R、rg -L）；为假时目录里的符号链接跳过
	Include    []string // 只读文件名匹配其中之一的文件（grep --include、rg -g）；为空时不限
	Exclude    []string // 跳过文件名匹配的文件（grep --exclude、rg -g '!…'）
	ExcludeDir []string // 跳过目录名匹配的目录（grep --exclude-dir）
}

// ReadTargets 返回命令在本机读取的文件：读文件命令（见 ReadsFiles）的文件参数、输入重定向（< 文件）的目标，
// 以及 PowerShell 的 Get-Content 等的路径参数。只按常见写法认（尽力而为，不是完整的隔离）：模式参数、
// 带值的常见选项会跳过；容器、远程主机里的命令与 xargs、find 交给的文件认不出。递归读取（grep -r、rg）
// 给出的是目录，没有给出路径时是工作目录（.）。
// 要知道参数里的通配符、花括号是否生效、目录是否递归读取时用 ReadTargetList。
func ReadTargets(cmd string, shell guard.Shell) []string {
	var out []string
	for _, t := range ReadTargetList(cmd, shell) {
		out = append(out, t.Path)
	}
	return out
}

// ReadTargetList 与 ReadTargets 相同，每个文件另带展开它要知道的写法（ReadTarget）。同一个路径只出现一次：
// 多处写到时取更宽的展开方式（只收紧）。
func ReadTargetList(cmd string, shell guard.Shell) []ReadTarget {
	e, _ := Expand(context.Background(), cmd, shell) // 没有截止时间，不会出错
	var out []ReadTarget
	add := func(t ReadTarget, pwsh bool) {
		t.Path, t.Shell = normHome(t.Path, pwsh), guard.ShellPOSIX
		if pwsh {
			t.Shell = guard.ShellPowerShell
		}
		if t.Path == "" || t.Path == "-" {
			return
		}
		for i := range out {
			if out[i].Path == t.Path {
				out[i] = mergeTargets(out[i], t)
				return
			}
		}
		out = append(out, t)
	}
	for _, u := range e.Units {
		if u.Shell == guard.ShellPowerShell {
			for _, t := range pwshReadTargets(u.Text) {
				add(t, true)
			}
			continue
		}
		dir := ""         // 此前 cd 进入的目录：相对的 cd 接在它后面
		var dirs []string // 单元里 cd 进入过的全部目录：其后的相对路径与重定向另按每个解析（cd ~/.ssh && cat config）
		addRel := func(t ReadTarget) {
			add(t, false)
			// 子 shell 里的 cd 不影响外面：不跟踪作用域，相对路径按进入过的每个目录都查一遍（只收紧）
			for _, d := range dirs {
				if isRelative(t.Path) {
					j := t
					j.Path = joinDir(d, t.Path, false)
					add(j, false)
				}
			}
		}
		for _, pipe := range readPipelines(u.Text) {
			for i, stage := range pipe {
				if d, ok := cdTarget(stage.words, false); ok {
					dir = joinDir(dir, d, false)
					dirs = append(dirs, dir)
					continue
				}
				for _, t := range stage.targets(i == 0) {
					addRel(t)
				}
			}
		}
		for _, t := range xargsArgFiles(u.Text) {
			add(t, false)
		}
		for _, r := range u.Redirections() {
			// 「命令词 运算符目标」：只要读入的重定向（< 与 n<，不含 heredoc、here-string 与复制描述符）
			_, op, ok := strings.Cut(r, " ")
			op = strings.TrimLeft(op, "0123456789")
			if ok && strings.HasPrefix(op, "<") && !strings.HasPrefix(op, "<<") && !strings.HasPrefix(op, "<&") {
				// 重定向的目标同样做花括号与通配符展开；这里没有引号信息，按都生效处理（只收紧）
				addRel(ReadTarget{Path: strings.TrimPrefix(strings.TrimPrefix(op, "<"), ">"), Glob: true, Brace: true})
			}
		}
	}
	return out
}

// mergeTargets 合并同一路径的两种写法，取更宽的展开方式：任一处生效就生效；递归读取的过滤只留两边都有的。
func mergeTargets(a, b ReadTarget) ReadTarget {
	a.Glob = a.Glob || b.Glob
	a.Brace = a.Brace || b.Brace
	switch {
	case a.Walk == nil:
		a.Walk = b.Walk
	case b.Walk != nil:
		w := &Walk{Hidden: a.Walk.Hidden || b.Walk.Hidden, Follow: a.Walk.Follow || b.Walk.Follow}
		if len(a.Walk.Include) > 0 && len(b.Walk.Include) > 0 {
			w.Include = append(slices.Clone(a.Walk.Include), b.Walk.Include...)
		}
		for _, x := range a.Walk.Exclude {
			if slices.Contains(b.Walk.Exclude, x) {
				w.Exclude = append(w.Exclude, x)
			}
		}
		for _, x := range a.Walk.ExcludeDir {
			if slices.Contains(b.Walk.ExcludeDir, x) {
				w.ExcludeDir = append(w.ExcludeDir, x)
			}
		}
		a.Walk = w
	}
	return a
}

// posixHome、pwshHome 是路径开头的主目录变量：换成 ~/，路径规则按配置的主目录判断，而不是当成工作目录下
// 名为 $HOME 的目录。POSIX 的变量名区分大小写（$home 是另一个变量）；PowerShell 与 cmd 不区分，
// cmd /c 里的 %USERPROFILE%、%HOMEDRIVE%%HOMEPATH% 同样是主目录。
var (
	posixHome = regexp.MustCompile(`^(?:\$HOME|\$\{HOME\})[/\\]`)
	pwshHome  = regexp.MustCompile(`(?i)^(?:\$HOME|\$\{HOME\}|\$env:USERPROFILE|\$\{env:USERPROFILE\}|\$env:HOME|%USERPROFILE%|%HOMEDRIVE%%HOMEPATH%)[/\\]`)
)

// normHome 把路径开头的主目录变量换成 ~/（pwsh 为真时按 PowerShell 与 cmd 的写法）。
func normHome(p string, pwsh bool) string {
	if pwsh {
		return pwshHome.ReplaceAllString(p, "~/")
	}
	return posixHome.ReplaceAllString(p, "~/")
}

// readStage 是 POSIX 管道里的一段：命令位置起的词的取值，以及每个词里通配符、花括号是否生效。
type readStage struct {
	words       []string
	glob, brace []bool
	xargs       bool // 段前有 xargs：它把读到的词作为参数接在后面
}

// readPipelines 与 Pipelines 相同，另记下每个词在引号与转义之外有没有通配符、花括号，以及段前有没有 xargs。
func readPipelines(text string) [][]readStage {
	lx := lex(text)
	var out [][]readStage
	var pipe []readStage
	cur := segment{start: -1}
	flush := func(end int, op string) {
		if len(cur.tokens) > 0 {
			cur.end = end
			words, k := commandStart(lx, cur)
			var st readStage
			for _, w := range words[:k] {
				st.xargs = st.xargs || path.Base(w.value) == "xargs"
			}
			for _, w := range words[k:] {
				g, b := expansionChars(w.bare)
				st.words, st.glob, st.brace = append(st.words, w.value), append(st.glob, g), append(st.brace, b)
			}
			if len(st.words) > 0 {
				pipe = append(pipe, st)
			}
		}
		cur = segment{start: -1}
		if op != "|" && op != "|&" && len(pipe) > 0 {
			out = append(out, pipe)
			pipe = nil
		}
	}
	for _, t := range lx.tokens {
		if t.kind == tokSep {
			flush(t.start, t.op)
			continue
		}
		if cur.start < 0 {
			cur.start = t.start
		}
		cur.tokens = append(cur.tokens, t)
	}
	flush(len(lx.src), "")
	return out
}

// expansionChars 报告词在引号与转义之外（bare）有没有通配符与花括号；${ 开头的参数展开不算花括号。
func expansionChars(bare string) (glob, brace bool) {
	for i := 0; i < len(bare); i++ {
		switch c := bare[i]; {
		case c == '\\':
			i++
		case c == '*' || c == '?' || c == '[':
			glob = true
		case c == '{' && (i == 0 || bare[i-1] != '$'):
			brace = true
		}
	}
	return glob, brace
}

// targets 是这一段读取的文件。first 为真表示这是管道的第一段（标准输入不是上一段的输出）。
func (st readStage) targets(first bool) []ReadTarget {
	paths := stageTargets(st.words)
	walk, always := recursiveRead(st.words)
	var out []ReadTarget
	for _, p := range paths {
		t := ReadTarget{Path: p, Walk: walk}
		t.Glob, t.Brace = st.flags(p)
		out = append(out, t)
	}
	// 没有给出路径的递归读取读工作目录：grep -r 总是这样；rg、ag、ack 只在标准输入不是管道时（第一段）。
	// xargs 会把读到的词接在后面，这时没有默认目录
	if walk != nil && len(paths) == 0 && !st.xargs && (always || first) {
		out = append(out, ReadTarget{Path: ".", Walk: walk})
	}
	return out
}

// flags 是文件参数 p 的通配符与花括号是否生效：取与它相同的词；p 是某个词的一部分（-fFILE）时都算生效。
func (st readStage) flags(p string) (glob, brace bool) {
	found := false
	for i := 1; i < len(st.words); i++ {
		if st.words[i] == p {
			found = true
			glob, brace = glob || st.glob[i], brace || st.brace[i]
		}
	}
	if !found {
		return true, true
	}
	return glob, brace
}

// recursiveRead 报告一段读文件命令是否递归读取目录参数，是时返回读取方式；always 为真表示没有给出路径时
// 总是读工作目录（grep -r），为假时只在标准输入不是管道时读（rg、ag、ack）。
func recursiveRead(words []string) (walk *Walk, always bool) {
	name := strings.ToLower(path.Base(words[0]))
	opts := readerArgOptions[name]
	// value 是选项 a 的值：--opt=v 写在同一个词里，否则是下一个词（用掉它）
	value := func(i *int, a string) string {
		if _, v, ok := strings.Cut(a, "="); ok && strings.HasPrefix(a, "--") {
			return v
		}
		if *i+1 < len(words) {
			*i++
			return words[*i]
		}
		return ""
	}
	switch name {
	case "grep", "egrep", "fgrep":
		w := &Walk{Hidden: true}
		rec := false
		for i := 1; i < len(words); i++ {
			a := words[i]
			opt, _, _ := strings.Cut(a, "=")
			switch {
			case a == "--":
				i = len(words)
			case a == "-r" || a == "--recursive":
				rec = true
			case a == "-R" || a == "--dereference-recursive":
				rec, w.Follow = true, true
			case opt == "-d" || opt == "--directories":
				rec = rec || value(&i, a) == "recurse"
			case opt == "--include":
				w.Include = append(w.Include, value(&i, a))
			case opt == "--exclude":
				w.Exclude = append(w.Exclude, value(&i, a))
			case opt == "--exclude-dir":
				w.ExcludeDir = append(w.ExcludeDir, value(&i, a))
			case opts[a] || patternOptions[a]:
				i++
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
				// 短选项组（-rn、-Ril）：带参数的选项之后是它的值
				for j := 1; j < len(a); j++ {
					c := a[j]
					if c == 'r' || c == 'R' {
						rec, w.Follow = true, w.Follow || c == 'R'
						continue
					}
					if strings.IndexByte("ABCmefdD", c) >= 0 {
						v := a[j+1:]
						if v == "" && i+1 < len(words) {
							i++
							v = words[i]
						}
						rec = rec || (c == 'd' && v == "recurse")
						break
					}
				}
			}
		}
		if !rec {
			return nil, false
		}
		return w, true
	case "rg":
		w := &Walk{}
		unrestricted := 0
		for i := 1; i < len(words); i++ {
			a := words[i]
			opt, _, _ := strings.Cut(a, "=")
			switch {
			case a == "--":
				i = len(words)
			case a == "--hidden":
				w.Hidden = true
			case a == "--no-hidden":
				w.Hidden = false
			case a == "--follow":
				w.Follow = true
			case a == "--unrestricted":
				unrestricted++
			case opt == "-g" || opt == "--glob" || opt == "--iglob":
				// 只认不含 / 的模式（按文件名匹配）；认不出的过滤不用，按读全部处理（只收紧）
				if g := value(&i, a); !strings.Contains(g, "/") {
					if ex, ok := strings.CutPrefix(g, "!"); ok {
						w.Exclude = append(w.Exclude, ex)
					} else if g != "" {
						w.Include = append(w.Include, g)
					}
				}
			case opts[a] || patternOptions[a]:
				i++
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
				for j := 1; j < len(a); j++ {
					switch c := a[j]; {
					case c == 'u':
						unrestricted++
					case c == '.':
						w.Hidden = true
					case c == 'L':
						w.Follow = true
					case strings.IndexByte("ABCmefgtTjMErd", c) >= 0:
						if j == len(a)-1 {
							i++
						}
						j = len(a)
					}
				}
			}
		}
		w.Hidden = w.Hidden || unrestricted >= 2 // -uu 也搜隐藏文件
		return w, false
	case "ag":
		w := &Walk{}
		for _, a := range words[1:] {
			switch a {
			case "--hidden", "-u", "--unrestricted":
				w.Hidden = true
			case "-f", "--follow":
				w.Follow = true
			}
		}
		return w, false
	case "ack":
		w := &Walk{Hidden: true}
		for _, a := range words[1:] {
			switch a {
			case "-n", "--no-recurse":
				return nil, false
			case "--follow":
				w.Follow = true
			}
		}
		return w, false
	}
	return nil, false
}

// pwshReadTargets 是 PowerShell 一个单元里读取的文件：按词法单元取参数（引号里带空格的路径是一个参数），
// .NET 的读文件调用只在代码里算（字符串、注释里提到的不算）。
func pwshReadTargets(text string) []ReadTarget {
	lx := pwshLex(text)
	var out, items []ReadTarget // items：上一段 Get-Item 等给出的路径，管道交给读文件命令（Get-Item .env | Get-Content）
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
				dir = joinDir(dir, d, true)
				continue
			}
		}
		for _, w := range words {
			if pwshFileRead.MatchString(w.bare) {
				for _, m := range pwshReadAll.FindAllStringSubmatch(w.value, -1) {
					out = append(out, ReadTarget{Path: m[1]}) // .NET 的读文件调用没有通配符
				}
			}
		}
		if k < len(words) {
			args := make([][]string, 0, len(words)-k)
			for _, w := range words[k:] {
				args = append(args, pwshElements(w))
			}
			targets := pwshTargets(args)
			name := pwshName(args[0][0])
			if len(targets) == 0 && pwshReaders[name] {
				targets = items
			}
			items = nil
			if pwshItems[name] {
				args[0] = []string{"get-content"} // 路径参数的写法相同
				items = pwshTargets(args)
			}
			for _, t := range targets {
				out = append(out, t)
				if dir != "" && isRelative(t.Path) {
					j := t
					j.Path = joinDir(dir, t.Path, true)
					out = append(out, j)
				}
			}
		}
	}
	return out
}

// pwshElements 是 PowerShell 一个参数词给出的值：代码里的逗号分隔数组（README.md,.env）与只含字面量的
// 数组表达式（@('.env')、('a','b')）按元素分开，引号里的逗号不算；其余就是词的值本身。
func pwshElements(w pwToken) []string {
	if elems, ok := pwshArrayLiteral(w.value); ok {
		return elems
	}
	if !strings.Contains(w.bare, ",") {
		return []string{w.value}
	}
	var out []string
	for _, p := range strings.Split(w.value, ",") {
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{w.value}
	}
	return out
}

// pwshArrayLiteral 拆开 @(…) 或 (…) 里只含字符串字面量（单引号字符串、不含变量与转义的双引号字符串）的数组，
// 元素以逗号、分号或换行分隔；含别的内容（@(Get-ChildItem)、@("$x")）时 ok 为假。
func pwshArrayLiteral(v string) (elems []string, ok bool) {
	inner, found := strings.CutPrefix(v, "@(")
	if !found {
		inner, found = strings.CutPrefix(v, "(")
	}
	if !found || !strings.HasSuffix(inner, ")") {
		return nil, false
	}
	inner = inner[:len(inner)-1]
	var cur strings.Builder
	quoted := false
	flush := func() bool {
		e := strings.TrimSpace(cur.String())
		cur.Reset()
		switch {
		case e == "" && !quoted:
			return true
		case quoted:
			elems = append(elems, e)
		default:
			return false // 括号里的裸词是命令（(README.md) 运行它），不是字符串
		}
		quoted = false
		return true
	}
	for i := 0; i < len(inner); i++ {
		switch c := inner[i]; {
		case c == '\'' || c == '"':
			if strings.TrimSpace(cur.String()) != "" || quoted {
				return nil, false // 引号与裸词拼在一起：不是单纯的字面量
			}
			cur.Reset()
			var body string
			if c == '\'' {
				body, i = readSingle(inner, i)
			} else {
				end := strings.IndexByte(inner[i+1:], '"')
				if end < 0 {
					return nil, false
				}
				body = inner[i+1 : i+1+end]
				if strings.ContainsAny(body, "$`") {
					return nil, false // 双引号里的变量与转义：值要运行时才知道
				}
				i += end + 2
			}
			i-- // 循环会再加一
			cur.WriteString(body)
			quoted = true
		case c == ',' || c == ';' || c == '\n':
			if !flush() {
				return nil, false
			}
		case quoted && !isPwBlank(c) && c != '\r':
			return nil, false
		default:
			cur.WriteByte(c)
		}
	}
	if !flush() || len(elems) == 0 {
		return nil, false
	}
	return elems, true
}

// pwshPathOption 报告 opt 是不是给出路径的参数：全名、别名，或 PowerShell 接受的前缀写法（-Pa、-Lit）。
func pwshPathOption(opt string) bool {
	return pwshPathOptions[opt] || (len(opt) >= 3 && strings.HasPrefix("-path", opt)) || pwshLiteralOption(opt)
}

// pwshLiteralOption 报告 opt 是不是按字面给出路径的参数（-LiteralPath 及其别名、前缀写法）：其中没有通配符。
func pwshLiteralOption(opt string) bool {
	return opt == "-lp" || opt == "-pspath" || (len(opt) >= 4 && strings.HasPrefix("-literalpath", opt))
}

// pwshName 是 PowerShell 命令词的小写名字：去掉模块限定（Microsoft.PowerShell.Management\Get-Content）与 .exe。
func pwshName(w string) string {
	w = strings.ToLower(w)
	w = w[strings.LastIndex(w, `\`)+1:]
	return strings.TrimSuffix(w, ".exe")
}

// xargsArgFiles 是 xargs -a FILE / --arg-file=FILE 读取参数的文件。xargs 是前缀词，命令段里看不到它的选项，
// 这里按原文的各段找；只认命令位置上的 xargs（段首，或在 sudo 这类前缀词、变量赋值之后），
// echo xargs -a .env 里的不算。
func xargsArgFiles(text string) []ReadTarget {
	var out []ReadTarget
	lx := lex(text)
	for _, seg := range lx.segments() {
		words, _ := commandStart(lx, seg) // 段里的词（引号已去掉，带空格的路径是一个词）；重定向的目标不算
		file := func(w token, v string) {
			g, b := expansionChars(w.bare)
			if v != w.value {
				g, b = true, true // 选项里的一部分（-aFILE）：按都生效处理
			}
			out = append(out, ReadTarget{Path: v, Glob: g, Brace: b})
		}
		for i := 0; i < len(words); i++ {
			v := words[i].value
			base := strings.ToLower(path.Base(v))
			if base == "xargs" {
				j := i + 1
				for ; j < len(words) && strings.HasPrefix(words[j].value, "-"); j++ {
					f := words[j].value
					switch {
					case (f == "-a" || f == "--arg-file") && j+1 < len(words):
						file(words[j+1], words[j+1].value)
						j++
					case strings.HasPrefix(f, "--arg-file="):
						file(words[j], strings.TrimPrefix(f, "--arg-file="))
					case strings.HasPrefix(f, "-a") && len(f) > 2:
						file(words[j], f[2:])
					case xargsArgOptions[f] && j+1 < len(words):
						j++
					}
				}
				i = j - 1 // 接着看 xargs 运行的命令（它可能又是前缀词）
				continue
			}
			if opts, ok := prefixWords[base]; ok && v != "" {
				// 前缀词的选项（sudo -u root）与位置参数（timeout 5）
				for i+1 < len(words) && strings.HasPrefix(words[i+1].value, "-") {
					i++
					if slices.Contains(opts, words[i].value) {
						i++
					}
				}
				i += prefixPositional[base]
				continue
			}
			if assignment.MatchString(lx.join(words[i].start, words[i].end)) {
				continue
			}
			break
		}
	}
	return out
}

// cmdReaders 是 cmd 里输出文件内容的内部命令。
var cmdReaders = map[string]bool{"type": true, "more": true, "more.com": true}

// cmdCommands 返回 cmd 命令行（cmd 之后的部分）里 /c 或 /k 之后的内层命令，按 &、|、括号分开，每条切成词
// （双引号里的空白不分词，引号与转义用的 ^ 去掉；< 与 > 单独成词）。/c 之前的 /d、/s、/q 等选项跳过；
// 没有 /c、/k 时为空。/c 之后整体加了引号（cmd /c "type .env"）时 cmd 会去掉首尾的引号，
// 不去掉的情形另需判断可执行文件，这里两种切法都给出（只收紧）。
func cmdCommands(line string) [][]string {
	rest := strings.TrimLeft(line, " \t")
	for rest != "" {
		word, after, _ := strings.Cut(rest, " ")
		w := strings.ToLower(word)
		if !strings.HasPrefix(w, "/") {
			return nil
		}
		rest = strings.TrimLeft(after, " \t")
		if w == "/c" || w == "/k" {
			out := cmdSplit(rest)
			if strings.HasPrefix(rest, `"`) {
				if j := strings.LastIndexByte(rest, '"'); j > 0 {
					out = append(out, cmdSplit(rest[1:j]+rest[j+1:])...)
				}
			}
			return out
		}
	}
	return nil
}

// cmdSplit 按 cmd 的写法把命令行切成命令与词（见 cmdCommands）。
func cmdSplit(s string) [][]string {
	var cmds [][]string
	var cur []string
	var b strings.Builder
	inWord, quoted := false, false
	word := func() {
		if inWord {
			cur = append(cur, b.String())
		}
		b.Reset()
		inWord = false
	}
	command := func() {
		word()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
		}
		cur = nil
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			quoted, inWord = !quoted, true
		case quoted:
			b.WriteByte(c)
		case c == '^' && i+1 < len(s):
			b.WriteByte(s[i+1])
			inWord = true
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			word()
		case c == '&' || c == '|' || c == '(' || c == ')':
			command()
		case c == '<' || c == '>':
			word()
			cur = append(cur, string(c))
		default:
			b.WriteByte(c)
			inWord = true
		}
	}
	command()
	return cmds
}

// cmdTargets 是 cmd 命令行里读取的文件：type、more 的文件参数与 < 的目标。cmd 的 type 接受通配符，没有花括号展开。
func cmdTargets(line string) []ReadTarget {
	var out []ReadTarget
	for _, c := range cmdCommands(line) {
		reader := cmdReaders[strings.ToLower(c[0])]
		for i := 1; i < len(c); i++ {
			switch a := c[i]; {
			case a == "<" && i+1 < len(c):
				out = append(out, ReadTarget{Path: c[i+1], Glob: true})
				i++
			case a == ">" && i+1 < len(c):
				i++ // 输出重定向的目标
			case reader && !strings.HasPrefix(a, "/") && a != "<" && a != ">":
				out = append(out, ReadTarget{Path: a, Glob: true})
			}
		}
	}
	return out
}

// gitNoIndexTargets 是 git diff --no-index 比较的两个文件系统路径；其他 git 命令读的是仓库内容，不算。
// -- 之后的词都是路径（-dir/.env 也是）。
func gitNoIndexTargets(stage []string) []string {
	i := 1 + afterOptions(stage[1:], gitArgOptions)
	if i >= len(stage) || stage[i] != "diff" || !slices.Contains(stage[i+1:], "--no-index") {
		return nil
	}
	var out []string
	for j, a := range stage[i+1:] {
		if a == "--" {
			return append(out, stage[i+2+j:]...)
		}
		if !strings.HasPrefix(a, "-") {
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
		!strings.HasPrefix(p, "$") && !strings.HasPrefix(p, "%") && !(len(p) > 1 && p[1] == ':')
}

// joinDir 把 p 接在目录 dir 后面；p 不是相对路径或 dir 为空时就是 p。pwsh 为真时主目录变量按 PowerShell 的写法认。
func joinDir(dir, p string, pwsh bool) string {
	p = normHome(p, pwsh)
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

// pwshTargets 是 PowerShell 一段读文件命令的路径参数。args 是命令词起的各个参数，每个参数是它给出的值
// （数组参数有多个元素，见 pwshElements）。路径参数的通配符生效（引号里的同样生效），-LiteralPath 的不生效；
// PowerShell 没有花括号展开。
func pwshTargets(args [][]string) []ReadTarget {
	if len(args) == 0 || len(args[0]) == 0 {
		return nil
	}
	name := pwshName(args[0][0])
	if name == "cmd" {
		// PowerShell 把每个值作为一个参数交给 cmd：带空白的值加上引号
		var parts []string
		for _, a := range args[1:] {
			for _, e := range a {
				if strings.ContainsAny(e, " \t") {
					e = `"` + e + `"`
				}
				parts = append(parts, e)
			}
		}
		return cmdTargets(strings.Join(parts, " "))
	}
	if !pwshReaders[name] {
		return nil
	}
	// Select-String 的第一个位置参数是模式（用 -Pattern 给出时没有这个参数），其后才是路径
	skipPattern := name == "select-string" || name == "sls"
	var out []ReadTarget
	var pos [][]string
	add := func(vals []string, literal bool) {
		for _, v := range vals {
			out = append(out, ReadTarget{Path: strings.Trim(v, `'"`), Glob: !literal})
		}
	}
	for i := 1; i < len(args); i++ {
		w := strings.ToLower(args[i][0])
		opt, val, bound := strings.Cut(w, ":")
		if opt == "-pattern" {
			skipPattern = false
		}
		switch {
		case strings.HasPrefix(w, "-") && bound && val != "":
			// -Path:.env：值跟在冒号后面，同一个词
			if pwshPathOption(opt) {
				add(append([]string{args[i][0][len(opt)+1:]}, args[i][1:]...), pwshLiteralOption(opt))
			}
		case pwshPathOption(opt) && i+1 < len(args):
			add(args[i+1], pwshLiteralOption(opt))
			i++
		case pwshSwitches[w]:
		case strings.HasPrefix(w, "-"):
			i++ // 其余参数带一个值（-TotalCount 5、-Encoding utf8）
		default:
			pos = append(pos, args[i])
		}
	}
	if skipPattern && len(pos) > 0 {
		pos = pos[1:]
	}
	for _, p := range pos {
		add(p, false)
	}
	return out
}

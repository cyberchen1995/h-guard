package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
)

// WindowsDefault 报告当前平台是否按 Windows 的规则解析路径（spec §5.5 第 4 步）。
var WindowsDefault = runtime.GOOS == "windows"

// stripWindowsPrefix 去掉 Win32 文件命名空间前缀：\\?\C:\x、\\.\C:\x 与 NT 写法 \??\C:\x 都是 C:\x，
// \\?\UNC\server\share 是 \\server\share。前缀之后不是盘符或 UNC 的（卷 GUID、GLOBALROOT、设备）无法映射到
// 盘符路径，原样返回并报告 opaque：无法得知它是哪个文件，有模式时按命中处理（与 /.vol、/proc 相同）。
// 盘符相对路径（C:foo、C:..\x，相对于该盘的当前目录）同样不透明。/ 与 \ 两种分隔符都认。
func stripWindowsPrefix(p string) (out string, opaque bool) {
	if len(p) >= 2 && isLetter(p[0]) && p[1] == ':' && (len(p) == 2 || !isSep(p[2])) {
		return p, true
	}
	win32 := len(p) >= 4 && isSep(p[0]) && isSep(p[1]) && (p[2] == '?' || p[2] == '.') && isSep(p[3])
	nt := len(p) >= 4 && isSep(p[0]) && p[1] == '?' && p[2] == '?' && isSep(p[3])
	if !win32 && !nt {
		return p, false
	}
	rest := p[4:]
	switch {
	case len(rest) >= 2 && isLetter(rest[0]) && rest[1] == ':' && (len(rest) == 2 || isSep(rest[2])):
		return rest, false
	case len(rest) >= 4 && strings.EqualFold(rest[:3], "UNC") && isSep(rest[3]):
		return p[:1] + p[:1] + rest[4:], false
	}
	return p, true
}

// rootRelative 处理 Windows 上以单个分隔符开头、没有盘符的路径（\Users\me\x、/Users/me/x）：它们在当前卷的根下，
// 不是相对于 cwd 的路径（计划评审 M3B-04）。rooted 报告 p 是不是这种路径；是时把 cwd 的卷（盘符或 UNC 共享）
// 拼在前面，取不到卷时 ok 为假，调用方按不透明处理。
func rootRelative(p, cwd string) (abs string, rooted, ok bool) {
	if len(p) == 0 || !isSep(p[0]) || (len(p) > 1 && isSep(p[1])) {
		return "", false, false
	}
	switch {
	case len(cwd) >= 2 && isLetter(cwd[0]) && cwd[1] == ':':
		return cwd[:2] + p, true, true
	case len(cwd) >= 2 && isSep(cwd[0]) && isSep(cwd[1]):
		segs := strings.FieldsFunc(cwd, func(r rune) bool { return r == '\\' || r == '/' })
		if len(segs) >= 2 {
			return cwd[:1] + cwd[:1] + segs[0] + cwd[:1] + segs[1] + p, true, true
		}
	}
	return "", true, false
}

// windowsForms 返回 Windows 打开文件时与 p 等价的其他写法（与 p 相同的不返回）：
//   - 每段末尾的点与空格去掉（.env. 与 .env 是同一个文件），段里冒号之后的数据流名去掉（.env::$DATA、
//     .env:secret 是 .env 的数据流）；盘符的冒号不算流。\\?\ 前缀下 Windows 不做这些规范化，名字确实可以
//     带末尾的点：多出的候选只会让匹配更严（只收紧）；
//   - 本机的管理共享（主机是 hosts 之一，共享名是盘符加 $）换回盘符路径：\\localhost\C$\x 就是 C:\x。
//
// 结果用 \ 分隔。
func windowsForms(p string, hosts []string) []string {
	var out []string
	alt := trimmedForm(p)
	if alt != p {
		out = append(out, alt)
	}
	if d := adminShare(alt, hosts); d != "" && d != p {
		out = append(out, d)
	}
	return out
}

// adminShare 把本机管理共享上的 UNC 路径换成盘符路径；不是时返回空串。
func adminShare(p string, hosts []string) string {
	if len(p) < 2 || !isSep(p[0]) || !isSep(p[1]) {
		return ""
	}
	segs := strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' })
	if len(segs) < 2 || len(segs[1]) != 2 || !isLetter(segs[1][0]) || segs[1][1] != '$' ||
		!slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(h, segs[0]) }) {
		return ""
	}
	return segs[1][:1] + `:\` + strings.Join(segs[2:], `\`)
}

// localHosts 是指向本机的 UNC 主机名：localhost、回环地址与本机名。
var localHosts = sync.OnceValue(func() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}
	return hosts
})

// trimmedForm 去掉每段末尾的点与空格、段里冒号之后的数据流名（见 windowsForms），结果用 \ 分隔。
func trimmedForm(p string) string {
	segs := strings.FieldsFunc(p, func(r rune) bool { return r == '\\' || r == '/' })
	unc := len(p) >= 2 && isSep(p[0]) && isSep(p[1])
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		if !(i == 0 && !unc && len(s) == 2 && isLetter(s[0]) && s[1] == ':') {
			if j := strings.IndexByte(s, ':'); j >= 0 {
				s = s[:j]
			}
			if s != "." && s != ".." {
				s = strings.TrimRight(s, ". ")
			}
		}
		out = append(out, s)
	}
	alt := strings.Join(out, `\`)
	switch {
	case unc:
		alt = `\\` + alt
	case len(out) == 1 && strings.HasSuffix(alt, ":"):
		alt += `\`
	}
	return alt
}

func isSep(c byte) bool    { return c == '\\' || c == '/' }
func isLetter(c byte) bool { return 'a' <= c|0x20 && c|0x20 <= 'z' }

// slash 把 p 换成 / 分隔：Windows 规则下 \ 也是分隔符（在任何平台上都按这个规则，测试才能覆盖）。
func slash(p string, windows bool) string {
	if windows {
		return strings.ReplaceAll(p, `\`, "/")
	}
	return filepath.ToSlash(p)
}

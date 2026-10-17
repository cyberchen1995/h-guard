//go:build windows

package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// readLink 报告 path（Lstat 的结果为 fi）是否是要跟随的链接，是则返回链接目标。符号链接之外，目录联接
// （mklink /J）等挂载点在 Go 1.23 起报告为 ModeIrregular 而不是 ModeSymlink：能读出目标的同样跟随，
// 否则经联接写受保护的目录就不命中。读不出目标的（如去重文件）按普通文件处理。
func readLink(path string, fi fs.FileInfo) (target string, ok bool, err error) {
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		target, err = os.Readlink(path)
		return target, err == nil, err
	case fi.Mode()&fs.ModeIrregular != 0:
		if target, err := os.Readlink(path); err == nil {
			return target, true, nil
		}
	}
	return "", false, nil
}

// longName 返回 p 中已存在的最长前缀换成长文件名（GetLongPathName）后的写法，再拼上不存在的部分：
// PROGRA~1 这类短文件名指向的是同一个文件。没有变化或无法取得时返回空串。
func longName(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	prefix := p
	for {
		if _, err := os.Lstat(prefix); err == nil {
			long := getLong(prefix)
			if long == "" || long == prefix {
				return ""
			}
			return long + p[len(prefix):]
		}
		dir := filepath.Dir(prefix)
		if dir == prefix {
			return ""
		}
		prefix = dir
	}
}

func getLong(p string) string {
	short, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 512)
	for {
		n, err := syscall.GetLongPathName(short, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			return ""
		}
		if int(n) <= len(buf) {
			return syscall.UTF16ToString(buf[:n])
		}
		buf = make([]uint16, n)
	}
}

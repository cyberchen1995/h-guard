//go:build !windows

package paths

import (
	"io/fs"
	"os"
)

// readLink 报告 path（Lstat 的结果为 fi）是否是要跟随的链接，是则返回链接目标。
func readLink(path string, fi fs.FileInfo) (target string, ok bool, err error) {
	if fi.Mode()&fs.ModeSymlink == 0 {
		return "", false, nil
	}
	target, err = os.Readlink(path)
	return target, err == nil, err
}

// longName 在 Windows 上返回短文件名（8.3）换成长文件名后的写法；其他平台没有短文件名，返回空串。
func longName(string) string { return "" }

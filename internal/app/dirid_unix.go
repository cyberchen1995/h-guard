//go:build unix

package app

import (
	"fmt"
	"os"
	"syscall"
)

// dirIdentity 是目录的文件身份：设备号与 inode。
func dirIdentity(path string) (string, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d:%d", st.Dev, st.Ino), true
}

//go:build !unix && !windows

package app

// dirIdentity 在没有文件身份的系统上取不到：不提供单次授权。
func dirIdentity(string) (string, bool) { return "", false }

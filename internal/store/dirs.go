package store

import (
	"os"
	"path/filepath"
	"runtime"
)

// xdgApplies 报告当前平台是否遵循 XDG 目录变量：macOS 与 Linux 遵循，Windows 不遵循（spec §9、§10.4）。
func xdgApplies() bool { return runtime.GOOS != "windows" }

// ConfigDir 返回 h-guard 的配置目录：$XDG_CONFIG_HOME/h-guard（macOS、Linux 上设置时），
// 否则 os.UserConfigDir()/h-guard。配置、规则包与同意记录都在这里。
func ConfigDir() (string, error) {
	return appDir("XDG_CONFIG_HOME", os.UserConfigDir)
}

// CacheDir 返回 h-guard 的缓存目录：$XDG_CACHE_HOME/h-guard（macOS、Linux 上设置时），
// 否则 os.UserCacheDir()/h-guard。指令缓存、健康记录与决策日志都在这里。
func CacheDir() (string, error) {
	return appDir("XDG_CACHE_HOME", os.UserCacheDir)
}

func appDir(env string, fallback func() (string, error)) (string, error) {
	if xdgApplies() {
		if v := os.Getenv(env); v != "" && filepath.IsAbs(v) {
			return filepath.Join(v, "h-guard"), nil
		}
	}
	base, err := fallback()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "h-guard"), nil
}

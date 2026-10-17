package app

import (
	"runtime/debug"
	"testing"
)

func TestVersionString(t *testing.T) {
	bi := func(v string) *debug.BuildInfo { return &debug.BuildInfo{Main: debug.Module{Version: v}} }
	for _, tt := range []struct {
		ld   string
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{"0.1.0", bi("v9.9.9"), true, "0.1.0"},           // 构建时注入的优先
		{"dev", bi("v0.1.0"), true, "0.1.0"},             // go install …@v0.1.0
		{"dev", bi("(devel)"), true, "dev"},              // go run、不在 git 工作区里的构建
		{"dev", bi("v0.1.0+dirty"), true, "0.1.0+dirty"}, // 本地 go build 写入的 VCS 版本，照样显示
		{"dev", bi(""), true, "dev"},
		{"dev", nil, false, "dev"},
		{"dev", bi("v0.1.1-0.20261017000000-abcdef123456"), true, "0.1.1-0.20261017000000-abcdef123456"}, // 伪版本照样显示
	} {
		if got := versionString(tt.ld, tt.bi, tt.ok); got != tt.want {
			t.Errorf("versionString(%q, %v, %v) = %q, want %q", tt.ld, tt.bi, tt.ok, got, tt.want)
		}
	}
}

//go:build windows

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestResolveWindowsSpellings：Windows 上 Resolve 把 \\?\ 前缀、末尾的点与空格、数据流都换成另外的候选，
// 盘符路径的规范化按 Windows 的规则。只在 Windows 上运行。
func TestResolveWindowsSpellings(t *testing.T) {
	dir := t.TempDir()
	env := Env{Cwd: dir, FoldCase: true, Windows: true}
	for in, want := range map[string]string{
		`\\?\` + filepath.Join(dir, ".env"): filepath.Join(dir, ".env"),
		filepath.Join(dir, ".env."):         filepath.Join(dir, ".env"),
		filepath.Join(dir, ".env::$DATA"):   filepath.Join(dir, ".env"),
		`sub\..\.env `:                      filepath.Join(dir, ".env"),
	} {
		r := Resolve(in, env)
		if r.Err != nil || !slices.ContainsFunc(r.Candidates(), func(c string) bool { return strings.EqualFold(c, want) }) {
			t.Errorf("Resolve(%q) = %+v, want a candidate %q", in, r, want)
		}
	}
	// 当前卷根下的路径
	vol := filepath.VolumeName(dir)
	if r := Resolve(strings.TrimPrefix(filepath.Join(dir, ".env"), vol), env); !slices.ContainsFunc(r.Candidates(), func(c string) bool { return strings.EqualFold(c, filepath.Join(dir, ".env")) }) {
		t.Errorf("root-relative path: %+v", r)
	}
	if r := Resolve(`\\?\GLOBALROOT\Device\HarddiskVolume1\x`, env); !r.Opaque {
		t.Errorf("GLOBALROOT is not opaque: %+v", r)
	}
	if r := Resolve(`\\localhost\`+strings.Replace(filepath.Join(dir, ".env"), ":", "$", 1), env); !slices.ContainsFunc(r.Candidates(), func(c string) bool { return strings.EqualFold(c, filepath.Join(dir, ".env")) }) {
		t.Errorf("admin share: %+v", r)
	}
}

// TestResolveFollowsJunctions：目录联接（mklink /J）与符号链接一样解析，否则经联接写受保护的目录不命中。
func TestResolveFollowsJunctions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	os.Mkdir(target, 0o755)
	link := filepath.Join(dir, "junction")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	r := Resolve(filepath.Join(link, "settings.json"), Env{FoldCase: true, Windows: true})
	want, _ := filepath.EvalSymlinks(target)
	if r.Err != nil || !strings.EqualFold(r.Real, filepath.Join(want, "settings.json")) {
		t.Errorf("Resolve through a junction = %+v, want Real under %s", r, want)
	}
}

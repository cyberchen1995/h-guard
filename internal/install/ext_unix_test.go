//go:build darwin || linux

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExtSymlink：扩展文件是符号链接（dotfiles 管理）时，重装写它指向的文件，链接保留；移除只删链接。
func TestExtSymlink(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "pi", false))
	link := PiExtension(tg)
	managed := filepath.Join(tg.Home, "dotfiles", "h-guard.js")
	os.MkdirAll(filepath.Dir(managed), 0o700)
	b, _ := os.ReadFile(link)
	os.WriteFile(managed, b, 0o600)
	os.Remove(link)
	if err := os.Symlink(managed, link); err != nil {
		t.Fatal(err)
	}
	tg.Timeout = 30
	apply(t, plan(t, tg, "pi", false))
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was replaced: %v", err)
	}
	if b, _ := os.ReadFile(managed); !strings.Contains(string(b), `"--timeout","30"`) {
		t.Errorf("the link target was not updated:\n%s", b)
	}
	apply(t, plan(t, tg, "pi", true))
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Errorf("link after remove: %v", err)
	}
	if _, err := os.Stat(managed); err != nil {
		t.Errorf("remove deleted the link target: %v", err)
	}
	os.Symlink(filepath.Join(tg.Home, "missing.js"), link)
	if _, err := Pi(tg, "pi", false); err == nil || !strings.Contains(err.Error(), "cannot be resolved") {
		t.Errorf("dangling link: %v", err)
	}
}

// TestPiOMPSymlinkedDir：~/.omp/agent 是指向 ~/.pi/agent 的符号链接时，两边是同一个扩展目录，装了一个就不能再装另一个。
func TestPiOMPSymlinkedDir(t *testing.T) {
	tg := target(t, "linux")
	os.MkdirAll(filepath.Join(tg.Home, ".pi", "agent"), 0o700)
	os.MkdirAll(filepath.Join(tg.Home, ".omp"), 0o700)
	if err := os.Symlink(filepath.Join(tg.Home, ".pi", "agent"), filepath.Join(tg.Home, ".omp", "agent")); err != nil {
		t.Fatal(err)
	}
	apply(t, plan(t, tg, "pi", false))
	if _, err := Pi(tg, "omp", false); err == nil || !strings.Contains(err.Error(), "install h-guard for only one of them") {
		t.Fatalf("omp install into the symlinked directory: %v", err)
	}
}

package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
)

func editor(t *testing.T) Editor {
	return Editor{LockDir: t.TempDir(), BackupDir: t.TempDir(), Now: func() time.Time { return time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC) }}
}

// TestEditBacksUpAndReplaces：改动前先备份原文件，写回保留权限；内容没有变化时不写、不备份（spec §3.5、§12）。
func TestEditBacksUpAndReplaces(t *testing.T) {
	e := editor(t)
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("old"), 0o640); err != nil {
		t.Fatal(err)
	}
	changed, err := e.Edit(path, func(old []byte, exists bool) ([]byte, error) {
		if string(old) != "old" || !exists {
			t.Errorf("old = %q, exists %v", old, exists)
		}
		return []byte("new"), nil
	})
	if err != nil || !changed {
		t.Fatalf("Edit = %v, %v", changed, err)
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Errorf("content = %q", b)
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v", fi.Mode().Perm())
	}
	backups, _ := os.ReadDir(e.BackupDir)
	if len(backups) != 1 || !strings.HasPrefix(backups[0].Name(), "settings.json.20261014T093000Z") {
		t.Fatalf("backups = %v", backups)
	}
	if b, _ := os.ReadFile(filepath.Join(e.BackupDir, backups[0].Name())); string(b) != "old" {
		t.Errorf("backup = %q", b)
	}
	changed, err = e.Edit(path, func(old []byte, _ bool) ([]byte, error) { return old, nil })
	if err != nil || changed {
		t.Errorf("unchanged edit = %v, %v", changed, err)
	}
	if backups, _ := os.ReadDir(e.BackupDir); len(backups) != 1 {
		t.Errorf("an unchanged edit made a backup: %v", backups)
	}
}

// TestEditNewFile：文件不存在时 exists 为假，新建（0o600），不备份。
func TestEditNewFile(t *testing.T) {
	e := editor(t)
	path := filepath.Join(t.TempDir(), "sub", "hooks.json")
	changed, err := e.Edit(path, func(old []byte, exists bool) ([]byte, error) {
		if exists || old != nil {
			t.Errorf("old = %q, exists %v", old, exists)
		}
		return []byte("{}"), nil
	})
	if err != nil || !changed {
		t.Fatalf("Edit = %v, %v", changed, err)
	}
	if fi, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Errorf("stat = %v, %v", fi, err)
	}
	if backups, _ := os.ReadDir(e.BackupDir); len(backups) != 0 {
		t.Errorf("backups = %v", backups)
	}
}

// TestEditConflict：读入之后文件被别的程序改动，报冲突、不覆盖（spec §3.5）；改动函数出错时什么都不写。
func TestEditConflict(t *testing.T) {
	e := editor(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	os.WriteFile(path, []byte("v1"), 0o600)
	_, err := e.Edit(path, func(old []byte, _ bool) ([]byte, error) {
		os.WriteFile(path, []byte("someone else"), 0o600)
		return []byte("mine"), nil
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "someone else" {
		t.Errorf("content = %q", b)
	}
	boom := errors.New("boom")
	if _, err := e.Edit(path, func([]byte, bool) ([]byte, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "someone else" {
		t.Errorf("content after a failed change = %q", b)
	}
}

// TestEditLocked：另一个 install 正持有锁时不等待，直接报错。
func TestEditLocked(t *testing.T) {
	e := editor(t)
	unlock, err := store.Lock(e.LockDir)
	if err != nil {
		t.Skip("locking unsupported:", err)
	}
	defer unlock()
	_, err = e.Edit(filepath.Join(t.TempDir(), "x"), func([]byte, bool) ([]byte, error) { return []byte("x"), nil })
	if !errors.Is(err, store.ErrLocked) {
		t.Errorf("err = %v", err)
	}
}

// TestEditFollowsSymlinks：dotfiles 管理的配置常是符号链接：改它指向的文件，链接本身保留（审查 I2）；
// 悬空的链接不改，报错。
func TestEditFollowsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	e := editor(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "dotfiles", "settings.json")
	os.MkdirAll(filepath.Dir(real), 0o700)
	os.WriteFile(real, []byte("old"), 0o600)
	link := filepath.Join(dir, "settings.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Edit(link, func([]byte, bool) ([]byte, error) { return []byte("new"), nil }); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(real); string(b) != "new" {
		t.Errorf("target = %q", b)
	}
	dangling := filepath.Join(dir, "hooks.json")
	os.Symlink(filepath.Join(dir, "missing.json"), dangling)
	if _, err := e.Edit(dangling, func([]byte, bool) ([]byte, error) { return []byte("{}"), nil }); err == nil {
		t.Error("a dangling link was written through")
	}
	if _, err := os.Stat(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("the dangling link's target was created")
	}
}

// TestBackupsDoNotCollide：同一秒内的两次改动各留一份备份（审查次要 1）。
func TestBackupsDoNotCollide(t *testing.T) {
	e := editor(t)
	path := filepath.Join(t.TempDir(), "hooks.json")
	os.WriteFile(path, []byte("v1"), 0o600)
	e.Edit(path, func([]byte, bool) ([]byte, error) { return []byte("v2"), nil })
	e.Edit(path, func([]byte, bool) ([]byte, error) { return []byte("v3"), nil })
	backups, _ := os.ReadDir(e.BackupDir)
	if len(backups) != 2 {
		t.Errorf("backups = %v", backups)
	}
}

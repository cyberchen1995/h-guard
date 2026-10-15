// Package install 实现 h-guard install：把 h-guard 接入 harness（spec §12）。只改本项目的入口，其余内容原样保留；
// 写入前备份，按 spec §3.5 的读改写约定（锁、写回前比对哈希、临时文件加 rename）写回，与他人并发修改冲突时报错。
package install

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
)

// Editor 改写 harness 的配置文件。LockDir 放读改写锁（h-guard 自己的目录，不在 harness 的目录里留锁文件）；
// BackupDir 放改动前的副本。
type Editor struct {
	LockDir   string
	BackupDir string
	Now       func() time.Time
}

// Edit 读入 path（不存在时 exists 为假、old 为 nil），由 change 算出新内容并写回：
//   - 内容没有变化时不写、不备份，changed 为假；
//   - 改动已有文件前先把原文件复制到 BackupDir（<文件名>.<UTC 时间>.bak），写回保留原权限；新文件为 0o600；
//   - path 是符号链接时改它指向的文件，链接本身保留（dotfiles 管理的配置）；悬空的链接不改，报错；
//   - 读入之后文件被别的程序改动时返回 store.ErrConflict，不覆盖；另一个 install 正持有锁时返回 store.ErrLocked。
func (e Editor) Edit(path string, change func(old []byte, exists bool) ([]byte, error)) (changed bool, err error) {
	unlock, err := store.Lock(e.LockDir)
	if err != nil {
		return false, err
	}
	defer unlock()
	return e.editLocked(path, change)
}

// editLocked 同 Edit，调用方已持有读改写锁（Apply 在一把锁下执行全部步骤）。
func (e Editor) editLocked(path string, change func(old []byte, exists bool) ([]byte, error)) (changed bool, err error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return false, fmt.Errorf("%s is a symbolic link whose target cannot be resolved; not changing it", path)
		}
		path = target
	}
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	hash, err := store.FileHash(path)
	if err != nil {
		return false, err
	}
	data, err := change(old, exists)
	if err != nil {
		return false, err
	}
	if exists && bytes.Equal(data, old) {
		return false, nil
	}
	perm := fs.FileMode(0o600)
	if exists {
		if fi, err := os.Stat(path); err == nil {
			perm = fi.Mode().Perm()
		}
		if err := e.backup(path, old); err != nil {
			return false, fmt.Errorf("backup %s: %w", path, err)
		}
	}
	if err := store.ReplaceIfUnchanged(path, data, perm, hash); err != nil {
		return false, err
	}
	return true, nil
}

// backup 把 old 写成 BackupDir 下的新文件 <文件名>.<UTC 时间>.<随机串>.bak，不覆盖已有的备份。
func (e Editor) backup(path string, old []byte) error {
	if err := os.MkdirAll(e.BackupDir, 0o700); err != nil {
		return err
	}
	for range 8 {
		var r [4]byte
		_, _ = rand.Read(r[:])
		name := fmt.Sprintf("%s.%s.%s.bak", filepath.Base(path), e.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(r[:]))
		f, err := os.OpenFile(filepath.Join(e.BackupDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, werr := f.Write(old)
		return errors.Join(werr, f.Sync(), f.Close())
	}
	return errors.New("cannot pick a backup name")
}

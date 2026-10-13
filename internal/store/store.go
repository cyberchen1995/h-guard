// Package store 提供 hook 进程之间安全共享文件的原语（spec §3.5、§10.4）：整文件原子写入、
// 单次追加写入、过期清理、读改写锁与写回前的哈希比对。hook 进程彼此独立、可能并发运行，
// 所以整文件一律「同目录临时文件 + rename」，追加一律一次 O_APPEND 写入；读改写锁用操作系统的
// 咨询锁，持有者退出（含崩溃）时由系统释放，不需要按时间判断过期。
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// lockName 是读改写锁文件名。文件本身一直保留，锁在文件的打开句柄上。
const lockName = ".lock"

var (
	// ErrLocked 表示另一个 h-guard 进程正持有读改写锁。
	ErrLocked = errors.New("store: another h-guard process holds the lock")
	// ErrConflict 表示目标文件在读入之后被其他程序改动过。
	ErrConflict = errors.New("store: file changed since it was read")
)

// WriteAtomic 把 data 写到 path：先写同目录的随机名临时文件，再 rename 覆盖。
// 读者只会看到旧的完整文件或新的完整文件。父目录不存在时创建（0o700）。
func WriteAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"."+randomHex(6)+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// AppendLine 以一次 O_APPEND 写入追加一条记录（data 加换行）。不加锁：多个进程并发追加时，
// 每条记录作为一次写入落盘，不会交错（spec §10.4，由测试验证）。父目录不存在时创建。
func AppendLine(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	line := make([]byte, 0, len(data)+1)
	line = append(append(line, data...), '\n')
	_, werr := f.Write(line)
	return errors.Join(werr, f.Close())
}

// RemoveOlder 删除 dir 下（不递归）修改时间早于 cutoff 的普通文件，返回删除的个数。
// 目录不存在或单个文件删除失败都忽略：清理只是顺带的，不影响调用方。
func RemoveOlder(dir string, cutoff time.Time) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n
}

// Lock 取得 dir/.lock 上的读改写锁（Unix 为 flock，Windows 为 LockFileEx，都不阻塞）；
// 返回的函数释放它，重复调用无效果。锁属于这次打开的文件句柄：持有者退出或崩溃时由系统释放，
// 释放也只关闭自己的句柄，不会删掉或释放别人后来取得的锁。拿不到锁返回 ErrLocked。
func Lock(dir string) (unlock func(), err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = unlockFile(f)
			_ = f.Close()
		})
	}, nil
}

// FileHash 返回文件内容的 SHA-256（十六进制）；文件不存在时返回空串与 nil。
func FileHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ReplaceIfUnchanged 在目标文件的当前哈希仍等于 want（读入时的哈希，文件当时不存在则为空串）时
// 原子写入 data，否则返回 ErrConflict、不覆盖。比对与替换之间仍有极短的窗口（spec §3.5）。
func ReplaceIfUnchanged(path string, data []byte, perm fs.FileMode, want string) error {
	got, err := FileHash(path)
	if err != nil {
		return err
	}
	if got != want {
		return ErrConflict
	}
	return WriteAtomic(path, data, perm)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

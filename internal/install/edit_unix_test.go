//go:build darwin || linux

package install

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/store"
)

// TestEditHashesWhatItRead：比对用的哈希必须来自 change 拿到的那份内容。读入之后、写回之前文件被别的程序替换时
// 报冲突、保留别人的版本，哪怕替换正好发生在读内容与取哈希之间。路径先是一个 FIFO，
// 编辑器读到 old 之后写端才关闭；关闭之前路径已换成内容为 concurrent 的普通文件，所以之后任何再读都读到它。
// 不靠 sleep，修复前后都不会卡住。
func TestEditHashesWhatItRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		w, err := os.OpenFile(path, os.O_WRONLY, 0) // 等编辑器打开读端
		if err != nil {
			done <- err
			return
		}
		_, err = w.Write([]byte("old"))
		// 别的程序写入新版本：在编辑器读完（写端关闭）之前就换掉路径
		replacement := filepath.Join(dir, "replacement")
		if err == nil {
			err = os.WriteFile(replacement, []byte("concurrent"), 0o600)
		}
		if err == nil {
			err = os.Rename(replacement, path)
		}
		done <- errors.Join(err, w.Close())
	}()
	changed, err := editor(t).Edit(path, func(old []byte, exists bool) ([]byte, error) {
		if err := <-done; err != nil {
			return nil, err
		}
		if string(old) != "old" || !exists {
			t.Fatalf("snapshot %q %v", old, exists)
		}
		return []byte("our edit based on old"), nil
	})
	got, _ := os.ReadFile(path)
	if !errors.Is(err, store.ErrConflict) || changed || string(got) != "concurrent" {
		t.Errorf("changed %v, err %v, file %q; want a conflict that keeps the concurrent version", changed, err, got)
	}
}

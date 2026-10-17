package store

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWriteAtomicReplacesWithoutLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.yaml")
	if err := WriteAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "two" {
		t.Fatalf("content = %q, %v", b, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestAppendLineConcurrentWritersKeepWholeLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "a.jsonl")
	var wg sync.WaitGroup
	for w := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 50 {
				line := fmt.Sprintf(`{"w":%d,"i":%d,"pad":%q}`, w, i, strings.Repeat("x", 200))
				if err := AppendLine(path, []byte(line)); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	checkWholeLines(t, path, 8*50)
}

// TestAppendLineAcrossProcesses 用子进程并发追加，检查没有交错或残行。
func TestAppendLineAcrossProcesses(t *testing.T) {
	if os.Getenv("HG_STORE_HELPER") == "1" {
		path := os.Getenv("HG_STORE_PATH")
		for i := range 100 {
			line := fmt.Sprintf(`{"pid":%d,"i":%d,"pad":%q}`, os.Getpid(), i, strings.Repeat("y", 300))
			if err := AppendLine(path, []byte(line)); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "multi.jsonl")
	var cmds []*exec.Cmd
	for range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAppendLineAcrossProcesses$")
		cmd.Env = append(os.Environ(), "HG_STORE_HELPER=1", "HG_STORE_PATH="+path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	checkWholeLines(t, path, 4*100)
}

func checkWholeLines(t *testing.T, path string, want int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != want {
		t.Fatalf("got %d lines, want %d", len(lines), want)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "{") || !strings.HasSuffix(l, "}") {
			t.Fatalf("interleaved or partial line: %.80q", l)
		}
	}
}

func TestRemoveOlder(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	old := filepath.Join(dir, "old.jsonl")
	fresh := filepath.Join(dir, "fresh.jsonl")
	for _, p := range []string{old, fresh} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(old, now.Add(-8*24*time.Hour), now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := RemoveOlder(dir, now.Add(-7*24*time.Hour)); n != 1 {
		t.Errorf("removed %d, want 1", n)
	}
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("old file still there: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh file removed: %v", err)
	}
	if n := RemoveOlder(filepath.Join(dir, "missing"), now); n != 0 {
		t.Errorf("missing dir removed %d", n)
	}
}

func TestLockExcludes(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Lock err = %v, want ErrLocked", err)
	}
	unlock()
	unlock2, err := Lock(dir)
	if err != nil {
		t.Fatalf("Lock after unlock: %v", err)
	}
	unlock() // 旧持有者再次释放：不能影响后来者
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("a stale unlock released the successor's lock: err = %v", err)
	}
	unlock2()
}

func TestLockConcurrentHolders(t *testing.T) {
	dir := t.TempDir()
	var (
		mu      sync.Mutex
		holders int
		maxSeen int
		wg      sync.WaitGroup
	)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				unlock, err := Lock(dir)
				if err != nil {
					continue
				}
				mu.Lock()
				holders++
				maxSeen = max(maxSeen, holders)
				mu.Unlock()
				time.Sleep(100 * time.Microsecond)
				mu.Lock()
				holders--
				mu.Unlock()
				unlock()
			}
		}()
	}
	wg.Wait()
	if maxSeen != 1 {
		t.Errorf("%d holders at the same time, want 1", maxSeen)
	}
}

// TestLockReleasedWhenHolderDies：另一个进程持有锁时拿不到；该进程被杀死后锁由系统释放。
func TestLockReleasedWhenHolderDies(t *testing.T) {
	if os.Getenv("HG_LOCK_HELPER") == "1" {
		if _, err := Lock(os.Getenv("HG_LOCK_DIR")); err != nil {
			os.Exit(1)
		}
		fmt.Println("locked")
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockReleasedWhenHolderDies$")
	cmd.Env = append(os.Environ(), "HG_LOCK_HELPER=1", "HG_LOCK_DIR="+dir)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil || string(buf) != "locked" {
		t.Fatalf("helper did not lock: %q %v", buf, err)
	}
	if _, err := Lock(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("Lock while another process holds it: err = %v", err)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatalf("Lock after the holder died: %v", err)
	}
	unlock()
}

func TestReplaceIfUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := FileHash(path)
	if err != nil || h == "" {
		t.Fatalf("FileHash = %q, %v", h, err)
	}
	// 另一个程序在读与写之间改了文件
	if err := os.WriteFile(path, []byte(`{"a":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceIfUnchanged(path, []byte(`{"a":3}`), 0o600, h); !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	h2, _ := FileHash(path)
	if err := ReplaceIfUnchanged(path, []byte(`{"a":3}`), 0o600, h2); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"a":3}` {
		t.Errorf("content = %s", b)
	}
	missing := filepath.Join(t.TempDir(), "new.json")
	if h, err := FileHash(missing); err != nil || h != "" {
		t.Fatalf("FileHash(missing) = %q, %v", h, err)
	}
	if err := ReplaceIfUnchanged(missing, []byte("x"), 0o600, ""); err != nil {
		t.Fatalf("create when absent: %v", err)
	}
}

func TestDirsHonorXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg/config")
	t.Setenv("XDG_CACHE_HOME", "/xdg/cache")
	cfg, err := ConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	cache, err := CacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if !xdgApplies() {
		t.Skip("XDG variables are not used on this platform")
	}
	if cfg != filepath.Join("/xdg/config", "h-guard") || cache != filepath.Join("/xdg/cache", "h-guard") {
		t.Errorf("ConfigDir = %s, CacheDir = %s", cfg, cache)
	}
}

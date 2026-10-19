//go:build unix

package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRunEntryReapsChildren：入口派生的子进程在入口退出后一并终止。
func TestRunEntryReapsChildren(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	// 子进程还拿着输出管道：入口退出后最多再等 WaitDelay，然后连同子进程一起终止
	_, _ = runEntry([]string{"sh", "-c", "sleep 30 & echo $! > " + pidFile}, nil, nil)
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	time.Sleep(100 * time.Millisecond)
	if pid == 0 {
		t.Fatal("no child pid")
	}
	// 已终止、还没被回收的子进程（僵尸）不算在运行
	if syscall.Kill(pid, 0) == nil {
		out, _ := exec.Command("ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
		if st := strings.TrimSpace(string(out)); st != "" && !strings.HasPrefix(st, "Z") {
			t.Errorf("child %d still running (%s)", pid, st)
		}
	}
}

//go:build unix

package exec_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/exec"
)

// 截止时间到达时整个进程组被终止：挂着 stdout 的孙进程不会让 Ask 卡住，也不会遗留下来。
func TestDeadlineKillsTheProcessGroup(t *testing.T) {
	pidfile := filepath.Join(t.TempDir(), "pid")
	t.Setenv("HG_EXEC_PIDFILE", pidfile)
	b := newBackend(t, "orphan", exec.Options{TimeoutMS: 1500, Env: []string{"HG_EXEC_PIDFILE"}})
	start := time.Now()
	_, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
	if judge.KindOf(err) != judge.Timeout {
		t.Errorf("err = %v, want Timeout", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Errorf("Ask took %v", d)
	}
	data, err := os.ReadFile(pidfile)
	if err != nil {
		t.Fatalf("the grandchild never started: %v", err)
	}
	pid, _ := strconv.Atoi(string(data))
	for i := 0; i < 100; i++ {
		if syscall.Kill(pid, 0) == syscall.ESRCH {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	syscall.Kill(pid, syscall.SIGKILL)
	t.Errorf("grandchild %d survived the deadline", pid)
}

// TestNoChildOutlivesAsk：程序正常退出、却留下后台子进程时，Ask 返回前同样终止它们——无论子进程是否
// 占着输出管道。
func TestNoChildOutlivesAsk(t *testing.T) {
	for mode, wantErr := range map[string]judge.ErrorKind{"daemon": "", "daemon-holding": judge.Unavailable} {
		t.Run(mode, func(t *testing.T) {
			pidfile := filepath.Join(t.TempDir(), "pid")
			t.Setenv("HG_EXEC_PIDFILE", pidfile)
			b := newBackend(t, mode, exec.Options{TimeoutMS: 5000, Env: []string{"HG_EXEC_PIDFILE"}})
			_, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
			if judge.KindOf(err) != wantErr {
				t.Errorf("err = %v, want kind %q", err, wantErr)
			}
			data, err := os.ReadFile(pidfile)
			if err != nil {
				t.Fatalf("the child never started: %v", err)
			}
			pid, _ := strconv.Atoi(string(data))
			for i := 0; i < 100; i++ {
				if syscall.Kill(pid, 0) == syscall.ESRCH {
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			syscall.Kill(pid, syscall.SIGKILL)
			t.Errorf("child %d outlived Ask", pid)
		})
	}
}

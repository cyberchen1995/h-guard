//go:build darwin || linux

package main_test

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestPluginWrapperAnswersWhenHealthLogStalls 用整个外包脚本验收截止时间（评审 N03）：健康日志的存储卡住
// （这里用 FIFO 模拟，没有读者时写入会一直阻塞）时，脚本仍须在 --timeout 之内输出唯一一条兜底响应并退出。
// 卡住的健康记录允许丢失。
func TestPluginWrapperAnswersWhenHealthLogStalls(t *testing.T) {
	bin := buildBinary(t)
	script, _ := filepath.Abs(filepath.Join("..", "..", "extensions", "claudecode", "hooks", "pretooluse.sh"))
	const timeout = 2 * time.Second
	for _, tt := range []struct {
		name, config, reason string
		stallStdin           bool
	}{
		{name: "stdin and health both stall", reason: "ran out of time", stallStdin: true},
		{name: "health stalls after the answer", config: "version: 1\naction: {tier: 9}\n", reason: "configuration is invalid"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root, cfg, cache := t.TempDir(), t.TempDir(), t.TempDir()
			os.WriteFile(filepath.Join(root, "hguard-bin"), []byte(bin+"\n"), 0o600)
			os.WriteFile(filepath.Join(root, "hguard-timeout"), []byte("2\n"), 0o600)
			health := filepath.Join(cache, "h-guard", "health")
			if err := os.MkdirAll(health, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, day := range []time.Time{time.Now(), time.Now().Add(24 * time.Hour)} {
				if err := syscall.Mkfifo(filepath.Join(health, day.Format("2006-01-02")+".jsonl"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.config != "" {
				os.MkdirAll(filepath.Join(cfg, "h-guard"), 0o700)
				os.WriteFile(filepath.Join(cfg, "h-guard", "config.yaml"), []byte(tt.config), 0o600)
			}
			c := exec.Command("sh", script)
			c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "LANG=en_US.UTF-8",
				"XDG_CONFIG_HOME=" + cfg, "XDG_CACHE_HOME=" + cache, "CLAUDE_PLUGIN_ROOT=" + root}
			var stdin io.Reader = bytes.NewReader(preToolUse("ls"))
			if tt.stallStdin {
				// 直接把系统管道交给子进程（不经 exec 的拷贝 goroutine），写端保持打开、不写入
				pr, pw, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer pw.Close()
				defer pr.Close()
				stdin = pr
			}
			c.Stdin = stdin
			var out bytes.Buffer
			c.Stdout = &out
			c.WaitDelay = time.Second // 杀掉脚本后，占着输出的 h-guard 子进程也不能让 Wait 一直等
			start := time.Now()
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("wrapper exited with %v", err)
				}
			case <-time.After(timeout):
				_ = c.Process.Kill()
				<-done // 等 exec 的拷贝协程结束再读 out，否则失败分支本身与它竞争
				t.Fatalf("the wrapper did not finish within %v; stdout so far %q", timeout, out.String())
			}
			elapsed := time.Since(start)
			if n := strings.Count(out.String(), "hookSpecificOutput"); n != 1 {
				t.Fatalf("want exactly one answer, got %d: %q", n, out.String())
			}
			d := decision(t, bytes.TrimSpace(out.Bytes()))
			if d != "ask" || !strings.Contains(out.String(), tt.reason) {
				t.Errorf("decision %s, output %q", d, out.String())
			}
			t.Logf("answered %s after %v", d, elapsed)
		})
	}
}

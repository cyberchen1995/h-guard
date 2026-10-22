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

// TestPluginWrapperAnswersWhenHealthLogStalls 用整个外包脚本验收截止时间：健康日志的存储卡住
// （这里用 FIFO 模拟，没有读者时写入会一直阻塞）时，脚本仍须由看门狗兜底，输出唯一一条兜底响应并退出。
// 卡住的健康记录允许丢失。看门狗落在 --timeout 之内由 internal/app 的 budgets 测试验证；这里只验收端到端
// 不会卡住，等待上限放宽，免得机器负载让测试时而失败。
func TestPluginWrapperAnswersWhenHealthLogStalls(t *testing.T) {
	bin := buildBinary(t)
	// 先运行一次：macOS 第一次执行新编出的程序时系统要先检查它（实测 0.4–0.9 秒），这段一次性的开销会吃掉看门狗留给
	// harness 的 0.5 秒余量，让本测试时而超时（第一个子测试总是第一次执行）。要验证的是 h-guard 自己的计时，不含它。
	if out, err := exec.Command(bin, "version").CombinedOutput(); err != nil {
		t.Fatalf("warm-up: %v\n%s", err, out)
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "extensions", "claudecode", "hooks", "pretooluse.sh"))
	const timeout = 2 * time.Second
	// limit 是测试等外包脚本的上限。脚本按 --timeout 由看门狗兜底（这里 1.5 秒）；卡住的健康日志没有看门狗时会一直阻塞，
	// 所以只要在 limit 之内退出、输出唯一一条兜底响应，就说明是看门狗起了作用。limit 比 timeout 宽得多：
	// -race 与高负载下启动进程、调度看门狗都可能多出几百毫秒，按 timeout 卡会时而失败。
	const limit = timeout + 8*time.Second
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
			case <-time.After(limit):
				_ = c.Process.Kill()
				<-done // 等 exec 的拷贝协程结束再读 out，否则失败分支本身与它竞争
				t.Fatalf("the wrapper did not finish within %v; stdout so far %q", limit, out.String())
			}
			elapsed := time.Since(start)
			if n := strings.Count(out.String(), "hookSpecificOutput"); n != 1 {
				t.Fatalf("want exactly one answer, got %d: %q", n, out.String())
			}
			d := decision(t, bytes.TrimSpace(out.Bytes()))
			if d != "ask" || !strings.Contains(out.String(), tt.reason) {
				t.Errorf("decision %s, output %q", d, out.String())
			}
			t.Logf("answered %s after %v (--timeout %v)", d, elapsed, timeout)
		})
	}
}

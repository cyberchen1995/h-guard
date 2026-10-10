// Command hookrec 把 hook 或扩展收到的输入原样记下来，供 M0 录制 harness 样本（spec §7.5）。
// 它不做任何安全判断，只在 stdin 含 -canary 指定的字符串时按 -mode 回复。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, time.Now))
}

// run 返回退出码：0 正常（含 -h）；1 参数错误或运行错误。永不返回 2：Claude Code 与 Codex
// 都可能把 2 当作阻止，录制工具不能意外阻止（评审 H05）。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, now func() time.Time) int {
	opt := options{Now: now}
	fs := flag.NewFlagSet("hookrec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&opt.Out, "out", "", "记录目录（必填）")
	fs.StringVar(&opt.Event, "event", "unknown", "事件或 hook 名，写进记录和文件名")
	fs.StringVar(&opt.Format, "format", "codex", "回复格式：codex 或 ext")
	fs.StringVar(&opt.Mode, "mode", "record", "回复模式：codex 为 "+strings.Join(modes["codex"], "、")+"；ext 为 "+strings.Join(modes["ext"], "、"))
	fs.StringVar(&opt.Canary, "canary", "", "只有 stdin 含该字符串时才按模式回复")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if opt.Out == "" {
		fmt.Fprintln(stderr, "hookrec: -out is required")
		return 1
	}
	if err := checkMode(opt); err != nil {
		fmt.Fprintln(stderr, "hookrec:", err)
		return 1
	}
	data, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "hookrec:", err)
		return 1
	}
	reply, err := handle(data, opt)
	if err != nil {
		fmt.Fprintln(stderr, "hookrec:", err)
		return 1
	}
	if len(reply) > 0 {
		_, _ = stdout.Write(reply)
	}
	return 0
}

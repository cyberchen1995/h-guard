// Command tagstat 统计本机 Claude Code 与 Codex 会话记录里用户消息的开头标签，用来发现自动消息的写法
// （spec §5.4、§7.5）。只输出计数、标签名、字段名与白名单字段的取值，不输出消息内容、路径、ID 或未知字段的取值。
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tagstat:", err)
		os.Exit(1)
	}
	claudeDir := flag.String("claude-dir", filepath.Join(home, ".claude", "projects"), "Claude Code 会话记录目录")
	codexDir := flag.String("codex-dir", filepath.Join(home, ".codex", "sessions"), "Codex 会话记录目录")
	flag.Parse()
	out := []Summary{
		scanDir("claudecode", *claudeDir, claudeUser),
		scanDir("codex", *codexDir, codexUser),
	}
	if err := writeJSON(os.Stdout, out); err != nil {
		fmt.Fprintln(os.Stderr, "tagstat:", err)
		os.Exit(1)
	}
}

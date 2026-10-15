// Package extensions 内嵌 harness 的接入文件，由 h-guard install 写出（spec §7.7、§12）。tests 目录不内嵌。
package extensions

import "embed"

// ClaudeCode 是 Claude Code 插件（经典 PreToolUse hook 与 mod），根目录为 claudecode/。
//
//go:embed claudecode/.claude-plugin claudecode/hooks
var ClaudeCode embed.FS

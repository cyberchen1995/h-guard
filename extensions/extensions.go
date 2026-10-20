// Package extensions 内嵌 harness 的接入文件，由 h-guard install 写出。tests 目录不内嵌。
package extensions

import "embed"

// ClaudeCode 是 Claude Code 插件（经典 PreToolUse hook 与 mod），根目录为 claudecode/。
//
//go:embed claudecode/.claude-plugin claudecode/hooks
var ClaudeCode embed.FS

// OpenCode 是 opencode 1.x 的插件（单个文件）。
//
//go:embed opencode/h-guard.js
var OpenCode []byte

// Pi 是 pi 与 oh-my-pi（omp）共用的扩展（单个文件）。
//
//go:embed pi/h-guard.js
var Pi []byte

// DSH 是 DeepSeek Harness 的 Cordis 插件（单个文件）。
//
//go:embed dsh/h-guard.mjs
var DSH []byte

// OpenClaw 是 OpenClaw 的原生插件（清单、package.json 与入口），根目录为 openclaw/。
//
//go:embed openclaw/openclaw.plugin.json openclaw/package.json openclaw/index.mjs
var OpenClaw embed.FS

// Hermes 是 Hermes Agent 的 Python 插件（plugin.yaml 与 __init__.py），根目录为 hermes/。
//
//go:embed hermes/plugin.yaml hermes/__init__.py
var Hermes embed.FS

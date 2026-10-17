#!/bin/sh
# h-guard 的经典 PreToolUse hook：把 Claude Code 的 hook 输入交给 h-guard。
# h-guard 无法运行（找不到、启动失败、非零退出）时输出 ask，让这次工具调用请求确认。
# 插件根目录的两个文件由 install 写入（第一行有效）：hguard-bin 是 h-guard 的路径，没有时用 PATH 中的 h-guard；
# hguard-timeout 是传给 h-guard 的 --timeout 秒数，须与 hooks.json 中的超时一致，没有或无效时为 20。
# h-guard 自己保证在 --timeout 之前输出并退出（看门狗），脚本在它退出后原样转交。
root=${CLAUDE_PLUGIN_ROOT:-$(dirname "$0")/..}
bin=$(head -n 1 "$root/hguard-bin" 2>/dev/null)
[ -n "$bin" ] || bin=h-guard
timeout=$(head -n 1 "$root/hguard-timeout" 2>/dev/null)
case $timeout in
'' | *[!0-9]*) timeout=20 ;;
esac
if out=$("$bin" hook claudecode --event PreToolUse --timeout "$timeout" 2>/dev/null); then
  printf '%s' "$out"
  exit 0
fi
printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"h-guard could not run its check, so this tool call needs your confirmation."}}'
exit 0

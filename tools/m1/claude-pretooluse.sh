#!/usr/bin/env bash
# M1：录制 Claude Code 插件内经典 PreToolUse 的原生输入（spec §7.7、§13）。每个场景用一份插件副本
# （--plugin-dir）：hguard-bin 指向只调用 hookrec 的小脚本，经典 PreToolUse 的输入原样记下、不回复（放行）；
# mod 照常经 hguard.json 记录 prompt.submit 与 tool.result，用来核对两边的会话 ID。不改全局配置。
# 用法：export HG_M1_WORK=<空目录>; tools/m1/claude-pretooluse.sh; 然后 tools/m1/import.sh
export HG_M0_WORK="${HG_M1_WORK:?请先 export HG_M1_WORK（一个空的工作目录）}"
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../m0/lib.sh"
build_tools m0mcp

VERSION="$(claude --version | awk '{print $1}')"
MCP_TOOL=mcp__hgm0__hg_m0_report
log "Claude Code $VERSION，工作目录 $WORK"
mkdir -p "$WORK/claudecode"

# [PERM_MODE=…] scenario NAME PROMPT [SETUP]：SETUP 在场景目录里执行
scenario() {
  selected "$1" || return 0
  local name="$1" dir="$WORK/claudecode/$1" plugin="$WORK/claudecode/$1.plugin" mcp="$WORK/claudecode/$1.mcp.json"
  local stream="$WORK/claudecode/$1.stream.jsonl" stderr="$WORK/claudecode/$1.stderr"
  local secret_file="$WORK/claudecode/$1.mcp-secret" shim rc=0
  rm -rf "${RAW:?}/claudecode/${name:?}" "${dir:?}" "${plugin:?}"
  mkdir -p "$dir"
  write_manifest claudecode "$name" "$VERSION"
  cp -R "$REPO_ROOT/extensions/claudecode" "$plugin"
  mod_config claudecode "$name" record record record "" > "$plugin/hguard.json"
  shim="$plugin/pretooluse-rec.sh"
  printf '#!/bin/sh\nexec %s\n' "$(shq "$BIN/hookrec" -out "$RAW/claudecode/$name" -event PreToolUse -format codex -mode record)" > "$shim"
  chmod +x "$shim"
  printf '%s\n' "$shim" > "$plugin/hguard-bin"
  printf 'hg-m1-mcp\n' > "$secret_file"
  jq -n --arg bin "$BIN/m0mcp" --arg file "$secret_file" \
    '{mcpServers: {hgm0: {type: "stdio", command: $bin, args: ["-secret-file", $file]}}}' > "$mcp"
  if [[ -n "${3:-}" ]]; then (cd "$dir" && eval "$3"); fi
  log "运行场景 $name（${PERM_MODE:-acceptEdits}）"
  (cd "$dir" && claude -p "$2" \
      --plugin-dir "$plugin" --setting-sources project,local \
      --mcp-config "$mcp" --strict-mcp-config \
      --model haiku --output-format stream-json --verbose --permission-mode "${PERM_MODE:-acceptEdits}" \
      --allowedTools "Bash(echo:*)" Read Write Edit Grep Monitor "$MCP_TOOL") \
    < /dev/null > "$stream" 2> "$stderr" || rc=$?
  log "场景 $name：退出码 $rc，PreToolUse 记录 $(record_count claudecode "$name" PreToolUse) 条"
}

scenario pre-bash "Use the Bash tool to run exactly: echo hg-m1-bash. Then reply with its output."
if [[ "$(record_count claudecode pre-bash PreToolUse)" == 0 ]]; then
  log "未录到 PreToolUse：插件的经典 hook 没有运行，停止。见 $WORK/claudecode/pre-bash.stderr"
  exit 1
fi
scenario pre-files "Use the Read tool to read notes.txt. Then use the Grep tool to search for hello in the current directory. Then use the Write tool to create copy.txt with the same content as notes.txt. Then use the Edit tool to replace hello with bye in copy.txt." \
  "printf 'hello\n' > notes.txt"
scenario pre-monitor "Use the Monitor tool to run exactly: echo hg-m1-monitor. Report the first line it prints, then stop the monitor."
scenario pre-mcp "Call the hg_m0_report tool of the hgm0 MCP server. Reply with exactly the value of its code field and nothing else."
PERM_MODE=default scenario pre-mode-default "Use the Bash tool to run exactly: echo hg-m1-default. Then reply with its output."
PERM_MODE=auto scenario pre-mode-auto "Use the Bash tool to run exactly: echo hg-m1-auto. Then reply with its output."
PERM_MODE=bypassPermissions scenario pre-mode-bypass "Use the Bash tool to run exactly: echo hg-m1-bypass. Then reply with its output."
log "完成。导入：tools/m1/import.sh"

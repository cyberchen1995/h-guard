#!/usr/bin/env bash
# 用 claude -p 录制 Claude Code 的样本并做金丝雀验证（spec §7.5）。每个场景用临时目录里的一份 mod 副本
# （--plugin-dir），hguard.json 指向 hookrec；不改全局配置，不用 settings hook。
# 输出用 stream-json：最终回复与给用户的提示（ui_log 等）分开采集，工具输出不算提示。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_tools m0mcp

VERSION="$(claude --version | awk '{print $1}')"
MCP_TOOL=mcp__hgm0__hg_m0_report
# 目标工具（逗号分隔的 jq 正则）：证据只算这些工具的（评审 C2）
T_BASH='^Bash$'
T_READ='^Read$'
T_MCP="^${MCP_TOOL}\$"
T_FILES='^Read$,^Write$,^Edit$'
T_MONITOR='^Monitor$'
log "Claude Code $VERSION，工作目录 $WORK"
mkdir -p "$WORK/claudecode"
facts_begin claudecode

# [PERM_MODE=…] scenario NAME CHECK RESULT PROMPT_MODE TRIGGER SECRET TOOLS PROMPT [SETUP]
# SETUP 在场景目录里执行；MCP 服务读取的秘密文件在场景目录之外，路径由 $MCP_SECRET 给出（评审 C2）。
scenario() {
  selected "$1" || return 0
  local name="$1" dir="$WORK/claudecode/$1" plugin="$WORK/claudecode/$1.plugin" mcp="$WORK/claudecode/$1.mcp.json"
  local stream="$WORK/claudecode/$1.stream.jsonl" result="$WORK/claudecode/$1.result.txt"
  local notices="$WORK/claudecode/$1.notices.jsonl" stderr="$WORK/claudecode/$1.stderr"
  local secret_file="$WORK/claudecode/$1.mcp-secret" rc=0
  rm -rf "${RAW:?}/claudecode/${name:?}" "${dir:?}" "${plugin:?}"
  rm -f "${secret_file:?}"
  mkdir -p "$dir"
  write_manifest claudecode "$name" "$VERSION"
  cp -R "$REPO_ROOT/extensions/claudecode" "$plugin"
  mod_config claudecode "$name" "$2" "$3" "$4" "$5" > "$plugin/hguard.json"
  jq -n --arg bin "$BIN/m0mcp" --arg file "$secret_file" \
    '{mcpServers: {hgm0: {type: "stdio", command: $bin, args: ["-secret-file", $file]}}}' > "$mcp"
  if [[ -n "${9:-}" ]]; then (cd "$dir" && export MCP_SECRET="$secret_file" && eval "$9"); fi
  log "运行场景 $name"
  (cd "$dir" && claude -p "$8" \
      --plugin-dir "$plugin" --setting-sources project,local \
      --mcp-config "$mcp" --strict-mcp-config \
      --model haiku --output-format stream-json --verbose --permission-mode "${PERM_MODE:-acceptEdits}" \
      --allowedTools "Bash(echo:*)" "Bash(cat:*)" Read Write Edit Monitor "$MCP_TOOL") \
    > "$stream" 2> "$stderr" || rc=$?
  stream_split "$stream" "$result" "$notices"
  record_facts claudecode "$name" "$rc" "$result" "$6" "$7" "$stderr" "$notices"
}


S_CAT="$(new_canary)"; S_ERR_CTRL="$(new_canary)"; S_READ_CTRL="$(new_canary)"; S_MCP_CTRL="$(new_canary)"
S_PROMPT_CTRL="$(new_canary)"; S_DENY="$(new_canary)"; S_ASK="$(new_canary)"; S_ASK_AUTO="$(new_canary)"
S_ASK_BYPASS="$(new_canary)"; S_PROMPT="$(new_canary)"; S_REPLACE="$(new_canary)"; S_ERR="$(new_canary)"
S_WARN="$(new_canary)"; S_READ="$(new_canary)"; S_MCP="$(new_canary)"
# 被拦下后不许换别的办法，否则证据归不到目标工具（评审 I6）
STOP=" If the command is blocked, or its output is withheld or replaced, do not run any other command or tool; just reply BLOCKED."
STOP_TOOL=" If the call is blocked, or its result is withheld or replaced, do not use any other tool; just reply BLOCKED."
P_CAT="Use the Bash tool to run exactly: cat entry.txt. Reply with exactly its stdout and nothing else.$STOP"
P_ERR="Use the Bash tool to run exactly: cat entry.txt missing.txt. It fails because missing.txt does not exist; that is expected. Exactly one line of its output starts with HGCANARY; reply with exactly that line and nothing else.$STOP"
P_READ="Use the Read tool to read memo.txt. Reply with exactly its contents and nothing else.$STOP_TOOL"
P_MCP="Call the hg_m0_report tool of the hgm0 MCP server. Reply with exactly the value of its code field and nothing else.$STOP_TOOL"
p_entry() { printf 'Use the Bash tool to run exactly: cat %s. Reply with exactly its stdout and nothing else.%s' "$1" "$STOP"; }

scenario prompt-plain record record record "" "" "" "Reply with the single word OK."
if [[ "$(record_count claudecode prompt-plain prompt.submit)" == 0 ]]; then
  log "未录到 prompt.submit：mod 没有加载，停止。见 $WORK/claudecode/prompt-plain.stderr"
  exit 1
fi

# 正对照：hook 只记录，工具应执行、模型应能复述秘密串
scenario control-cat record record record "" "$S_CAT" "$T_BASH" "$P_CAT" "printf '%s\n' '$S_CAT' > entry.txt"
gate_control claudecode control-cat "$S_CAT" "$T_BASH" "$WORK/claudecode/control-cat.result.txt"
scenario control-bash-error record record record "" "$S_ERR_CTRL" "$T_BASH" "$P_ERR" "printf '%s\n' '$S_ERR_CTRL' > entry.txt"
scenario control-read record record record "" "$S_READ_CTRL" "$T_READ" "$P_READ" "printf '%s\n' '$S_READ_CTRL' > memo.txt"
scenario control-mcp record record record "" "$S_MCP_CTRL" "$T_MCP" "$P_MCP" "printf '%s\n' '$S_MCP_CTRL' > \"\$MCP_SECRET\""
scenario control-prompt record record record "" "$S_PROMPT_CTRL" "" \
  "Remember this code: $S_PROMPT_CTRL. Reply with exactly the code and nothing else."

# 只记录行为的场景
scenario bash-echo record record record "" "" "$T_BASH" \
  "Use the Bash tool to run exactly: echo hg-m0-bash. Then reply with its output."
scenario file-ops record record record "" "" "$T_FILES" \
  "Use the Read tool to read notes.txt. Then use the Write tool to create copy.txt with the same content. Then use the Edit tool to replace hello with bye in copy.txt." \
  "printf 'hello\n' > notes.txt"
scenario monitor record record record "" "" "$T_MONITOR" \
  "Use the Monitor tool to run exactly: echo hg-m0-monitor. Report the first line it prints, then stop the monitor."
scenario ask-pre ask record record "entry-q.txt" "$S_ASK" "$T_BASH" "$(p_entry entry-q.txt)" \
  "printf '%s\n' '$S_ASK' > entry-q.txt"
PERM_MODE=auto scenario ask-auto ask record record "entry-q.txt" "$S_ASK_AUTO" "$T_BASH" "$(p_entry entry-q.txt)" \
  "printf '%s\n' '$S_ASK_AUTO' > entry-q.txt"
PERM_MODE=bypassPermissions scenario ask-bypass ask record record "entry-q.txt" "$S_ASK_BYPASS" "$T_BASH" "$(p_entry entry-q.txt)" \
  "printf '%s\n' '$S_ASK_BYPASS' > entry-q.txt"

# 拦截与扣下
scenario deny-pre deny record record "entry-d.txt" "$S_DENY" "$T_BASH" "$(p_entry entry-d.txt)" \
  "printf '%s\n' '$S_DENY' > entry-d.txt"
scenario block-prompt record record deny "$S_PROMPT" "$S_PROMPT" "" \
  "Remember this code: $S_PROMPT. Reply with exactly the code and nothing else."
scenario replace-bash record deny record "$S_REPLACE" "$S_REPLACE" "$T_BASH" "$P_CAT" "printf '%s\n' '$S_REPLACE' > entry.txt"
scenario replace-bash-error record deny record "$S_ERR" "$S_ERR" "$T_BASH" "$P_ERR" "printf '%s\n' '$S_ERR' > entry.txt"
scenario warn-bash record warn record "$S_WARN" "$S_WARN" "$T_BASH" "$P_CAT" "printf '%s\n' '$S_WARN' > entry.txt"
scenario replace-read record deny record "$S_READ" "$S_READ" "$T_READ" "$P_READ" "printf '%s\n' '$S_READ' > memo.txt"
scenario replace-mcp record deny record "$S_MCP" "$S_MCP" "$T_MCP" "$P_MCP" "printf '%s\n' '$S_MCP' > \"\$MCP_SECRET\""

log "完成。事实表：$WORK/claudecode-facts.tsv；判定表：$WORK/claudecode-verdict.md"
judge_facts claudecode

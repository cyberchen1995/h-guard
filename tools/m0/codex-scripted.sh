#!/usr/bin/env bash
# 用 codex exec 录制 Codex 的样本并做金丝雀验证（spec §7.5）。只用临时项目里的 .codex/hooks.json，
# MCP 服务用 -c 覆盖传入，不改全局配置。若项目级 hooks 不加载，可通过 CODEX_EXTRA_ARGS 追加参数
# （见 docs/verification/m0-checklist.md）。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_tools m0mcp

VERSION="$(codex --version | awk '{print $2}')"
PROJ="$WORK/codex/proj"
# MCP 服务读取的秘密文件放在项目目录之外，agent 不能直接读到它（评审 C2）
export MCP_SECRET="$WORK/codex/mcp-secret"
# 目标工具（逗号分隔的 jq 正则）：证据只算这些工具的。Codex hook 中 MCP 工具名的写法以录制为准
T_BASH='^Bash$'
T_PATCH='^apply_patch$'
T_MCP='hg_m0_report'
mkdir -p "$PROJ/.codex"
[[ -d "$PROJ/.git" ]] || (cd "$PROJ" && git init -q)
log "Codex $VERSION，项目目录 $PROJ"
facts_header codex
read -r -a EXTRA <<< "${CODEX_EXTRA_ARGS:-}"
MCP_ARGS=(-c "mcp_servers.hgm0.command=$(toml_str "$BIN/m0mcp")"
  -c "mcp_servers.hgm0.args=[\"-secret-file\", $(toml_str "$MCP_SECRET")]")

# scenario NAME PRE POST PROMPT_MODE TRIGGER SECRET TOOLS PROMPT [SETUP]
scenario() {
  local name="$1" result="$WORK/codex/$1.last.txt" stderr="$WORK/codex/$1.stderr"
  local events="$WORK/codex/$1.events.jsonl" rc=0
  rm -rf "${RAW:?}/codex/${name:?}"
  rm -f "${result:?}" "${PROJ:?}"/*.txt "${MCP_SECRET:?}"
  write_manifest codex "$name" "$VERSION"
  hooks_json codex "$name" "$2" "$3" "$4" "$5" > "$PROJ/.codex/hooks.json"
  if [[ -n "${9:-}" ]]; then (cd "$PROJ" && eval "$9"); fi
  log "运行场景 $name"
  codex exec --cd "$PROJ" --skip-git-repo-check --sandbox workspace-write \
      --dangerously-bypass-hook-trust --json -o "$result" "${MCP_ARGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"} "$8" \
    > "$events" 2> "$stderr" || rc=$?
  record_facts codex "$name" "$rc" "$result" "$6" "$7" "$stderr" "$events"
}

# gate NAME SECRET TOOLS：门槛场景没通过就停止，免得整轮录制都是 inconclusive
gate() {
  if [[ "$(record_count codex "$1" PostToolUse "$2" "$3")" == 0 \
    || "$(has_text "$WORK/codex/$1.last.txt" "$2")" != yes ]]; then
    log "正对照 $1 未通过（工具没执行，或模型没复述），停止。见 $WORK/codex/$1.*"
    exit 1
  fi
}

S_CAT="$(new_canary)"; S_ERR_CTRL="$(new_canary)"; S_MCP_CTRL="$(new_canary)"; S_PROMPT_CTRL="$(new_canary)"
S_DENY="$(new_canary)"; S_ASK="$(new_canary)"; S_PROMPT="$(new_canary)"; S_BLOCK="$(new_canary)"
S_ERR="$(new_canary)"; S_MCP="$(new_canary)"
# 被拦下后不许换别的办法，否则证据归不到目标工具（评审 I6）
STOP=" If the command is blocked, or its output is withheld or replaced, do not run any other command or tool; just reply BLOCKED."
P_CAT="Run the shell command: cat entry.txt. Reply with exactly its stdout and nothing else.$STOP"
P_ERR="Run the shell command: cat entry.txt missing.txt. It fails because missing.txt does not exist; that is expected. Reply with exactly the first line of its output and nothing else.$STOP"
P_MCP="Call the hg_m0_report tool of the hgm0 MCP server. Reply with exactly the value of its code field and nothing else. If the call is blocked, or its result is withheld or replaced, do not use any other tool; just reply BLOCKED."
p_entry() { printf 'Run the shell command: cat %s. Reply with exactly its stdout and nothing else.%s' "$1" "$STOP"; }

mkdir -p "$WORK/codex"
scenario prompt-plain record record record "" "" "" "Reply with the single word OK."
if [[ "$(record_count codex prompt-plain UserPromptSubmit)" == 0 ]]; then
  log "未录到 UserPromptSubmit：项目级 hooks 没有加载。按 docs/verification/m0-checklist.md「Codex hooks 未加载」处理"
  exit 1
fi

# 正对照
scenario control-cat record record record "" "$S_CAT" "$T_BASH" "$P_CAT" "printf '%s\n' '$S_CAT' > entry.txt"
gate control-cat "$S_CAT" "$T_BASH"
scenario control-bash-error record record record "" "$S_ERR_CTRL" "$T_BASH" "$P_ERR" "printf '%s\n' '$S_ERR_CTRL' > entry.txt"
scenario control-mcp record record record "" "$S_MCP_CTRL" "$T_MCP" "$P_MCP" "printf '%s\n' '$S_MCP_CTRL' > \"\$MCP_SECRET\""
scenario control-prompt record record record "" "$S_PROMPT_CTRL" "" \
  "Remember this code: $S_PROMPT_CTRL. Reply with exactly the code and nothing else."

# 只记录行为的场景
scenario bash-echo record record record "" "" "$T_BASH" \
  "Run the shell command: echo hg-m0-bash. Then reply with its output."
scenario apply-patch record record record "" "" "$T_PATCH" \
  "Using apply_patch for every file change: create a.txt containing the line alpha, then rename a.txt to b.txt, then delete b.txt."

# 拦截与替换
scenario deny-pre deny record record "entry-d.txt" "$S_DENY" "$T_BASH" "$(p_entry entry-d.txt)" \
  "printf '%s\n' '$S_DENY' > entry-d.txt"
scenario ask-pre ask record record "entry-q.txt" "$S_ASK" "$T_BASH" "$(p_entry entry-q.txt)" \
  "printf '%s\n' '$S_ASK' > entry-q.txt"
scenario block-prompt record record block-prompt "$S_PROMPT" "$S_PROMPT" "" \
  "Remember this code: $S_PROMPT. Reply with exactly the code and nothing else."
scenario block-bash record block-output record "$S_BLOCK" "$S_BLOCK" "$T_BASH" "$P_CAT" "printf '%s\n' '$S_BLOCK' > entry.txt"
scenario block-bash-error record block-output record "$S_ERR" "$S_ERR" "$T_BASH" "$P_ERR" "printf '%s\n' '$S_ERR' > entry.txt"
scenario block-mcp record block-output record "$S_MCP" "$S_MCP" "$T_MCP" "$P_MCP" "printf '%s\n' '$S_MCP' > \"\$MCP_SECRET\""

log "完成。事实表：$WORK/codex-facts.tsv；判定表：$WORK/codex-verdict.md"
judge_facts codex

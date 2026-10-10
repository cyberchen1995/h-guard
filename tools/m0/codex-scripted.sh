#!/usr/bin/env bash
# 用 codex exec 录制 Codex 的样本并做金丝雀验证（spec §7.5）。只用临时项目里的 .codex/hooks.json，
# MCP 服务用 -c 覆盖传入，不改全局配置。若项目级 hooks 不加载，可通过 CODEX_EXTRA_ARGS 追加参数
# （见 docs/verification/m0-checklist.md）。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
build_tools m0mcp

VERSION="$(codex --version | awk '{print $2}')"
PROJ="$WORK/codex/proj"
mkdir -p "$PROJ/.codex"
[[ -d "$PROJ/.git" ]] || (cd "$PROJ" && git init -q)
log "Codex $VERSION，项目目录 $PROJ"
facts_header codex
read -r -a EXTRA <<< "${CODEX_EXTRA_ARGS:-}"
MCP_ARGS=(-c "mcp_servers.hgm0.command=$(toml_str "$BIN/m0mcp")"
  -c "mcp_servers.hgm0.args=[\"-secret-file\", $(toml_str "$PROJ/mcp-secret.txt")]")

# scenario NAME PRE POST PROMPT_MODE TRIGGER SECRET TARGET PROMPT [SETUP]
scenario() {
  local name="$1" result="$WORK/codex/$1.last.txt" stderr="$WORK/codex/$1.stderr"
  local events="$WORK/codex/$1.events.jsonl" rc=0
  rm -rf "${RAW:?}/codex/$name"
  rm -f "$result" "$PROJ"/*.txt
  write_manifest codex "$name" "$VERSION"
  hooks_json codex "$name" "$2" "$3" "$4" "$5" > "$PROJ/.codex/hooks.json"
  if [[ -n "${9:-}" ]]; then (cd "$PROJ" && eval "$9"); fi
  log "运行场景 $name"
  codex exec --cd "$PROJ" --skip-git-repo-check --sandbox workspace-write \
      --dangerously-bypass-hook-trust --json -o "$result" "${MCP_ARGS[@]}" ${EXTRA[@]+"${EXTRA[@]}"} "$8" \
    > "$events" 2> "$stderr" || rc=$?
  record_facts codex "$name" "$rc" "$result" "$6" "$7" "$stderr" "$events"
}

S_CAT="$(new_canary)"; S_MCP_CTRL="$(new_canary)"; S_PROMPT_CTRL="$(new_canary)"
S_DENY="$(new_canary)"; S_ASK="$(new_canary)"; S_PROMPT="$(new_canary)"; S_BLOCK="$(new_canary)"; S_MCP="$(new_canary)"
P_CAT="Run the shell command: cat token.txt. Reply with exactly its stdout and nothing else."
P_MCP="Call the hg_m0_report tool of the hgm0 MCP server. Reply with exactly the value of its code field and nothing else."

mkdir -p "$WORK/codex"
scenario prompt-plain record record record "" "" "" "Reply with the single word OK."
if [[ "$(record_count codex prompt-plain UserPromptSubmit)" == 0 ]]; then
  log "未录到 UserPromptSubmit：项目级 hooks 没有加载。按 docs/verification/m0-checklist.md「Codex hooks 未加载」处理"
  exit 1
fi
scenario bash-echo record record record "" "" Bash \
  "Run the shell command: echo hg-m0-bash. Then reply with its output."
scenario apply-patch record record record "" "" apply_patch \
  "Using apply_patch for every file change: create a.txt containing the line alpha, then rename a.txt to b.txt, then delete b.txt."

# 正对照
scenario control-cat record record record "" "$S_CAT" Bash "$P_CAT" "printf '%s\n' '$S_CAT' > token.txt"
scenario control-mcp record record record "" "$S_MCP_CTRL" "" "$P_MCP" "printf '%s\n' '$S_MCP_CTRL' > mcp-secret.txt"
scenario control-prompt record record record "" "$S_PROMPT_CTRL" "" \
  "Remember this code: $S_PROMPT_CTRL. Reply with exactly the code and nothing else."

# 拦截与替换
scenario deny-pre deny record record "deny.txt" "$S_DENY" Bash \
  "Run the shell command: cat deny.txt. Reply with exactly its stdout, or say DENIED if it did not run." \
  "printf '%s\n' '$S_DENY' > deny.txt"
scenario ask-pre ask record record "ask.txt" "$S_ASK" Bash \
  "Run the shell command: cat ask.txt. Reply with exactly its stdout, or say DENIED if it did not run." \
  "printf '%s\n' '$S_ASK' > ask.txt"
scenario block-prompt record record block-prompt "$S_PROMPT" "$S_PROMPT" "" \
  "Remember this code: $S_PROMPT. Reply with exactly the code and nothing else."
scenario block-bash record block-output record "$S_BLOCK" "$S_BLOCK" Bash "$P_CAT" "printf '%s\n' '$S_BLOCK' > token.txt"
scenario block-mcp record block-output record "$S_MCP" "$S_MCP" "" "$P_MCP" "printf '%s\n' '$S_MCP' > mcp-secret.txt"

log "完成。事实表：$WORK/codex-facts.tsv；判定表：$WORK/codex-verdict.md"
judge_facts codex

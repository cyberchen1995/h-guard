#!/usr/bin/env bash
# 把本次录制的全部原始记录整组导入 testdata/fixtures，并列出 Claude Code 提示词的来源取值（只计数）。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for h in claudecode codex; do
  if [[ -d "$RAW/$h" ]]; then import_all "$h"; fi
done
log "Claude Code prompt.submit 的 origin.kind 取值与次数："
for f in "$RAW"/claudecode/*/*-prompt.submit.json; do
  [[ -e "$f" ]] || continue
  jq -r '.stdin.data.origin.kind // "(none)"' "$f"
done | sort | uniq -c >&2
log "导入完成。运行 go test ./internal/fixtures/ -v 校验样本。"

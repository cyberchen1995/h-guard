#!/usr/bin/env bash
# 把 M1 录制的 Claude Code 记录整组导入 testdata/fixtures（同场景整组替换，其他场景保留）。
export HG_M0_WORK="${HG_M1_WORK:?请先 export HG_M1_WORK}"
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../m0/lib.sh"
import_all claudecode
log "导入完成。运行 go test ./internal/fixtures/ ./pkg/harness/claudecode/ -run Recorded -v 校验样本。"

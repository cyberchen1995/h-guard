#!/usr/bin/env bash
# 准备 Codex 交互录制：在临时目录写项目级 hooks 并打印启动命令。操作步骤见 docs/verification/m0-checklist.md。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="$(codex --version | awk '{print $2}')"
dir="$WORK/codex/interactive"
rm -rf "${RAW:?}/codex/interactive"
mkdir -p "$dir/.codex"
[[ -d "$dir/.git" ]] || (cd "$dir" && git init -q)
write_manifest codex interactive "$VERSION"
# 只拦下含 HG-DROP-ME 的提示词（清单 C3），其余全部只记录
hooks_json codex interactive record record block-prompt "HG-DROP-ME" > "$dir/.codex/hooks.json"
cat <<EOF
在新的终端标签页里执行：

  cd $(shq "$dir") && codex

首次启动时 Codex 会询问是否信任该目录及其 hooks，请选择信任（只影响这个临时目录）。
EOF

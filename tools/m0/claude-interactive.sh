#!/usr/bin/env bash
# 准备 Claude Code 交互录制：生成 mod 副本并打印启动命令。操作步骤见 docs/verification/m0-checklist.md。
# shellcheck source=tools/m0/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

VERSION="$(claude --version | awk '{print $1}')"
dir="$WORK/claudecode/interactive"
plugin="$WORK/claudecode/interactive.plugin"
rm -rf "${RAW:?}/claudecode/interactive" "$plugin"
mkdir -p "$dir"
write_manifest claudecode interactive "$VERSION"
printf 'hg-m0 ask target\n' > "$dir/ask-me.txt"
cp -R "$REPO_ROOT/extensions/claudecode" "$plugin"
# 只对 cat ask-me.txt 请求确认、只拦下含 HG-DROP-ME 的提示词，其余全部只记录
mod_config claudecode interactive ask record deny "ask-me.txt" "HG-DROP-ME" > "$plugin/hguard.json"
cat <<EOF
在新的终端标签页里执行：

  cd $(shq "$dir") && claude --plugin-dir $(shq "$plugin") --setting-sources project,local

按清单完成后用 /exit 退出。
EOF

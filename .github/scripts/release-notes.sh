#!/usr/bin/env bash
# 从 CHANGELOG 取出一个版本的发布说明，写到标准输出。
#
# 用法：.github/scripts/release-notes.sh <版本> [<CHANGELOG 路径>]
#   <版本>  不带 v 前缀，如 0.1.0 或 0.1.0-rc.1；预发布后缀（第一个 - 起）去掉后查找对应的正式版一节
#   路径    默认是仓库根目录的 CHANGELOG.md
#
# 取的是 "## [<版本>] - <日期>" 一节的正文：不含标题行，到下一个 "## " 开头的行为止，去掉首尾空行。
# 正式版要求日期不是 unreleased（防止忘了填日期就发布）；预发布版允许 unreleased。
# 找不到这一节、或正式版的日期仍是 unreleased 时以 1 退出。
set -u

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
	echo "usage: $0 <version> [<changelog>]" >&2
	exit 2
fi
version=$1
if [ $# -eq 2 ]; then
	changelog=$2
else
	changelog="$(cd "$(dirname "$0")/../.." && pwd)/CHANGELOG.md"
fi
if [ ! -f "$changelog" ]; then
	echo "release-notes: $changelog not found" >&2
	exit 1
fi

base=${version%%-*}
prerelease=0
if [ "$base" != "$version" ]; then
	prerelease=1
fi

awk -v base="$base" -v pre="$prerelease" '
BEGIN { prefix = "## [" base "] - "; found = 0; inside = 0; n = 0; failed = 0 }
inside && /^## / { inside = 0 }
index($0, prefix) == 1 && !found {
	found = 1
	date = substr($0, length(prefix) + 1)
	sub(/[ \t\r]+$/, "", date)
	if (date == "") {
		print "release-notes: section [" base "] has no date" > "/dev/stderr"
		failed = 1
		exit
	}
	if (date == "unreleased" && pre == 0) {
		print "release-notes: section [" base "] is still dated unreleased" > "/dev/stderr"
		failed = 1
		exit
	}
	inside = 1
	next
}
inside { lines[++n] = $0 }
END {
	# 规则里的 exit 仍会进入 END，这里先按失败退出。
	if (failed) exit 1
	if (!found) {
		print "release-notes: no section [" base "] in the changelog" > "/dev/stderr"
		exit 1
	}
	first = 1
	while (first <= n && lines[first] ~ /^[ \t\r]*$/) first++
	last = n
	while (last >= first && lines[last] ~ /^[ \t\r]*$/) last--
	for (i = first; i <= last; i++) print lines[i]
}
' "$changelog"

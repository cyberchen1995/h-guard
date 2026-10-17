#!/usr/bin/env bash
# release-notes.sh 的测试：用临时 CHANGELOG 覆盖正式版、预发布版、缺失版本与节的边界。
# macOS 自带的 bash 3.2 与 Linux 的 bash 都能运行；任一用例失败时以 1 退出。
#
# 用法：bash .github/scripts/release-notes_test.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/release-notes.sh"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/release-notes-test.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT

failures=0

fail() {
	echo "FAIL: $1"
	failures=$((failures + 1))
}

# run <名字> <CHANGELOG 内容> <版本>：运行脚本，结果放进 $out 与 $code。
run() {
	printf '%s' "$2" >"$tmp/$1.md"
	out=$(bash "$script" "$3" "$tmp/$1.md" 2>"$tmp/$1.err")
	code=$?
}

dated='# Changelog

## [Unreleased]

- Pending change.

## [0.1.0] - 2026-10-20

First public release.

### Added

- Feature one.

## [0.0.9] - 2026-09-01

- Old entry.
'

undated='# Changelog

## [Unreleased]

- Pending change.

## [0.1.0] - unreleased

First public release.

### Added

- Feature one.
'

# 正文去掉首尾空行。
expected='First public release.

### Added

- Feature one.
'

# 1. 正式版、有日期：取到正文，不含标题行，不含下一节。
run final-dated "$dated" 0.1.0
if [ "$code" -ne 0 ]; then
	fail "0.1.0 with a date: exit $code, want 0"
elif [ "$out" != "$(printf '%s' "$expected")" ]; then
	fail "0.1.0 with a date: unexpected body:
$out"
elif printf '%s\n' "$out" | grep -q '^## '; then
	fail "0.1.0 with a date: body contains a heading line"
fi

# 2. 正式版、日期为 unreleased：退出 1。
run final-undated "$undated" 0.1.0
if [ "$code" -ne 1 ]; then
	fail "0.1.0 dated unreleased: exit $code, want 1"
fi

# 3. 预发布版、日期为 unreleased：取到 [0.1.0] 一节。
run rc-undated "$undated" 0.1.0-rc.1
if [ "$code" -ne 0 ]; then
	fail "0.1.0-rc.1 dated unreleased: exit $code, want 0"
elif [ "$out" != "$(printf '%s' "$expected")" ]; then
	fail "0.1.0-rc.1 dated unreleased: unexpected body:
$out"
fi

# 4. 预发布版、有日期：同样取到。
run rc-dated "$dated" 0.1.0-rc.1
if [ "$code" -ne 0 ]; then
	fail "0.1.0-rc.1 with a date: exit $code, want 0"
elif [ "$out" != "$(printf '%s' "$expected")" ]; then
	fail "0.1.0-rc.1 with a date: unexpected body:
$out"
fi

# 5. 版本不存在：退出 1。
run missing "$dated" 0.2.0
if [ "$code" -ne 1 ]; then
	fail "0.2.0 missing: exit $code, want 1"
fi

# 6. 正文到下一个 "## " 为止：[Unreleased] 在 [0.1.0] 之上时不被取到，之后的旧版本也不被取到。
run boundary "$dated" 0.1.0
if [ "$code" -ne 0 ] || [ -z "$out" ]; then
	fail "0.1.0 boundary: exit $code with empty or missing body"
fi
case "$out" in
*"Pending change"* | *"Old entry"* | *"[Unreleased]"*)
	fail "0.1.0 body leaks into neighbouring sections:
$out"
	;;
esac

if [ "$failures" -ne 0 ]; then
	echo "$failures case(s) failed"
	exit 1
fi
echo "ok: release-notes.sh"

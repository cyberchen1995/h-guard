#!/usr/bin/env bash
# 逐个检查 <base>..<head> 上的每个提交，合并提交也逐个检查（解决冲突时可能单独引入问题，
# 不能由两个父提交都通过推出它通过）。本地与 CI 共用。
#
# 只做便宜的检查：每个提交要能构建（vet 连测试文件一起编译）、格式与 vet 通过、说明干净。
# 测试不在这里跑：PR 是 squash 合并的，进 main 的只有 head，它的测试由 CI 的 test 矩阵跑；
# 对每个提交跑完整测试要十几分钟一个，几十个提交的 PR 永远跑不完。
#
# 用法：.github/scripts/each-commit.sh <base> <head>
#
# 每个提交：
#   msg     用当前工作树里的 TestCommitMetadata 检查提交说明（HG_COMMIT=<提交>）
#   其余各项在临时目录里用 git worktree add --detach 检出这个提交后运行，不动当前工作区：
#   gofmt   gofmt -l 列出 git 跟踪的 .go 文件中格式不对的（应当没有输出）
#   vet     go vet
#   winvet  GOOS=windows go vet
# 包列表是 go list -e ./... 去掉 /tests/ 下的包。
#
# 每个提交输出一行：<短提交号> <标题> | msg=ok gofmt=ok vet=ok winvet=ok
# 失败的项写 FAIL，后面括号里是这一项的日志路径（日志保留，通过的项的日志删掉）。
# 任一项失败时最后以 1 退出。
set -u

if [ $# -ne 2 ]; then
	echo "usage: $0 <base> <head>" >&2
	exit 2
fi
base=$1
head=$2

root=$(git rev-parse --show-toplevel) || exit 2
cd "$root" || exit 2

commits=$(git rev-list --reverse "$base..$head") || exit 2
if [ -z "$commits" ]; then
	echo "no commits in $base..$head"
	exit 0
fi

logdir=$(mktemp -d "${TMPDIR:-/tmp}/each-commit.XXXXXX") || exit 2
wt="$logdir/worktree"

# shellcheck disable=SC2329 # 由 trap 调用
cleanup() {
	if [ -d "$wt" ]; then
		git -C "$root" worktree remove --force "$wt" >/dev/null 2>&1
	fi
	git -C "$root" worktree prune >/dev/null 2>&1
	rm -rf "$wt"
	# 没有失败的日志时整个目录删掉
	if [ -z "$(ls -A "$logdir" 2>/dev/null)" ]; then
		rm -rf "$logdir"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

failed=0

# check <名字> <目录> <日志> <命令...>：在目录里运行命令，成功时 ok 并删掉日志，否则 FAIL(日志路径)。
check() {
	local name=$1 dir=$2 log=$3
	shift 3
	if (cd "$dir" && "$@") >"$log" 2>&1; then
		rm -f "$log"
		result="$result $name=ok"
	else
		result="$result $name=FAIL($log)"
		failed=1
	fi
}

# gofmt -l 有输出也算失败
# shellcheck disable=SC2329 # 经 check 调用
run_gofmt() {
	local out
	out=$(git ls-files -z '*.go' | xargs -0 gofmt -l) || {
		printf '%s\n' "$out"
		return 1
	}
	if [ -n "$out" ]; then
		printf '%s\n' "$out"
		return 1
	fi
}

for sha in $commits; do
	short=$(git rev-parse --short "$sha")
	title=$(git log -1 --format=%s "$sha")
	result=""

	check msg "$root" "$logdir/$short-msg.log" \
		env HG_COMMIT="$sha" go test -count=1 -run '^TestCommitMetadata$' ./internal/repocheck/

	if git worktree add --detach -q "$wt" "$sha" >"$logdir/$short-worktree.log" 2>&1; then
		rm -f "$logdir/$short-worktree.log"
		pkgs=$(cd "$wt" && go list -e ./... | grep -v /tests/)
		check gofmt "$wt" "$logdir/$short-gofmt.log" run_gofmt
		# shellcheck disable=SC2086 # 包列表按空白分开
		check vet "$wt" "$logdir/$short-vet.log" go vet $pkgs
		# shellcheck disable=SC2086
		check winvet "$wt" "$logdir/$short-winvet.log" env GOOS=windows go vet $pkgs
		git worktree remove --force "$wt" >/dev/null 2>&1
		rm -rf "$wt"
	else
		result="$result gofmt=FAIL vet=FAIL winvet=FAIL (checkout: $logdir/$short-worktree.log)"
		failed=1
	fi

	echo "$short $title |$result"
done

exit "$failed"

#!/usr/bin/env bash
# M0 录制脚本的公共部分，由其他脚本 source（spec §7.5）。
# 不修改任何全局 harness 配置：Claude Code 用临时目录里的 mod 副本，Codex 用临时项目的 hooks 配置。
set -euo pipefail

: "${HG_M0_WORK:?请先 export HG_M0_WORK，见 docs/verification/m0-checklist.md 第 0 节}"
if ! command -v jq >/dev/null 2>&1; then
  printf '[m0] 需要 jq 1.6 或更新版本\n' >&2
  exit 1
fi
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# 用物理路径：harness 报告的 cwd 是解析符号链接后的写法（macOS 上是 /private/var/...）；
# WORK_LINK 是 HG_M0_WORK 的绝对写法，记录里也可能出现它，导入时两种都替换
WORK="$(cd "$HG_M0_WORK" && pwd -P)"
WORK_LINK="$(cd "$HG_M0_WORK" && pwd -L)"
BIN="$WORK/bin"
RAW="$WORK/raw"
RUN_ID="${HG_M0_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
REASON_MARK="h-guard M0 test"      # hookrec 回复里的原因文本
REPLACED_MARK="[h-guard replaced]" # hookrec 扣下或替换输出时用的标记
mkdir -p "$BIN" "$RAW"

log() { printf '[m0] %s\n' "$*" >&2; }

# build_tools NAME...：把 tools/NAME 编译到 $BIN；程序不存在或比任一 Go 源码旧时重新编译，
# 避免修改代码后在同一个 HG_M0_WORK 里重跑时用到旧程序（评审 I5）
build_tools() {
  local t
  for t in "$@"; do
    if [[ ! -x "$BIN/$t" || -n "$(find "$REPO_ROOT/go.mod" "$REPO_ROOT/pkg" "$REPO_ROOT/internal" "$REPO_ROOT/tools/$t" \
      -newer "$BIN/$t" \( -name '*.go' -o -name go.mod \) -print -quit 2>/dev/null)" ]]; then
      # 先编译到临时文件再改名：整体替换，go build 也不会拒绝覆盖非目标文件
      (cd "$REPO_ROOT" && go build -o "$BIN/$t.new" "./tools/$t") && mv -f "$BIN/$t.new" "$BIN/$t"
    fi
  done
}
build_tools hookrec fiximport m0verdict

# new_canary：随机秘密串，只出现在临时文件或被拦截的输入里
new_canary() { printf 'HGCANARY-%s' "$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"; }

# shq ARG...：按 POSIX shell 单引号规则逐个引用参数，以空格连接（评审 H06）。-- 之后的参数即使以 - 开头也不当作 jq 选项
shq() { jq -rn '$ARGS.positional | @sh' --args -- "$@"; }

# toml_str S：TOML 基本字符串（JSON 字符串转义与之兼容）
toml_str() { jq -rn --arg s "$1" '$s | @json'; }

# hook_cmd HARNESS SCENARIO EVENT MODE TRIGGER：一条 Codex 原生 hook 的 hookrec 命令
hook_cmd() {
  shq "$BIN/hookrec" -out "$RAW/$1/$2" -event "$3" -format codex -mode "$4" -canary "${5:-}"
}

# hooks_json HARNESS SCENARIO PRE_MODE POST_MODE PROMPT_MODE TRIGGER：原生 hooks 配置（Codex 用；不写 matcher，
# 匹配全部工具）。HARNESS 只决定记录目录。
hooks_json() {
  local pre post prompt
  # 先单独赋值：命令替换失败时 set -e 立即退出，不会生成空命令
  pre="$(hook_cmd "$1" "$2" PreToolUse "$3" "$6")"
  post="$(hook_cmd "$1" "$2" PostToolUse "$4" "$6")"
  prompt="$(hook_cmd "$1" "$2" UserPromptSubmit "$5" "$6")"
  jq -n --arg pre "$pre" --arg post "$post" --arg prompt "$prompt" \
    '{hooks: {
        PreToolUse: [{hooks: [{type: "command", command: $pre, timeout: 30}]}],
        PostToolUse: [{hooks: [{type: "command", command: $post, timeout: 30}]}],
        UserPromptSubmit: [{hooks: [{type: "command", command: $prompt, timeout: 30}]}]}}'
}

# mod_config HARNESS SCENARIO CHECK_MODE RESULT_MODE PROMPT_MODE TRIGGER [PROMPT_TRIGGER]：Claude Code mod 的
# hguard.json。每个 hook 一条 hookrec 命令（ext 格式），mod 会在其后追加 --event <hook>。
mod_config() {
  jq -n --arg bin "$BIN/hookrec" --arg out "$RAW/$1/$2" \
    --arg check "$3" --arg result "$4" --arg prompt "$5" --arg trig "${6:-}" --arg ptrig "${7:-${6:-}}" '
    def cmd($mode; $t): [$bin, "-format", "ext", "-out", $out, "-mode", $mode, "-canary", $t];
    {commands: {
        "tool.check": cmd($check; $trig),
        "tool.result": cmd($result; $trig),
        "prompt.submit": cmd($prompt; $ptrig)},
     timeout_ms: 20000}'
}

# write_manifest HARNESS SCENARIO VERSION：在场景的记录目录写批次信息，导入时以它为准（评审 H07）
write_manifest() {
  mkdir -p "$RAW/$1/$2"
  jq -n --arg run "$RUN_ID" --arg h "$1" --arg v "$3" --arg p "$PLATFORM" --arg s "$2" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{run_id: $run, harness: $h, version: $v, platform: $p, scenario: $s, recorded_at: $at}' \
    > "$RAW/$1/$2/manifest.json"
}

# pre_event、post_event HARNESS：工具调用前、调用后事件的名字；tool_key HARNESS：记录中工具名的位置
pre_event() { if [[ "$1" == codex ]]; then echo PreToolUse; else echo tool.check; fi; }
post_event() { if [[ "$1" == codex ]]; then echo PostToolUse; else echo tool.result; fi; }
tool_key() { if [[ "$1" == codex ]]; then echo tool_name; else echo data.tool; fi; }

# JQ_DEFS：记录的工具名与工具输出。TOOLS 是逗号分隔的 jq 正则，为空时匹配任何工具。
# 工具输出指 Codex 的 tool_response、扩展请求的 result；工具输入与 hook 回复不算（评审 H02）。
# shellcheck disable=SC2016 # $key 等由 jq 解释
JQ_DEFS='def tool_of: ((.stdin | objects | getpath($key | split("."))) // "") | tostring;
def tool_in($tools): tool_of as $tool | ($tools | split(",") | map(select(. != ""))) as $rs
  | ($rs | length) == 0 or any($rs[]; . as $r | $tool | test($r));
def output_has($t): [.stdin | objects | (.tool_response, .result) | .. | strings | select(contains($t))] | length > 0;'

# count_records HARNESS SCENARIO EVENT FILTER [JQ_ARGS...]：满足 FILTER 的记录条数；EVENT 为 * 表示全部事件
count_records() {
  local h="$1" dir="$RAW/$1/$2" event="$3" filter="$4" n=0 f
  shift 4
  # shellcheck disable=SC2231 # EVENT 为 * 时要展开为通配
  for f in "$dir"/*-$event.json; do
    [[ -e "$f" ]] || continue
    if jq -e --arg key "$(tool_key "$h")" "$@" "$JQ_DEFS $filter" "$f" >/dev/null 2>&1; then
      n=$((n + 1))
    fi
  done
  echo "$n"
}

# record_count HARNESS SCENARIO EVENT [TEXT] [TOOLS]：某场景某事件的记录条数。给 TEXT 时只数工具输出中
# 按字面含 TEXT 的记录；给 TOOLS 时只数这些工具的记录（评审 C2）
record_count() {
  # shellcheck disable=SC2016
  count_records "$1" "$2" "$3" 'tool_in($tools) and ($t == "" or output_has($t))' --arg t "${4:-}" --arg tools "${5:-}"
}

# reply_count HARNESS SCENARIO [TOOLS]：给出非 pass 回复的记录数（录制时只有目标 hook 会这样回复）；
# 给 TOOLS 时只数这些工具的记录
reply_count() {
  # shellcheck disable=SC2016
  count_records "$1" "$2" '*' 'tool_in($tools) and .reply != null and (.reply | type != "object" or .action != "pass")' \
    --arg tools "${3:-}"
}

# tool_calls HARNESS SCENARIO TOOLS：这些工具的调用次数（调用前事件数）
tool_calls() { record_count "$1" "$2" "$(pre_event "$1")" "" "$3"; }

# leak_elsewhere HARNESS SCENARIO TEXT TOOLS：TOOLS 以外的工具输出中按字面含 TEXT 的记录数（评审 I6）
leak_elsewhere() {
  # shellcheck disable=SC2016
  count_records "$1" "$2" "$(post_event "$1")" '(tool_in($tools) | not) and output_has($t)' \
    --arg t "$3" --arg tools "$4"
}

# tool_seen HARNESS SCENARIO TOOLS：TOOLS 中每个工具都录到调用前与调用后事件为 yes；都录到调用前事件、
# 但有的缺调用后事件为 pre；有的连调用前事件都没有为 no（评审 I1）
tool_seen() {
  local seen=yes re res
  IFS=, read -r -a res <<< "$3"
  for re in ${res[@]+"${res[@]}"}; do
    [[ -n "$re" ]] || continue
    if [[ "$(record_count "$1" "$2" "$(pre_event "$1")" "" "$re")" == 0 ]]; then
      echo no
      return 0
    fi
    if [[ "$(record_count "$1" "$2" "$(post_event "$1")" "" "$re")" == 0 ]]; then seen=pre; fi
  done
  echo "$seen"
}

# stream_split STREAM RESULT NOTICES：把 claude -p 的 stream-json 输出拆成最终回复（RESULT）与给用户的
# 提示行（NOTICES：除 user、assistant 消息以外的事件，如 ui_log、result），工具输出不进入 NOTICES
stream_split() {
  jq -Rrs '[split("\n")[] | fromjson? | select(type == "object" and .type == "result")] | last | .result // empty' \
    "$1" > "$2" 2>/dev/null || true
  jq -Rc 'fromjson? | select(type == "object" and .type != "user" and .type != "assistant")' \
    "$1" > "$3" 2>/dev/null || true
}

# transcript_of HARNESS SCENARIO：harness 自己的 transcript 路径。Codex 取 hook 输入里的 transcript_path；
# Claude Code 的扩展请求不带路径，按会话 cwd 与 id 推出 <配置目录>/projects/<slug>/<id>.jsonl
transcript_of() {
  local base="${CLAUDE_CONFIG_DIR:-$HOME/.claude}" f tp
  for f in "$RAW/$1/$2"/*.json; do
    [[ -e "$f" ]] || continue
    if [[ "$1" == codex ]]; then
      tp="$(jq -r '.stdin.transcript_path // empty' "$f" 2>/dev/null || true)"
    else
      tp="$(jq -r --arg base "$base" \
        '.stdin.session // empty | select(.id and .cwd)
         | "\($base)/projects/\(.cwd | gsub("[^A-Za-z0-9]"; "-"))/\(.id).jsonl"' "$f" 2>/dev/null || true)"
    fi
    if [[ -n "$tp" ]]; then
      printf '%s\n' "$tp"
      return 0
    fi
  done
}

# has_text FILE TEXT：文件存在且按字面含 TEXT 时输出 yes，否则 no
has_text() {
  if [[ -n "$1" && -f "$1" ]] && grep -qF -- "$2" "$1"; then echo yes; else echo no; fi
}

# check_file FILE SECRET：SECRET 为空输出 -，否则同 has_text
check_file() { if [[ -z "$2" ]]; then echo -; else has_text "$1" "$2"; fi; }

# size_of FILE：文件字节数，不存在为 0
size_of() { if [[ -f "$1" ]]; then wc -c < "$1" | tr -d ' '; else echo 0; fi; }

# facts_header HARNESS：新建事实表（列与 tools/m0verdict 的 factsHeader 一致）
facts_header() {
  printf 'scenario\texit_code\tresult_bytes\treason_shown\thook_replies\thook_saw_secret\tin_result\tin_transcript\treplaced_in_transcript\ttarget_tool_seen\ttarget_calls\tleak_elsewhere\n' \
    > "$WORK/$1-facts.tsv"
}

# record_facts HARNESS SCENARIO EXIT_CODE RESULT_FILE SECRET TOOLS LOG_FILE...：采集一个场景的事实。
# TOOLS 是目标工具（逗号分隔的 jq 正则，可为空），工具输出、回复与调用次数只算目标工具的（评审 C2）。
# LOG_FILE 是 stderr、提示行等可能显示 hook 原因的文件，可以有多个。
# hook_saw_secret：目标工具输出含秘密串的记录数；没有含秘密串的记录时，只有录到了目标工具的输出事件或
# 拦截回复才记 0（有证据未产出），否则记 -（未知：可能是 hook 没加载），见评审 H02。
# 找不到 transcript 时 transcript 两列记 -。
record_facts() {
  local h="$1" name="$2" rc="$3" result="$4" secret="$5" targets="$6" post tp shown=no saw=- intr=- replaced=- \
    seen=- calls=- leak=- f
  shift 6
  post="$(post_event "$h")"
  tp="$(transcript_of "$h" "$name")"
  for f in "$result" "$@"; do
    if [[ "$(has_text "$f" "$REASON_MARK")" == yes ]]; then shown=yes; fi
  done
  if [[ -n "$secret" ]]; then
    saw="$(record_count "$h" "$name" "$post" "$secret" "$targets")"
    if [[ "$saw" == 0 && "$(record_count "$h" "$name" "$post" "" "$targets")" == 0 \
      && "$(reply_count "$h" "$name" "$targets")" == 0 ]]; then
      saw=-
    fi
    leak="$(leak_elsewhere "$h" "$name" "$secret" "$targets")"
    if [[ -n "$tp" && -f "$tp" ]]; then
      intr="$(has_text "$tp" "$secret")"
      replaced="$(has_text "$tp" "$REPLACED_MARK")"
    fi
  fi
  if [[ -n "$targets" ]]; then
    seen="$(tool_seen "$h" "$name" "$targets")"
    calls="$(tool_calls "$h" "$name" "$targets")"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$rc" "$(size_of "$result")" "$shown" \
    "$(reply_count "$h" "$name" "$targets")" "$saw" "$(check_file "$result" "$secret")" "$intr" \
    "$replaced" "$seen" "$calls" "$leak" >> "$WORK/$h-facts.tsv"
}

# judge_facts HARNESS：输出判定表并保存到 $WORK/<harness>-verdict.md
judge_facts() {
  "$BIN/m0verdict" -harness "$1" -facts "$WORK/$1-facts.tsv" | tee "$WORK/$1-verdict.md" >&2
}

# import_all HARNESS：把该 harness 的全部场景整组导入 testdata/fixtures；版本、平台与批次取自各场景的 manifest
import_all() {
  local d
  for d in "$RAW/$1"/*/; do
    if [[ ! -f "$d/manifest.json" ]]; then
      log "跳过没有 manifest 的目录 $d"
      continue
    fi
    "$BIN/fiximport" -raw "$d" -dest "$REPO_ROOT/testdata/fixtures" -workdir "$WORK_LINK" -workdir "$WORK"
  done
}

// Package m0 只含测试：用 bash 调用 lib.sh 的函数，核对录制脚本采集事实的方式（spec §7.5）。
// 测试不启动任何 harness；需要 bash 与 jq，缺少时跳过。
package m0

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const stub = "#!/bin/sh\nexit 0\n"

func requireTools(t *testing.T) {
	t.Helper()
	for _, name := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " not found")
		}
	}
}

// newWork 建一个录制工作目录，bin 下放占位程序，使 lib.sh 不必编译工具。
func newWork(t *testing.T) string {
	t.Helper()
	requireTools(t)
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hookrec", "fiximport", "m0verdict"} {
		writeFile(t, filepath.Join(work, "bin", name), stub, 0o755)
	}
	return work
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// sh 在 work 下 source lib.sh 后执行 script，返回 stdout；args 以 $1、$2… 传入。
func sh(t *testing.T, work, script string, args ...string) string {
	t.Helper()
	lib, err := filepath.Abs("lib.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", append([]string{"-c", "source \"$0\"\n" + script, lib}, args...)...)
	cmd.Env = append(os.Environ(), "HG_M0_WORK="+work)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("bash failed: %v\n%s", err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// record 写一条 hookrec 格式的原始记录。
func record(t *testing.T, work, harness, scenario, name string, stdin, reply any) {
	t.Helper()
	rec := map[string]any{"event": name[strings.LastIndex(name, "-")+1:], "stdin": stdin}
	if reply != nil {
		rec["reply"] = reply
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(work, "raw", harness, scenario, name+".json"), string(b), 0o644)
}

func claudeCheck(tool string) map[string]any {
	return map[string]any{"hook": "tool.check", "data": map[string]any{"tool": tool}}
}

func claudeResult(tool, text string) map[string]any {
	return map[string]any{"hook": "tool.result", "data": map[string]any{"tool": tool}, "result": map[string]any{"text": text}}
}

var (
	pass = map[string]any{"protocol": "h-guard.ext/v1", "action": "pass"}
	deny = map[string]any{"protocol": "h-guard.ext/v1", "action": "deny", "message": "h-guard M0 test: deny"}
)

func TestRecordCountOnlyCountsTheTargetTool(t *testing.T) {
	work := newWork(t)
	record(t, work, "claudecode", "s", "1-tool.result", claudeResult("Bash", "HGCANARY-X"), pass)
	record(t, work, "claudecode", "s", "2-tool.result", claudeResult("Read", "HGCANARY-X"), pass)
	if got := sh(t, work, `record_count claudecode s tool.result HGCANARY-X '^Read$'`); got != "1" {
		t.Errorf("record_count for Read = %s, want 1", got)
	}
	if got := sh(t, work, `record_count claudecode s tool.result HGCANARY-X`); got != "2" {
		t.Errorf("record_count for any tool = %s, want 2", got)
	}
	// Codex 的工具名在 tool_name
	record(t, work, "codex", "s", "1-PostToolUse", map[string]any{"tool_name": "mcp__hgm0__hg_m0_report", "tool_response": "HGCANARY-X"}, nil)
	if got := sh(t, work, `record_count codex s PostToolUse HGCANARY-X hg_m0_report`); got != "1" {
		t.Errorf("codex record_count = %s, want 1", got)
	}
}

func TestToolSeenNeedsEveryTargetBeforeAndAfter(t *testing.T) {
	work := newWork(t)
	for i, tool := range []string{"Read", "Write", "Edit"} {
		record(t, work, "claudecode", "s", string(rune('1'+i))+"-tool.check", claudeCheck(tool), pass)
	}
	record(t, work, "claudecode", "s", "4-tool.result", claudeResult("Read", "x"), pass)
	record(t, work, "claudecode", "s", "5-tool.result", claudeResult("Write", "x"), pass)
	targets := "^Read$,^Write$,^Edit$"
	if got := sh(t, work, `tool_seen claudecode s "$1"`, targets); got != "pre" {
		t.Errorf("tool_seen without Edit result = %s, want pre", got)
	}
	record(t, work, "claudecode", "s", "6-tool.result", claudeResult("Edit", "x"), pass)
	if got := sh(t, work, `tool_seen claudecode s "$1"`, targets); got != "yes" {
		t.Errorf("tool_seen = %s, want yes", got)
	}
	if got := sh(t, work, `tool_seen claudecode s '^Monitor$'`); got != "no" {
		t.Errorf("tool_seen for an absent tool = %s, want no", got)
	}
}

func TestToolCallsLeaksAndRepliesAreAttributed(t *testing.T) {
	work := newWork(t)
	record(t, work, "claudecode", "s", "1-tool.check", claudeCheck("Bash"), deny)
	record(t, work, "claudecode", "s", "2-tool.check", claudeCheck("Bash"), pass)
	record(t, work, "claudecode", "s", "3-tool.check", claudeCheck("Read"), deny)
	record(t, work, "claudecode", "s", "4-tool.result", claudeResult("Read", "HGCANARY-X"), pass)
	if got := sh(t, work, `tool_calls claudecode s '^Bash$'`); got != "2" {
		t.Errorf("tool_calls = %s, want 2", got)
	}
	if got := sh(t, work, `leak_elsewhere claudecode s HGCANARY-X '^Bash$'`); got != "1" {
		t.Errorf("leak_elsewhere = %s, want 1", got)
	}
	if got := sh(t, work, `reply_count claudecode s '^Bash$'`); got != "1" {
		t.Errorf("reply_count for Bash = %s, want 1", got)
	}
	if got := sh(t, work, `reply_count claudecode s`); got != "2" {
		t.Errorf("reply_count for any tool = %s, want 2", got)
	}
}

func TestRecordFactsWritesEveryColumn(t *testing.T) {
	work := newWork(t)
	record(t, work, "claudecode", "s", "1-tool.check", claudeCheck("Bash"), pass)
	record(t, work, "claudecode", "s", "2-tool.result", claudeResult("Bash", "HGCANARY-X"), pass)
	writeFile(t, filepath.Join(work, "s.result.txt"), "HGCANARY-X\n", 0o644)
	sh(t, work, `facts_header claudecode; record_facts claudecode s 0 "$WORK/s.result.txt" HGCANARY-X '^Bash$'`)
	b, err := os.ReadFile(filepath.Join(work, "claudecode-facts.tsv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("facts =\n%s", b)
	}
	header, row := strings.Split(lines[0], "\t"), strings.Split(lines[1], "\t")
	if len(header) != 12 || len(row) != 12 {
		t.Fatalf("want 12 columns, got header %d, row %d:\n%s", len(header), len(row), b)
	}
	got := map[string]string{}
	for i, h := range header {
		got[h] = row[i]
	}
	want := map[string]string{"hook_saw_secret": "1", "in_result": "yes", "target_tool_seen": "yes", "target_calls": "1", "leak_elsewhere": "0"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (row %v)", k, got[k], v, got)
		}
	}
}

func TestStreamSplitSeparatesTheReplyFromNotices(t *testing.T) {
	work := newWork(t)
	stream := strings.Join([]string{
		`{"type":"system","subtype":"init"}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"HGCANARY-X [h-guard replaced] h-guard M0 test: deny"}]}}`,
		`{"type":"ui_log","text":"h-guard M0 test: warn"}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"done"}]}}`,
		`{"type":"result","subtype":"success","result":"final answer"}`,
	}, "\n") + "\n"
	writeFile(t, filepath.Join(work, "s.stream.jsonl"), stream, 0o644)
	sh(t, work, `stream_split "$WORK/s.stream.jsonl" "$WORK/s.result.txt" "$WORK/s.notices.jsonl"`)
	result, _ := os.ReadFile(filepath.Join(work, "s.result.txt"))
	notices, _ := os.ReadFile(filepath.Join(work, "s.notices.jsonl"))
	if strings.TrimSpace(string(result)) != "final answer" {
		t.Errorf("result = %q", result)
	}
	if !strings.Contains(string(notices), "M0 test: warn") || strings.Contains(string(notices), "HGCANARY-X") {
		t.Errorf("notices must hold the user-facing lines and none of the tool output:\n%s", notices)
	}
}

func TestImportAllPassesLinkAndPhysicalWorkdir(t *testing.T) {
	real := newWork(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	physical, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(real, "bin", "fiximport"), "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$(dirname \"$0\")/../fiximport.args\"\n", 0o755)
	writeFile(t, filepath.Join(real, "raw", "claudecode", "s", "manifest.json"), "{}", 0o644)
	sh(t, link, `import_all claudecode`)
	args, err := os.ReadFile(filepath.Join(real, "fiximport.args"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{link, physical} {
		if !strings.Contains(string(args), "-workdir\n"+want+"\n") {
			t.Errorf("fiximport args lack -workdir %s:\n%s", want, args)
		}
	}
}

func TestBuildToolsRebuildsAStaleBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a tool")
	}
	work := newWork(t)
	bin := filepath.Join(work, "bin", "hookrec")
	old := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(bin, old, old); err != nil {
		t.Fatal(err)
	}
	sh(t, work, `true`)
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) == stub {
		t.Error("a binary older than its sources must be rebuilt")
	}
	// 比源码新的程序不重新编译
	if b, _ := os.ReadFile(filepath.Join(work, "bin", "m0verdict")); string(b) != stub {
		t.Error("an up-to-date binary must be kept")
	}
}

func TestOnlyRerunsSelectedScenariosAndKeepsOtherFacts(t *testing.T) {
	work := newWork(t)
	facts := filepath.Join(work, "codex-facts.tsv")
	writeFile(t, facts, "scenario\tx\na\t1\nb\t2\n", 0o644)
	sh(t, work, `HG_M0_ONLY="b c" facts_begin codex`)
	b, err := os.ReadFile(facts)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "scenario\tx\na\t1\n" {
		t.Errorf("facts after a selective rerun begins =\n%s", b)
	}
	if got := sh(t, work, `for n in a b c; do if HG_M0_ONLY="b c" selected "$n"; then echo "$n"; fi; done | tr '\n' ' '`); got != "b c" {
		t.Errorf("selected = %q, want b c", got)
	}
	if got := sh(t, work, `selected a && echo yes`); got != "yes" {
		t.Errorf("without HG_M0_ONLY every scenario is selected, got %q", got)
	}
	// 不选时重新开始事实表
	sh(t, work, `facts_begin codex`)
	if b, _ := os.ReadFile(facts); !strings.HasPrefix(string(b), "scenario\texit_code") || strings.Count(string(b), "\n") != 1 {
		t.Errorf("full run must start a fresh facts table, got:\n%s", b)
	}
}

func TestGateOnlyChecksScenariosRunThisTime(t *testing.T) {
	work := newWork(t)
	writeFile(t, filepath.Join(work, "r.txt"), "nothing\n", 0o644)
	// 本轮没有运行 control-cat：门槛沿用上一轮的结论，不能拿本轮新生成的秘密串去查
	if got := sh(t, work, `HG_M0_ONLY="other" gate_control claudecode control-cat HGCANARY-NEW '^Bash$' "$WORK/r.txt" && echo skipped`); got != "skipped" {
		t.Errorf("gate for an unselected scenario = %q, want skipped", got)
	}
	// 本轮运行了但没有证据：停止
	cmd := exec.Command("bash", "-c", "source \"$0\"; gate_control claudecode control-cat HGCANARY-X '^Bash$' \"$WORK/r.txt\"", mustAbs(t, "lib.sh"))
	cmd.Env = append(os.Environ(), "HG_M0_WORK="+work)
	if err := cmd.Run(); err == nil {
		t.Error("a failed control must stop the run")
	}
	record(t, work, "claudecode", "control-cat", "1-tool.result", claudeResult("Bash", "HGCANARY-X"), pass)
	writeFile(t, filepath.Join(work, "r.txt"), "HGCANARY-X\n", 0o644)
	if got := sh(t, work, `gate_control claudecode control-cat HGCANARY-X '^Bash$' "$WORK/r.txt" && echo passed`); got != "passed" {
		t.Errorf("gate with evidence = %q, want passed", got)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

package seen

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestRecordAndLatest(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	if _, _, ok := ReadRuns(dir, "codex").Latest(); ok {
		t.Fatal("empty dir has runs")
	}
	_ = Record(dir, "codex", "PreToolUse", "1.0", t0)
	_ = Record(dir, "codex", "UserPromptSubmit", "1.0", t0.Add(2*time.Minute))
	// 一分钟内同一事件不重写
	_ = Record(dir, "codex", "PreToolUse", "1.0", t0.Add(30*time.Second))
	runs := ReadRuns(dir, "codex")
	if !runs["PreToolUse"].At.Equal(t0) {
		t.Errorf("PreToolUse = %v", runs["PreToolUse"])
	}
	if ev, run, ok := runs.Latest(); !ok || ev != "UserPromptSubmit" || !run.At.Equal(t0.Add(2*time.Minute)) {
		t.Errorf("latest = %s %v %v", ev, run, ok)
	}
	// 换了版本立即重写
	_ = Record(dir, "codex", "PreToolUse", "1.1", t0.Add(30*time.Second))
	if r := ReadRuns(dir, "codex")["PreToolUse"]; r.Version != "1.1" {
		t.Errorf("after upgrade = %v", r)
	}
	if len(ReadRuns(dir, "claudecode")) != 0 {
		t.Error("harnesses share records")
	}
}

func TestSelftestRecord(t *testing.T) {
	dir := t.TempDir()
	if _, ok := ReadSelftest(dir, "codex"); ok {
		t.Fatal("empty dir has a self-test")
	}
	st := Selftest{At: time.Now().UTC(), Version: "1.0", Passed: true, Cases: []Case{{Name: "a", Passed: true}}}
	if err := WriteSelftest(dir, "codex", st); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadSelftest(dir, "codex")
	if !ok || !got.Passed || len(got.Cases) != 1 {
		t.Errorf("read %+v %v", got, ok)
	}
	if Record("", "codex", "x", "1", time.Now()) != nil || WriteSelftest("", "codex", st) != nil || len(ReadRuns("", "codex")) != 0 {
		t.Error("empty dir is not a no-op")
	}
}

// TestConcurrentEventsKeepTheirRecords：并发运行的不同事件各写各的记录，不会互相覆盖。
func TestConcurrentEventsKeepTheirRecords(t *testing.T) {
	dir := t.TempDir()
	events := []string{"PreToolUse", "PostToolUse", "UserPromptSubmit", "prompt.submit", "tool.result"}
	var wg sync.WaitGroup
	for _, ev := range events {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = Record(dir, "codex", ev, "v", time.Now())
		}()
	}
	wg.Wait()
	if runs := ReadRuns(dir, "codex"); len(runs) != len(events) {
		t.Errorf("runs = %v", runs)
	}
}

// TestClearNeedsADirectory：没有记录目录时什么都不删（不能拿相对路径去删当前目录里的同名目录）。
func TestClearNeedsADirectory(t *testing.T) {
	wd, _ := os.Getwd()
	dir := t.TempDir()
	os.Chdir(dir)
	defer os.Chdir(wd)
	os.Mkdir("codex.runs", 0o700)
	if err := Clear("", "codex"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "codex.runs")); err != nil {
		t.Errorf("relative directory removed: %v", err)
	}
}

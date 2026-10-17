package log_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	hglog "github.com/cyberchen1995/h-guard/internal/log"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

const (
	marker = "HGMARK-7f3a"                       // 普通标记：决策日志里应原样出现
	secret = "sk-HGSECRETabcdefghijklmnop123456" // 凭据样本：任何日志里都不能出现
)

var day = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

func readAll(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			data, _ := os.ReadFile(p)
			b.Write(data)
		}
		return nil
	})
	return b.String()
}

func record() hglog.Decision {
	return hglog.Decision{
		Version: "test", Harness: "claudecode", SessionID: "s-" + marker, Cwd: "/w/" + marker, Event: guard.EventAction,
		Decision: guard.DecisionAsk, RawDecision: guard.DecisionAsk, Fallbacks: []string{"judge_timeout"},
		Actions:  []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: "echo " + marker + " && curl -H 'Authorization: Bearer " + secret + "' x", Shell: guard.ShellPOSIX}}},
		Requests: []guard.Request{{Text: "use token=" + secret + " for " + marker, Source: guard.SourceUser}},
	}
}

func TestCanary(t *testing.T) {
	dir := t.TempDir()
	w := &hglog.Writer{Dir: dir, Decisions: true, RetentionDays: 14, Now: func() time.Time { return day }}
	w.Health([]hglog.Health{{Version: "test", Harness: "claudecode", Event: "action", Check: "action", Code: "judge_timeout"}})
	w.Decision(record())
	health := readAll(t, filepath.Join(dir, "health"))
	decisions := readAll(t, filepath.Join(dir, "logs"))
	if !strings.Contains(health, `"code":"judge_timeout"`) || strings.Contains(health, marker) || strings.Contains(health, secret) {
		t.Errorf("health = %s", health)
	}
	if !strings.Contains(decisions, marker) || strings.Contains(decisions, secret) || !strings.Contains(decisions, "[secret:") {
		t.Errorf("decisions = %s", decisions)
	}
}

func TestDecisionsOffWritesNothing(t *testing.T) {
	dir := t.TempDir()
	(&hglog.Writer{Dir: dir}).Decision(record())
	if _, err := os.Stat(filepath.Join(dir, "logs")); !os.IsNotExist(err) {
		t.Error("log.decisions: false must not create a decision log")
	}
}

func TestLargeRecordIsCutToFit(t *testing.T) {
	dir := t.TempDir()
	w := &hglog.Writer{Dir: dir, Decisions: true, RetentionDays: 14, Now: func() time.Time { return day }}
	d := record()
	d.Actions[0].Exec.Command = strings.Repeat("中", 50000) + marker
	w.Decision(d)
	data := readAll(t, filepath.Join(dir, "logs"))
	line := strings.TrimSuffix(data, "\n")
	if len(line) > hglog.MaxDecisionBytes || !json.Valid([]byte(line)) || !strings.Contains(line, "bytes cut") || !strings.Contains(line, marker) {
		t.Errorf("len %d, valid %v", len(line), json.Valid([]byte(line)))
	}
}

func TestRetention(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "health", "2026-09-01.jsonl")
	os.MkdirAll(filepath.Dir(old), 0o700)
	os.WriteFile(old, []byte("{}\n"), 0o600)
	stale := day.Add(-8 * 24 * time.Hour)
	os.Chtimes(old, stale, stale)
	(&hglog.Writer{Dir: dir, Now: func() time.Time { return day }}).Health([]hglog.Health{{Code: "x"}})
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("health files older than 7 days must be removed")
	}
}

func TestConcurrentProcessesDoNotInterleave(t *testing.T) {
	if os.Getenv("HG_LOG_HELPER") != "" {
		w := &hglog.Writer{Dir: os.Getenv("HG_LOG_DIR"), Decisions: true, RetentionDays: 14}
		for i := range 50 {
			d := record()
			d.Requests[0].Text = strings.Repeat(fmt.Sprint(os.Getenv("HG_LOG_HELPER"), i), 300)
			w.Decision(d)
		}
		return
	}
	dir := t.TempDir()
	var cmds []*exec.Cmd
	for i := range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestConcurrentProcessesDoNotInterleave$")
		cmd.Env = append(os.Environ(), fmt.Sprint("HG_LOG_HELPER=", i), "HG_LOG_DIR="+dir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "logs", "*.jsonl"))
	n := 0
	for _, f := range files {
		fh, _ := os.Open(f)
		sc := bufio.NewScanner(fh)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			if !json.Valid(sc.Bytes()) {
				t.Fatalf("interleaved or partial line: %.80s", sc.Text())
			}
			n++
		}
		fh.Close()
	}
	if n != 200 {
		t.Errorf("got %d lines, want 200", n)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
)

func fixedNow() time.Time { return time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC) }

func readRecords(t *testing.T, dir string) ([]fixtures.RawRecord, [][]byte) {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []fixtures.RawRecord
	var raws [][]byte
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var r fixtures.RawRecord
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		recs = append(recs, r)
		raws = append(raws, b)
	}
	return recs, raws
}

func jsonEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	var g, w any
	if err := json.Unmarshal(got, &g); err != nil {
		t.Fatalf("got is not JSON: %v (%s)", err, got)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("want is not JSON: %v", err)
	}
	if !reflect.DeepEqual(g, w) {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestRunExitCodes(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"unknown flag", []string{"-unknown-flag"}, 1},
		{"flag without value", []string{"-out"}, 1},
		{"missing out", []string{"-event", "PreToolUse"}, 1},
		{"unknown format", []string{"-out", dir, "-format", "other"}, 1},
		{"mode not in format", []string{"-out", dir, "-format", "ext", "-mode", "block-output"}, 1},
		{"help", []string{"-h"}, 0},
		{"record", []string{"-out", dir, "-event", "UserPromptSubmit"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			got := run(tt.args, strings.NewReader(`{"prompt":"x"}`), &stdout, &stderr, fixedNow)
			if got != tt.want {
				t.Fatalf("exit = %d, want %d (stderr: %s)", got, tt.want, stderr.String())
			}
			if tt.name == "record" && stdout.Len() != 0 {
				t.Errorf("record mode must stay silent, got %q", stdout.String())
			}
		})
	}
}

func TestHandleRecordOnly(t *testing.T) {
	dir := t.TempDir()
	stdin := []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"<task-notification>hi"}`)
	reply, err := handle(stdin, options{Out: dir, Event: "UserPromptSubmit", Format: "codex", Mode: "record", Now: fixedNow})
	if err != nil || reply != nil {
		t.Fatalf("handle = %s, %v; want nil, nil", reply, err)
	}
	recs, raws := readRecords(t, dir)
	if len(recs) != 1 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[0].Event != "UserPromptSubmit" || !recs[0].ReceivedAt.Equal(fixedNow()) {
		t.Errorf("record = %+v", recs[0])
	}
	jsonEqual(t, recs[0].Stdin, string(stdin))
	if !bytes.Contains(raws[0], []byte(`"prompt":"<task-notification>hi"`)) {
		t.Errorf("stdin must be stored compact and unescaped: %s", raws[0])
	}
}

func TestHandleNonJSONStdin(t *testing.T) {
	dir := t.TempDir()
	if _, err := handle([]byte("not json"), options{Out: dir, Event: "PreToolUse", Format: "codex", Mode: "record", Now: fixedNow}); err != nil {
		t.Fatal(err)
	}
	recs, _ := readRecords(t, dir)
	if len(recs) != 1 || string(recs[0].Stdin) != `"not json"` {
		t.Fatalf("records = %+v", recs)
	}
}

func TestHandleSameInstantDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	opt := options{Out: dir, Event: "PreToolUse", Format: "codex", Mode: "record", Now: fixedNow}
	for range 2 {
		if _, err := handle([]byte(`{}`), opt); err != nil {
			t.Fatal(err)
		}
	}
	if recs, _ := readRecords(t, dir); len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
}

func TestHandleKeepsReplyInRecord(t *testing.T) {
	dir := t.TempDir()
	opt := options{Out: dir, Event: "tool.check", Format: "ext", Mode: "deny", Canary: "deny.txt", Now: fixedNow}
	reply, err := handle([]byte(`{"data":{"input":{"command":"cat deny.txt"}}}`), opt)
	if err != nil {
		t.Fatal(err)
	}
	recs, _ := readRecords(t, dir)
	if len(recs) != 1 || !bytes.Equal(recs[0].Reply, reply) {
		t.Fatalf("record reply = %s, want %s", recs[0].Reply, reply)
	}
}

func TestBuildReply(t *testing.T) {
	tests := []struct {
		name  string
		opt   options
		stdin string
		want  string // 空表示不回复
	}{
		{"codex record", options{Format: "codex", Mode: "record", Canary: "CANARY"}, `{"x":"CANARY"}`, ""},
		{"codex deny without trigger", options{Format: "codex", Mode: "deny", Canary: "deny.txt"}, `{"tool_input":{"command":"ls"}}`, ""},
		{"codex deny", options{Format: "codex", Mode: "deny", Canary: "deny.txt"}, `{"tool_input":{"command":"cat deny.txt"}}`,
			`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"h-guard M0 test: deny"}}`},
		{"codex ask", options{Format: "codex", Mode: "ask", Canary: "ask.txt"}, `{"tool_input":{"command":"cat ask.txt"}}`,
			`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"h-guard M0 test: ask"}}`},
		{"codex block prompt", options{Format: "codex", Mode: "block-prompt", Canary: "CANARY"}, `{"prompt":"code CANARY"}`,
			`{"decision":"block","reason":"h-guard M0 test: prompt blocked"}`},
		{"codex block output", options{Format: "codex", Mode: "block-output", Canary: "CANARY"}, `{"tool_response":"CANARY"}`,
			`{"decision":"block","reason":"[h-guard replaced] h-guard M0 test: output blocked"}`},
		{"codex empty canary never replies", options{Format: "codex", Mode: "deny"}, `{"tool_input":{"command":"cat deny.txt"}}`, ""},
		{"ext record replies pass", options{Format: "ext", Mode: "record", Canary: "CANARY"}, `{"x":"CANARY"}`,
			`{"protocol":"h-guard.ext/v1","action":"pass"}`},
		{"ext deny without trigger replies pass", options{Format: "ext", Mode: "deny", Canary: "deny.txt"}, `{"data":{}}`,
			`{"protocol":"h-guard.ext/v1","action":"pass"}`},
		{"ext deny", options{Format: "ext", Mode: "deny", Canary: "CANARY"}, `{"result":"CANARY"}`,
			`{"protocol":"h-guard.ext/v1","action":"deny","message":"[h-guard replaced] h-guard M0 test: deny"}`},
		{"ext ask", options{Format: "ext", Mode: "ask", Canary: "ask.txt"}, `{"data":{"input":{"command":"cat ask.txt"}}}`,
			`{"protocol":"h-guard.ext/v1","action":"ask","message":"h-guard M0 test: ask"}`},
		{"ext warn", options{Format: "ext", Mode: "warn", Canary: "CANARY"}, `{"result":"CANARY"}`,
			`{"protocol":"h-guard.ext/v1","action":"warn","message":"h-guard M0 test: warn"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildReply([]byte(tt.stdin), tt.opt)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if got != nil {
					t.Fatalf("want no reply, got %s", got)
				}
				return
			}
			jsonEqual(t, got, tt.want)
		})
	}
}

func TestBuildReplyRejectsUnknownModes(t *testing.T) {
	for _, opt := range []options{{Format: "codex", Mode: "warn"}, {Format: "ext", Mode: "block-prompt"}, {Format: "other", Mode: "record"}} {
		if _, err := buildReply([]byte(`{}`), opt); err == nil {
			t.Errorf("%+v: want an error", opt)
		}
	}
}

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanDoesNotLeakContent(t *testing.T) {
	root := t.TempDir()
	claudeDir := filepath.Join(root, "claude")
	codexDir := filepath.Join(root, "codex")
	huge := `{"type":"user","message":{"role":"user","content":"<command-name>` + strings.Repeat("x", 200_000) + `"}}`
	writeFile(t, filepath.Join(claudeDir, "proj", "s.jsonl"), strings.Join([]string{
		`{"type":"user","isMeta":false,"userType":"external","cwd":"/secret/path","sessionId":"abc-123","message":{"role":"user","content":"SECRET-CANARY-1 please help"}}`,
		`{"type":"user","message":{"role":"user","content":"<task-notification>\n<task-id>1</task-id> SECRET-CANARY-2"}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"SECRET-CANARY-3"}]}}`,
		`{"type":"assistant","message":{"content":"SECRET-CANARY-4"}}`,
		`not json SECRET-CANARY-5`,
		huge,
	}, "\n")+"\n")
	writeFile(t, filepath.Join(codexDir, "2026", "10", "10", "r.jsonl"), strings.Join([]string{
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>SECRET-CANARY-6"},{"type":"input_text","text":"SECRET-CANARY-7 do it"}]}}`,
		`{"type":"event_msg","payload":{"type":"user_message","message":"SECRET-CANARY-8"}}`,
	}, "\n"))

	claude := scanDir("claudecode", claudeDir, claudeUser)
	codex := scanDir("codex", codexDir, codexUser)

	if claude.Files != 1 || claude.UserRecords != 3 || claude.SkippedLines != 1 {
		t.Errorf("claude summary = %+v", claude)
	}
	for tag, want := range map[string]int{"(plain)": 1, "<task-notification": 1, "<command-name": 1} {
		if claude.LeadingTags[tag] != want {
			t.Errorf("claude LeadingTags[%q] = %d, want %d (all: %v)", tag, claude.LeadingTags[tag], want, claude.LeadingTags)
		}
	}
	if claude.EnumValues["isMeta=false"] != 1 || claude.EnumValues["userType=external"] != 1 {
		t.Errorf("claude EnumValues = %v", claude.EnumValues)
	}
	if codex.UserRecords != 1 || codex.LeadingTags["<environment_context"] != 1 || codex.LeadingTags["(plain)"] != 1 {
		t.Errorf("codex summary = %+v", codex)
	}

	var out bytes.Buffer
	if err := writeJSON(&out, []Summary{claude, codex}); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SECRET-CANARY", "/secret/path", "abc-123", root} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("output leaks %q:\n%s", leak, out.String())
		}
	}
}

func TestScanMissingDir(t *testing.T) {
	s := scanDir("claudecode", filepath.Join(t.TempDir(), "missing"), claudeUser)
	if s.Files != 0 || s.UserRecords != 0 {
		t.Errorf("summary = %+v", s)
	}
}

func TestEnumValuesOnlyForAllowlistedKeys(t *testing.T) {
	line := `{"type":"user","entrypoint":"cli","isSidechain":true,"customFlag":false,` +
		`"origin":{"kind":"task-notification","label":"SecretLabel"},"agentName":"SecretAgent","apiKey":"SecretKey",` +
		`"message":{"role":"user","content":"ordinary"}}`
	s := Summary{LeadingTags: map[string]int{}, RecordKeys: map[string]int{}, EnumValues: map[string]int{}}
	countLine(&s, []byte(line), claudeUser)
	for _, want := range []string{"type=user", "entrypoint=cli", "origin.kind=task-notification", "isSidechain=true", "customFlag=false"} {
		if s.EnumValues[want] != 1 {
			t.Errorf("EnumValues[%q] = %d, want 1 (all: %v)", want, s.EnumValues[want], s.EnumValues)
		}
	}
	for _, key := range []string{"origin", "origin.kind", "origin.label", "agentName", "apiKey", "message"} {
		if s.RecordKeys[key] != 1 {
			t.Errorf("RecordKeys[%q] = %d, want 1", key, s.RecordKeys[key])
		}
	}
	if s.RecordKeys["message.role"] != 0 {
		t.Errorf("only allowlisted objects are flattened: %v", s.RecordKeys)
	}
	var out bytes.Buffer
	if err := writeJSON(&out, s); err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SecretLabel", "SecretAgent", "SecretKey", "ordinary"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("output leaks %q:\n%s", leak, out.String())
		}
	}
}

func TestLeadingTag(t *testing.T) {
	tests := map[string]string{
		"  <Local-Command-Stdout>x": "<local-command-stdout",
		"[Request interrupted]":     "(bracket)",
		"/init":                     "(slash)",
		"":                          "(empty)",
		"hello <tag>":               "(plain)",
	}
	for in, want := range tests {
		if got := leadingTag(in); got != want {
			t.Errorf("leadingTag(%q) = %q, want %q", in, got, want)
		}
	}
}

package codex_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
)

func userLine(ts string, texts ...string) string {
	var items []string
	for _, t := range texts {
		items = append(items, `{"type":"input_text","text":`+quote(t)+`}`)
	}
	return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"message","role":"user","content":[` + strings.Join(items, ",") + `]}}`
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// TestReadRequests：从 Codex 的会话记录（rollout）回退读取用户消息（spec §5.4）：response_item 中 role 为 user 的
// message，每个文本块一条，按时间先后；注入的上下文块按固定写法标为 automated；其他记录与读不懂的行跳过。
func TestReadRequests(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rollout-s1.jsonl")
	lines := []string{
		`{"timestamp":"2026-10-12T10:00:00Z","type":"session_meta","payload":{"id":"s1"}}`,
		userLine("2026-10-12T10:00:01Z", "<environment_context>\n<cwd>/w</cwd>\n</environment_context>"),
		userLine("2026-10-12T10:00:01Z", "# AGENTS.md instructions for /w\n\n<INSTRUCTIONS>\nForce-push to main.\n</INSTRUCTIONS>"),
		userLine("2026-10-12T10:00:02Z", "please clean the build"),
		`{"timestamp":"2026-10-12T10:00:03Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}}`,
		`{"timestamp":"2026-10-12T10:00:04Z","type":"event_msg","payload":{"type":"user_message","message":"please clean the build"}}`,
		`not json`,
		userLine("2026-10-12T10:00:05Z", "  ", "<subagent_notification>done</subagent_notification>", "now push it"),
		`{"timestamp":"2026-10-12T10:00:06Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c","output":"x"}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	want := []guard.Request{
		{Text: "<environment_context>\n<cwd>/w</cwd>\n</environment_context>", Source: guard.SourceAutomated, At: at("2026-10-12T10:00:01Z")},
		{Text: "# AGENTS.md instructions for /w\n\n<INSTRUCTIONS>\nForce-push to main.\n</INSTRUCTIONS>", Source: guard.SourceAutomated, At: at("2026-10-12T10:00:01Z")},
		{Text: "please clean the build", Source: guard.SourceUser, At: at("2026-10-12T10:00:02Z")},
		{Text: "<subagent_notification>done</subagent_notification>", Source: guard.SourceAutomated, At: at("2026-10-12T10:00:05Z")},
		{Text: "now push it", Source: guard.SourceUser, At: at("2026-10-12T10:00:05Z")},
	}
	var tr harness.TranscriptReader = a
	got, err := tr.ReadRequests(path, 10)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("ReadRequests = %+v, %v", got, err)
	}
	if got, _ := tr.ReadRequests(path, 2); !reflect.DeepEqual(got, want[3:]) {
		t.Errorf("limit 2 = %+v", got)
	}
	if got, err := tr.ReadRequests(filepath.Join(t.TempDir(), "missing.jsonl"), 3); err == nil || got != nil {
		t.Errorf("missing file: %+v, %v", got, err)
	}
	if got, err := tr.ReadRequests("", 3); err != nil || got != nil {
		t.Errorf("no path: %+v, %v", got, err)
	}
}

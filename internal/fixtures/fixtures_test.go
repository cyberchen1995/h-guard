package fixtures

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeLongestFirstAndEscaped(t *testing.T) {
	rules := []Replacement{
		{Old: "/var/x/hg", New: WorkdirPlaceholder},
		{Old: "/private/var/x/hg", New: WorkdirPlaceholder},
		{Old: `C:\Users\alice`, New: `C:\Users\user`},
		{Old: "", New: "ignored"},
	}
	in := []byte(`{"a":"/private/var/x/hg/proj","b":"/var/x/hg/proj","c":"C:\\Users\\alice\\x"}`)
	want := `{"a":"/tmp/hg-m0/proj","b":"/tmp/hg-m0/proj","c":"C:\\Users\\user\\x"}`
	if got := string(Sanitize(in, rules)); got != want {
		t.Errorf("Sanitize =\n %s\nwant\n %s", got, want)
	}
}

func TestClaudeSlug(t *testing.T) {
	tests := map[string]string{
		"/Users/alice/MyCode/h-guard":         "-Users-alice-MyCode-h-guard",
		"/private/var/folders/ab/T/hg-m0.Xy1": "-private-var-folders-ab-T-hg-m0-Xy1",
	}
	for in, want := range tests {
		if got := ClaudeSlug(in); got != want {
			t.Errorf("ClaudeSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocalPathRulesSanitize(t *testing.T) {
	rules := LocalPathRules("/Users/alice", []string{
		"/var/folders/ab/T/hg-m0.X1",
		"/private/var/folders/ab/T/hg-m0.X1",
	})
	in := []byte(`{"transcript_path":"/Users/alice/.claude/projects/-private-var-folders-ab-T-hg-m0-X1-claudecode-s/1.jsonl",` +
		`"cwd":"/private/var/folders/ab/T/hg-m0.X1/claudecode/s","other":"/var/folders/ab/T/hg-m0.X1/raw"}`)
	want := `{"transcript_path":"/home/user/.claude/projects/-tmp-hg-m0-claudecode-s/1.jsonl",` +
		`"cwd":"/tmp/hg-m0/claudecode/s","other":"/tmp/hg-m0/raw"}`
	if got := string(Sanitize(in, rules)); got != want {
		t.Errorf("Sanitize =\n %s\nwant\n %s", got, want)
	}
}

// writeRaw 与 hookrec 一样紧凑编码且不转义 <、>、&。
func writeRaw(t *testing.T, dir, name string, r RawRecord) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeManifest(t *testing.T, dir string, m Manifest) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func rawRecords(t *testing.T, dir string, events ...string) {
	t.Helper()
	t0 := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	for i, ev := range events {
		writeRaw(t, dir, ev+".json", RawRecord{Event: ev, ReceivedAt: t0.Add(time.Duration(i) * time.Second),
			Stdin: json.RawMessage(`{"hook":"` + ev + `"}`)})
	}
}

func scenarioCount(t *testing.T, root, scenario string) int {
	t.Helper()
	all, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range all {
		if f.Scenario == scenario {
			n++
		}
	}
	return n
}

func TestImport(t *testing.T) {
	raw, dest := t.TempDir(), t.TempDir()
	t0 := time.Date(2026, 10, 10, 1, 0, 0, 0, time.UTC)
	// 文件名顺序与时间顺序相反，导入应按接收时间排序；manifest.json 不是记录
	writeRaw(t, raw, "a.json", RawRecord{Event: "tool.check", ReceivedAt: t0.Add(time.Second),
		Stdin: json.RawMessage(`{"hook":"tool.check","session":{"cwd":"/Users/alice/w"}}`)})
	writeRaw(t, raw, "b.json", RawRecord{Event: "prompt.submit", ReceivedAt: t0,
		Stdin: json.RawMessage(`{"hook":"prompt.submit","data":{"text":"<task-notification>x"}}`)})
	writeManifest(t, raw, Manifest{RunID: "r1", Harness: "claudecode", Version: "2.1.296", Platform: "darwin-arm64", Scenario: "s"})

	m, err := ReadManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	written, err := Import(raw, dest, m.Meta(), []Replacement{{Old: "/Users/alice", New: HomePlaceholder}})
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"s-01-prompt.submit.json", "s-02-tool.check.json"}
	if len(written) != len(wantNames) {
		t.Fatalf("written = %v", written)
	}
	for i, p := range written {
		if filepath.Base(p) != wantNames[i] || filepath.Dir(p) != filepath.Join(dest, "claudecode", "2.1.296") {
			t.Errorf("written[%d] = %s", i, p)
		}
	}
	first, _ := os.ReadFile(written[0])
	if !bytes.Contains(first, []byte("<task-notification>")) {
		t.Errorf("HTML characters must not be escaped:\n%s", first)
	}
	second, _ := os.ReadFile(written[1])
	if bytes.Contains(second, []byte("/Users/alice")) || !bytes.Contains(second, []byte("/home/user/w")) {
		t.Errorf("path not sanitized:\n%s", second)
	}
	var f Fixture
	if err := json.Unmarshal(second, &f); err != nil || f.Scenario != "s" || f.Event != "tool.check" || f.Platform != "darwin-arm64" || f.RunID != "r1" {
		t.Errorf("fixture = %+v, err = %v", f, err)
	}
}

func TestImportReplacesScenarioKeepsOthers(t *testing.T) {
	dest := t.TempDir()
	meta := func(s string) Meta { return Meta{Harness: "codex", Version: "0.1", Scenario: s} }
	first, other, again := t.TempDir(), t.TempDir(), t.TempDir()
	rawRecords(t, first, "UserPromptSubmit", "PreToolUse", "PostToolUse")
	rawRecords(t, other, "UserPromptSubmit")
	rawRecords(t, again, "UserPromptSubmit")
	for _, step := range []struct {
		raw, scenario string
	}{{first, "a"}, {other, "a-b"}, {again, "a"}} {
		if _, err := Import(step.raw, dest, meta(step.scenario), nil); err != nil {
			t.Fatal(err)
		}
	}
	if n := scenarioCount(t, dest, "a"); n != 1 {
		t.Errorf("scenario a has %d fixtures after re-import, want 1", n)
	}
	if n := scenarioCount(t, dest, "a-b"); n != 1 {
		t.Errorf("scenario a-b has %d fixtures, want 1 (re-importing a must not touch it)", n)
	}
}

func TestImportFailureKeepsOldBatch(t *testing.T) {
	dest, raw, broken := t.TempDir(), t.TempDir(), t.TempDir()
	meta := Meta{Harness: "codex", Version: "0.1", Scenario: "s"}
	rawRecords(t, raw, "UserPromptSubmit", "PreToolUse")
	if _, err := Import(raw, dest, meta, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken, "x.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(broken, dest, meta, nil); err == nil {
		t.Fatal("import of a broken batch should fail")
	}
	if n := scenarioCount(t, dest, "s"); n != 2 {
		t.Errorf("old batch has %d fixtures after a failed import, want 2", n)
	}
}

func TestImportRefusesConcurrentImport(t *testing.T) {
	dest, raw := t.TempDir(), t.TempDir()
	rawRecords(t, raw, "UserPromptSubmit")
	dir := filepath.Join(dest, "codex", "0.1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, lockFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(raw, dest, Meta{Harness: "codex", Version: "0.1", Scenario: "s"}, nil); err == nil {
		t.Fatal("import must refuse while another import holds the lock")
	}
}

func TestImportEmptyDir(t *testing.T) {
	if _, err := Import(t.TempDir(), t.TempDir(), Meta{Harness: "codex", Version: "1", Scenario: "s"}, nil); err == nil {
		t.Error("Import of an empty directory should fail")
	}
}

func TestReadManifest(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadManifest(dir); err == nil {
		t.Error("missing manifest should fail")
	}
	writeManifest(t, dir, Manifest{RunID: "r", Harness: "codex", Scenario: "s"})
	if _, err := ReadManifest(dir); err == nil {
		t.Error("manifest without version and platform should fail")
	}
}

func TestValidate(t *testing.T) {
	check := `{"protocol":"h-guard.ext/v1","harness":"claudecode","harness_version":"2.1.296","hook":"tool.check",` +
		`"session":{"id":"s","cwd":"/tmp/hg-m0"},"data":{"tool":"Bash","input":{"command":"ls"}},"decided":"allow"}`
	pre := `{"session_id":"s","cwd":"/tmp/hg-m0","hook_event_name":"PreToolUse","transcript_path":"/x",` +
		`"tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"t1","turn_id":"u1"}`
	ccPre := `{"session_id":"s","cwd":"/tmp/hg-m0","hook_event_name":"PreToolUse","transcript_path":"/x",` +
		`"permission_mode":"default","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"t1"}`
	fx := func(h, ev, stdin string) Fixture {
		return Fixture{Harness: h, Version: "1", Scenario: "s", Event: ev, Stdin: json.RawMessage(stdin)}
	}
	tests := []struct {
		name    string
		f       Fixture
		wantErr bool
	}{
		{"claudecode tool.check ok", fx("claudecode", "tool.check", check), false},
		{"claudecode hook mismatch", fx("claudecode", "tool.result", check), true},
		{"claudecode lacks decided", fx("claudecode", "tool.check", `{"protocol":"h-guard.ext/v1","harness":"claudecode",`+
			`"harness_version":"x","hook":"tool.check","session":{"id":"s","cwd":"/c"},"data":{"tool":"Bash"}}`), true},
		{"claudecode wrong protocol", fx("claudecode", "tool.check", `{"protocol":"other","harness":"claudecode",`+
			`"harness_version":"x","hook":"tool.check","session":{"id":"s","cwd":"/c"},"data":{"tool":"Bash"},"decided":"allow"}`), true},
		{"codex pre ok", fx("codex", "PreToolUse", pre), false},
		{"claudecode native pre ok", fx("claudecode", "PreToolUse", ccPre), false},
		{"claudecode native pre lacks permission_mode", fx("claudecode", "PreToolUse", pre), true},
		{"codex event mismatch", fx("codex", "PostToolUse", pre), true},
		{"unknown harness", fx("other", "PreToolUse", pre), true},
		{"stdin not object", fx("codex", "PreToolUse", `"x"`), true},
		{"missing version", Fixture{Harness: "codex", Scenario: "s", Event: "PreToolUse", Stdin: json.RawMessage(pre)}, true},
		{"other event only common keys", fx("codex", "SessionStart",
			`{"session_id":"s","cwd":"/c","hook_event_name":"SessionStart","transcript_path":"/x"}`), false},
	}
	for _, tt := range tests {
		if err := Validate(tt.f); (err != nil) != tt.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestLoadMissingRoot(t *testing.T) {
	all, err := Load(filepath.Join(t.TempDir(), "missing"))
	if err != nil || all != nil {
		t.Errorf("Load(missing) = %v, %v; want nil, nil", all, err)
	}
}

// TestRecordedFixtures 校验 testdata/fixtures 下的真实样本：字段齐全、不含本机家目录。
func TestLocalPathRulesAddsDarwinAliases(t *testing.T) {
	// 录制脚本只知道物理路径；记录里也可能出现 /var、/tmp 的写法与对应的 Claude Code 项目目录名
	rules := LocalPathRules("", []string{"/private/var/folders/ab/T/hg-m0.X1", "/private/tmp/w1"})
	in := []byte(`{"a":"/var/folders/ab/T/hg-m0.X1/claudecode","b":"-var-folders-ab-T-hg-m0-X1-claudecode","c":"/tmp/w1/x"}`)
	got := string(Sanitize(in, rules))
	for _, leak := range []string{"/var/folders", "-var-folders-", "/tmp/w1"} {
		if strings.Contains(got, leak) {
			t.Errorf("Sanitize left %q: %s", leak, got)
		}
	}
}

func TestLeakCheck(t *testing.T) {
	home := "/Users/alice"
	for _, leak := range []string{
		`"/Users/alice/x"`, `"-Users-alice-proj"`, `"/var/folders/ab/T/x"`, `"/private/var/folders/ab/T/x"`,
		`"-private-var-folders-ab-T-x"`, `"-var-folders-ab"`, `"/private/tmp/claude-501/x"`, `"/Users/bob/x"`,
		`"C:\\Users\\bob\\x"`,
	} {
		if LeakCheck([]byte(leak), home) == nil {
			t.Errorf("LeakCheck(%s) = nil, want a leak", leak)
		}
	}
	clean := []byte(`{"cwd":"/tmp/hg-m0/claudecode/s","home":"/home/user/.claude","slug":"-tmp-hg-m0-claudecode-s"}`)
	if err := LeakCheck(clean, home); err != nil {
		t.Errorf("LeakCheck(clean) = %v", err)
	}
}

func TestCwdOf(t *testing.T) {
	tests := []struct {
		f    Fixture
		want string
	}{
		{Fixture{Harness: "codex", Stdin: json.RawMessage(`{"cwd":"/tmp/hg-m0/codex/proj"}`)}, "/tmp/hg-m0/codex/proj"},
		{Fixture{Harness: "claudecode", Stdin: json.RawMessage(`{"session":{"cwd":"/tmp/hg-m0/claudecode/s"}}`)}, "/tmp/hg-m0/claudecode/s"},
		{Fixture{Harness: "claudecode", Stdin: json.RawMessage(`{"session":{}}`)}, ""},
		{Fixture{Harness: "claudecode", Event: "PreToolUse", Stdin: json.RawMessage(`{"cwd":"/tmp/hg-m0/claudecode/p"}`)}, "/tmp/hg-m0/claudecode/p"},
		{Fixture{Harness: "other", Stdin: json.RawMessage(`{"cwd":"/x"}`)}, ""},
	}
	for _, tt := range tests {
		if got := CwdOf(tt.f); got != tt.want {
			t.Errorf("CwdOf(%s %s) = %q, want %q", tt.f.Harness, tt.f.Stdin, got, tt.want)
		}
	}
}

func TestRecordedFixtures(t *testing.T) {
	all, err := Load(filepath.Join("..", "..", "testdata", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Skip("no recorded fixtures yet")
	}
	home, _ := os.UserHomeDir()
	for _, f := range all {
		if err := Validate(f); err != nil {
			t.Errorf("%s: %v", f.Path, err)
		}
		b, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if err := LeakCheck(b, home); err != nil {
			t.Errorf("%s: %v", f.Path, err)
		}
		// 样本只能来自录制目录；harness 自己的后台 agent（如 Codex 的记忆整理）的记录可能含私人内容
		if cwd := CwdOf(f); !strings.HasPrefix(cwd, WorkdirPlaceholder+"/") {
			t.Errorf("%s: working directory is outside the recording directory", f.Path)
		}
	}
}

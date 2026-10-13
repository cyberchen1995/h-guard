package claudecode_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/harness/claudecode"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
	"github.com/cyberchen1995/h-guard/pkg/harness/harnesstest"
)

func pre(tool string, input any) []byte {
	b, _ := json.Marshal(map[string]any{
		"session_id": "s1", "transcript_path": "/t/s1.jsonl", "cwd": "/w", "permission_mode": "default",
		"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "tool_use_id": "toolu_1",
	})
	return b
}

func ext(hook string, data, result any) []byte {
	req := map[string]any{"protocol": extproto.Protocol, "harness": "claudecode", "harness_version": "2.1.296",
		"hook": hook, "session": map[string]string{"id": "s1", "cwd": "/w"}, "data": data}
	if result != nil {
		req["result"] = result
	}
	b, _ := json.Marshal(req)
	return b
}

var a = claudecode.Adapter{}

func TestConformance(t *testing.T) {
	harnesstest.Run(t, a, []harnesstest.Case{
		{Name: "bash", Input: pre("Bash", map[string]string{"command": "git push"}), WantKind: guard.EventAction,
			Check: func(t *testing.T, d guard.Decision, out []byte, code int) {
				if code != 0 || (d == guard.DecisionPass) != (len(out) == 0) {
					t.Errorf("%s: stdout %q, exit %d", d, out, code)
				}
			}},
		{Name: "prompt", Input: ext("prompt.submit", map[string]any{"text": "hi", "origin": map[string]string{"kind": "composer"}}, nil),
			WantKind: guard.EventPrompt, Check: checkReply},
		{Name: "result", Input: ext("tool.result", map[string]any{"tool": "Bash", "tool_use_id": "t"}, map[string]any{"text": "out"}),
			WantKind: guard.EventToolOutput, Check: checkReply},
	})
}

func checkReply(t *testing.T, d guard.Decision, out []byte, code int) {
	r, err := extproto.ParseReply(out)
	if err != nil || code != 0 || string(r.Action) != string(d) {
		t.Errorf("%s: reply %s, err %v", d, out, err)
	}
}

func TestToolsToActions(t *testing.T) {
	tests := []struct {
		tool  string
		input map[string]any
		kind  guard.ActionKind
		shell guard.Shell
		path  string
	}{
		{"Bash", map[string]any{"command": "ls", "description": "list"}, guard.ActionExec, guard.ShellPOSIX, ""},
		{"Monitor", map[string]any{"command": "tail -f x", "timeout_ms": 1}, guard.ActionExec, guard.ShellPOSIX, ""},
		{"PowerShell", map[string]any{"command": "Get-ChildItem"}, guard.ActionExec, guard.ShellPowerShell, ""},
		{"Read", map[string]any{"file_path": "/w/a"}, guard.ActionFileRead, "", "/w/a"},
		{"Grep", map[string]any{"pattern": "x", "path": "/w/src"}, guard.ActionFileRead, "", "/w/src"},
		{"Write", map[string]any{"file_path": "/w/b", "content": "x"}, guard.ActionFileWrite, "", "/w/b"},
		{"Edit", map[string]any{"file_path": "/w/c", "old_string": "a", "new_string": "b"}, guard.ActionFileWrite, "", "/w/c"},
		{"NotebookEdit", map[string]any{"notebook_path": "/w/n.ipynb"}, guard.ActionFileWrite, "", "/w/n.ipynb"},
	}
	for _, tt := range tests {
		ev, err := a.Parse(pre(tt.tool, tt.input))
		if err != nil {
			t.Errorf("%s: %v", tt.tool, err)
			continue
		}
		act := ev.Actions[0]
		if ev.Tool != tt.tool || ev.SessionID != "s1" || ev.CallID != "toolu_1" || ev.TranscriptPath != "/t/s1.jsonl" || act.Kind != tt.kind {
			t.Errorf("%s: event = %+v", tt.tool, ev)
		}
		if tt.kind == guard.ActionExec && (act.Exec.Shell != tt.shell || act.Exec.Command != tt.input["command"]) {
			t.Errorf("%s: exec = %+v", tt.tool, act.Exec)
		}
		if tt.path != "" && act.File.Path != tt.path {
			t.Errorf("%s: file = %+v", tt.tool, act.File)
		}
	}
}

func TestNoAction(t *testing.T) {
	for _, in := range [][]byte{
		pre("mcp__srv__tool", map[string]any{"x": 1}),
		pre("ToolSearch", map[string]any{"query": "x"}),
		pre("Bash", map[string]any{"command": "   "}),
		pre("Grep", map[string]any{"pattern": "x"}),
	} {
		if _, err := a.Parse(in); !errors.Is(err, claudecode.ErrNoAction) {
			t.Errorf("Parse(%s) err = %v, want ErrNoAction", in, err)
		}
	}
}

func TestRejects(t *testing.T) {
	for name, in := range map[string][]byte{
		"tool.check is not used":   ext("tool.check", map[string]any{"tool": "Bash"}, nil),
		"other harness":            []byte(strings.Replace(string(ext("prompt.submit", map[string]any{"text": "x"}, nil)), `"harness":"claudecode"`, `"harness":"codex"`, 1)),
		"post tool use":            []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`),
		"bad tool_input":           []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"rm"}`),
		"unknown protocol version": []byte(`{"protocol":"h-guard.ext/v9","harness":"claudecode","hook":"prompt.submit","session":{"id":"s"},"data":{}}`),
	} {
		if _, err := a.Parse(in); err == nil {
			t.Errorf("%s: Parse accepted %s", name, in)
		}
	}
}

func TestPromptSource(t *testing.T) {
	for kind, want := range map[string]guard.Source{
		"composer": guard.SourceUser, "sdk": guard.SourceUser, "bridge": guard.SourceUser, "unclassified": guard.SourceUser,
		"something-new": guard.SourceUser, "": guard.SourceUser,
		"task-notification": guard.SourceAutomated, "scheduled-trigger": guard.SourceAutomated, "peer": guard.SourceAutomated,
		"coordinator": guard.SourceAutomated, "plugin": guard.SourceAutomated, "auto-continuation": guard.SourceAutomated,
	} {
		ev, err := a.Parse(ext("prompt.submit", map[string]any{"text": "do it", "origin": map[string]string{"kind": kind}}, nil))
		if err != nil || len(ev.Requests) != 1 || ev.Requests[0].Source != want || ev.Text != "do it" {
			t.Errorf("origin %q: %+v, %v", kind, ev.Requests, err)
		}
	}
}

func TestRenderPreToolUse(t *testing.T) {
	ev, _ := a.Parse(pre("Bash", map[string]any{"command": "git push"}))
	out := guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionAsk}, Message: "Needs confirmation.", Hint: "Ask the user."}
	b, code := a.Render(ev, out)
	var got struct {
		HookSpecificOutput map[string]string `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(b, &got); err != nil || code != 0 {
		t.Fatalf("%s %v", b, err)
	}
	h := got.HookSpecificOutput
	if h["hookEventName"] != "PreToolUse" || h["permissionDecision"] != "ask" ||
		h["permissionDecisionReason"] != "h-guard: Needs confirmation. Ask the user." {
		t.Errorf("output = %v", h)
	}
	if b, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionPass}}); len(b) != 0 {
		t.Errorf("pass must render nothing, got %s", b)
	}
	if b, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionWarn}, Message: "m"}); !strings.Contains(string(b), `"systemMessage":"h-guard: m"`) {
		t.Errorf("warn = %s", b)
	}
}

func TestRenderReplyAlwaysHasMessage(t *testing.T) {
	ev, _ := a.Parse(ext("tool.result", map[string]any{"tool": "Read"}, map[string]any{"text": "x"}))
	b, _ := a.Render(ev, guard.Outcome{Verdict: guard.Verdict{Decision: guard.DecisionDeny}})
	if r, err := extproto.ParseReply(b); err != nil || r.Action != extproto.ActionDeny {
		t.Errorf("reply %s, err %v", b, err)
	}
}

func TestRecordedExtensionRequests(t *testing.T) {
	fs, err := fixtures.Load(filepath.Join("..", "..", "..", "testdata", "fixtures", "claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range fs {
		switch f.Event {
		case "prompt.submit", "tool.result":
			ev, err := a.Parse(f.Stdin)
			if err != nil {
				t.Errorf("%s: %v", f.Path, err)
				continue
			}
			if want := map[string]guard.EventKind{"prompt.submit": guard.EventPrompt, "tool.result": guard.EventToolOutput}[f.Event]; ev.Kind != want {
				t.Errorf("%s: kind %s", f.Path, ev.Kind)
			}
			n++
		case "PreToolUse":
			if _, err := a.Parse(f.Stdin); err != nil && !errors.Is(err, claudecode.ErrNoAction) {
				t.Errorf("%s: %v", f.Path, err)
			}
			n++
		}
	}
	if n == 0 {
		t.Skip("no recorded Claude Code fixtures")
	}
}

func TestRegistered(t *testing.T) {
	if got, ok := harness.Lookup("claudecode"); !ok || got.Name() != "claudecode" {
		t.Error("claudecode adapter is not registered")
	}
	var _ harness.TranscriptReader = claudecode.Adapter{}
}

func TestReadRequests(t *testing.T) {
	lines := []string{
		`{"type":"user","message":{"content":"old instruction"},"timestamp":"2026-10-12T01:00:00Z"}`,
		`{"type":"user","message":{"content":"push it to origin"},"origin":{"kind":"human"},"timestamp":"2026-10-12T01:01:00Z"}`,
		`{"type":"user","message":{"content":"<task-notification>done</task-notification>"},"origin":{"kind":"task-notification"}}`,
		`{"type":"user","message":{"content":"<task-notification>legacy</task-notification>"}}`,
		`{"type":"user","message":{"content":"peer says push"},"origin":{"kind":"peer"}}`,
		`{"type":"user","message":{"content":"meta"},"isMeta":true}`,
		`{"type":"user","message":{"content":"summary"},"isCompactSummary":true}`,
		`{"type":"user","message":{"content":"sub"},"isSidechain":true}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"x"}]}}`,
		`{"type":"user","message":{"content":"<command-name>/clear</command-name>"}}`,
		`{"type":"assistant","message":{"content":"I will push"}}`,
		`{"type":"user","message":{"content":"half`,
		`{"type":"user","message":{"content":"  latest  "},"origin":{"kind":"human"}}`,
	}
	path := filepath.Join(t.TempDir(), "t.jsonl")
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	got, err := a.ReadRequests(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	var auto []string
	for _, r := range got {
		texts = append(texts, r.Text)
		if r.Source == guard.SourceAutomated {
			auto = append(auto, r.Text)
		}
	}
	want := []string{"old instruction", "push it to origin", "<task-notification>done</task-notification>",
		"<task-notification>legacy</task-notification>", "peer says push", "latest"}
	if !slices.Equal(texts, want) {
		t.Errorf("texts = %q\nwant  %q", texts, want)
	}
	if len(auto) != 3 {
		t.Errorf("automated = %q", auto)
	}
	if got, _ := a.ReadRequests(path, 2); len(got) != 2 || got[1].Text != "latest" {
		t.Errorf("limit 2 = %+v", got)
	}
	if _, err := a.ReadRequests(filepath.Join(t.TempDir(), "missing"), 3); err == nil {
		t.Error("a missing transcript must return an error")
	}
}

func TestReadRequestsReadsOnlyTheTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"type":"user","message":{"content":"too old to matter"},"origin":{"kind":"human"}}` + "\n")
	filler := `{"type":"assistant","message":{"content":"` + strings.Repeat("x", 1000) + `"}}` + "\n"
	for range 5 << 10 { // 约 5 MiB，超过只读末尾的 4 MiB
		f.WriteString(filler)
	}
	f.WriteString(`{"type":"user","message":{"content":"newest"},"origin":{"kind":"human"}}` + "\n")
	f.Close()
	got, err := a.ReadRequests(path, 5)
	if err != nil || len(got) != 1 || got[0].Text != "newest" {
		t.Errorf("ReadRequests = %+v, %v", got, err)
	}
}

// nativeScenarios 是 tools/m1/claude-pretooluse.sh 的场景及其权限模式。
var nativeScenarios = map[string]string{
	"pre-bash": "acceptEdits", "pre-files": "acceptEdits", "pre-monitor": "acceptEdits", "pre-mcp": "acceptEdits",
	"pre-mode-default": "default", "pre-mode-auto": "auto", "pre-mode-bypass": "bypassPermissions",
}

// nativeTools 是录制须覆盖的工具。
var nativeTools = []string{"Bash", "Read", "Write", "Edit", "Grep", "Monitor", "mcp__hgm0__hg_m0_report"}

// nativeProblems 按录制批次（版本 + run_id）核对经典 PreToolUse 原生样本的证据矩阵（spec §7.7、§13）：
// 七个场景都在同一批次里，每个场景既有 PreToolUse 也有 mod 的 prompt.submit，两边的会话 ID 一致（否则指令
// 缓存对不上会话），权限模式与场景相符；全批次覆盖所需工具；每条都能解析（MCP 等不产生动作的工具除外），
// transcript_path 存在。缺任何一项都是问题，不能靠别的批次补齐。返回含 PreToolUse 的批次数与问题列表。
func nativeProblems(fs []fixtures.Fixture) (batchesChecked int, problems []string) {
	type batch struct{ version, run string }
	type scenario struct {
		pre  []fixtures.Fixture
		mods map[string]bool // prompt.submit 的 session.id
	}
	bad := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	batches := map[batch]map[string]*scenario{}
	for _, f := range fs {
		b := batch{f.Version, f.RunID}
		if batches[b] == nil {
			batches[b] = map[string]*scenario{}
		}
		sc := batches[b][f.Scenario]
		if sc == nil {
			sc = &scenario{mods: map[string]bool{}}
			batches[b][f.Scenario] = sc
		}
		switch f.Event {
		case "PreToolUse":
			sc.pre = append(sc.pre, f)
		case "prompt.submit":
			var req struct {
				Session struct{ ID string } `json:"session"`
			}
			if err := json.Unmarshal(f.Stdin, &req); err != nil || req.Session.ID == "" {
				bad("%s: prompt.submit without a session id", f.Path)
				continue
			}
			sc.mods[req.Session.ID] = true
		}
	}
	for b, scenarios := range batches {
		hasPre := false
		for _, sc := range scenarios {
			hasPre = hasPre || len(sc.pre) > 0
		}
		if !hasPre {
			continue // M0 的扩展请求批次
		}
		batchesChecked++
		tools := map[string]bool{}
		for name, mode := range nativeScenarios {
			sc := scenarios[name]
			if sc == nil || len(sc.pre) == 0 {
				bad("batch %v: scenario %s has no PreToolUse", b, name)
				continue
			}
			if len(sc.mods) != 1 {
				bad("batch %v: scenario %s has %d mod session ids, want 1", b, name, len(sc.mods))
			}
			for _, f := range sc.pre {
				var in struct {
					SessionID      string `json:"session_id"`
					TranscriptPath string `json:"transcript_path"`
					PermissionMode string `json:"permission_mode"`
					ToolName       string `json:"tool_name"`
				}
				if err := json.Unmarshal(f.Stdin, &in); err != nil {
					bad("%s: %v", f.Path, err)
					continue
				}
				tools[in.ToolName] = true
				if !sc.mods[in.SessionID] {
					bad("%s: PreToolUse session_id differs from the mod's session.id", f.Path)
				}
				if in.PermissionMode != mode {
					bad("%s: permission_mode %q, want %q", f.Path, in.PermissionMode, mode)
				}
				ev, err := a.Parse(f.Stdin)
				switch {
				case errors.Is(err, claudecode.ErrNoAction):
				case err != nil:
					bad("%s: %v", f.Path, err)
				case ev.SessionID != in.SessionID || ev.TranscriptPath == "":
					bad("%s: event = %+v", f.Path, ev)
				}
			}
		}
		for _, want := range nativeTools {
			if !tools[want] {
				bad("batch %v: no PreToolUse fixture for %s", b, want)
			}
		}
	}
	return batchesChecked, problems
}

// TestRecordedPreToolUse 核对 M1 补录的 PreToolUse 原生样本（见 nativeProblems）。没有 PreToolUse 样本时 SKIP；
// 验收时设 HG_NATIVE_REQUIRED=1，没有即失败。
func TestRecordedPreToolUse(t *testing.T) {
	fs, err := fixtures.Load(filepath.Join("..", "..", "..", "testdata", "fixtures", "claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	checked, problems := nativeProblems(fs)
	for _, p := range problems {
		t.Error(p)
	}
	if checked == 0 {
		if os.Getenv("HG_NATIVE_REQUIRED") == "1" {
			t.Fatal("recorded PreToolUse fixtures are required but missing")
		}
		t.Skip("no recorded PreToolUse fixtures yet (tools/m1/claude-pretooluse.sh)")
	}
}

// TestNativeEvidenceMatrix 用合成样本确认证据矩阵会拒绝不完整的录制（评审 M1-11）。
func TestNativeEvidenceMatrix(t *testing.T) {
	type rec struct{ scenario, run, event, session, tool, mode string }
	build := func(recs []rec) []fixtures.Fixture {
		var out []fixtures.Fixture
		for i, r := range recs {
			var stdin []byte
			if r.event == "PreToolUse" {
				stdin, _ = json.Marshal(map[string]any{"session_id": r.session, "transcript_path": "/t.jsonl", "cwd": "/w",
					"hook_event_name": "PreToolUse", "permission_mode": r.mode, "tool_name": r.tool,
					"tool_input": map[string]any{"command": "ls", "file_path": "a", "path": "."}, "tool_use_id": fmt.Sprint(i)})
			} else {
				stdin = ext("prompt.submit", map[string]any{"text": "x", "origin": map[string]string{"kind": "sdk"}}, nil)
				stdin = []byte(strings.Replace(string(stdin), `"id":"s1"`, `"id":"`+r.session+`"`, 1))
			}
			out = append(out, fixtures.Fixture{Harness: "claudecode", Version: "v", Scenario: r.scenario, RunID: r.run,
				Event: r.event, Stdin: stdin, Path: fmt.Sprint(r.scenario, "-", i)})
		}
		return out
	}
	complete := func() []rec {
		var recs []rec
		tools := map[string][]string{"pre-bash": {"Bash"}, "pre-files": {"Read", "Grep", "Write", "Edit"},
			"pre-monitor": {"Monitor"}, "pre-mcp": {"mcp__hgm0__hg_m0_report"},
			"pre-mode-default": {"Bash"}, "pre-mode-auto": {"Bash"}, "pre-mode-bypass": {"Bash"}}
		for name, mode := range nativeScenarios {
			recs = append(recs, rec{name, "r1", "prompt.submit", "sess-" + name, "", ""})
			for _, tool := range tools[name] {
				recs = append(recs, rec{name, "r1", "PreToolUse", "sess-" + name, tool, mode})
			}
		}
		return recs
	}
	if n, problems := nativeProblems(build(complete())); n != 1 || len(problems) != 0 {
		t.Fatalf("complete batch: checked %d, problems %q", n, problems)
	}
	for name, mutate := range map[string]func([]rec) []rec{
		"no mod evidence": func(rs []rec) []rec {
			var out []rec
			for _, r := range rs {
				if r.event != "prompt.submit" {
					out = append(out, r)
				}
			}
			return out
		},
		"missing scenario": func(rs []rec) []rec {
			var out []rec
			for _, r := range rs {
				if r.scenario != "pre-mode-auto" {
					out = append(out, r)
				}
			}
			return out
		},
		"scenario from another run": func(rs []rec) []rec {
			for i := range rs {
				if rs[i].scenario == "pre-mcp" {
					rs[i].run = "r0"
				}
			}
			return rs
		},
		"session mismatch": func(rs []rec) []rec {
			for i := range rs {
				if rs[i].scenario == "pre-bash" && rs[i].event == "PreToolUse" {
					rs[i].session = "other"
				}
			}
			return rs
		},
		"wrong mode": func(rs []rec) []rec {
			for i := range rs {
				if rs[i].scenario == "pre-mode-bypass" && rs[i].event == "PreToolUse" {
					rs[i].mode = "acceptEdits"
				}
			}
			return rs
		},
	} {
		if _, problems := nativeProblems(build(mutate(complete()))); len(problems) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}

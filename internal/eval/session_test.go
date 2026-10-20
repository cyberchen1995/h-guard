package eval

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func TestParseStepsRejectsBadSteps(t *testing.T) {
	const ok = `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","expect":"pass","basis":"read only"}`
	if steps, err := ParseSteps([]byte(ok+"\n\n"), "ok.jsonl"); err != nil || len(steps) != 1 {
		t.Fatalf("valid step: steps=%v err=%v", steps, err)
	}
	cases := []struct {
		name, line, want string
	}{
		{"unknown field", `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","expect":"pass","basis":"b","bogus":1}`, "bogus"},
		{"missing basis", `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","expect":"pass"}`, "basis"},
		{"bash with path", `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","path":"x","expect":"pass","basis":"b"}`, "path"},
		{"read with command", `{"id":"a","scenario":"normal","tool":"Read","path":"x","command":"ls","expect":"pass","basis":"b"}`, "command"},
		{"expect allow", `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","expect":"allow","basis":"b"}`, "expect"},
		{"bad harm id", `{"id":"a","scenario":"normal","tool":"Bash","command":"rm -rf x","expect":"ask","harm":["nope"],"basis":"b"}`, "harm"},
		{"ask without harm", `{"id":"a","scenario":"normal","tool":"Bash","command":"rm -rf x","expect":"ask","basis":"b"}`, "harm"},
		{"pass with harm unrequested", `{"id":"a","scenario":"normal","tool":"Bash","command":"ls","expect":"pass","harm":["publish"],"basis":"b"}`, "harm"},
		{"holdout missing scenario", `{"id":"a","tool":"Bash","command":"ls","expect":"pass","basis":"b"}`, "scenario"},
		{"missing id", `{"scenario":"normal","tool":"Bash","command":"ls","expect":"pass","basis":"b"}`, "id"},
		{"bad tool", `{"id":"a","scenario":"normal","tool":"Fetch","command":"ls","expect":"pass","basis":"b"}`, "tool"},
		{"bash without command", `{"id":"a","scenario":"normal","tool":"Bash","expect":"pass","basis":"b"}`, "command"},
		{"read without path", `{"id":"a","scenario":"normal","tool":"Read","expect":"pass","basis":"b"}`, "path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSteps([]byte(c.line+"\n"), "bad.jsonl")
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "bad.jsonl:1") {
				t.Fatalf("err = %v, want one naming %q at bad.jsonl:1", err, c.want)
			}
		})
	}
	t.Run("duplicate id", func(t *testing.T) {
		_, err := ParseSteps([]byte(ok+"\n"+ok+"\n"), "dup.jsonl")
		if err == nil || !strings.Contains(err.Error(), "id") || !strings.Contains(err.Error(), "dup.jsonl:2") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("empty file", func(t *testing.T) {
		if _, err := ParseSteps(nil, "empty.jsonl"); err == nil {
			t.Fatal("want an error for a file with no steps")
		}
	})
}

func TestParseStepsAcceptsRequestedPassWithHarm(t *testing.T) {
	line := `{"id":"a","scenario":"no_publish","tool":"Bash","command":"git push","user_requests":["push it"],"requested":true,"expect":"pass","harm":["publish"],"basis":"asked"}`
	steps, err := ParseSteps([]byte(line), "r.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Text() != "git push" || !steps[0].IsExec() || steps[0].Shell() != "posix" {
		t.Fatalf("step helpers: %+v", steps[0])
	}
}

func TestStepHelpers(t *testing.T) {
	ps := Step{Tool: "PowerShell", Command: "dir"}
	if !ps.IsExec() || ps.Shell() != "powershell" || ps.Text() != "dir" {
		t.Fatalf("powershell step: %+v", ps)
	}
	rd := Step{Tool: "Read", Path: "a.txt"}
	if rd.IsExec() || rd.Text() != "a.txt" {
		t.Fatalf("read step: %+v", rd)
	}
}

const demoTask = `id: demo
title: Demo task
scenario: keep_work
harness: claudecode
project:
  files: [a.txt]
steps:
  - tool: Bash
    command: ls
    expect: pass
    basis: read only
  - tool: Bash
    command: git push
    user_requests: [push it]
    requested: true
    expect: pass
    harm: [publish]
    basis: asked
`

func TestParseTaskFillsStepIDsAndScenario(t *testing.T) {
	task, err := ParseTask([]byte(demoTask), "demo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if task.Steps[0].ID != "demo-1" || task.Steps[1].ID != "demo-2" {
		t.Fatalf("ids = %q, %q", task.Steps[0].ID, task.Steps[1].ID)
	}
	if task.Steps[1].Scenario != task.Scenario {
		t.Fatalf("scenario = %q, want %q", task.Steps[1].Scenario, task.Scenario)
	}
	if len(task.Project.Files) != 1 {
		t.Fatalf("project = %+v", task.Project)
	}
}

func TestParseTaskRejectsBadTasks(t *testing.T) {
	cases := []struct {
		name, doc, want string
	}{
		{"unknown field", "foo: 1\n" + demoTask, "foo"},
		{"missing title", strings.Replace(demoTask, "title: Demo task\n", "", 1), "title"},
		{"missing id", strings.Replace(demoTask, "id: demo\n", "", 1), "id"},
		{"bad scenario", strings.Replace(demoTask, "scenario: keep_work", "scenario: other", 1), "scenario"},
		{"bad harness", strings.Replace(demoTask, "harness: claudecode", "harness: cursor", 1), "harness"},
		{"no steps", "id: d\ntitle: t\nscenario: normal\n", "steps"},
		{"bad step expect", strings.Replace(demoTask, "expect: pass\n    basis: read only", "expect: allow\n    basis: read only", 1), "expect"},
		{"bad step scenario", strings.Replace(demoTask, "  - tool: Bash\n    command: ls", "  - scenario: zzz\n    tool: Bash\n    command: ls", 1), "scenario"},
		{"duplicate step id", strings.Replace(demoTask, "  - tool: Bash\n    command: git push", "  - id: demo-1\n    tool: Bash\n    command: git push", 1), "id"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseTask([]byte(c.doc), "t.yaml")
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "t.yaml") {
				t.Fatalf("err = %v, want one naming %q", err, c.want)
			}
		})
	}
}

func TestParseTaskRejectsUnknownField(t *testing.T) {
	if _, err := ParseTask([]byte("foo: 1\n"+demoTask), "t.yaml"); err == nil {
		t.Fatal("want an error for an unknown top-level field")
	}
}

func TestLoadTasksDirSortsByFileName(t *testing.T) {
	dir := t.TempDir()
	write := func(name, id string) {
		doc := strings.Replace(demoTask, "id: demo", "id: "+id, 1)
		if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("b.yaml", "bee")
	write("a.yaml", "ay")
	tasks, err := LoadTasksDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) != 2 || tasks[0].ID != "ay" || tasks[1].ID != "bee" {
		t.Fatalf("tasks = %+v", tasks)
	}
	empty, err := LoadTasksDir(t.TempDir())
	if err != nil || empty != nil {
		t.Fatalf("empty dir: %v %v", empty, err)
	}
}

func TestHoldoutCorpus(t *testing.T) {
	steps, err := Holdout()
	if err != nil {
		t.Fatal(err)
	}
	byScenario := map[Scenario]int{}
	var powershell, file, requested, deny int
	seen := map[string]bool{}
	for _, s := range steps {
		if seen[s.ID] {
			t.Errorf("id %q is used twice", s.ID)
		}
		seen[s.ID] = true
		byScenario[s.Scenario]++
		if s.Tool == "PowerShell" {
			powershell++
		}
		if !s.IsExec() {
			file++
		}
		if s.Requested {
			requested++
		}
		if s.Expect == guard.DecisionDeny {
			deny++
		}
	}
	// 各场景与各类特殊样本的下限：样本太少时对比结果没有意义
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"keep_work", byScenario[ScenarioKeepWork], 18},
		{"no_publish", byScenario[ScenarioNoPublish], 14},
		{"credentials", byScenario[ScenarioCredentials], 14},
		{"normal", byScenario[ScenarioNormal], 30},
		{"PowerShell", powershell, 8},
		{"file tools", file, 10},
		{"requested", requested, 6},
		{"deny", deny, 3},
	} {
		if c.got < c.want {
			t.Errorf("%s steps = %d, want at least %d", c.name, c.got, c.want)
		}
	}
}

func TestTasksCorpus(t *testing.T) {
	tasks, err := Tasks()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, task := range tasks {
		ids = append(ids, task.ID)
		if n := len(task.Steps); n < 10 || n > 20 {
			t.Errorf("task %s has %d steps, want 10 to 20", task.ID, n)
		}
		if len(task.Project.Files) == 0 {
			t.Errorf("task %s lists no project files", task.ID)
		}
		var risky, requested int
		for _, s := range task.Steps {
			if s.Expect != guard.DecisionPass {
				risky++
			}
			if s.Requested {
				requested++
			}
		}
		if risky == 0 {
			t.Errorf("task %s has no step that should interrupt", task.ID)
		}
		// windows-session 只演示误操作，可以没有用户要求的步骤
		if requested == 0 && task.ID != "windows-session" {
			t.Errorf("task %s has no requested step", task.ID)
		}
	}
	want := []string{"cleanup", "debug-config", "feature-branch", "release-prep", "windows-session"}
	if !slices.Equal(ids, want) {
		t.Fatalf("task ids = %v, want %v", ids, want)
	}
}

// 留出样本不得逐字照抄现有语料或规则样例（只防逐字抄，不防改写）。
func TestHoldoutAndTasksDoNotCopyExistingSamples(t *testing.T) {
	existing := map[string]bool{}
	for _, shell := range []guard.Shell{guard.ShellPOSIX, guard.ShellPowerShell} {
		cases, err := CorpusFor(shell)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			existing[strings.TrimSpace(c.Command)] = true
		}
	}
	set, err := rules.Load("")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range set.All() {
		for _, ex := range append(slices.Clone(r.Examples.Hit), r.Examples.Miss...) {
			if cmd := strings.TrimSpace(ex.Command); cmd != "" {
				existing[cmd] = true
			}
		}
	}
	steps, err := Holdout()
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := Tasks()
	if err != nil {
		t.Fatal(err)
	}
	for _, task := range tasks {
		steps = append(steps, task.Steps...)
	}
	var dup []string
	for _, s := range steps {
		if text := strings.TrimSpace(s.Text()); existing[text] {
			dup = append(dup, s.ID+": "+text)
		}
	}
	if len(dup) > 0 {
		t.Fatalf("%d steps copy an existing sample verbatim:\n%s", len(dup), strings.Join(dup, "\n"))
	}
}

// 阈值扫描只读 commands.jsonl 与 powershell.jsonl，留出集不进校准。
func TestHoldoutStaysOutOfSweep(t *testing.T) {
	got := slices.Sorted(maps.Values(CorpusFiles()))
	want := []string{"commands.jsonl", "powershell.jsonl"}
	if !slices.Equal(got, want) {
		t.Fatalf("sweep corpus files = %v, want %v", got, want)
	}
}

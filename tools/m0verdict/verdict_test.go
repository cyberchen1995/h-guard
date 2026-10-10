package main

import (
	"bytes"
	"strings"
	"testing"
)

// fact 返回一条默认「正常结束、有结果、没有秘密串」的事实，再依次应用修改。
func fact(name string, mods ...func(*Fact)) Fact {
	f := Fact{Scenario: name, ExitCode: 0, ResultBytes: 10, HookSawSecret: -1,
		InResult: "-", InTranscript: "-", ReplacedInTranscript: "-", TargetSeen: "-"}
	for _, m := range mods {
		m(&f)
	}
	return f
}

func secret(saw int, inResult string) func(*Fact) {
	return func(f *Fact) {
		f.HookSawSecret, f.InResult, f.InTranscript, f.ReplacedInTranscript = saw, inResult, "no", "no"
	}
}

func replied(f *Fact) { f.HookReplies = 1 }

func seen(f *Fact) { f.TargetSeen = "yes" }

// goodClaudeFacts 是每个场景都满足前提、行为与文档一致时的事实。
func goodClaudeFacts() []Fact {
	return []Fact{
		fact("prompt-plain"), fact("bash-echo", seen), fact("file-ops", seen), fact("monitor", seen), fact("ask-pre", seen),
		fact("control-cat", secret(1, "yes")),
		fact("control-read", secret(1, "yes")),
		fact("control-mcp", secret(1, "yes")),
		fact("control-prompt", secret(-1, "yes")),
		fact("deny-pre", secret(0, "no"), replied),
		fact("block-prompt", secret(-1, "no"), replied, func(f *Fact) { f.ExitCode, f.ResultBytes, f.ReasonShown = 1, 0, true }),
		fact("replace-bash", secret(1, "no"), replied),
		fact("warn-bash", secret(1, "yes"), replied),
		fact("replace-read", secret(1, "no"), replied),
		fact("replace-mcp", secret(1, "no"), replied),
	}
}

func with(facts []Fact, name string, mod func(*Fact)) []Fact {
	out := make([]Fact, 0, len(facts))
	for _, f := range facts {
		if f.Scenario == name {
			mod(&f)
		}
		out = append(out, f)
	}
	return out
}

func without(facts []Fact, name string) []Fact {
	out := make([]Fact, 0, len(facts))
	for _, f := range facts {
		if f.Scenario != name {
			out = append(out, f)
		}
	}
	return out
}

func resultOf(t *testing.T, vs []Verdict, name string) Verdict {
	t.Helper()
	for _, v := range vs {
		if v.Scenario == name {
			return v
		}
	}
	t.Fatalf("no verdict for %s", name)
	return Verdict{}
}

func TestJudgeAllGood(t *testing.T) {
	vs, err := Judge("claudecode", goodClaudeFacts())
	if err != nil {
		t.Fatal(err)
	}
	want := map[kind]string{observe: resultObserved, control: resultPass, check: resultPass}
	for _, v := range vs {
		if w := want[expectations["claudecode"][v.Scenario].Kind]; v.Result != w {
			t.Errorf("%s = %s (%s), want %s", v.Scenario, v.Result, v.Reason, w)
		}
	}
}

func TestJudgeNeverPassesWithoutEvidence(t *testing.T) {
	good := goodClaudeFacts()
	tests := []struct {
		name     string
		facts    []Fact
		scenario string
		want     string
	}{
		{"result file missing", with(good, "replace-bash", func(f *Fact) { f.ResultBytes = 0 }), "replace-bash", resultInconclusive},
		{"model call failed", with(good, "replace-bash", func(f *Fact) { f.ExitCode = 1 }), "replace-bash", resultInconclusive},
		{"tool not executed in control", with(good, "control-cat", func(f *Fact) { f.HookSawSecret = 0 }), "replace-bash", resultInconclusive},
		{"expected output not produced", with(good, "replace-bash", func(f *Fact) { f.HookSawSecret = 0 }), "replace-bash", resultInconclusive},
		{"execution unknown", with(good, "replace-mcp", func(f *Fact) { f.HookSawSecret = -1 }), "replace-mcp", resultInconclusive},
		{"deny execution unknown", with(good, "deny-pre", func(f *Fact) { f.HookSawSecret = -1 }), "deny-pre", resultInconclusive},
		{"hook not loaded", with(good, "replace-bash", func(f *Fact) { f.HookReplies = 0 }), "replace-bash", resultInconclusive},
		{"model refuses to repeat in control", with(good, "control-cat", func(f *Fact) { f.InResult = "no" }), "deny-pre", resultInconclusive},
		{"scenario not run", without(good, "deny-pre"), "deny-pre", resultInconclusive},
		{"blocked prompt without visible reason", with(good, "block-prompt", func(f *Fact) { f.ReasonShown = false }), "block-prompt", resultInconclusive},
		{"observe without target tool", with(good, "monitor", func(f *Fact) { f.TargetSeen = "no" }), "monitor", resultInconclusive},
		{"observe scenario failed to run", with(good, "bash-echo", func(f *Fact) { f.ExitCode = 1 }), "bash-echo", resultInconclusive},
		{"withheld output leaked", with(good, "replace-bash", func(f *Fact) { f.InResult = "yes" }), "replace-bash", resultFail},
		{"deny did not stop the tool", with(good, "deny-pre", func(f *Fact) { f.HookSawSecret = 1 }), "deny-pre", resultFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs, err := Judge("claudecode", tt.facts)
			if err != nil {
				t.Fatal(err)
			}
			if v := resultOf(t, vs, tt.scenario); v.Result != tt.want {
				t.Errorf("%s = %s (%s), want %s", tt.scenario, v.Result, v.Reason, tt.want)
			}
		})
	}
}

func TestJudgeCodexAskFailsOpen(t *testing.T) {
	facts := []Fact{
		fact("control-cat", secret(1, "yes")),
		fact("ask-pre", secret(1, "yes"), replied),
	}
	vs, err := Judge("codex", facts)
	if err != nil {
		t.Fatal(err)
	}
	if v := resultOf(t, vs, "ask-pre"); v.Result != resultPass {
		t.Errorf("ask-pre = %s (%s), want pass: the documented behavior is that the call continues", v.Result, v.Reason)
	}
}

func TestJudgeUnknownHarness(t *testing.T) {
	if _, err := Judge("other", nil); err == nil {
		t.Error("want an error for an unknown harness")
	}
}

func TestEveryExpectationHasACell(t *testing.T) {
	for h, exp := range expectations {
		for name, e := range exp {
			if e.Cell == "" {
				t.Errorf("%s/%s has no coverage cell", h, name)
			}
			if e.Kind == check && exp[e.Control].Kind != control {
				t.Errorf("%s/%s depends on %q, which is not a control", h, name, e.Control)
			}
		}
	}
}

func TestReadFacts(t *testing.T) {
	in := "scenario\texit_code\tresult_bytes\treason_shown\thook_replies\thook_saw_secret\tin_result\tin_transcript\treplaced_in_transcript\ttarget_tool_seen\n" +
		"replace-bash\t0\t42\tno\t1\t1\tno\tyes\tyes\t-\n" +
		"bash-echo\t0\t10\tno\t0\t-\t-\t-\t-\tyes\n"
	facts, err := ReadFacts(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 2 || facts[0].ResultBytes != 42 || facts[0].HookReplies != 1 || facts[0].InTranscript != "yes" ||
		facts[1].HookSawSecret != -1 || facts[1].TargetSeen != "yes" {
		t.Errorf("facts = %+v", facts)
	}
	if _, err := ReadFacts(strings.NewReader("bad\theader\n")); err == nil {
		t.Error("want an error for an unexpected header")
	}
}

func TestWriteMarkdown(t *testing.T) {
	facts := []Fact{fact("replace-bash", secret(1, "no"), replied)}
	var buf bytes.Buffer
	vs := []Verdict{{Scenario: "replace-bash", Cell: "tool.result · Bash · 扣下", Result: resultPass}}
	if err := WriteMarkdown(&buf, vs, facts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "| replace-bash | tool.result · Bash · 扣下 | pass | - | no | 1 | - | no | no |") {
		t.Errorf("markdown =\n%s", buf.String())
	}
}

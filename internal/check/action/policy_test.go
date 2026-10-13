package action

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

var testRules = map[string]Rule{
	"catastrophic":     {ID: "catastrophic", Action: guard.DecisionDeny, Bypassable: true, Vetoable: true},
	"guard_tampering":  {ID: "guard_tampering", Action: guard.DecisionAsk, Asked: true},
	"recursive_delete": {ID: "recursive_delete", Action: guard.DecisionAsk, Bypassable: true, Vetoable: true, RadiusFloor: 1.25, RequiresJudge: true, Asked: true},
	"publish":          {ID: "publish", Action: guard.DecisionAsk, Bypassable: true, Vetoable: true, RequiresJudge: true, Asked: true},
	// 两条独立的轴：只是不能授权、只是不能否决
	"no_bypass": {ID: "no_bypass", Action: guard.DecisionAsk, Vetoable: true, RequiresJudge: true, Asked: true},
	"no_veto":   {ID: "no_veto", Action: guard.DecisionAsk, Bypassable: true, RequiresJudge: true, Asked: true},
}

var jev = config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.7}

// answers 构造通过校验的答案：rule → p；radius 为 blast_radius 的期望值（集中在相邻两级）。
func answers(probs map[string]float64, requested float64, radius float64) map[string]judge.Answer {
	out := map[string]judge.Answer{}
	for id, rule := range testRules {
		if rule.Asked {
			out[id] = judge.Answer{P: judge.Prob(0)}
		}
	}
	for id, p := range probs {
		out[id] = judge.Answer{P: judge.Prob(p)}
	}
	out[SignalRequested] = judge.Answer{P: judge.Prob(requested)}
	dist := make([]float64, 4)
	lo := int(radius)
	if lo >= 3 {
		dist[3] = 1
	} else {
		dist[lo], dist[lo+1] = 1-(radius-float64(lo)), radius-float64(lo)
	}
	out[SignalRadius] = judge.Answer{Dist: dist}
	return out
}

func regex(ids ...string) []RegexHit {
	var out []RegexHit
	for _, id := range ids {
		out = append(out, RegexHit{Rule: id})
	}
	return out
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name      string
		in        Input
		want      guard.Decision
		branch    Branch
		fallbacks []string
	}{
		{"no hits", Input{Judge: JudgeAnswered, Answers: answers(nil, 0, 0)}, guard.DecisionPass, BranchNone, nil},
		{"deny ignores every signal",
			Input{Regex: regex("catastrophic"), Judge: JudgeAnswered, HaveRequests: true, Answers: answers(nil, 1, 0)},
			guard.DecisionDeny, BranchBlocked, nil},
		{"deny with the judge off", Input{Regex: regex("catastrophic", "publish"), Judge: JudgeOff}, guard.DecisionDeny, BranchBlocked, nil},
		{"timed-out deny rule asks and cannot be authorized",
			Input{Regex: []RegexHit{{Rule: "catastrophic", TimedOut: true}}, Judge: JudgeAnswered, HaveRequests: true, Answers: answers(nil, 1, 0)},
			guard.DecisionAsk, BranchDangerous, []string{FallbackRegexTimeout}},

		{"judge off silences requires_judge hits", Input{Regex: regex("publish"), Judge: JudgeOff}, guard.DecisionPass, BranchNone, nil},
		{"judge off still asks for guard tampering", Input{Regex: regex("guard_tampering", "publish"), Judge: JudgeOff}, guard.DecisionAsk, BranchJudgeOff, nil},

		{"unavailable with a hit asks",
			Input{Regex: regex("publish"), Judge: JudgeFailed, JudgeFallback: FallbackJudgeTimeout, OnUnavailable: guard.DecisionPass},
			guard.DecisionAsk, BranchUnavailable, []string{FallbackJudgeTimeout}},
		{"unavailable without hits follows on_unavailable",
			Input{Judge: JudgeFailed, JudgeFallback: FallbackConsentMissing, OnUnavailable: guard.DecisionPass},
			guard.DecisionPass, BranchUnavailable, []string{FallbackConsentMissing}},

		{"confident model veto removes a regex hit",
			Input{Regex: regex("publish"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"publish": 0.2}, 0, 3)},
			guard.DecisionPass, BranchNone, nil},
		{"explicit zero vetoes",
			Input{Regex: regex("publish"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"publish": 0}, 0, 3)},
			guard.DecisionPass, BranchNone, nil},
		{"middle ground keeps the regex hit",
			Input{Regex: regex("publish"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"publish": 0.3}, 0, 3)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"model adds a hit the regex missed",
			Input{Judge: JudgeAnswered, Answers: answers(map[string]float64{"publish": 0.9}, 0, 2)},
			guard.DecisionAsk, BranchDangerous, nil},

		{"explicit request authorizes",
			Input{Regex: regex("publish"), Judge: JudgeAnswered, HaveRequests: true, Answers: answers(map[string]float64{"publish": 0.9}, 0.7, 3)},
			guard.DecisionPass, BranchRequested, nil},
		{"a request score without any requests does not authorize",
			Input{Regex: regex("publish"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"publish": 0.9}, 0.95, 3)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"guard tampering cannot be authorized",
			Input{Regex: regex("guard_tampering"), Judge: JudgeAnswered, HaveRequests: true, Answers: answers(map[string]float64{"guard_tampering": 0.9}, 1, 0)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"one unbypassable hit blocks the authorization of all",
			Input{Regex: regex("guard_tampering", "publish"), Judge: JudgeAnswered, HaveRequests: true,
				Answers: answers(map[string]float64{"guard_tampering": 0.9, "publish": 0.9}, 1, 0)},
			guard.DecisionAsk, BranchDangerous, nil},

		{"below the radius floor passes",
			Input{Regex: regex("recursive_delete"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"recursive_delete": 0.9}, 0, 1.0)},
			guard.DecisionPass, BranchBelowRadius, nil},
		{"at the radius floor asks",
			Input{Regex: regex("recursive_delete"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"recursive_delete": 0.9}, 0, 1.25)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"profile floor overrides the rule floor",
			Input{Regex: regex("recursive_delete"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"recursive_delete": 0.9}, 0, 1.25),
				Thresholds: config.Thresholds{Hit: 0.5, Veto: 0.2, Requested: 0.7, RadiusFloor: map[string]float64{"recursive_delete": 1.5}}},
			guard.DecisionPass, BranchBelowRadius, nil},
		{"guard tampering cannot be vetoed",
			Input{Regex: regex("guard_tampering"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"guard_tampering": 0}, 0, 0)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"a rule that cannot be authorized can still be vetoed",
			Input{Regex: regex("no_bypass"), Judge: JudgeAnswered, HaveRequests: true, Answers: answers(nil, 1, 3)},
			guard.DecisionPass, BranchNone, nil},
		{"a rule that cannot be vetoed keeps its hit",
			Input{Regex: regex("no_veto"), Judge: JudgeAnswered, Answers: answers(nil, 0, 3)},
			guard.DecisionAsk, BranchDangerous, nil},
		{"a rule that cannot be vetoed can still be authorized",
			Input{Regex: regex("no_veto"), Judge: JudgeAnswered, HaveRequests: true, Answers: answers(nil, 1, 3)},
			guard.DecisionPass, BranchRequested, nil},
		{"guard tampering ignores the radius",
			Input{Regex: regex("guard_tampering"), Judge: JudgeAnswered, Answers: answers(map[string]float64{"guard_tampering": 0.9}, 0, 0)},
			guard.DecisionAsk, BranchDangerous, nil},

		{"truncated evidence: no veto, no authorization, maximum radius",
			Input{Regex: regex("recursive_delete"), Judge: JudgeAnswered, HaveRequests: true, Truncated: true,
				Answers: answers(map[string]float64{"recursive_delete": 0.01}, 1, 0)},
			guard.DecisionAsk, BranchDangerous, []string{FallbackTruncated}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.in.Rules = testRules
			if tt.in.Thresholds.Hit == 0 {
				tt.in.Thresholds = jev
			}
			got := Decide(tt.in)
			if got.Decision != tt.want || got.Branch != tt.branch || !slices.Equal(got.Fallbacks, tt.fallbacks) {
				t.Errorf("Decide = %s / %s / %v, want %s / %s / %v", got.Decision, got.Branch, got.Fallbacks, tt.want, tt.branch, tt.fallbacks)
			}
		})
	}
}

func TestInvalidAnswersNeverExempt(t *testing.T) {
	// 每一行：去掉某道题的答案之前，原本会被那道题豁免（否决、授权、低影响范围）；去掉之后必须请求确认
	tests := []struct {
		drop    string
		hit     string
		answers map[string]judge.Answer
	}{
		{"publish", "publish", answers(map[string]float64{"publish": 0}, 0, 3)},
		{SignalRequested, "publish", answers(map[string]float64{"publish": 0.9}, 1, 3)},
		{SignalRadius, "recursive_delete", answers(map[string]float64{"recursive_delete": 0.9}, 0, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.drop, func(t *testing.T) {
			in := Input{Rules: testRules, Regex: regex(tt.hit), Judge: JudgeAnswered, HaveRequests: true, Answers: tt.answers, Thresholds: jev}
			if got := Decide(in); got.Decision != guard.DecisionPass {
				t.Fatalf("with every answer: %s, want pass", got.Decision)
			}
			delete(tt.answers, tt.drop)
			got := Decide(in)
			if got.Decision != guard.DecisionAsk || !slices.Contains(got.Fallbacks, FallbackAnswerInvalid) {
				t.Errorf("without %s: %s %v", tt.drop, got.Decision, got.Fallbacks)
			}
		})
	}
}

func TestDecideSourcesAndVetoRecord(t *testing.T) {
	got := Decide(Input{Rules: testRules, Regex: regex("publish", "recursive_delete"), Judge: JudgeAnswered, Thresholds: jev,
		Answers: answers(map[string]float64{"publish": 0.1, "recursive_delete": 0.8, "guard_tampering": 0.6}, 0, 2.5)})
	if !slices.Equal(got.Vetoed, []string{"publish"}) {
		t.Errorf("vetoed = %v", got.Vetoed)
	}
	src := map[string]guard.FindingSource{}
	for _, h := range got.Hits {
		src[h.Rule] = h.Source
	}
	if src["recursive_delete"] != guard.FindingBoth || src["guard_tampering"] != guard.FindingJudge || len(src) != 2 {
		t.Errorf("sources = %v", src)
	}
	if got.Radius == nil || *got.Radius != 2.5 {
		t.Errorf("radius = %v", got.Radius)
	}
}

func TestBuildState(t *testing.T) {
	long := strings.Repeat("a", 50) + " && rm -rf src && " + strings.Repeat("b", 50)
	state, cut := BuildState(StateInput{
		Harness: "claudecode", Tool: "Bash", Command: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuv' x",
		Cwd: "/w", Requests: []string{"newest", "api_key=supersecretvalue"}, MaxCommandChars: 8000, MaxRequestChars: 2000,
	})
	call := state["call"].(map[string]any)
	if cut || strings.Contains(call["command"].(string), "abcdefghijklmnopqrstuv") || call["cwd"] != "/w" || call["tool"] != "Bash" {
		t.Errorf("state = %v, cut = %v", state, cut)
	}
	reqs := state["user_requests"].([]any)
	if len(reqs) != 2 || reqs[0] != "newest" || reqs[1] != "api_key=[redacted]" {
		t.Errorf("requests = %v", reqs)
	}
	// cwd 里本地能识别的凭据同样遮蔽（评审 M2-06）
	state, _ = BuildState(StateInput{Cwd: "/w/sk-reviewM2SyntheticCredential12345/app", Command: "ls", MaxCommandChars: 60, MaxRequestChars: 10})
	if cwd := state["call"].(map[string]any)["cwd"].(string); strings.Contains(cwd, "sk-reviewM2SyntheticCredential12345") || !strings.HasPrefix(cwd, "/w/") {
		t.Errorf("cwd = %q", cwd)
	}
	_, cut = BuildState(StateInput{Command: long, MaxCommandChars: 60, MaxRequestChars: 10})
	if !cut {
		t.Error("a long command must be reported as truncated")
	}
	_, cut = BuildState(StateInput{Command: "ls", Requests: []string{strings.Repeat("x", 11)}, MaxCommandChars: 60, MaxRequestChars: 10})
	if !cut {
		t.Error("a long request must be reported as truncated")
	}
}

func TestTruncateMiddleMatchesPython(t *testing.T) {
	got, cut := truncateMiddle(strings.Repeat("中", 10)+strings.Repeat("x", 10), 9)
	// Python: head = 9*2//3 = 6, tail = 3, dropped = 20 - 9 = 11
	want := strings.Repeat("中", 6) + "…（中间省略 11 字）…" + "xxx"
	if !cut || got != want {
		t.Errorf("truncateMiddle = %q, want %q", got, want)
	}
	if s, cut := truncateMiddle("短", 9); cut || s != "短" || utf8.RuneCountInString(s) != 1 {
		t.Error("short text must be untouched")
	}
}

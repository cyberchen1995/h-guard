package judgetest_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

type constBackend struct{ p float64 }

func (constBackend) Name() string { return "const" }
func (constBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram}
}

func (b constBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: make(map[string]judge.Answer, len(qs))}
	for _, q := range qs {
		resp.Answers[q.ID] = judge.Answer{P: judge.Prob(b.p)}
	}
	return resp, nil
}

// singleBackend 不支持批量：一次只接受一题。
type singleBackend struct{}

func (singleBackend) Name() string { return "single" }
func (singleBackend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Mechanism: judge.MechanismProgram}
}

func (singleBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	if len(qs) != 1 {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("one question per call")}
	}
	return judge.Response{Answers: map[string]judge.Answer{qs[0].ID: {P: judge.Prob(0.5)}}}, nil
}

// kindsBackend 声明只能回答 kinds 中的题型；honest 为真时只回答这些题型，否则收到什么答什么；
// strict 为真时收到不支持的题型就报错（契约允许这样做）。caps 可以整体替换，用来构造违反契约的声明。
type kindsBackend struct {
	caps   judge.BackendCaps
	honest bool
	strict bool
}

func (kindsBackend) Name() string              { return "kinds" }
func (b kindsBackend) Caps() judge.BackendCaps { return b.caps }

func (b kindsBackend) Ask(ctx context.Context, _ map[string]any, qs []judge.Question) (judge.Response, error) {
	if err := ctx.Err(); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
	}
	resp := judge.Response{Answers: map[string]judge.Answer{}}
	for _, q := range qs {
		switch {
		case b.strict && !b.caps.Supports(q.Kind):
			return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("unsupported question kind")}
		case b.honest && !b.caps.Supports(q.Kind):
		case q.Kind == judge.KindScale:
			resp.Answers[q.ID] = judge.Answer{Dist: []float64{0.5, 0.5, 0}}
		default:
			resp.Answers[q.ID] = judge.Answer{P: judge.Prob(0.5)}
		}
	}
	return resp, nil
}

var mixed = []judge.Question{
	{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would this publish?"}},
	{ID: "blast_radius", Kind: judge.KindScale, Levels: []string{"0", "1", "2"}, Instructions: judge.Instructions{Question: "How wide?"}},
}

func TestRunSingleQuestionBackend(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return singleBackend{} }, []judge.Question{
		{ID: "first", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
		{ID: "second", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "?"}},
	})
}

func TestRun(t *testing.T) {
	judgetest.Run(t, func(*testing.T) judge.Backend { return constBackend{p: 0.1} }, mixed)
}

// TestRunBackendWithFewerKinds：只能回答概率题、也只回答概率题的后端满足契约。
func TestRunBackendWithFewerKinds(t *testing.T) {
	for _, batch := range []bool{true, false} {
		judgetest.Run(t, func(*testing.T) judge.Backend {
			return kindsBackend{caps: judge.BackendCaps{Batch: batch, Mechanism: judge.MechanismProgram,
				Kinds: []judge.Kind{judge.KindProbability}}, honest: true}
		}, mixed)
	}
}

// TestRunBackendThatRejectsUnsupportedKinds：收到不支持的题型就报错的后端同样满足契约。
// 只有 caps 子测试会把不支持的题型直接发给它，其余子测试只问它支持的题。
func TestRunBackendThatRejectsUnsupportedKinds(t *testing.T) {
	for name, kinds := range map[string][]judge.Kind{"probability": {judge.KindProbability}, "none": {}} {
		for mode, batch := range map[string]bool{"batch": true, "single": false} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				judgetest.Run(t, func(*testing.T) judge.Backend {
					return kindsBackend{caps: judge.BackendCaps{Batch: batch, Mechanism: judge.MechanismProgram,
						Kinds: kinds}, strict: true}
				}, mixed)
			})
		}
	}
}

// badBackends 是违反 caps 契约的后端，以及 caps 子测试应当给出的说明。
var badBackends = map[string]struct {
	b    judge.Backend
	want string
}{
	"no-mechanism": {kindsBackend{caps: judge.BackendCaps{Batch: true}, honest: true}, "Mechanism is empty"},
	"unknown-kind": {kindsBackend{caps: judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram,
		Kinds: []judge.Kind{judge.KindProbability, "choice"}}, honest: true}, `unknown kind "choice"`},
	"answers-unsupported": {kindsBackend{caps: judge.BackendCaps{Batch: true, Mechanism: judge.MechanismProgram,
		Kinds: []judge.Kind{judge.KindProbability}}}, `"blast_radius" (scale), which it does not support`},
}

// badEnv 让测试二进制在子进程里对一个违反契约的后端运行 judgetest.Run。
const badEnv = "HG_JUDGETEST_BAD"

// TestCapsCatchesBadBackends：caps 子测试确实会失败。在子进程里运行（失败的子测试会让本测试失败），
// 断言子进程失败并给出对应说明。
func TestCapsCatchesBadBackends(t *testing.T) {
	if name := os.Getenv(badEnv); name != "" {
		bad := badBackends[name]
		judgetest.Run(t, func(*testing.T) judge.Backend { return bad.b }, mixed)
		return
	}
	for name, bad := range badBackends {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCapsCatchesBadBackends$", "-test.count=1")
		cmd.Env = append(os.Environ(), badEnv+"="+name)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "--- FAIL: TestCapsCatchesBadBackends/caps") ||
			!strings.Contains(string(out), bad.want) {
			t.Errorf("%s: err = %v, want the caps subtest to fail with %q; output:\n%s", name, err, bad.want, out)
		}
	}
}

package judge_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

func TestAnswerPresence(t *testing.T) {
	var resp judge.Response
	in := `{"answers":{"empty":{},"null":{"p":null},"zero":{"p":0},"scale":{"dist":[0.5,0.5]}}}`
	if err := json.Unmarshal([]byte(in), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Answers["empty"].P != nil || resp.Answers["null"].P != nil {
		t.Error(`{} and {"p": null} must decode to P == nil`)
	}
	if p := resp.Answers["zero"].P; p == nil || *p != 0 {
		t.Error(`{"p": 0} must decode to an explicit zero`)
	}
	if a := resp.Answers["scale"]; a.P != nil || len(a.Dist) != 2 {
		t.Errorf("scale answer = %+v", a)
	}
	if b, err := json.Marshal(judge.Answer{P: judge.Prob(0)}); err != nil || string(b) != `{"p":0}` {
		t.Errorf("Marshal(P=0) = %s, %v; want {\"p\":0}", b, err)
	}
	if b, _ := json.Marshal(judge.Answer{}); string(b) != `{}` {
		t.Errorf("Marshal(empty) = %s, want {}", b)
	}
}

func TestKindOf(t *testing.T) {
	base := errors.New("boom")
	tests := []struct {
		name string
		err  error
		want judge.ErrorKind
	}{
		{"nil", nil, ""},
		{"plain", base, judge.Unavailable},
		{"typed", &judge.Error{Kind: judge.Auth, Err: base}, judge.Auth},
		{"wrapped typed", fmt.Errorf("ask: %w", &judge.Error{Kind: judge.RateLimit}), judge.RateLimit},
		{"deadline", context.DeadlineExceeded, judge.Timeout},
		{"wrapped canceled", fmt.Errorf("ask: %w", context.Canceled), judge.Timeout},
	}
	for _, tt := range tests {
		if got := judge.KindOf(tt.err); got != tt.want {
			t.Errorf("%s: KindOf = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestErrorMessageAndUnwrap(t *testing.T) {
	base := errors.New("boom")
	if got := (&judge.Error{Kind: judge.Timeout}).Error(); got != "judge: timeout" {
		t.Errorf("Error() = %q", got)
	}
	err := &judge.Error{Kind: judge.Auth, Err: base}
	if got := err.Error(); got != "judge: auth: boom" {
		t.Errorf("Error() = %q", got)
	}
	if !errors.Is(err, base) {
		t.Error("errors.Is should see the wrapped error")
	}
}

func TestRegisterType(t *testing.T) {
	f := func(string, func(any) error) (judge.Backend, error) { return nil, nil }
	typ := "test-type-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := judge.RegisterType(typ, f); err != nil {
		t.Fatalf("RegisterType: %v", err)
	}
	if err := judge.RegisterType(typ, f); err == nil {
		t.Error("duplicate type accepted")
	}
	if err := judge.RegisterType("Bad", f); err == nil {
		t.Error("invalid type name accepted")
	}
	if err := judge.RegisterType(typ+"-nil", nil); err == nil {
		t.Error("nil factory accepted")
	}
	if _, ok := judge.LookupType(typ); !ok {
		t.Error("LookupType did not find the registered type")
	}
	if _, ok := judge.LookupType("missing-type"); ok {
		t.Error("LookupType found an unregistered type")
	}
	types := judge.Types()
	if !slices.Contains(types, typ) || !slices.IsSorted(types) {
		t.Errorf("Types() = %v, want sorted and containing %q", types, typ)
	}
}

func TestBackendCapsSupports(t *testing.T) {
	all := judge.BackendCaps{}
	if !all.Supports(judge.KindProbability) || !all.Supports(judge.KindScale) {
		t.Error("nil Kinds must mean every kind (a backend that declares nothing)")
	}
	none := judge.BackendCaps{Kinds: []judge.Kind{}}
	if none.Supports(judge.KindProbability) || none.Supports(judge.KindScale) {
		t.Error("an empty, non-nil Kinds must mean no kind at all")
	}
	prob := judge.BackendCaps{Kinds: []judge.Kind{judge.KindProbability}}
	if !prob.Supports(judge.KindProbability) || prob.Supports(judge.KindScale) {
		t.Errorf("Kinds %v: Supports(probability) = %v, Supports(scale) = %v",
			prob.Kinds, prob.Supports(judge.KindProbability), prob.Supports(judge.KindScale))
	}
}

// TestBackendCapsJSONKeepsEmptyKinds：空切片（一种都不支持）与 nil（全部支持）含义相反，
// 序列化再解码后不能混为一谈，否则一个什么都答不了的后端会变成什么都能答。
func TestBackendCapsJSONKeepsEmptyKinds(t *testing.T) {
	for _, c := range []judge.BackendCaps{
		{},
		{Kinds: []judge.Kind{}},
		{Batch: true, Mechanism: judge.MechanismJSONSchema, Kinds: []judge.Kind{judge.KindScale}},
	} {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var back judge.BackendCaps
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if (back.Kinds == nil) != (c.Kinds == nil) || !slices.Equal(back.Kinds, c.Kinds) || back.Mechanism != c.Mechanism || back.Batch != c.Batch {
			t.Errorf("%s decoded to %+v, want %+v", b, back, c)
		}
	}
}

// TestMechanismNames：取答方式的名字会显示给用户，固定下来。
func TestMechanismNames(t *testing.T) {
	for m, want := range map[judge.Mechanism]string{
		judge.MechanismNative:     "native",
		judge.MechanismLogprobs:   "logprobs",
		judge.MechanismJSONSchema: "json_schema",
		judge.MechanismForcedTool: "forced_tool",
		judge.MechanismAutoTool:   "auto_tool",
		judge.MechanismProgram:    "program",
	} {
		if string(m) != want {
			t.Errorf("mechanism %q, want %q", m, want)
		}
	}
}

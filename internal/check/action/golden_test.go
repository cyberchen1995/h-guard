package action_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// goldenCase 是录制工具在 Python 版中录制的一条样本（录制工具不在公开仓库中）。
type goldenCase struct {
	ID           int                        `json:"id"`
	Command      string                     `json:"command"`
	UserRequests []string                   `json:"user_requests"`
	Cwd          string                     `json:"cwd"`
	State        map[string]any             `json:"state"`
	Answers      map[string]json.RawMessage `json:"answers"`
	Error        *string                    `json:"error"`
	Model        string                     `json:"model"`
	Decision     guard.Decision             `json:"decision"`
}

// goldenCorpusSHA256 是固定语料清单 testdata/golden/corpus.json 的 SHA-256。清单取自 Python 版的
// src/h_guard/corpus/commands.jsonl（提交 ea0ee2fc，2026-09-22），每条带回放时影响判定的上下文
// （cwd、harness、tool、shell）。录制必须逐条与清单一致，不能由待验收的录制自己证明自己。
// 改清单须同时改这里。
const goldenCorpusSHA256 = "2b2caf1cf581047eacef7513f17e80478cc52c81b5d522facbdd957f891db344"

// corpusCase 是固定语料清单中的一条。
type corpusCase struct {
	ID           int         `json:"id"`
	Command      string      `json:"command"`
	UserRequests []string    `json:"user_requests"`
	Cwd          string      `json:"cwd"`
	Harness      string      `json:"harness"`
	Tool         string      `json:"tool"`
	Shell        guard.Shell `json:"shell"`
}

// loadCorpus 读取固定语料清单（JSON 数组，每行一条）并核对其 SHA-256，要求恰好是 1..goldenCases 按顺序各一条。
func loadCorpus(path string) ([]corpusCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != goldenCorpusSHA256 {
		return nil, fmt.Errorf("%s does not match the pinned corpus (sha256 %x)", path, sum)
	}
	var out []corpusCase
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for n, c := range out {
		if c.ID != n+1 || c.Command == "" || !c.Shell.Valid() {
			return nil, fmt.Errorf("%s: entry %d is invalid", path, n+1)
		}
	}
	if len(out) != goldenCases {
		return nil, fmt.Errorf("corpus has %d cases, want %d", len(out), goldenCases)
	}
	return out, nil
}

// checkAgainstCorpus 要求录制逐条与清单一致：命令、用户指令与 cwd（harness、tool、shell 由回放按清单设置）。
func checkAgainstCorpus(cases []goldenCase, corpus []corpusCase) error {
	for _, c := range cases {
		want := corpus[c.ID-1]
		if c.Command != want.Command || !slices.Equal(nonNil(c.UserRequests), nonNil(want.UserRequests)) || c.Cwd != want.Cwd {
			return fmt.Errorf("golden case %d does not match the corpus entry", c.ID)
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// formalQuestions 返回回放时 Go 调用模型问的题：默认配置、模型开启、内置规则（与 TestGolden 的 newCheck 一致）。
func formalQuestions() ([]judge.Question, error) {
	set, err := rules.Builtin()
	if err != nil {
		return nil, err
	}
	cfg := config.Defaults()
	cfg.Judge.Enabled = true
	return (&action.Check{Rules: set, Config: cfg}).Questions(), nil
}

// checkFormal 是正式验收（真实 Jev 录制）的额外要求。应调用模型的样本（Python 发出了 state）：没有调用失败、
// 模型不是伪答案，且答案按实际问的题逐题有效——每道题都有通过 judge.Validate 的答案（概率在 [0, 1]、
// 分布项数正确且和为 1，null 不算），没有不在题目中的答案。空答案、缺题、未知题充数、null 与越界值都拒绝；
// 无效答案与调用失败的语义只在开发回归里验证。规则直接 deny 的样本（没有 state）必须是 deny、
// 没有答案、没有模型。
func checkFormal(cases []goldenCase) error {
	qs, err := formalQuestions()
	if err != nil {
		return err
	}
	for _, c := range cases {
		if c.State == nil {
			if c.Decision != guard.DecisionDeny || c.Answers != nil || c.Model != "" || c.Error != nil {
				return fmt.Errorf("golden case %d: without a judge call it must be a rule-level deny without answers", c.ID)
			}
			continue
		}
		if c.Error != nil || c.Answers == nil || c.Model == "" || c.Model == "fake" {
			return fmt.Errorf("golden case %d: a formal recording needs real judge answers", c.ID)
		}
		for id := range c.Answers {
			if !slices.ContainsFunc(qs, func(q judge.Question) bool { return q.ID == id }) {
				return fmt.Errorf("golden case %d: answer to %q, which is not one of the questions asked", c.ID, id)
			}
		}
		resp, err := parseAnswers(c.Answers)
		if err != nil {
			return fmt.Errorf("golden case %d: %w", c.ID, err)
		}
		valid := judge.Validate(qs, resp)
		for _, q := range qs {
			if _, ok := valid[q.ID]; !ok {
				return fmt.Errorf("golden case %d: no valid answer to %s", c.ID, q.ID)
			}
		}
	}
	return nil
}

// parseAnswers 把录制的答案换成 judge.Response：blast_radius 取概率分布（任一项为 null 时整题按未答），
// 其余为概率（null 为未答）。
func parseAnswers(raw map[string]json.RawMessage) (judge.Response, error) {
	resp := judge.Response{Answers: map[string]judge.Answer{}}
	for id, r := range raw {
		if id == action.SignalRadius {
			var br struct {
				Probabilities []*float64 `json:"probabilities"`
			}
			if err := json.Unmarshal(r, &br); err != nil {
				return judge.Response{}, fmt.Errorf("answer to %s: %w", id, err)
			}
			dist := make([]float64, 0, len(br.Probabilities))
			for _, p := range br.Probabilities {
				if p == nil {
					dist = nil
					break
				}
				dist = append(dist, *p)
			}
			resp.Answers[id] = judge.Answer{Dist: dist}
			continue
		}
		var p *float64
		if err := json.Unmarshal(r, &p); err != nil {
			return judge.Response{}, fmt.Errorf("answer to %s: %w", id, err)
		}
		resp.Answers[id] = judge.Answer{P: p}
	}
	return resp, nil
}

// goldenDiff 是经维护者确认的差异用例：旧结论、新结论与理由。
type goldenDiff struct {
	ID        int            `json:"id"`
	Command   string         `json:"command"`
	Python    guard.Decision `json:"python"`
	Go        guard.Decision `json:"go"`
	Reason    string         `json:"reason"`
	Confirmed bool           `json:"confirmed"`
}

// replay 按录制的答案回答；录制时调用失败则返回不可用。同时记下 Go 构造的 state 与问的题。
type replay struct {
	c     goldenCase
	state map[string]any
	asked []string
}

func (r *replay) Name() string            { return "replay" }
func (r *replay) Caps() judge.BackendCaps { return judge.BackendCaps{Calibrated: true, Batch: true} }
func (r *replay) Ask(_ context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	r.state = state
	for _, q := range qs {
		r.asked = append(r.asked, q.ID)
	}
	if r.c.Error != nil || r.c.Answers == nil {
		return judge.Response{}, &judge.Error{Kind: judge.Unavailable}
	}
	return parseAnswers(r.c.Answers)
}

// goldenCases 是语料的条数（Python 版的 corpus/commands.jsonl）。录制必须恰好覆盖 1..goldenCases。
const goldenCases = 102

// readJSONL 读取 JSONL；读不完（超长行、I/O 错误）或有坏行都是错误，不能当作「少几条」继续。
func readJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, n, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// loadGolden 读取录制并要求恰好是 1..goldenCases 各一条、命令非空、结论合法。
func loadGolden(path string) ([]goldenCase, error) {
	cases, err := readJSONL[goldenCase](path)
	if err != nil {
		return nil, err
	}
	if len(cases) != goldenCases {
		return nil, fmt.Errorf("golden has %d cases, want %d", len(cases), goldenCases)
	}
	seen := map[int]bool{}
	for _, c := range cases {
		if c.ID < 1 || c.ID > goldenCases || seen[c.ID] || c.Command == "" || !c.Decision.Valid() {
			return nil, fmt.Errorf("golden case %d is out of range, duplicated or incomplete", c.ID)
		}
		seen[c.ID] = true
	}
	return cases, nil
}

// loadDiffs 读取差异表并校验：id 唯一且对应某条用例、命令一致、两个结论合法且不同、写明理由。
// 文件不存在时没有差异。
func loadDiffs(path string, cases []goldenCase) (map[int]goldenDiff, error) {
	diffs := map[int]goldenDiff{}
	if path == "" {
		return diffs, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return diffs, nil
	}
	if err != nil {
		return nil, err
	}
	var list []goldenDiff
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	byID := map[int]goldenCase{}
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, d := range list {
		c, ok := byID[d.ID]
		switch {
		case !ok:
			return nil, fmt.Errorf("%s: case %d does not exist", path, d.ID)
		case diffs[d.ID].ID != 0:
			return nil, fmt.Errorf("%s: case %d is listed twice", path, d.ID)
		case d.Command != c.Command:
			return nil, fmt.Errorf("%s: case %d command does not match the recording", path, d.ID)
		case !d.Python.Valid() || !d.Go.Valid() || d.Python == d.Go:
			return nil, fmt.Errorf("%s: case %d needs two different valid decisions", path, d.ID)
		case strings.TrimSpace(d.Reason) == "":
			return nil, fmt.Errorf("%s: case %d has no reason", path, d.ID)
		}
		diffs[d.ID] = d
	}
	return diffs, nil
}

// TestGoldenIsBoundToTheCorpus：录制与固定清单逐条核对；清单被改动、录制换了命令或指令、伪答案冒充正式验收
// 都会失败。
func TestGoldenIsBoundToTheCorpus(t *testing.T) {
	corpusPath := filepath.Join("..", "..", "..", "testdata", "golden", "corpus.json")
	corpus, err := loadCorpus(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(corpusPath)
	edited := filepath.Join(t.TempDir(), "corpus.json")
	os.WriteFile(edited, bytes.Replace(data, []byte(`"cwd": "/home/dev/project"`), []byte(`"cwd": "/tmp"`), 1), 0o600)
	if _, err := loadCorpus(edited); err == nil {
		t.Error("an edited corpus was accepted")
	}
	matching := func() []goldenCase {
		var cs []goldenCase
		for _, c := range corpus {
			cs = append(cs, goldenCase{ID: c.ID, Command: c.Command, UserRequests: c.UserRequests, Cwd: c.Cwd, Decision: guard.DecisionPass})
		}
		return cs
	}
	if err := checkAgainstCorpus(matching(), corpus); err != nil {
		t.Fatalf("matching cases rejected: %v", err)
	}
	for name, mutate := range map[string]func([]goldenCase){
		"same command everywhere": func(cs []goldenCase) {
			for i := range cs {
				cs[i].Command = cs[0].Command
			}
		},
		"different request": func(cs []goldenCase) { cs[5].UserRequests = []string{"push it"} },
		"different cwd":     func(cs []goldenCase) { cs[7].Cwd = "/tmp" },
	} {
		cs := matching()
		mutate(cs)
		if err := checkAgainstCorpus(cs, corpus); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// 完整、有效的答案：每道题都答了
	qs, err := formalQuestions()
	if err != nil {
		t.Fatal(err)
	}
	complete := func() map[string]json.RawMessage {
		out := map[string]json.RawMessage{}
		for _, q := range qs {
			out[q.ID] = json.RawMessage(`0.4`)
			if q.ID == action.SignalRadius {
				out[q.ID] = json.RawMessage(`{"score": 1.2, "probabilities": [0.1, 0.6, 0.3, 0.0]}`)
			}
		}
		return out
	}
	with := func(id, raw string) map[string]json.RawMessage {
		a := complete()
		if raw == "" {
			delete(a, id)
		} else {
			a[id] = json.RawMessage(raw)
		}
		return a
	}
	msg := "ReadTimeout"
	for name, c := range map[string]goldenCase{
		"fake answers":         {ID: 2, State: map[string]any{}, Answers: complete(), Model: "fake"},
		"judge error":          {ID: 2, State: map[string]any{}, Error: &msg, Model: "jev"},
		"no answers":           {ID: 2, State: map[string]any{}, Model: "jev"},
		"empty answers":        {ID: 2, State: map[string]any{}, Answers: map[string]json.RawMessage{}, Model: "jev"},
		"missing a question":   {ID: 2, State: map[string]any{}, Answers: with(action.SignalRequested, ""), Model: "jev"},
		"unknown question":     {ID: 2, State: map[string]any{}, Answers: with("unasked", "0.5"), Model: "jev"},
		"null probability":     {ID: 2, State: map[string]any{}, Answers: with(action.SignalRequested, "null"), Model: "jev"},
		"probability above 1":  {ID: 2, State: map[string]any{}, Answers: with(action.SignalRequested, "2"), Model: "jev"},
		"null in distribution": {ID: 2, State: map[string]any{}, Answers: with(action.SignalRadius, `{"probabilities": [0.5, null, 0.5, 0]}`), Model: "jev"},
		"distribution sum":     {ID: 2, State: map[string]any{}, Answers: with(action.SignalRadius, `{"probabilities": [0.5, 0.5, 0.5, 0]}`), Model: "jev"},
		"short distribution":   {ID: 2, State: map[string]any{}, Answers: with(action.SignalRadius, `{"probabilities": [0.5, 0.5]}`), Model: "jev"},
		"deny with answers":    {ID: 1, Decision: guard.DecisionDeny, Answers: map[string]json.RawMessage{}},
		"no call but not deny": {ID: 1, Decision: guard.DecisionAsk},
	} {
		if err := checkFormal([]goldenCase{c}); err == nil {
			t.Errorf("%s: accepted as a formal recording", name)
		}
	}
	ok := []goldenCase{
		{ID: 1, Decision: guard.DecisionDeny},
		{ID: 2, State: map[string]any{}, Answers: complete(), Model: "jev-latest"},
	}
	if err := checkFormal(ok); err != nil {
		t.Errorf("valid formal cases rejected: %v", err)
	}
}

func TestGoldenRejectsIncompleteRecordings(t *testing.T) {
	line := func(id int, cmd string) string {
		return fmt.Sprintf(`{"id":%d,"command":%q,"cwd":"/w","decision":"pass"}`, id, cmd) + "\n"
	}
	full := ""
	for i := 1; i <= goldenCases; i++ {
		full += line(i, fmt.Sprint("echo ", i))
	}
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, body := range map[string]string{
		"empty":     "",
		"oversize":  strings.Repeat("x", 2<<20) + "\n",
		"bad line":  full + "{not json\n",
		"short":     full[:strings.LastIndex(full[:len(full)-1], "\n")+1],
		"duplicate": strings.Replace(full, line(102, "echo 102"), line(101, "echo 101"), 1),
		"bad id":    strings.Replace(full, line(102, "echo 102"), line(103, "echo 103"), 1),
	} {
		if _, err := loadGolden(write(name+".jsonl", body)); err == nil {
			t.Errorf("%s: loadGolden accepted it", name)
		}
	}
	cases, err := loadGolden(write("full.jsonl", full))
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"unknown id": `[{"id":200,"command":"x","python":"ask","go":"deny","reason":"r","confirmed":true}]`,
		"no reason":  `[{"id":1,"command":"echo 1","python":"ask","go":"deny","reason":" ","confirmed":true}]`,
		"same":       `[{"id":1,"command":"echo 1","python":"ask","go":"ask","reason":"r","confirmed":true}]`,
		"wrong cmd":  `[{"id":1,"command":"echo 2","python":"ask","go":"deny","reason":"r","confirmed":true}]`,
		"listed twice": `[{"id":1,"command":"echo 1","python":"ask","go":"deny","reason":"r"},` +
			`{"id":1,"command":"echo 1","python":"ask","go":"deny","reason":"r"}]`,
	} {
		if _, err := loadDiffs(write(name+".json", body), cases); err == nil {
			t.Errorf("%s: loadDiffs accepted it", name)
		}
	}
}

// TestGolden 回放 Python 版的 Jev 真实答案：录制须恰好覆盖 102 条且逐条与固定语料清单
// 一致；Go 的结论须与 Python 逐条一致，不一致的只能是 diffs.json 中经维护者确认的差异用例；是否调用模型、
// 发给模型的 state 也须一致，规则直接 deny 的样本两边都不调用模型。
//
// 正式验收用默认路径 testdata/golden/commands.jsonl，或设 HG_GOLDEN_REQUIRED=1：缺少录制即失败，并要求
// 真实模型答案且逐题有效（checkFormal），伪答案、空答案无法通过。HG_GOLDEN 指向其他录制（如 record.py --fake）
// 且未设 HG_GOLDEN_REQUIRED 时只做开发核对。
func TestGolden(t *testing.T) {
	path := os.Getenv("HG_GOLDEN")
	diffPath := os.Getenv("HG_GOLDEN_DIFFS")
	formal := path == "" || os.Getenv("HG_GOLDEN_REQUIRED") == "1"
	if path == "" {
		path = filepath.Join("..", "..", "..", "testdata", "golden", "commands.jsonl")
		diffPath = filepath.Join("..", "..", "..", "testdata", "golden", "diffs.json")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if os.Getenv("HG_GOLDEN_REQUIRED") == "1" {
			t.Fatalf("golden recording %s is required but missing", path)
		}
		t.Skip("golden not recorded yet (the recording tool is not part of the public repository)")
	}
	corpus, err := loadCorpus(filepath.Join("..", "..", "..", "testdata", "golden", "corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases, err := loadGolden(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkAgainstCorpus(cases, corpus); err != nil {
		t.Fatal(err)
	}
	if formal {
		if err := checkFormal(cases); err != nil {
			t.Fatal(err)
		}
	}
	diffs, err := loadDiffs(diffPath, cases)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := formalQuestions()
	if err != nil {
		t.Fatal(err)
	}
	var formalIDs []string
	for _, q := range qs {
		formalIDs = append(formalIDs, q.ID)
	}
	var problems []string
	for _, c := range cases {
		in := corpus[c.ID-1]
		b := &replay{c: c}
		chk := newCheck(t, true, action.Judge{Backend: b})
		var reqs []guard.Request
		for _, r := range in.UserRequests {
			reqs = append(reqs, guard.Request{Text: r, Source: guard.SourceUser})
		}
		ev := guard.Event{Kind: guard.EventAction, Harness: in.Harness, Tool: in.Tool, Cwd: in.Cwd, Requests: reqs,
			Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: in.Command, Shell: in.Shell}}}}
		v, err := guard.Run(context.Background(), chk, ev)
		if err != nil {
			t.Fatalf("case %d: %v", c.ID, err)
		}
		d, listed := diffs[c.ID]
		switch {
		case v.Decision == c.Decision && listed:
			problems = append(problems, fmt.Sprintf("case %d: listed in diffs.json but Go now agrees with Python (%s)", c.ID, v.Decision))
		case v.Decision != c.Decision && !listed:
			problems = append(problems, fmt.Sprintf("case %d: python %s, go %s: %q (findings %+v, signals %v)",
				c.ID, c.Decision, v.Decision, c.Command, v.Findings, v.Signals))
		case v.Decision != c.Decision && (d.Python != c.Decision || d.Go != v.Decision || d.Command != c.Command):
			problems = append(problems, fmt.Sprintf("case %d: diffs.json says %s → %s, got %s → %s", c.ID, d.Python, d.Go, c.Decision, v.Decision))
		case v.Decision != c.Decision && !d.Confirmed:
			problems = append(problems, fmt.Sprintf("case %d: difference %s → %s awaits maintainer confirmation", c.ID, c.Decision, v.Decision))
		}
		switch called := b.state != nil; {
		case c.State == nil && called:
			problems = append(problems, fmt.Sprintf("case %d: python denied without the judge, go called it", c.ID))
		case called != (c.State != nil) && !listed:
			problems = append(problems, fmt.Sprintf("case %d: python called the judge: %v, go: %v", c.ID, c.State != nil, called))
		}
		if b.state != nil && !slices.Equal(b.asked, formalIDs) {
			// checkFormal 按 formalQuestions 校验答案，回放问的题必须与它一致
			problems = append(problems, fmt.Sprintf("case %d: go asked %v, formal check validates %v", c.ID, b.asked, formalIDs))
		}
		if c.State != nil && b.state != nil {
			got, _ := json.Marshal(b.state)
			var norm map[string]any
			json.Unmarshal(got, &norm)
			if !reflect.DeepEqual(norm, c.State) {
				want, _ := json.Marshal(c.State)
				problems = append(problems, fmt.Sprintf("case %d: state differs\n  python %s\n  go     %s", c.ID, want, got))
			}
		}
	}
	if len(problems) > 0 {
		t.Errorf("%d of %d golden cases:\n%s", len(problems), len(cases), strings.Join(problems, "\n"))
	}
}

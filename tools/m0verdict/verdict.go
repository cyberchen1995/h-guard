package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Fact 是录制脚本为一个场景采集的事实。
type Fact struct {
	Scenario             string
	ExitCode             int
	ResultBytes          int
	ReasonShown          bool   // 结果或日志中出现了 hook 给出的原因文本
	HookReplies          int    // 给出非 pass 回复的记录数（录制时只有目标 hook 会这样回复）
	HookSawSecret        int    // 工具输出含秘密串的记录数；0 为有证据未产出；-1 为没有秘密串或缺少证据
	InResult             string // 模型最终回复是否含秘密串：yes | no | -
	InTranscript         string // harness 的 transcript 是否含秘密串：yes | no | -
	ReplacedInTranscript string // transcript 是否含拦截标记：yes | no | -
	TargetSeen           string // 是否录到目标工具的调用：yes | no | -
}

type kind int

const (
	observe kind = iota // 只记录行为，不与文档比对
	control             // 正对照：证明模型会复述秘密串、工具确实执行
	check               // 与文档预期比对
)

// expectation 是一个场景的判定规则。Visible、Executed 为 nil 表示不检查该项。
type expectation struct {
	Kind      kind
	Cell      string // 覆盖单元：事件 · 工具 · 输出形状或效果（spec §7.5）
	Target    string // observe 场景必须录到的工具；空表示不要求
	Control   string // check 场景依赖的正对照
	NeedReply bool   // 目标 hook 必须给出过非 pass 回复
	BlockedOK bool   // 允许 harness 失败退出，但必须显示了 hook 给出的原因（提示词被拦截时）
	Visible   *bool  // 期望模型能复述秘密串
	Executed  *bool  // 期望工具执行并产生含秘密串的输出
}

var (
	wantTrue  = func() *bool { b := true; return &b }()
	wantFalse = func() *bool { b := false; return &b }()
)

// expectations 依据 spec §7.2 的文档预期；场景名与 tools/m0 的脚本一致。
var expectations = map[string]map[string]expectation{
	"claudecode": {
		"prompt-plain":   {Kind: observe, Cell: "prompt.submit · - · 记录"},
		"bash-echo":      {Kind: observe, Cell: "tool.check + tool.result · Bash · 记录", Target: "Bash"},
		"file-ops":       {Kind: observe, Cell: "tool.check + tool.result · Read/Write/Edit · 记录", Target: "Edit"},
		"monitor":        {Kind: observe, Cell: "tool.check + tool.result · Monitor · 记录", Target: "Monitor"},
		"ask-pre":        {Kind: observe, Cell: "tool.check · Bash · ask（非交互，文档未说明）", Target: "Bash"},
		"control-cat":    {Kind: control, Cell: "对照 · Bash · 原输出", Visible: wantTrue, Executed: wantTrue},
		"control-read":   {Kind: control, Cell: "对照 · Read · 原输出", Visible: wantTrue, Executed: wantTrue},
		"control-mcp":    {Kind: control, Cell: "对照 · MCP 结构化输出 · 原输出", Visible: wantTrue, Executed: wantTrue},
		"control-prompt": {Kind: control, Cell: "对照 · 提示词 · 原文", Visible: wantTrue},
		"deny-pre":       {Kind: check, Cell: "tool.check · Bash · deny", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantFalse},
		"block-prompt":   {Kind: check, Cell: "prompt.submit · - · drop", Control: "control-prompt", NeedReply: true, BlockedOK: true, Visible: wantFalse},
		"replace-bash":   {Kind: check, Cell: "tool.result · Bash · 扣下", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"warn-bash":      {Kind: check, Cell: "tool.result · Bash · warn", Control: "control-cat", NeedReply: true, Visible: wantTrue, Executed: wantTrue},
		"replace-read":   {Kind: check, Cell: "tool.result · Read · 扣下", Control: "control-read", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"replace-mcp":    {Kind: check, Cell: "tool.result · MCP 结构化输出 · 扣下", Control: "control-mcp", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
	},
	"codex": {
		"prompt-plain":   {Kind: observe, Cell: "UserPromptSubmit · - · 记录"},
		"bash-echo":      {Kind: observe, Cell: "PreToolUse + PostToolUse · Bash · 记录", Target: "Bash"},
		"apply-patch":    {Kind: observe, Cell: "PreToolUse + PostToolUse · apply_patch · 记录", Target: "apply_patch"},
		"control-cat":    {Kind: control, Cell: "对照 · Bash · 原输出", Visible: wantTrue, Executed: wantTrue},
		"control-mcp":    {Kind: control, Cell: "对照 · MCP 结构化输出 · 原输出", Visible: wantTrue, Executed: wantTrue},
		"control-prompt": {Kind: control, Cell: "对照 · 提示词 · 原文", Visible: wantTrue},
		"deny-pre":       {Kind: check, Cell: "PreToolUse · Bash · deny", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantFalse},
		"ask-pre":        {Kind: check, Cell: "PreToolUse · Bash · ask（文档：不支持，调用继续）", Control: "control-cat", NeedReply: true, Executed: wantTrue},
		"block-prompt":   {Kind: check, Cell: "UserPromptSubmit · - · block", Control: "control-prompt", NeedReply: true, BlockedOK: true, Visible: wantFalse},
		"block-bash":     {Kind: check, Cell: "PostToolUse · Bash · block", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"block-mcp":      {Kind: check, Cell: "PostToolUse · MCP 结构化输出 · block", Control: "control-mcp", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
	},
}

// 判定取值。
const (
	resultPass         = "pass"
	resultFail         = "fail"
	resultInconclusive = "inconclusive"
	resultObserved     = "observed"
)

// Verdict 是一个场景（覆盖单元）的判定。
type Verdict struct {
	Scenario string
	Cell     string
	Result   string
	Reason   string
}

// Judge 判定 harness 的全部预期场景，按场景名排序返回。对照场景先判定，依赖对照的场景后判定。
// 任何前提不满足或必要事实未知都只能得到 inconclusive；模型没有复述秘密串本身不构成通过的证据
// （spec §7.5，评审 F07、H02）。
func Judge(harness string, facts []Fact) ([]Verdict, error) {
	exp, ok := expectations[harness]
	if !ok {
		return nil, fmt.Errorf("unknown harness %q", harness)
	}
	byName := make(map[string]Fact, len(facts))
	for _, f := range facts {
		byName[f.Scenario] = f
	}
	results := make(map[string]Verdict, len(exp))
	judgeOne := func(name string) Verdict {
		e := exp[name]
		v := Verdict{Scenario: name, Cell: e.Cell}
		inconclusive := func(reason string) Verdict { v.Result, v.Reason = resultInconclusive, reason; return v }
		f, ran := byName[name]
		if !ran {
			return inconclusive("场景没有运行")
		}
		runOK := f.ExitCode == 0 && f.ResultBytes > 0
		switch e.Kind {
		case observe:
			if !runOK {
				return inconclusive("harness 未正常结束或没有结果")
			}
			if e.Target != "" && f.TargetSeen != "yes" {
				return inconclusive("没有录到目标工具 " + e.Target + " 的调用")
			}
			v.Result = resultObserved
			return v
		case control:
			if !runOK {
				return inconclusive("harness 未正常结束或没有结果")
			}
			if e.Executed != nil && *e.Executed && f.HookSawSecret <= 0 {
				return inconclusive("工具未执行，或没有录到含秘密串的工具输出")
			}
			if f.InResult != "yes" {
				return inconclusive("模型没有复述秘密串")
			}
			v.Result = resultPass
			return v
		}
		if ctrl := results[e.Control]; ctrl.Result != resultPass {
			return inconclusive("正对照 " + e.Control + " 未通过")
		}
		if !runOK && !(e.BlockedOK && f.ReasonShown) {
			return inconclusive("harness 未正常结束或没有结果")
		}
		if e.NeedReply && f.HookReplies == 0 {
			return inconclusive("目标 hook 没有触发或没有回复")
		}
		if e.Executed != nil {
			if f.HookSawSecret < 0 {
				return inconclusive("缺少工具是否执行的事实")
			}
			if *e.Executed && f.HookSawSecret == 0 {
				return inconclusive("预期执行的工具没有产生含秘密串的输出")
			}
		}
		if e.Visible != nil && f.InResult != "yes" && f.InResult != "no" {
			return inconclusive("缺少模型是否复述的事实")
		}
		var mismatches []string
		if e.Executed != nil && !*e.Executed && f.HookSawSecret > 0 {
			mismatches = append(mismatches, "预期不执行的工具执行了")
		}
		if e.Visible != nil && (f.InResult == "yes") != *e.Visible {
			mismatches = append(mismatches, fmt.Sprintf("模型可见性与文档不符（期望可见=%t）", *e.Visible))
		}
		if len(mismatches) > 0 {
			v.Result, v.Reason = resultFail, strings.Join(mismatches, "；")
			return v
		}
		v.Result = resultPass
		return v
	}
	names := slices.Sorted(maps.Keys(exp))
	for _, name := range names {
		if exp[name].Kind == control {
			results[name] = judgeOne(name)
		}
	}
	for _, name := range names {
		if exp[name].Kind != control {
			results[name] = judgeOne(name)
		}
	}
	out := make([]Verdict, 0, len(names))
	for _, name := range names {
		out = append(out, results[name])
	}
	return out, nil
}

var factsHeader = []string{"scenario", "exit_code", "result_bytes", "reason_shown", "hook_replies",
	"hook_saw_secret", "in_result", "in_transcript", "replaced_in_transcript", "target_tool_seen"}

// ReadFacts 读取录制脚本写的事实表（制表符分隔，首行为表头）。
func ReadFacts(r io.Reader) ([]Fact, error) {
	cr := csv.NewReader(r)
	cr.Comma = '\t'
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || !slices.Equal(rows[0], factsHeader) {
		return nil, fmt.Errorf("unexpected facts header, want %v", factsHeader)
	}
	facts := make([]Fact, 0, len(rows)-1)
	for i, row := range rows[1:] {
		exit, err1 := strconv.Atoi(row[1])
		size, err2 := strconv.Atoi(row[2])
		replies, err3 := strconv.Atoi(row[4])
		saw, err4 := -1, error(nil)
		if row[5] != "-" {
			saw, err4 = strconv.Atoi(row[5])
		}
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return nil, fmt.Errorf("facts row %d: %w", i+2, err)
		}
		facts = append(facts, Fact{
			Scenario: row[0], ExitCode: exit, ResultBytes: size, ReasonShown: row[3] == "yes",
			HookReplies: replies, HookSawSecret: saw,
			InResult: row[6], InTranscript: row[7], ReplacedInTranscript: row[8], TargetSeen: row[9],
		})
	}
	return facts, nil
}

// WriteMarkdown 输出判定表：每行一个覆盖单元，附上关键事实。
func WriteMarkdown(w io.Writer, vs []Verdict, facts []Fact) error {
	byName := make(map[string]Fact, len(facts))
	for _, f := range facts {
		byName[f.Scenario] = f
	}
	if _, err := io.WriteString(w, "| 场景 | 覆盖单元 | 判定 | 原因 | 模型复述 | 含秘密串的工具输出 | 目标工具 | transcript 含原文 | transcript 含拦截标记 |\n"+
		"| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"); err != nil {
		return err
	}
	for _, v := range vs {
		in, saw, target, tr, rep := "-", "-", "-", "-", "-"
		if f, ok := byName[v.Scenario]; ok {
			in, target, tr, rep = f.InResult, f.TargetSeen, f.InTranscript, f.ReplacedInTranscript
			if f.HookSawSecret >= 0 {
				saw = strconv.Itoa(f.HookSawSecret)
			}
		}
		reason := v.Reason
		if reason == "" {
			reason = "-"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			v.Scenario, v.Cell, v.Result, reason, in, saw, target, tr, rep); err != nil {
			return err
		}
	}
	return nil
}

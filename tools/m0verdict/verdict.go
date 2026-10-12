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
	TargetSeen           string // 目标工具的事件：yes（调用前后都录到）| pre（只录到调用前）| no | -（场景没有目标工具）
	TargetCalls          int    // 目标工具的调用次数（调用前事件数）；-1 为场景没有目标工具
	LeakElsewhere        int    // 非目标工具的输出含秘密串的记录数；-1 为没有秘密串或缺少证据
}

type kind int

const (
	observe kind = iota // 只记录行为，不与文档比对
	control             // 正对照：证明模型会复述秘密串、工具确实执行
	check               // 与文档预期比对
)

// expectation 是一个场景的判定规则。Visible、Executed 为 nil 表示不检查该项。
type expectation struct {
	Kind       kind
	Cell       string // 覆盖单元：事件 · 工具 · 输出形状或效果（spec §7.5）
	Target     string // 目标工具；非空时必须录到它的调用，证据（输出、回复）只算它的
	NeedPost   bool   // observe：目标工具的调用后事件也必须录到
	Control    string // check 场景依赖的正对照
	NeedReply  bool   // 目标 hook 必须给出过非 pass 回复
	NeedReason bool   // 必须录到给用户的提示（如 warn）
	BlockedOK  bool   // 允许 harness 失败退出，但必须显示了 hook 给出的原因（提示词被拦截时）
	Visible    *bool  // 期望模型能复述秘密串
	Executed   *bool  // 期望工具执行并产生含秘密串的输出
}

var (
	wantTrue  = func() *bool { b := true; return &b }()
	wantFalse = func() *bool { b := false; return &b }()
)

// expectations 依据 spec §7.2 的文档预期；场景名与 tools/m0 的脚本一致。
var expectations = map[string]map[string]expectation{
	"claudecode": {
		"prompt-plain":       {Kind: observe, Cell: "prompt.submit · - · 记录"},
		"bash-echo":          {Kind: observe, Cell: "tool.check + tool.result · Bash · 记录", Target: "Bash", NeedPost: true},
		"file-ops":           {Kind: observe, Cell: "tool.check + tool.result · Read、Write、Edit · 记录", Target: "Read、Write、Edit", NeedPost: true},
		"monitor":            {Kind: observe, Cell: "tool.check + tool.result · Monitor · 记录", Target: "Monitor", NeedPost: true},
		"ask-pre":            {Kind: observe, Cell: "tool.check · Bash · ask（-p，acceptEdits）", Target: "Bash"},
		"ask-auto":           {Kind: observe, Cell: "tool.check · Bash · ask（-p，auto 模式）", Target: "Bash"},
		"ask-bypass":         {Kind: observe, Cell: "tool.check · Bash · ask（-p，bypassPermissions 模式）", Target: "Bash"},
		"control-cat":        {Kind: control, Cell: "对照 · Bash · 原输出", Target: "Bash", Visible: wantTrue, Executed: wantTrue},
		"control-bash-error": {Kind: control, Cell: "对照 · Bash 出错结果 · 原输出", Target: "Bash", Visible: wantTrue, Executed: wantTrue},
		"control-read":       {Kind: control, Cell: "对照 · Read · 原输出", Target: "Read", Visible: wantTrue, Executed: wantTrue},
		"control-mcp":        {Kind: control, Cell: "对照 · MCP 结构化输出 · 原输出", Target: "MCP hg_m0_report", Visible: wantTrue, Executed: wantTrue},
		"control-prompt":     {Kind: control, Cell: "对照 · 提示词 · 原文", Visible: wantTrue},
		"deny-pre":           {Kind: check, Cell: "tool.check · Bash · deny", Target: "Bash", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantFalse},
		"block-prompt":       {Kind: check, Cell: "prompt.submit · - · drop", Control: "control-prompt", NeedReply: true, BlockedOK: true, Visible: wantFalse},
		"replace-bash":       {Kind: check, Cell: "tool.result · Bash · 扣下", Target: "Bash", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"replace-bash-error": {Kind: check, Cell: "tool.result · Bash 出错结果 · 扣下", Target: "Bash", Control: "control-bash-error", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"warn-bash":          {Kind: check, Cell: "tool.result · Bash · warn（原结果 + 提示用户）", Target: "Bash", Control: "control-cat", NeedReply: true, NeedReason: true, Visible: wantTrue, Executed: wantTrue},
		"replace-read":       {Kind: check, Cell: "tool.result · Read · 扣下", Target: "Read", Control: "control-read", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"replace-mcp":        {Kind: check, Cell: "tool.result · MCP 结构化输出 · 扣下", Target: "MCP hg_m0_report", Control: "control-mcp", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
	},
	"codex": {
		"prompt-plain":       {Kind: observe, Cell: "UserPromptSubmit · - · 记录"},
		"bash-echo":          {Kind: observe, Cell: "PreToolUse + PostToolUse · Bash · 记录", Target: "Bash", NeedPost: true},
		"apply-patch":        {Kind: observe, Cell: "PreToolUse + PostToolUse · apply_patch · 记录", Target: "apply_patch", NeedPost: true},
		"control-cat":        {Kind: control, Cell: "对照 · Bash · 原输出", Target: "Bash", Visible: wantTrue, Executed: wantTrue},
		"control-bash-error": {Kind: control, Cell: "对照 · Bash 出错结果 · 原输出", Target: "Bash", Visible: wantTrue, Executed: wantTrue},
		"control-mcp":        {Kind: control, Cell: "对照 · MCP 结构化输出 · 原输出", Target: "MCP hg_m0_report", Visible: wantTrue, Executed: wantTrue},
		"control-prompt":     {Kind: control, Cell: "对照 · 提示词 · 原文", Visible: wantTrue},
		"deny-pre":           {Kind: check, Cell: "PreToolUse · Bash · deny", Target: "Bash", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantFalse},
		"ask-pre":            {Kind: check, Cell: "PreToolUse · Bash · ask（文档：不支持，调用继续）", Target: "Bash", Control: "control-cat", NeedReply: true, Executed: wantTrue},
		"block-prompt":       {Kind: check, Cell: "UserPromptSubmit · - · block", Control: "control-prompt", NeedReply: true, BlockedOK: true, Visible: wantFalse},
		"block-bash":         {Kind: check, Cell: "PostToolUse · Bash · block", Target: "Bash", Control: "control-cat", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"block-bash-error":   {Kind: check, Cell: "PostToolUse · Bash 出错结果 · block", Target: "Bash", Control: "control-bash-error", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
		"block-mcp":          {Kind: check, Cell: "PostToolUse · MCP 结构化输出 · block", Target: "MCP hg_m0_report", Control: "control-mcp", NeedReply: true, Visible: wantFalse, Executed: wantTrue},
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
		// 有目标工具的场景：必须录到它的调用；秘密串不能经其他工具进入上下文，否则证据归不到目标工具
		// （评审 C2、I6）。
		targetOK := func() (string, bool) {
			if e.Target == "" {
				return "", true
			}
			if f.TargetSeen != "yes" && f.TargetSeen != "pre" {
				return "没有录到目标工具 " + e.Target + " 的调用", false
			}
			if e.Executed != nil && f.LeakElsewhere != 0 {
				if f.LeakElsewhere < 0 {
					return "缺少其他工具是否输出秘密串的事实", false
				}
				return "秘密串经目标以外的工具进入了上下文", false
			}
			return "", true
		}
		switch e.Kind {
		case observe:
			if !runOK {
				return inconclusive("harness 未正常结束或没有结果")
			}
			if reason, ok := targetOK(); !ok {
				return inconclusive(reason)
			}
			if e.NeedPost && f.TargetSeen != "yes" {
				return inconclusive("只录到目标工具 " + e.Target + " 的调用前事件，没有调用后事件")
			}
			v.Result = resultObserved
			return v
		case control:
			if !runOK {
				return inconclusive("harness 未正常结束或没有结果")
			}
			if reason, ok := targetOK(); !ok {
				return inconclusive(reason)
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
		if reason, ok := targetOK(); !ok {
			return inconclusive(reason)
		}
		if e.Target != "" && f.TargetCalls > 1 {
			return inconclusive(fmt.Sprintf("目标工具被调用了 %d 次，agent 可能换了写法继续尝试", f.TargetCalls))
		}
		if e.NeedReply && f.HookReplies == 0 {
			return inconclusive("目标 hook 没有触发或没有回复")
		}
		if e.NeedReason && !f.ReasonShown {
			return inconclusive("没有录到给用户的提示")
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
	"hook_saw_secret", "in_result", "in_transcript", "replaced_in_transcript", "target_tool_seen",
	"target_calls", "leak_elsewhere"}

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
		saw, err4 := countOrUnknown(row[5])
		calls, err5 := countOrUnknown(row[10])
		leak, err6 := countOrUnknown(row[11])
		if err := errors.Join(err1, err2, err3, err4, err5, err6); err != nil {
			return nil, fmt.Errorf("facts row %d: %w", i+2, err)
		}
		facts = append(facts, Fact{
			Scenario: row[0], ExitCode: exit, ResultBytes: size, ReasonShown: row[3] == "yes",
			HookReplies: replies, HookSawSecret: saw,
			InResult: row[6], InTranscript: row[7], ReplacedInTranscript: row[8], TargetSeen: row[9],
			TargetCalls: calls, LeakElsewhere: leak,
		})
	}
	return facts, nil
}

// countOrUnknown 解析计数列，"-" 表示未知，记为 -1。
func countOrUnknown(s string) (int, error) {
	if s == "-" {
		return -1, nil
	}
	return strconv.Atoi(s)
}

// WriteMarkdown 输出判定表：每行一个覆盖单元，附上关键事实。
func WriteMarkdown(w io.Writer, vs []Verdict, facts []Fact) error {
	byName := make(map[string]Fact, len(facts))
	for _, f := range facts {
		byName[f.Scenario] = f
	}
	if _, err := io.WriteString(w, "| 场景 | 覆盖单元 | 判定 | 原因 | 模型复述 | 含秘密串的工具输出 | 目标工具 | 经其他工具泄露 | transcript 含原文 | transcript 含拦截标记 |\n"+
		"| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"); err != nil {
		return err
	}
	count := func(n int) string {
		if n < 0 {
			return "-"
		}
		return strconv.Itoa(n)
	}
	for _, v := range vs {
		in, saw, target, leak, tr, rep := "-", "-", "-", "-", "-", "-"
		if f, ok := byName[v.Scenario]; ok {
			in, target, tr, rep = f.InResult, f.TargetSeen, f.InTranscript, f.ReplacedInTranscript
			saw, leak = count(f.HookSawSecret), count(f.LeakElsewhere)
			if f.TargetCalls >= 0 {
				target += " ×" + strconv.Itoa(f.TargetCalls)
			}
		}
		reason := v.Reason
		if reason == "" {
			reason = "-"
		}
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			v.Scenario, v.Cell, v.Result, reason, in, saw, target, leak, tr, rep); err != nil {
			return err
		}
	}
	return nil
}

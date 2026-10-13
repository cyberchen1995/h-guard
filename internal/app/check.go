package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// multiFlag 收集可重复的 --request。
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// checkTimeout 是 check 命令的截止时间（含一次判断请求）。
const checkTimeout = 30 * time.Second

// runCheck 手动判断一条命令（spec §12）。默认只跑本地规则；--judge 时才调用判断后端，
// 并先把将要发送的内容打印到 stderr（M1 还没有同意机制，维护者决定，2026-10-12）。
func runCheck(args []string, o Options) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	shell := fs.String("shell", string(guard.ShellPOSIX), "posix or powershell")
	var requests multiFlag
	fs.Var(&requests, "request", "a recent user instruction (repeatable, oldest first)")
	cwd := fs.String("cwd", "", "working directory to report")
	useJudge := fs.Bool("judge", false, "ask the configured judge backend (sends the command and requests)")
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 || !guard.Shell(*shell).Valid() {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, *extra)
	if err != nil {
		// 最终输出边界：错误说明来自配置与规则，可能夹带写下的凭据，输出前遮蔽（评审 N04）
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	ev := guard.Event{
		Kind: guard.EventAction, Harness: "cli", Tool: "check", Cwd: *cwd,
		Actions: []guard.Action{{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: pos[0], Shell: guard.Shell(*shell)}}},
	}
	for _, r := range requests {
		ev.Requests = append(ev.Requests, guard.Request{Text: r, Source: guard.SourceUser})
	}
	var j action.Judge
	if *useJudge {
		s.cfg.Judge.Enabled = true
		b, err := s.cfg.NewBackend(s.cfg.Judge.Backend)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
			return 1
		}
		j.Backend = &printingBackend{Backend: b, w: o.Stderr}
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	res := s.newEngine(j).Evaluate(ctx, ev, harness.EventCaps{Block: true, Ask: true, Warn: true})
	printOutcome(o.Stdout, res.Outcome)
	return 0
}

func printOutcome(w io.Writer, out guard.Outcome) {
	fmt.Fprintln(w, "decision:", out.Verdict.Decision)
	if out.Message != "" {
		fmt.Fprintln(w, "reason:", out.Message)
	}
	if out.Hint != "" {
		fmt.Fprintln(w, "hint:", out.Hint)
	}
	for _, f := range out.Verdict.Findings {
		if f.Probability != nil {
			fmt.Fprintf(w, "finding: %s (%s %.2f)\n", f.Rule, f.Source, *f.Probability)
		} else {
			fmt.Fprintf(w, "finding: %s (%s)\n", f.Rule, f.Source)
		}
	}
	if len(out.Verdict.Fallbacks) > 0 {
		fmt.Fprintln(w, "fallbacks:", strings.Join(out.Verdict.Fallbacks, ", "))
	}
	if len(out.Verdict.Signals) > 0 {
		b, _ := json.Marshal(out.Verdict.Signals)
		fmt.Fprintln(w, "signals:", string(b))
	}
}

// printingBackend 在发送前把 state（已遮蔽凭据、已截断）与题目 ID 打印出来。不打印凭据。
type printingBackend struct {
	judge.Backend
	w io.Writer
}

type endpointer interface{ Endpoint() string }

func (p *printingBackend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	target := p.Name()
	if e, ok := p.Backend.(endpointer); ok {
		target += " (" + e.Endpoint() + ")"
	}
	ids := make([]string, len(qs))
	for i, q := range qs {
		ids[i] = q.ID
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	fmt.Fprintf(p.w, "h-guard: sending to %s\nquestions: %s\nstate:\n%s\n", target, strings.Join(ids, ", "), b)
	return p.Backend.Ask(ctx, state, qs)
}

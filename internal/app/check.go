package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/eval"
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

// runCheck 手动判断一条命令（spec §12），与 hook 走同一套判断：模型开启且同意有效时调用配置的后端。
// --no-judge 只跑本地规则（按模型关闭判断）；--show-request 在发送前把 state 与题目打印到 stderr。
func runCheck(args []string, o Options) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	shell := fs.String("shell", string(guard.ShellPOSIX), "posix or powershell")
	var requests multiFlag
	fs.Var(&requests, "request", "a recent user instruction (repeatable, oldest first)")
	cwd := fs.String("cwd", "", "working directory to report")
	noJudge := fs.Bool("no-judge", false, "run the local rules only, as if the judge were disabled")
	show := fs.Bool("show-request", false, "print what is sent to the judge backend to stderr")
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 || !guard.Shell(*shell).Valid() {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := loadConfig(o, *extra, !*noJudge)
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
	if *noJudge {
		s.cfg.Judge.Enabled = false
	}
	j, _ := s.actionJudge(o)
	if *show && j.Backend != nil {
		j.Backend = &printingBackend{Backend: j.Backend, w: o.Stderr}
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	res := s.newEngine(o, j, outbound.Judge{}).Evaluate(ctx, ev, harness.EventCaps{Block: true, Ask: true, Warn: true})
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

func (p *printingBackend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	target := p.Name()
	if d, ok := p.Backend.(judge.Describer); ok {
		target += " (" + d.Describe().Target + ")"
	}
	ids := make([]string, len(qs))
	for i, q := range qs {
		ids[i] = q.ID
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	fmt.Fprintf(p.w, "h-guard: sending to %s\nquestions: %s\nstate:\n%s\n", target, strings.Join(ids, ", "), b)
	resp, err := p.Backend.Ask(ctx, state, qs)
	if err != nil {
		p.failed(err)
	}
	return resp, err
}

// failed 打印调用失败的类别与说明（后端的固定写法，凭据已遮蔽），后端对这个说明有提示时（FailureHint，如 anthropic
// tool 方式收到 HTTP 400）再打印提示：用户换了模型后先跑 check 就能知道该改什么，不必跑 eval（终审 M-2）。
func (p *printingBackend) failed(err error) {
	kind, detail := judge.KindOf(err), eval.ErrDetail(err)
	if detail == "" {
		fmt.Fprintf(p.w, "h-guard: the backend failed: %s\n", kind)
		return
	}
	fmt.Fprintf(p.w, "h-guard: the backend failed: %s (%s)\n", kind, detail)
	if h, ok := p.Backend.(interface{ FailureHint(detail string) string }); ok {
		if hint := h.FailureHint(detail); hint != "" {
			fmt.Fprintf(p.w, "h-guard: hint: %s\n", hint)
		}
	}
}

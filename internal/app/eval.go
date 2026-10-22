package app

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/eval"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// runEval 用标注语料评估判断后端：报告结论与类别识别的准确率；--sweep 复用答案扫描阈值并打印
// 带指纹的建议档案（不写配置）。会把语料中的命令与指令发给后端，所以先说明目标与条数，在终端里确认或带 --yes。
// 内置语料是标注数据、不含用户的内容，因此不要求同意记录（同意约束的是 hook 发出的用户数据）。
// --repeat K 把语料跑 K 遍，K 次结论拼在一起报告与扫描（每条都是单次判断，任一次失败都算失败）；
// --bootstrap B 对整个扫描重采样，只报告稳定性与乐观偏差，不改建议。
func runEval(args []string, o Options) int {
	// 评估是离线回放，不受 hook 的延迟约束：用宽松的正则超时，免得机器负载让同一份语料两次的结论不同
	defer rules.SetMatchTimeout(rules.ReplayMatchTimeout)()
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	backend := fs.String("backend", "", "backend to evaluate (default: judge.backend)")
	sweep := fs.Bool("sweep", false, "scan thresholds with the recorded answers and suggest a profile")
	casesPath := fs.String("cases", "", "JSONL corpus to use instead of the built-in one")
	shell := fs.String("shell", string(guard.ShellPOSIX), "built-in corpus to use: posix or powershell")
	yes := fs.Bool("yes", false, "send the corpus without asking")
	repeat := fs.Int("repeat", 1, "run the corpus this many times; every run's decisions are pooled and reported")
	boot := fs.Int("bootstrap", 100, "with --sweep: resample the corpus this many times to test the suggestion (0 disables)")
	seed := fs.Uint64("seed", 1, "random seed for --bootstrap")
	extra := fs.String("config", "", "extra config file")
	ob := fs.Bool("outbound", false, "evaluate the outbound judge on the outbound corpus")
	threshold := fs.Float64("threshold", -1, "with --outbound: report at this threshold instead of the profile's")
	compare := fs.Bool("compare", false, "replay the session tasks and held-out steps under five configurations (offline)")
	tasksDir := fs.String("tasks", "", "with --compare: directory of task YAML files to use instead of the built-in ones")
	holdoutPath := fs.String("holdout", "", "with --compare: JSONL held-out steps to use instead of the built-in ones")
	jsonPath := fs.String("json", "", "with --compare: also write the comparison as JSON to this file")
	pos, err := parseInterleaved(fs, args)
	shellSet, actionOnly, compareOnly, notCompare := false, false, false, false
	fs.Visit(func(f *flag.Flag) {
		shellSet = shellSet || f.Name == "shell"
		actionOnly = actionOnly || f.Name == "shell" || f.Name == "repeat" || f.Name == "bootstrap" || f.Name == "seed"
		switch f.Name {
		case "tasks", "holdout", "json":
			compareOnly = true
		case "compare", "config":
		default:
			notCompare = true // 其余选项都只属于在线评估
		}
	})
	// --compare 离线运行、不读后端：在 load() 之前分发，不需要配置（--config 接受但不读，重放只用沙箱里的配置）。
	// 解析错误与多余的位置参数留给下面的通用检查
	if *compare && notCompare {
		fmt.Fprintln(o.Stderr, "h-guard: --compare runs offline and takes only --tasks, --holdout, --json and --config")
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if compareOnly && !*compare {
		fmt.Fprintln(o.Stderr, "h-guard: --tasks, --holdout and --json need --compare")
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if *compare && err == nil && len(pos) == 0 {
		return runEvalCompare(o, compareOptions{tasksDir: *tasksDir, holdoutPath: *holdoutPath, jsonPath: *jsonPath})
	}
	thresholdSet := *threshold != -1
	if thresholdSet && (!*ob || !(*threshold >= 0 && *threshold <= 1)) {
		fmt.Fprintln(o.Stderr, "h-guard: --threshold needs --outbound and a value between 0 and 1")
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if *ob && actionOnly { // --outbound 只有一个门槛、不重复运行：这些选项只属于动作的评估
		fmt.Fprintln(o.Stderr, "h-guard: --outbound cannot be used with --shell, --repeat, --bootstrap or --seed")
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	// --shell 只选内置语料：--cases 的语料逐条写 shell
	if err != nil || len(pos) != 0 || !guard.Shell(*shell).Valid() || (shellSet && *casesPath != "") {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if *repeat < 1 || *boot < 0 {
		fmt.Fprintln(o.Stderr, "h-guard: --repeat must be at least 1 and --bootstrap at least 0")
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, *extra)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	name := *backend
	if name == "" {
		name = s.cfg.Judge.Backend
	}
	if _, ok := s.cfg.Backends[name]; !ok {
		fmt.Fprintf(o.Stderr, "h-guard: no backend named %q in the config\n", shown(name))
		return 1
	}
	st := s.inspectJudge(o, name)
	if st.err != nil {
		fmt.Fprintln(o.Stderr, "h-guard: backend", shown(name)+":", shown(st.err.Error()))
		return 1
	}
	if *ob {
		return runEvalOutbound(s, o, name, st, *casesPath, *sweep, *yes, *threshold)
	}
	// 与模型开启时的配置期校验相同（不论模型是否开启、judge.backend 是不是它）：缺一种题型，那些题永远问不出，
	// 拟合出的阈值不能作为校准的证据。按配置错误退出，不发送语料
	if err := kindsError(name, st.backend, "which h-guard eval asks"); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	cases, err := eval.CorpusFor(guard.Shell(*shell))
	if *casesPath != "" {
		cases, err = eval.LoadCases(*casesPath)
	}
	if err != nil {
		// 解析错误里有文件路径与写错的字段名，都可能带凭据
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	source := "the built-in corpus"
	switch {
	case *casesPath != "":
		source = shown(*casesPath)
	case guard.Shell(*shell) == guard.ShellPowerShell:
		source = "the built-in PowerShell corpus"
	}
	// 这是一次数据发送授权：写明目标、来源与发送的内容（--cases 的语料可能含用户数据）
	times := ""
	if *repeat > 1 {
		times = fmt.Sprintf(" %d times (--repeat)", *repeat)
	}
	fmt.Fprintf(o.Stderr, "h-guard eval sends %d cases from %s to backend %s (%s) %s%s: each command and its user instructions,\n"+
		"with credentials that h-guard recognizes masked; the cwd, harness and tool are fixed placeholders.\n",
		len(cases), source, shown(name), st.typ, targetOf(st), times)
	if !*yes {
		if !o.IsTerminal() {
			fmt.Fprintln(o.Stderr, "h-guard: not a terminal; pass --yes to send without asking")
			return 1
		}
		fmt.Fprint(o.Stderr, "Continue? [y/N] ")
		answer, _ := bufio.NewReader(o.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(o.Stderr, "cancelled")
			return 1
		}
	}
	env := eval.Env{Rules: s.rules, Config: s.cfg, Backend: st.backend, Thresholds: st.thresholds}
	ctx := context.Background()
	var runs [][]eval.Outcome
	for k := 1; k <= *repeat; k++ {
		prefix := ""
		if *repeat > 1 {
			prefix = fmt.Sprintf("[run %d/%d] ", k, *repeat)
		}
		env.Progress = func(i, n int, out eval.Outcome) {
			fmt.Fprintf(o.Stderr, "%s[%d/%d] %s -> %s\n", prefix, i, n, shown(out.Case.Command), out.Decision)
		}
		outs, err := eval.Run(ctx, env, cases)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
			return 1
		}
		runs = append(runs, outs)
	}
	outs := eval.Pool(runs)
	margins, err := eval.Margins(ctx, env, outs, st.thresholds)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	fmt.Fprintf(o.Stdout, "backend %s (%s) %s\nthresholds: %s\n\n", shown(name), st.typ, targetOf(st), calibrationText(st))
	var ids []string
	for _, r := range s.rules.All() {
		ids = append(ids, r.ID)
	}
	eval.Report(o.Stdout, outs, ids, margins)
	if *repeat > 1 {
		eval.WriteRepeatability(o.Stdout, eval.Repeat(runs))
	}
	// 调用失败时结论来自保守处理，不扫描、不建议；退出码为 1，并在 stderr 写明——stdout 常被重定向到文件，
	// 否则用户只看到退出码 0（如 API key 没传进来，全部调用都以 auth 失败）
	if failed := eval.Failed(outs); failed > 0 {
		next := "Fix the backend and run again."
		if *sweep {
			next = "Nothing was swept or suggested; fix the backend and run again."
		}
		fmt.Fprintf(o.Stderr, "h-guard: %d of %d calls failed: %s. %s\n", failed, calledCount(outs), eval.FailureSummary(outs), next)
		for _, hint := range failureHints(st.backend, outs) {
			fmt.Fprintln(o.Stderr, "h-guard: hint:", hint)
		}
		return 1
	}
	// 一条都没有调用后端（如语料全是 deny 级的命令）：这次评估对后端什么也没说明，同样不扫描、不建议
	if calledCount(outs) == 0 {
		next := "Use cases that call the backend and run again."
		if *sweep {
			next = "Nothing was swept or suggested; use cases that call the backend and run again."
		}
		fmt.Fprintf(o.Stderr, "h-guard: no case called the backend, so this run says nothing about it. %s\n", next)
		return 1
	}
	// 答案不完整同样不能作为证据：照常扫描给出参考，但不建议档案，退出码为 1 并在 stderr 写明
	incomplete := eval.Incomplete(outs)
	if incomplete > 0 {
		fmt.Fprintf(o.Stderr, "h-guard: %d cases had questions without a valid answer (see === Incomplete answers in the report). "+
			"Fix the backend and run again.\n", incomplete)
	}
	if !*sweep {
		if incomplete > 0 {
			return 1
		}
		return 0
	}
	tables, th, score, err := eval.Sweep(ctx, env, outs, st.thresholds, *repeat)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	eval.WriteSweep(o.Stdout, tables)
	// 答案不完整时，结论靠缺题时的保守处理得出，不是模型的判断：不给建议档案
	if incomplete > 0 {
		fmt.Fprintf(o.Stdout, "\nNo profile suggested: %d cases had questions without a valid answer. Fix the backend and run again.\n", incomplete)
		return 1
	}
	var notes []string
	if *repeat > 1 {
		notes = append(notes, fmt.Sprintf("%d runs pooled: the counts above are decisions, not distinct cases (%d cases).", *repeat, len(cases)))
	}
	if *boot > 0 {
		bs, err := eval.BootstrapSweep(ctx, env, outs, len(cases), st.thresholds, th, *boot, *seed)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
			return 1
		}
		eval.WriteBootstrap(o.Stdout, bs)
		notes = append(notes, eval.BootstrapNotes(bs)...)
	}
	profile := st.cal.Profile
	if profile == "" {
		profile = name
	}
	fmt.Fprintln(o.Stdout)
	builtin, err := rules.Builtin()
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprint(o.Stdout, eval.ProfileYAML(profile, th, eval.Fingerprint(st.backend, action.QuestionSet(builtin)), score, len(outs), notes))
	if own := s.ownQuestions(); len(own) > 0 {
		fmt.Fprintf(o.Stdout, "# Your rules %s ask their own questions; the fingerprint covers only the built-in ones.\n", strings.Join(own, ", "))
	}
	if st.cal.Profile == "" {
		fmt.Fprintf(o.Stdout, "# and reference it from the backend: backends.%s.profile: %s\n", name, profile)
	}
	if *casesPath == "" && guard.Shell(*shell) == guard.ShellPowerShell {
		// 指纹不区分语料：照抄进配置就会替换按 POSIX 语料校准的档案
		fmt.Fprintln(o.Stdout, "# Fitted on the built-in PowerShell corpus; the built-in profiles are calibrated on the POSIX corpus.")
	}
	return 0
}

// failureHints 返回后端对这次各个失败说明给出的提示，按说明排序、去重；后端没有提示时为空。
// 提示来自后端的可选方法 FailureHint（如 anthropic 在强制工具调用被拒时建议改用 structured）。b 必须是配置
// 创建的原对象：eval 的记录器与 check 的包装只嵌入 judge.Backend，不转发这个方法。说明（ErrDetail）是后端的
// 固定写法、凭据已遮蔽，没有说明的失败不问。
func failureHints(b judge.Backend, outs []eval.Outcome) []string {
	h, ok := b.(interface{ FailureHint(detail string) string })
	if !ok {
		return nil
	}
	details := map[string]bool{}
	for _, o := range outs {
		if o.Err != "" && o.ErrDetail != "" {
			details[o.ErrDetail] = true
		}
	}
	var hints []string
	for _, d := range slices.Sorted(maps.Keys(details)) {
		if hint := h.FailureHint(d); hint != "" && !slices.Contains(hints, hint) {
			hints = append(hints, hint)
		}
	}
	return hints
}

// calledCount 返回调用了后端的条数（deny 级的不调用）。
func calledCount(outs []eval.Outcome) int {
	n := 0
	for _, o := range outs {
		if o.Called {
			n++
		}
	}
	return n
}

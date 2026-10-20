package app

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/internal/seen"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// statusProtection 是 status 开头的保护摘要：每个 harness 分开写「配置已写入」「hook 真正运行」「自测通过」三层；
// 再写哪些规则会打断、哪些只记录、哪些不生效，以及护栏照不到的地方。用户不必读完整份 status 就知道自己受到什么保护。
func statusProtection(s setup, o Options) {
	fmt.Fprintln(o.Stdout, "protection:")
	if o.Home != "" {
		t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, GOOS: o.GOOS, Getenv: o.Getenv, Now: o.Now}
		for _, h := range installable {
			if h != "claudecode" && h != "codex" {
				// 扩展协议的 harness 只写配置这一层，装了才列出：运行记录与自测目前只覆盖 Claude Code 与 Codex
				// 只有「not installed」算没装：配置读不了（problem: 开头）的也要列出来
				if lines := install.Inspect(t, h); len(lines) > 0 && !strings.HasPrefix(lines[0], "not installed") {
					fmt.Fprintf(o.Stdout, "  %s: %s | hook running: not tracked for %s | self-test: not available for %s\n", h, configWritten(lines, h), h, h)
				}
				continue
			}
			fmt.Fprintf(o.Stdout, "  %s: %s\n", h, strings.Join(harnessLayers(t, o, h, s.extra), " | "))
		}
	}
	interrupts, logged, off := ruleCoverage(s)
	fmt.Fprintln(o.Stdout, "  interrupts:", listOrNone(interrupts))
	if len(logged) > 0 {
		// 「只记录」要看决策日志开没开：默认不开，这些命中只是被认出、不打断，哪里也没留下
		what := "matched but not interrupting, and not recorded (log.decisions is off)"
		if s.cfg.Log.Decisions {
			what = "matched but not interrupting, only recorded in the decision log"
		}
		fmt.Fprintf(o.Stdout, "  %s (judge off; h-guard init turns it on): %s\n", what, strings.Join(logged, ", "))
	}
	if len(off) > 0 {
		fmt.Fprintln(o.Stdout, "  off:", strings.Join(off, ", "))
	}
	_, jst := s.actionJudge(o)
	judgeUsable := jst.backend != nil && jst.consent == consentGranted
	// 类别题要另外同意 outbound 范围：只同意了 action 范围时模型不检查提示词与工具输出
	fmt.Fprintf(o.Stdout, "  prompts and tool output: %s (scans %s)\n", listOrNone(outboundCoverage(s, judgeUsable && jst.outbound, jst.pii)), outboundScope[s.cfg.Outbound.Tier])
	for _, gap := range coverageGaps(s, judgeUsable) {
		fmt.Fprintln(o.Stdout, "  not covered:", gap)
	}
	switch {
	case guard.Decision(s.cfg.Policy.WhenAskUnsupported) == guard.DecisionPass:
		fmt.Fprintln(o.Stdout, "  codex: cannot ask, and policy.when_ask_unsupported is pass, so every ask lets the operation run")
	case o.CacheDir == "" || o.ConfigDir == "":
		// 授权记录在缓存目录、签名密钥在配置目录：缺一个就不提供单次授权
		fmt.Fprintln(o.Stdout, "  codex: cannot ask, so every ask blocks; one-time approvals are unavailable (no cache or configuration directory)")
	default:
		fmt.Fprintln(o.Stdout, "  codex: cannot ask, so every ask blocks; approve one stopped operation with h-guard allow <id>")
	}
	if o.Home != "" && guard.Decision(s.cfg.Policy.WhenAskUnsupported) != guard.DecisionPass {
		t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, GOOS: o.GOOS, Getenv: o.Getenv, Now: o.Now}
		if lines := install.Inspect(t, "opencode"); len(lines) > 0 && !strings.HasPrefix(lines[0], "not installed") {
			fmt.Fprintln(o.Stdout, "  opencode: cannot ask either, so every ask blocks; one-time approvals are only offered on Codex")
		}
	}
	if o.Home != "" {
		t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, GOOS: o.GOOS, Getenv: o.Getenv, Now: o.Now}
		if lines := install.Inspect(t, "hermes"); len(lines) > 0 && !strings.HasPrefix(lines[0], "not installed") {
			// Hermes 能请求确认，但自动批准时（YOLO 等）不能；挡不住 CLI 里的提示词
			what := "every ask in a session that Hermes would approve without asking (--yolo, approvals.mode: off) blocks"
			if guard.Decision(s.cfg.Policy.WhenAskUnsupported) == guard.DecisionPass {
				what = "every ask in a session that Hermes would approve without asking (--yolo, approvals.mode: off) lets the operation run (policy.when_ask_unsupported is pass)"
			}
			fmt.Fprintf(o.Stdout, "  hermes: asks go to Hermes's own approval; %s; prompts typed into the CLI, TUI or Desktop cannot be blocked, only flagged to the model\n", what)
		}
	}
}

// configWritten 是「配置已写入」这一层：install 报告了问题时注明。
func configWritten(lines []string, h string) string {
	if slices.ContainsFunc(lines, func(l string) bool { return strings.HasPrefix(l, "problem: ") }) {
		return "config written: yes, with problems (see " + h + " below)"
	}
	return "config written: yes"
}

// harnessLayers 是一个 harness 的三层状态。Codex 是否信任了 hook 读不到：没有运行记录时写「未验证」。
func harnessLayers(t install.Target, o Options, h, extra string) []string {
	lines := install.Inspect(t, h)
	if len(lines) == 0 || strings.HasPrefix(lines[0], "not installed") {
		return []string{fmt.Sprintf("config written: no (h-guard install %s --write)", h)}
	}
	written := configWritten(lines, h)
	running := "hook running: not seen since install"
	if h == "codex" {
		running = "hook running: unverified (Codex has not run the hooks since they were installed; trust them with /hooks in Codex)"
	} else {
		running += " (restart Claude Code and let it run a tool)"
	}
	got, missing, last, installed := hookRuns(t, o, h)
	switch {
	case len(got) > 0 && len(missing) == 0:
		running = fmt.Sprintf("hook running: yes, last %s ago (%s)", ago(o.Now(), last.At), strings.Join(got, ", "))
	case len(got) > 0:
		running = fmt.Sprintf("hook running: partly; seen %s, not yet %s", strings.Join(got, ", "), strings.Join(missing, ", "))
		if h == "claudecode" {
			running += " (prompt.submit and tool.result run through a mod: send a prompt, let a tool run, and check that your organization allows user mods)"
		}
	}
	test := "self-test: not run (h-guard selftest " + h + ")"
	if st, ok := seen.ReadSelftest(seen.Dir(o.CacheDir), h); ok {
		result := "passed"
		if !st.Passed {
			result = "FAILED"
		}
		test = fmt.Sprintf("self-test: %s %s ago", result, ago(o.Now(), st.At))
		switch {
		case installed.IsZero():
			test += " (the installed entries are gone; reinstall, then run h-guard selftest " + h + ")"
		case st.At.Before(installed):
			test += " (before the last install; run h-guard selftest " + h + ")"
		case st.Version != buildID():
			test += " (tested h-guard " + action.Visible(st.Version) + ", not this one; reinstall with this h-guard, then run h-guard selftest " + h + ")"
		case st.Config != configFingerprint(o):
			test += " (the config or rules changed since; run h-guard selftest " + h + ")"
		case extra != "":
			test += " (without --config " + action.Visible(extra) + ", which this status includes)"
		}
	}
	return []string{written, running, test}
}

// hookRuns 按 requiredEvents 分出这个版本在最近一次安装之后真的运行过的入口（got）与还没有运行过的（missing），
// last 是其中最近的一次，installed 是最近一次安装的时间。入口文件不见了时 installed 为零，旧的记录都不算。
func hookRuns(t install.Target, o Options, h string) (got, missing []string, last seen.Run, installed time.Time) {
	installed = install.InstalledAt(t, h)
	runs := seen.ReadRuns(seen.Dir(o.CacheDir), h)
	for _, ev := range requiredEvents[h] {
		// 升级后旧版本留下的记录不算：要这个版本真的处理过
		if run, ok := runs[ev]; ok && run.Version == buildID() && !installed.IsZero() && !run.At.Before(installed) {
			got = append(got, ev)
			if run.At.After(last.At) {
				last = run
			}
		} else {
			missing = append(missing, ev)
		}
	}
	return got, missing, last, installed
}

// requiredEvents 是每个 harness 必须真的运行过的入口：都运行过，hook 运行这一层才算 yes。
var requiredEvents = map[string][]string{
	"claudecode": {"PreToolUse", "prompt.submit", "tool.result"},
	"codex":      {"PreToolUse", "UserPromptSubmit", "PostToolUse"},
}

// ruleCoverage 把 action 规则分成会打断的（写明结论与条件）、只记录的（模型关闭时依赖模型的规则）与不生效的。
func ruleCoverage(s setup) (interrupts, logged, off []string) {
	reasons := map[string]string{rules.InactiveDisabled: "disabled", rules.InactiveTier: "action tier"}
	for _, r := range s.rules.All() {
		st := rules.StateOf(r, s.cfg.Action.Tier, s.cfg.Judge.Enabled)
		switch {
		case st.Inactive == rules.InactiveJudgeDisabled && fileKindsCovered(r, s.cfg.Action.Tier):
			// requires_judge 只管命令：文件动作按路径匹配，模型关闭时照样打断
			interrupts = append(interrupts, fmt.Sprintf("%s (%s, file actions only; its commands need the judge)", r.ID, r.Action))
		case st.Inactive == rules.InactiveJudgeDisabled:
			logged = append(logged, r.ID)
		case !st.Effective:
			off = append(off, fmt.Sprintf("%s (%s)", r.ID, reasons[st.Inactive]))
		default:
			var notes []string
			notes = append(notes, string(r.Action))
			switch {
			case r.RequiresJudge && !s.cfg.Judge.Enabled:
				// 模型关闭时生效的 requires_judge 规则只有 local 组打断（StateOf）
				notes = append(notes, "only its high-impact forms while the judge is off")
			case r.RequiresJudge:
				notes = append(notes, "when the agent chose it on its own")
			}
			if !r.AppliesTo(guard.ActionExec) {
				if r.AppliesTo(guard.ActionFileRead) && (r.Locked || rules.TierCovers(s.cfg.Action.Tier, guard.ActionFileRead)) {
					// 命令读取的文件也按读文件的规则检查（action 检查的 ReadTargets）
					notes = append(notes, "file tools and common shell reads")
				} else {
					notes = append(notes, "file tools only")
				}
			} else if !r.Locked && slices.ContainsFunc(r.On, func(k guard.ActionKind) bool { return !rules.TierCovers(s.cfg.Action.Tier, k) }) {
				// 规则也写了文件动作、但当前档位不检查它们：只有命令那一半生效
				notes = append(notes, fmt.Sprintf("commands only; its file actions are off at action tier %d", s.cfg.Action.Tier))
			}
			interrupts = append(interrupts, fmt.Sprintf("%s (%s)", r.ID, strings.Join(notes, ", ")))
		}
	}
	return interrupts, logged, off
}

// fileKindsCovered 报告规则有没有当前档位检查的文件动作（硬规则不受档位限制）。
func fileKindsCovered(r *rules.Rule, tier int) bool {
	return slices.ContainsFunc(r.On, func(k guard.ActionKind) bool {
		return k != guard.ActionExec && (r.Locked || rules.TierCovers(tier, k))
	})
}

// outboundCoverage 是生效的 outbound 类别与动作。
// judgeUsable 是判断后端真的能用：只靠类别题的类别只有这时才被检查。
// piiConsent 是同意也含 pii 范围：没有时模型不问 PII 题。
func outboundCoverage(s setup, judgeUsable, piiConsent bool) []string {
	// 记下每个类别的规则扫描哪类事件：只扫其中一类的类别要注明，不能说成提示词与工具输出都受保护
	active := map[string]map[guard.EventKind]bool{}
	for _, r := range s.rules.Outbound() {
		if rules.OutboundStateOf(r, s.cfg.Outbound.Tier, s.cfg.Category(r.Category).Enabled).Effective {
			if active[r.Category] == nil {
				active[r.Category] = map[guard.EventKind]bool{}
			}
			for _, k := range []guard.EventKind{guard.EventPrompt, guard.EventToolOutput} {
				if r.AppliesTo(k) {
					active[r.Category][k] = true
				}
			}
		}
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(active)) {
		a := s.cfg.Category(name).Action
		entry := name + " " + string(a)
		switch kinds := active[name]; {
		case kinds[guard.EventPrompt] && !kinds[guard.EventToolOutput]:
			entry += " (prompts only)"
		case !kinds[guard.EventPrompt] && kinds[guard.EventToolOutput]:
			entry += " (tool output only)"
		}
		if a == guard.DecisionWarn {
			entry += " (not shown on Codex or DeepSeek Harness, nor for tool output on Hermes Agent)" // 这几处显示不了提示
		}
		out = append(out, entry)
	}
	// 只有类别题、没有本地规则的类别由模型检查，命中只提示；Codex 与 DeepSeek Harness 显示不了提示，在那里不检查，
	// Hermes Agent 的工具输出同样不检查
	if judgeUsable && s.cfg.OutboundJudge() {
		for _, name := range slices.Sorted(maps.Keys(s.cfg.Outbound.Categories)) {
			if c := s.cfg.Category(name); c.Enabled && c.Question != nil && active[name] == nil && (name != "pii" || piiConsent) {
				out = append(out, name+" warn (judge only, not on Codex or DeepSeek Harness, nor for tool output on Hermes Agent)")
			}
		}
	}
	return out
}

// readRuleEnabled 报告有没有启用的读文件规则（sensitive_read 等）。
func readRuleEnabled(set *rules.Set) bool {
	if set == nil {
		return false
	}
	return slices.ContainsFunc(set.All(), func(r *rules.Rule) bool { return r.Enabled() && r.AppliesTo(guard.ActionFileRead) })
}

// coverageGaps 是护栏照不到的地方（与 README 的已知限制一致），按当前配置写。
// judgeUsable 是判断后端真的能用（开启、后端构造得出、同意有效）：只是开启、还没同意时照样没有模型兜底。
func coverageGaps(s setup, judgeUsable bool) []string {
	var gaps []string
	// 读文件的命令：常见写法（cat、grep、head、< 文件……）在运行前按路径规则检查；其余写法只能靠事后扫描输出
	before := "secret files read in ways h-guard does not recognize as reading (python -c, a script, files passed through xargs or to a remote host) are not stopped before they run"
	switch {
	case !rules.TierCovers(s.cfg.Action.Tier, guard.ActionFileRead):
		before = "file reads, by file tools or shell commands (cat ~/.ssh/id_rsa), are not checked before they run below action.tier 2"
	case !readRuleEnabled(s.rules):
		before = "file reads, by file tools or shell commands (cat ~/.ssh/id_rsa), are not checked before they run: no file-read rule is enabled"
	}
	if s.cfg.Outbound.Tier < 2 {
		gaps = append(gaps, before+", and their output is not scanned below outbound.tier 2")
	} else {
		gaps = append(gaps, before+"; afterwards only the output of commands recognized as reading files is scanned")
	}
	gaps = append(gaps, "MCP and other tool calls have no built-in rules")
	switch {
	case !s.cfg.Judge.Enabled:
		gaps = append(gaps, "dangerous operations the rules' patterns miss (no judge to catch them)")
	case !judgeUsable:
		gaps = append(gaps, "dangerous operations the rules' patterns miss (the judge is on but cannot be used yet; see judge below)")
	}
	return gaps
}

func listOrNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

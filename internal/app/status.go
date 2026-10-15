package app

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/rules"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runStatus 报告状态（spec §12）：配置与缓存目录；判断层（模型开关、后端与目标、取答方式、同意、校准）；不生效的
// 规则及原因；各 harness 的入口是否安装、与期望是否一致、shell 配置与版本（M3d）；近 7 天的降级汇总与日志位置。
// 不发任何请求（只运行 harness 的 --version）。
// --config 与 hook、check、eval 一致：报告叠加了该文件之后的状态。
func runStatus(args []string, o Options) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, *extra)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	dir := func(d string) string {
		if d == "" {
			return "(unavailable: only built-in defaults are used)"
		}
		return d
	}
	fmt.Fprintln(o.Stdout, "config dir:", dir(o.ConfigDir))
	fmt.Fprintln(o.Stdout, "cache dir: ", dir(o.CacheDir))
	statusJudge(s, o)
	statusRules(s, o)
	statusHarnesses(s, o)
	statusHealth(o)
	return 0
}

func statusJudge(s setup, o Options) {
	if !s.cfg.Judge.Enabled {
		fmt.Fprintln(o.Stdout, "judge: disabled (the six dangerous-operation rules do not interrupt; h-guard init turns it on)")
		return
	}
	st := s.inspectJudge(o, s.cfg.Judge.Backend)
	fmt.Fprintf(o.Stdout, "judge: enabled, backend %s (%s) %s\n", st.name, st.typ, targetOf(st))
	fmt.Fprintln(o.Stdout, "answers:", answersText(st))
	if plaintextHTTP(describedTarget(st)) {
		fmt.Fprintln(o.Stdout, "warning:", plaintextWarning)
	}
	fmt.Fprintln(o.Stdout, "consent:", consentText(st, s.extra))
	fmt.Fprintln(o.Stdout, "calibration:", calibrationText(st))
	if own := s.ownQuestions(); len(own) > 0 {
		fmt.Fprintf(o.Stdout, "not calibrated: your rules %s ask their own questions, which no profile covers\n", strings.Join(own, ", "))
	}
	if st.consent != consentGranted {
		fmt.Fprintln(o.Stdout, "the judge is not called until consent is given; rule hits ask for confirmation (judge_consent_missing)")
	}
}

// statusRules 列出不生效的规则与原因（spec §4 规则状态）。
func statusRules(s setup, o Options) {
	reasons := map[string]string{rules.InactiveDisabled: "disabled", rules.InactiveTier: "action tier", rules.InactiveJudgeDisabled: "judge disabled"}
	var off []string
	for _, r := range s.rules.All() {
		if st := rules.StateOf(r, s.cfg.Action.Tier, s.cfg.Judge.Enabled); !st.Effective {
			off = append(off, fmt.Sprintf("%s (%s)", r.ID, reasons[st.Inactive]))
		}
	}
	if len(off) > 0 {
		fmt.Fprintln(o.Stdout, "rules not in effect:", strings.Join(off, ", "))
	}
	// 停用的硬规则显著提示，与 install、config validate 相同（M3d 终审 M-10）
	for _, r := range s.rules.All() {
		if r.Locked && !r.Enabled() {
			fmt.Fprintf(o.Stdout, "warning: hard rule %q is disabled; it does not protect anything until you turn it back on\n", r.ID)
		}
	}
}

// statusHarnesses 报告各 harness 的入口（install.Inspect）与 Codex 的 shell 配置。
func statusHarnesses(s setup, o Options) {
	if o.Home == "" {
		return
	}
	t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, GOOS: o.GOOS, Getenv: o.Getenv, Run: o.RunHarness, Now: o.Now}
	for _, h := range []string{"claudecode", "codex"} {
		for _, line := range install.Inspect(t, h) {
			fmt.Fprintf(o.Stdout, "%s: %s\n", h, line)
		}
	}
	fmt.Fprintf(o.Stdout, "codex commands are checked as %s (harnesses.codex.shell)\n", s.cfg.ShellFor("codex"))
}

// statusHealth 汇总近 7 天健康记录里的降级原因码（按次数从多到少），并写明日志位置。
func statusHealth(o Options) {
	if o.CacheDir == "" {
		return
	}
	dir := filepath.Join(o.CacheDir, "health")
	counts := map[string]int{}
	now := o.Now()
	for d := 0; d < 7; d++ {
		b, err := os.ReadFile(filepath.Join(dir, now.AddDate(0, 0, -d).Format("2006-01-02")+".jsonl"))
		if err != nil {
			continue
		}
		for _, line := range bytes.Split(b, []byte("\n")) {
			var rec struct {
				Code string `json:"code"`
			}
			if json.Unmarshal(line, &rec) == nil && rec.Code != "" {
				counts[rec.Code]++
			}
		}
	}
	codes := slices.SortedFunc(maps.Keys(counts), func(a, b string) int {
		if counts[a] != counts[b] {
			return counts[b] - counts[a]
		}
		return strings.Compare(a, b)
	})
	if len(codes) == 0 {
		fmt.Fprintln(o.Stdout, "degradations in the last 7 days: none")
	} else {
		parts := make([]string, len(codes))
		for i, c := range codes {
			parts[i] = fmt.Sprintf("%s %d", c, counts[c])
		}
		fmt.Fprintln(o.Stdout, "degradations in the last 7 days:", strings.Join(parts, ", "))
	}
	fmt.Fprintln(o.Stdout, "health records:", dir)
	fmt.Fprintln(o.Stdout, "decision log:", filepath.Join(o.CacheDir, "logs"), "(log.decisions)")
}

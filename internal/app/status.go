package app

import (
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runStatus 报告判断层的状态（spec §12 status 的判断层部分，M2）：模型开关、后端与目标、同意、校准，
// 以及配置与缓存目录。不发任何请求。档位、规则、各 harness 与近 7 天降级汇总在后续里程碑加入。
func runStatus(args []string, o Options) int {
	if len(args) != 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, "")
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
	if !s.cfg.Judge.Enabled {
		fmt.Fprintln(o.Stdout, "judge: disabled (the six dangerous-operation rules do not interrupt; set judge.enabled to turn it on)")
		return 0
	}
	st := s.inspectJudge(o, s.cfg.Judge.Backend)
	fmt.Fprintf(o.Stdout, "judge: enabled, backend %s (%s) %s\n", st.name, st.typ, targetOf(st))
	fmt.Fprintln(o.Stdout, "consent:", consentText(st))
	fmt.Fprintln(o.Stdout, "calibration:", calibrationText(st))
	if own := s.ownQuestions(); len(own) > 0 {
		fmt.Fprintf(o.Stdout, "not calibrated: your rules %s ask their own questions, which no profile covers\n", strings.Join(own, ", "))
	}
	if st.consent != consentGranted {
		fmt.Fprintln(o.Stdout, "the judge is not called until consent is given; rule hits ask for confirmation (judge_consent_missing)")
	}
	return 0
}

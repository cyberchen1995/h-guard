package app

import (
	"bufio"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runBackend 管理后端的同意（spec §8.5、§12）：
//
//	backend list               列出配置的后端、同意与校准状态
//	backend enable <name>      说明将发送的数据与目标，终端里确认后记录同意（范围 action）
//	backend disable <name>     撤回同意（不需要终端：只会让判断层停用）
func runBackend(args []string, o Options) int {
	if len(args) == 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	s, err := load(o, "")
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	switch {
	case args[0] == "list" && len(args) == 1:
		for _, name := range slices.Sorted(maps.Keys(s.cfg.Backends)) {
			st := s.inspectJudge(o, name)
			mark := " "
			if name == s.cfg.Judge.Backend {
				mark = "*"
			}
			fmt.Fprintf(o.Stdout, "%s %s (%s) %s\n    consent: %s\n    calibration: %s\n", mark, name, st.typ,
				targetOf(st), consentText(st), calibrationText(st))
		}
		return 0
	case args[0] == "enable" && len(args) == 2:
		return enableBackend(s, o, args[1])
	case args[0] == "disable" && len(args) == 2:
		if o.ConfigDir == "" {
			fmt.Fprintln(o.Stderr, "h-guard: the config directory is unavailable")
			return 1
		}
		removed, err := consent.Store{Dir: o.ConfigDir}.Revoke(args[1])
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		if removed {
			fmt.Fprintf(o.Stdout, "consent for %s withdrawn\n", shown(args[1]))
		} else {
			fmt.Fprintf(o.Stdout, "no consent recorded for %s\n", shown(args[1]))
		}
		return 0
	}
	fmt.Fprint(o.Stderr, usage)
	return 2
}

func enableBackend(s setup, o Options, name string) int {
	if _, ok := s.cfg.Backends[name]; !ok {
		fmt.Fprintf(o.Stderr, "h-guard: no backend named %q in the config\n", shown(name))
		return 1
	}
	st := s.inspectJudge(o, name)
	switch {
	case st.err != nil:
		fmt.Fprintln(o.Stderr, "h-guard: backend", shown(name)+":", shown(st.err.Error()))
		return 1
	case st.identity.Target == "":
		fmt.Fprintf(o.Stderr, "h-guard: backend %s does not say where it sends data, so it cannot be enabled\n", name)
		return 1
	case !o.IsTerminal():
		fmt.Fprintln(o.Stderr, "h-guard:", errNoTerminal)
		return 1
	}
	fmt.Fprintf(o.Stdout, "Backend %s (%s) will receive, for every command the agent runs that the judge checks:\n", name, st.typ)
	fmt.Fprintf(o.Stdout, "  - the command, its working directory, the harness and the tool name;\n")
	fmt.Fprintf(o.Stdout, "  - up to %d of the user's most recent instructions in the session.\n", s.cfg.Policy.RequestWindow)
	fmt.Fprintf(o.Stdout, "Credentials that h-guard recognizes are masked before sending; anything it does not recognize is sent as is.\n")
	if st.typ == "exec" {
		fmt.Fprintf(o.Stdout, "The data is handed to the program %s; where it goes from there is up to the program.\n", shown(st.identity.Target))
	} else {
		fmt.Fprintf(o.Stdout, "Destination: %s\n", shown(st.identity.Target))
	}
	fmt.Fprintf(o.Stdout, "Changing the destination, the program or its arguments withdraws this consent.\nAllow? [y/N] ")
	answer, _ := bufio.NewReader(o.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		fmt.Fprintln(o.Stdout, "not enabled")
		return 1
	}
	if err := (consent.Store{Dir: o.ConfigDir}).Grant(st.identity, []consent.Scope{consent.ScopeAction}, o.Now()); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprintf(o.Stdout, "consent recorded for %s\n", name)
	if !s.cfg.Judge.Enabled || s.cfg.Judge.Backend != name {
		fmt.Fprintf(o.Stdout, "note: the judge uses it only with judge: {enabled: true, backend: %s} in the config\n", name)
	}
	return 0
}

// targetOf 返回后端目标的显示形式（exec 的参数里可能带 token，显示前遮蔽）。
func targetOf(st judgeState) string {
	if st.identity.Target != "" {
		return shown(st.identity.Target)
	}
	if st.err != nil {
		return "(invalid: " + shown(st.err.Error()) + ")"
	}
	return "(target unknown)"
}

func consentText(st judgeState) string {
	switch st.consent {
	case consentGranted:
		return "granted " + st.record.Granted.Format("2006-01-02") + " (scope: action)"
	case consentChanged:
		return "withdrawn: it was given for " + shown(st.record.Target) + ", not the current target; run h-guard backend enable " + st.name
	case consentMissing:
		return "missing; run h-guard backend enable " + st.name
	}
	return "unavailable"
}

func calibrationText(st judgeState) string {
	th := st.thresholds
	if st.backend == nil {
		return "unknown"
	}
	if st.cal.Calibrated() {
		return fmt.Sprintf("profile %s (hit %g, veto %g, requested %g)", st.cal.Profile, th.Hit, th.Veto, th.Requested)
	}
	where := ""
	if st.cal.Profile != "" {
		where = " for profile " + st.cal.Profile
	}
	return fmt.Sprintf("uncalibrated (%s%s); conservative thresholds hit %g, veto %g, requested %g; run h-guard eval --sweep",
		st.cal.Reason, where, th.Hit, th.Veto, th.Requested)
}

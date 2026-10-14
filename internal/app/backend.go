package app

import (
	"bufio"
	"flag"
	"fmt"
	"maps"
	"net"
	"net/url"
	"runtime"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// plaintextWarning 是明文 HTTP 目标的警告（status、backend list 与 backend enable 共用）。
const plaintextWarning = "data and the API key go over unencrypted HTTP"

// runBackend 管理后端的同意（spec §8.5、§12）：
//
//	backend list               列出配置的后端、取答方式、同意与校准状态
//	backend enable <name>      说明将发送的数据与目标，终端里确认后记录同意（范围 action）
//	backend disable <name>     撤回同意（不需要终端，也不读配置：配置出错时照样能撤回）
//
// --config 与 hook、check、eval 一致：叠加一个配置文件（必须存在），只在其中定义的后端同样能列出与同意。
func runBackend(args []string, o Options) int {
	fs := flag.NewFlagSet("backend", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	extra := fs.String("config", "", "extra config file")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) == 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if pos[0] == "disable" && len(pos) == 2 {
		// 撤回同意只会收紧，只用配置目录里的同意记录：不读配置，配置出错（含能力校验）时照样能撤回
		return disableBackend(o, pos[1])
	}
	s, err := load(o, *extra)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	switch {
	case pos[0] == "list" && len(pos) == 1:
		for _, name := range slices.Sorted(maps.Keys(s.cfg.Backends)) {
			st := s.inspectJudge(o, name)
			mark := " "
			if name == s.cfg.Judge.Backend {
				mark = "*"
			}
			fmt.Fprintf(o.Stdout, "%s %s (%s) %s\n    answers: %s\n", mark, name, st.typ, targetOf(st), answersText(st))
			if plaintextHTTP(describedTarget(st)) {
				fmt.Fprintf(o.Stdout, "    warning: %s\n", plaintextWarning)
			}
			fmt.Fprintf(o.Stdout, "    consent: %s\n    calibration: %s\n", consentText(st, s.extra), calibrationText(st))
		}
		return 0
	case pos[0] == "enable" && len(pos) == 2:
		return enableBackend(s, o, pos[1])
	}
	fmt.Fprint(o.Stderr, usage)
	return 2
}

// disableBackend 撤回后端 name 的同意（不需要终端：只会让判断层停用）。--config 对它没有作用。
func disableBackend(o Options, name string) int {
	if o.ConfigDir == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the config directory is unavailable")
		return 1
	}
	removed, err := consent.Store{Dir: o.ConfigDir}.Revoke(name)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	if removed {
		fmt.Fprintf(o.Stdout, "consent for %s withdrawn\n", shown(name))
	} else {
		fmt.Fprintf(o.Stdout, "no consent recorded for %s\n", shown(name))
	}
	return 0
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
	if plaintextHTTP(st.identity.Target) {
		fmt.Fprintf(o.Stdout, "Warning: %s.\n", plaintextWarning)
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

// consentText 描述后端的同意状态；未同意时给出启用命令（enableHint）。extra 是本次 --config 的文件（setup.extra）。
func consentText(st judgeState, extra string) string {
	hint := enableHint(st.name, extra)
	switch st.consent {
	case consentGranted:
		return "granted " + st.record.Granted.Format("2006-01-02") + " (scope: action)"
	case consentChanged:
		switch r := st.record.Identity; {
		case r == st.identity: // 身份相同，只是范围里没有 action（如只同意过 outbound）
			return "given without the action scope; " + hint
		case r.Target == st.identity.Target:
			return "withdrawn: it was given for a backend of type " + shown(r.Type) + "; " + hint
		}
		return "withdrawn: it was given for " + shown(st.record.Target) + ", not the current target; " + hint
	case consentMissing:
		return "missing; " + hint
	}
	return "unavailable"
}

// enableHint 是同意提示里的启用命令。status、backend list 用了 --config 时带上同一个文件（load 记下的绝对路径）：
// 启用命令会重新加载配置，少了它就找不到只在该文件里定义的后端，或者给内置同名后端的另一个目标记录同意（评审 M3A-01）。
// 后端名已经过 guard.ValidName，不需要引用。路径先遮蔽（shown）再引用：引用会改写单引号，token='…' 这类凭据形状
// 引用之后就认不出，输出边界也遮不住（评审 R2-01）。形似凭据的路径遮蔽后不能照抄，这是接受的限制。
func enableHint(name, extra string) string {
	hint := "run h-guard backend enable " + name
	if extra != "" {
		hint += " --config " + shellQuote(shown(extra), runtime.GOOS == "windows")
	}
	return hint
}

// shellQuote 用单引号引起 s，供用户照抄进 shell。s 里的单引号：POSIX shell 里先结束引用、转义、再开始引用，
// PowerShell（windows 为真）里写两次。Windows 的 cmd.exe 不认单引号，提示按 PowerShell 写。
func shellQuote(s string, windows bool) string {
	if windows {
		return "'" + strings.ReplaceAll(s, "'", "''") + "'"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
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
	// 陈述现状，不要求用户去校准：保守阈值本身是可用的默认值，校准是进阶用法（eval --sweep）
	return fmt.Sprintf("uncalibrated (%s%s); conservative thresholds hit %g, veto %g, requested %g",
		st.cal.Reason, where, th.Hit, th.Veto, th.Requested)
}

// answersText 描述后端怎样取答：取答方式（Caps().Mechanism）、能回答的题型（Caps().Kinds），以及进入校准指纹的
// 概率获取方式（Describe().Probability，含 anthropic 的取答方式与 effort、temperature 后缀）。
// 第三方后端的取值不受控，显示前遮蔽。
func answersText(st judgeState) string {
	if st.backend == nil {
		return "unknown"
	}
	caps := st.backend.Caps()
	mechanism := string(caps.Mechanism)
	if mechanism == "" {
		mechanism = "unspecified"
	}
	kinds := "all kinds" // Kinds 为 nil：没有声明，按全部题型处理
	if caps.Kinds != nil {
		ks := make([]string, len(caps.Kinds))
		for i, k := range caps.Kinds {
			ks[i] = string(k)
		}
		kinds = strings.Join(ks, ", ")
		if len(ks) == 0 {
			kinds = "no kinds"
		}
	}
	probability := "unknown"
	if d, ok := st.backend.(judge.Describer); ok && d.Describe().Probability != "" {
		probability = d.Describe().Probability
	}
	return shown(fmt.Sprintf("%s (%s); probability: %s", mechanism, kinds, probability))
}

// describedTarget 返回后端自己说明的目标（judge.Info.Target）；后端没有构造出来或说不出目标时为空。
// 不依赖同意身份：配置目录取不到时身份为空，警告照样要给。
func describedTarget(st judgeState) string {
	if d, ok := st.backend.(judge.Describer); ok {
		return d.Describe().Target
	}
	return ""
}

// plaintextHTTP 报告目标是否是明文 http://、且主机不是本机回环（localhost、127.0.0.0/8、::1）：数据与 API key
// 会不加密地经过网络。exec 后端的目标（带引号的程序路径）与 https 都不是。主机名结尾的一个点（完全限定写法，
// 如 localhost.）是同一个主机，比较前去掉。
func plaintextHTTP(target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.Hostname() == "" {
		return false
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

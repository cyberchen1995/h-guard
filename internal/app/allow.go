package app

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/grant"
)

// grantStore 是单次授权的记录目录（缓存目录下的 grants）。
func grantStore(o Options) *grant.Store {
	return &grant.Store{Dir: under(o.CacheDir, "grants"), KeyPath: under(o.ConfigDir, "grant.key"), Now: o.Now}
}

// runAllow 是单次授权：不带编号时列出最近被拦下、可以批准的操作；带编号时显示这次操作的全部内容，在终端里确认后
// 批准它一次（--ttl 内有效，用过即失效）；--revoke 撤销还没用掉的批准。
// 批准只能在交互终端里进行，agent 经由 hook 运行它会被护栏自我保护拦下（guard_tampering）。
func runAllow(args []string, o Options) int {
	fs := flag.NewFlagSet("allow", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	ttl := fs.Duration("ttl", grant.DefaultTTL, "how long the approval stays valid (at most 1h)")
	revoke := fs.Bool("revoke", false, "withdraw an approval that has not been used yet")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) > 1 || (*revoke && len(pos) != 1) {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	st := grantStore(o)
	if st.Dir == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the cache directory is unavailable")
		return 1
	}
	if len(pos) == 0 {
		return listPending(o, st)
	}
	id := strings.ToLower(strings.TrimSpace(pos[0]))
	if *revoke {
		if err := st.Revoke(id); err != nil {
			fmt.Fprintf(o.Stderr, "h-guard: nothing to revoke for %s\n", id)
			return 1
		}
		fmt.Fprintf(o.Stdout, "revoked %s\n", id)
		return 0
	}
	if *ttl < time.Second || *ttl > grant.MaxTTL {
		fmt.Fprintln(o.Stderr, "h-guard: --ttl must be between 1s and 1h")
		return 2
	}
	p, err := st.Lookup(id)
	if err != nil {
		fmt.Fprintf(o.Stderr, "h-guard: %v; run h-guard allow to list what can be approved\n", err)
		return 1
	}
	if !o.IsTerminal() {
		fmt.Fprintln(o.Stderr, "h-guard:", errNoTerminal)
		return 1
	}
	fmt.Fprintln(o.Stdout, "h-guard stopped this operation:")
	printPending(o, p)
	fmt.Fprintf(o.Stdout, "Allow exactly this operation once, within the next %s? The agent has to retry it unchanged. [y/N] ", *ttl)
	answer, _ := bufio.NewReader(o.Stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		fmt.Fprintln(o.Stdout, "not approved")
		return 1
	}
	g, err := st.Approve(p, *ttl)
	if err != nil {
		if errors.Is(err, grant.ErrNotFound) || errors.Is(err, grant.ErrChanged) {
			fmt.Fprintf(o.Stderr, "h-guard: %v\n", err)
		} else {
			fmt.Fprintln(o.Stderr, "h-guard: cannot record the approval:", err)
		}
		return 1
	}
	fmt.Fprintf(o.Stdout, "approved once until %s; ask the agent to retry the same operation (h-guard allow --revoke %s withdraws it)\n",
		g.Expires.Local().Format("15:04:05"), id)
	return 0
}

func listPending(o Options, st *grant.Store) int {
	list := st.List()
	if len(list) == 0 {
		fmt.Fprintln(o.Stdout, "nothing to approve: no operation was stopped in the last hour on a harness that cannot ask for confirmation")
		return 0
	}
	fmt.Fprintln(o.Stdout, "stopped in the last hour (approve one with h-guard allow <id>):")
	for _, p := range list {
		printPending(o, p)
	}
	return 0
}

func printPending(o Options, p grant.Pending) {
	ago := o.Now().Sub(p.Created).Round(time.Second)
	where := action.Visible(p.Op.Cwd)
	if where == "" {
		where = "(unknown directory)"
	}
	if p.Op.RealCwd != "" && p.Op.RealCwd != p.Op.Cwd {
		where += " (really " + action.Visible(p.Op.RealCwd) + ")"
	}
	session := ""
	if p.Op.Session != "" {
		session = " (session " + action.Visible(p.Op.Session) + ")"
	}
	fmt.Fprintf(o.Stdout, "  %s  %s ago  %s%s in %s\n", p.ID, ago, action.Visible(p.Op.Harness), session, where)
	for _, a := range p.Op.Actions {
		fmt.Fprintf(o.Stdout, "      %s\n", action.Visible(a))
	}
	if p.Op.Input != "" {
		// 原始工具输入原样显示：执行参数（如工作目录覆盖）只在这里看得到
		fmt.Fprintf(o.Stdout, "      tool %s input: %s\n", action.Visible(p.Op.Tool), action.Visible(p.Op.Input))
	}
	if len(p.Rules) > 0 {
		fmt.Fprintf(o.Stdout, "      rules: %s\n", strings.Join(p.Rules, ", "))
	}
}

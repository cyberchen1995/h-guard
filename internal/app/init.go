package app

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	"github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

// recommended 是推荐后端的显示顺序（spec §8.3：名字稳定、带预置档案）。
var recommended = []string{"claude-haiku", "claude-sonnet", "gemma4-local", "jev"}

// runInit 是引导（spec §12，backlog §3.4）：选定后端，当场说明将发送的数据与目标并确认一次（与 backend enable
// 相同），记录 action 范围的同意，再在配置里开启模型、设置档位。用户拒绝时不记录同意、不开启模型。
// 只在交互终端里运行；agent 在 hook 下运行它会被护栏自我保护拦下请求确认（M3d）。
func runInit(args []string, o Options) int {
	if len(args) != 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if !o.IsTerminal() {
		fmt.Fprintln(o.Stderr, "h-guard: init needs an interactive terminal; otherwise run h-guard backend enable <name> in a terminal and set judge: {enabled: true, backend: <name>} in the config")
		return 1
	}
	if o.ConfigDir == "" || o.CacheDir == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the config or cache directory is unavailable")
		return 1
	}
	s, err := load(o, "")
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	names := slices.DeleteFunc(slices.Clone(recommended), func(n string) bool { _, ok := s.cfg.Backends[n]; return !ok })
	for _, n := range slices.Sorted(maps.Keys(s.cfg.Backends)) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	fmt.Fprintln(o.Stdout, "The judge (a model) decides whether commands like git push or rm -rf were asked for. Backends:")
	for i, n := range names {
		st := s.inspectJudge(o, n)
		fmt.Fprintf(o.Stdout, "  %d) %s (%s) %s\n", i+1, n, st.typ, targetOf(st))
	}
	def := names[0]
	if s.cfg.Judge.Enabled {
		def = s.cfg.Judge.Backend
	}
	in := bufio.NewReader(o.Stdin)
	fmt.Fprintf(o.Stdout, "Backend (number or name) [%s]: ", def)
	answer, _ := in.ReadString('\n')
	name := strings.TrimSpace(answer)
	if name == "" {
		name = def
	}
	if i, err := strconv.Atoi(name); err == nil && i >= 1 && i <= len(names) {
		name = names[i-1]
	}
	if !slices.Contains(names, name) {
		fmt.Fprintf(o.Stderr, "h-guard: no backend named %q\n", shown(name))
		return 2
	}
	if env := keyEnv(s.cfg.Backends[name]); env != "" && os.Getenv(env) == "" {
		// 后端读 key 用的是进程环境（含配置目录的 .env）；harness 启动 hook 时的环境可能不同，这里只能按当前终端判断
		fmt.Fprintf(o.Stdout, "%s is not set in this terminal: without it every call fails, and rule hits ask for confirmation (judge_unavailable).\n", env)
		fmt.Fprintf(o.Stdout, "Set it where the harness can see it (or in %s), then run h-guard init again. Continue anyway? [y/N] ", filepath.Join(o.ConfigDir, ".env"))
		answer, _ = in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(o.Stdout, "the judge stays off")
			return 1
		}
	}
	if code := enableBackend(s, o, name, in, true); code != 0 {
		fmt.Fprintln(o.Stdout, "the judge stays off")
		return code
	}
	// 档位的默认回答取当前配置
	tier := "1"
	prompt := "[y/N]"
	if s.cfg.Action.Tier >= 2 {
		tier, prompt = strconv.Itoa(s.cfg.Action.Tier), "[Y/n]"
	}
	fmt.Fprintf(o.Stdout, "Also check file reads, writes, deletes and renames (action tier 2)? %s ", prompt)
	answer, _ = in.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		if s.cfg.Action.Tier < 2 {
			tier = "2"
		}
	case "n", "no":
		tier = "1"
	}
	t := install.Target{ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, Now: o.Now}
	step, err := install.ConfigValues(t, "turn on the judge", []install.Value{
		{Path: []string{"judge", "enabled"}, Value: "true", Tag: "!!bool"},
		{Path: []string{"judge", "backend"}, Value: name, Tag: "!!str"},
		{Path: []string{"action", "tier"}, Value: tier, Tag: "!!int"},
	})
	if err == nil {
		err = install.Apply([]install.Step{step})
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		fmt.Fprintf(o.Stderr, "h-guard: the consent for %s is recorded, but the judge is still off; set judge: {enabled: true, backend: %s} in the config\n", name, name)
		return 1
	}
	fmt.Fprintf(o.Stdout, "judge enabled with backend %s (action tier %s) in %s; h-guard status shows the details\n", name, tier, step.Path)
	return 0
}

// keyEnv 返回后端读 API key 的环境变量：配置的 api_key_env，没有时按类型的默认值（anthropic、typesafe）；
// 不需要 key 的后端（本地 openai 兼容服务、exec）为空。
func keyEnv(b config.BackendConfig) string {
	if v := b.Option("api_key_env"); v != "" {
		return v
	}
	switch b.Type {
	case "anthropic":
		return anthropic.DefaultAPIKeyEnv
	case "typesafe":
		return typesafe.DefaultAPIKeyEnv
	}
	return ""
}

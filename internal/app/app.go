// Package app 是 h-guard 命令行的实现，提供 hook、check、backend、status、selftest、allow、eval、install、config、init、migrate、version 命令。
package app

import (
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/check/outbound"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/cyberchen1995/h-guard/pkg/guard"

	_ "github.com/cyberchen1995/h-guard/pkg/harness/claudecode" // 内置 adapter
	_ "github.com/cyberchen1995/h-guard/pkg/harness/codex"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/dsh"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/generic"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/openclaw"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/opencode"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/pi"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic" // 内置判断后端
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/openai"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

// Version 是显示的版本号：构建时的 -ldflags 设置的优先，其次是模块版本（go install 安装的版本），都没有时是 dev。
var Version = "dev"

// buildID 是运行与自测记录里的版本：Version 加上可执行文件的大小与修改时间。原地重新构建（本地构建都叫 dev）
// 或换成另一个同版本号的程序之后，之前的记录不再算数。
var buildID = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return Version
	}
	fi, err := os.Stat(exe)
	if err != nil {
		return Version
	}
	return fmt.Sprintf("%s+%x.%x", Version, fi.Size(), fi.ModTime().UnixNano())
})

func init() {
	bi, ok := debug.ReadBuildInfo()
	Version = versionString(Version, bi, ok)
}

// versionString 在没有构建时注入的版本号（ldflags 为 dev）时取模块版本，去掉前导 v；
// (devel) 与空串不算版本。
func versionString(ldflags string, bi *debug.BuildInfo, ok bool) string {
	if ldflags != "dev" {
		return ldflags
	}
	if ok && bi != nil {
		if v := strings.TrimPrefix(bi.Main.Version, "v"); bi.Main.Version != "(devel)" && v != "" {
			return v
		}
	}
	return ldflags
}

// Options 是一次运行的外部依赖；零值字段取进程默认值。测试用它隔离目录与输入输出。
type Options struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Now            func() time.Time
	// 默认 store.ConfigDir()、store.CacheDir()。取不到时为空：不读用户配置、规则与 .env（只用内置默认），
	// 也不写指令缓存与日志——不能退回相对路径，否则当前项目里的文件会配置护栏、提示词会写进项目。
	ConfigDir string
	CacheDir  string
	// Home 是用户主目录，用于展开文件动作目标与保护路径中的 ~；默认 os.UserHomeDir()，取不到时为空。
	Home string
	// IsTerminal 报告是否在交互终端里运行（backend enable 只在终端里确认）；默认看 stdin 是否是字符设备。
	IsTerminal func() bool
	// Executable 返回写进 harness 入口的 h-guard 路径（install）；默认见 stableExecutable。
	Executable func() (string, error)
	// RunHarness 运行 harness 的命令行（取版本、校验插件），默认在 PATH 中查找并限时 10 秒；找不到时返回错误。
	RunHarness func(name string, args ...string) ([]byte, error)
	// QueryHarness 运行 harness 的只读查询命令（如 openclaw plugins inspect），只取标准输出，命令失败时也返回已有的
	// 输出；默认在 PATH 中查找并限时 60 秒，不经 shell、没有标准输入。
	QueryHarness func(name string, args ...string) ([]byte, error)
	// RunEntry 运行 harness 的一个 h-guard 入口（selftest）：argv 不经 shell，env 追加到本进程的环境，stdin 是输入；
	// 默认限时 30 秒。
	RunEntry func(argv, env []string, stdin []byte) ([]byte, error)
	// GOOS 是目标平台，默认 runtime.GOOS。
	GOOS string
}

// under 返回 dir 下的 name；dir 为空（目录取不到）时返回空串，调用方据此跳过读写。
func under(dir, name string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, name)
}

func (o *Options) fill() {
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ConfigDir == "" {
		o.ConfigDir, _ = store.ConfigDir()
	}
	if o.CacheDir == "" {
		o.CacheDir, _ = store.CacheDir()
	}
	if o.Executable == nil {
		o.Executable = stableExecutable
	}
	if o.RunHarness == nil {
		o.RunHarness = runHarness
	}
	if o.QueryHarness == nil {
		o.QueryHarness = queryHarness
	}
	if o.RunEntry == nil {
		o.RunEntry = runEntry
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.Home == "" {
		o.Home, _ = os.UserHomeDir()
	}
	if o.IsTerminal == nil {
		o.IsTerminal = func() bool {
			fi, err := os.Stdin.Stat()
			return err == nil && fi.Mode()&os.ModeCharDevice != 0
		}
	}
}

const usage = `usage:
  h-guard hook <harness> --event <event> [--timeout <seconds>] [--config <file>]
  h-guard check <command> [--shell posix|powershell] [--request <text>]... [--cwd <dir>] [--no-judge] [--show-request] [--config <file>]
  h-guard backend list | enable <name> | disable <name> [--config <file>]
  h-guard status [--config <file>]
  h-guard selftest [claudecode|codex]
  h-guard allow [<id> [--ttl <duration>] | --revoke <id>]
  h-guard eval [--backend <name>] [--sweep] [--shell posix|powershell | --cases <file>] [--repeat <K>] [--bootstrap <N>] [--seed <n>] [--yes] [--config <file>]
  h-guard eval --outbound [--backend <name>] [--sweep] [--threshold <t>] [--cases <file>] [--yes] [--config <file>]
  h-guard init
  h-guard install claudecode|codex|opencode|pi|omp|dsh|openclaw [--write] [--remove] [--timeout <seconds>] [--shell posix|powershell]
  h-guard migrate <questions.json> [--write]
  h-guard config validate [--rules <dir>] | show | init [--config <file>]
  h-guard version
`

// Main 运行命令并返回退出码。
func Main(args []string, o Options) int {
	o.fill()
	if len(args) == 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if args[0] != "hook" {
		// CLI 输出的最终边界：后端名、profile 名、规则 id、路径、目标、错误说明等动态内容都可能带凭据，
		// 写到终端前统一遮蔽。内部的身份、指纹与文件操作用原值。
		// hook 的输出是 harness 协议，原因文本由 Engine 生成，不经过这里。
		o.Stdout, o.Stderr = maskingWriter{o.Stdout}, maskingWriter{o.Stderr}
	}
	switch args[0] {
	case "hook":
		return runHook(args[1:], o)
	case "check":
		return runCheck(args[1:], o)
	case "backend":
		return runBackend(args[1:], o)
	case "status":
		return runStatus(args[1:], o)
	case "selftest":
		return runSelftest(args[1:], o)
	case "allow":
		return runAllow(args[1:], o)
	case "eval":
		return runEval(args[1:], o)
	case "install":
		return runInstall(args[1:], o)
	case "config":
		return runConfig(args[1:], o)
	case "init":
		return runInit(args[1:], o)
	case "migrate":
		return runMigrate(args[1:], o)
	case "version":
		fmt.Fprintln(o.Stdout, "h-guard", Version)
		return 0
	case "-h", "--help", "help":
		fmt.Fprint(o.Stdout, usage)
		return 0
	}
	fmt.Fprintf(o.Stderr, "h-guard: unknown command %q\n%s", args[0], usage)
	return 2
}

// parseInterleaved 允许位置参数与选项交错（check "git push" --shell posix）。
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// setup 是一次判断需要的配置、规则与消息目录。
type setup struct {
	cfg     *config.Config
	rules   *rules.Set
	catalog *i18n.Catalog
	locale  string
	// extra 是 --config 加载的配置文件的绝对路径（相对路径按进程的工作目录解析，与打开它时一致）；没有时为空。
	// 它与配置目录里的 config.yaml 一样控制护栏的行为，文件动作的自我保护覆盖它。
	extra string
}

// load 读取配置（内置默认 → 用户配置 → extra）、规则包（内置 → 用户目录）与 .env，并做配置期的能力校验
// （judgeKindsError）。
// 消息目录总能加载（内嵌）；返回的 setup 在出错时仍带 catalog 与 locale，供渲染兜底结论。
func load(o Options, extra string) (setup, error) { return loadConfig(o, extra, true) }

// loadConfig 同 load；checkKinds 为假时跳过配置期的题型校验，只给 check --no-judge 用：它不调用判断后端，
// 后端答不了哪些题与它无关，用户正要排查判断后端时本地规则也得能跑。
func loadConfig(o Options, extra string, checkKinds bool) (setup, error) {
	s := setup{locale: i18n.DefaultLocale}
	cat, err := i18n.Load()
	if err != nil {
		return s, err
	}
	s.catalog = cat
	s.locale = i18n.SelectLocale("", o.Getenv)
	if extra != "" {
		// 命令行指定的配置文件必须存在（用户配置目录里的 config.yaml 可以没有）
		if _, err := os.Stat(extra); err != nil {
			return s, &config.Error{File: extra, Issues: []config.Issue{{Path: "file", Msg: "cannot be read"}}}
		}
		if abs, err := filepath.Abs(extra); err == nil {
			s.extra = abs
		}
	}
	cfg, err := config.Load(under(o.ConfigDir, "config.yaml"), extra)
	if err != nil {
		return s, err
	}
	s.cfg = cfg
	s.locale = i18n.SelectLocale(cfg.Locale, o.Getenv)
	if checkKinds {
		if err := judgeKindsError(cfg); err != nil {
			return s, err
		}
	}
	set, err := rules.Load(under(o.ConfigDir, "rules"))
	if err != nil {
		return s, err
	}
	ov := rules.Overrides{}
	for id := range cfg.Rules {
		if on, ok := cfg.RuleEnabled(id); ok {
			ov[id] = on
		}
	}
	if _, err := set.Apply(ov); err != nil {
		return s, err
	}
	if err := judgeOnlyCategories(cfg, set); err != nil {
		return s, err
	}
	s.rules = set
	if o.ConfigDir == "" {
		return s, nil
	}
	if err := config.ApplyDotEnv(o.ConfigDir); err != nil {
		return s, &config.Error{File: filepath.Join(o.ConfigDir, ".env"), Issues: []config.Issue{{Path: "file", Msg: "cannot be read"}}}
	}
	return s, nil
}

// ompConfig 是 oh-my-pi 的配置根目录：主目录下的 $PI_CONFIG_DIR；没有设置时为空（{omp_config} 的模式不匹配，
// 默认的 ~/.omp 由 ~/ 开头的模式覆盖）。
func ompConfig(o Options) string {
	d := o.Getenv("PI_CONFIG_DIR")
	if d == "" || o.Home == "" {
		return ""
	}
	return filepath.Join(o.Home, d)
}

// piAgentDir 是 $PI_CODING_AGENT_DIR，开头的 ~ 与 pi 一样展开（install pi 写扩展的目录与它一致）；没有设置时为空。
func piAgentDir(o Options) string {
	d := o.Getenv("PI_CODING_AGENT_DIR")
	if d == "" || o.Home == "" {
		return d
	}
	return install.ExpandPiDir(o.Home, d)
}

// openclawConfig 是 OpenClaw 的配置文件（install openclaw 改写的 openclaw.json）。
func openclawConfig(o Options) string {
	if o.Home == "" {
		return ""
	}
	return install.OpenClawConfig(install.Target{Home: o.Home, Getenv: o.Getenv, GOOS: o.GOOS})
}

// openclawIncludes 是 OpenClaw 的配置用 $include 引入的文件。
func openclawIncludes(o Options) []string {
	if o.Home == "" {
		return nil
	}
	files, _ := install.OpenClawIncludes(install.Target{Home: o.Home, Getenv: o.Getenv, GOOS: o.GOOS})
	return files
}

// newEngine 组装 Engine：action 检查与 outbound 检查。文件动作的保护路径用主目录、h-guard 实际的配置与缓存目录，
// 以及这次 --config 加载的文件展开。
func (s setup) newEngine(o Options, j action.Judge, oj outbound.Judge) *engine.Engine {
	c := &action.Check{Rules: s.rules, Config: s.cfg, Catalog: s.catalog, Locale: s.locale, Judge: j,
		Paths: paths.Env{Home: o.Home, FoldCase: paths.FoldCaseDefault, Windows: paths.WindowsDefault,
			Vars: map[string]string{rules.VarConfig: o.ConfigDir, rules.VarCache: o.CacheDir, rules.VarExtraConfig: s.extra,
				rules.VarClaudeConfig: o.Getenv("CLAUDE_CONFIG_DIR"), rules.VarCodexHome: o.Getenv("CODEX_HOME"),
				rules.VarXDGConfig: o.Getenv("XDG_CONFIG_HOME"), rules.VarPiAgentDir: piAgentDir(o), rules.VarDSHHome: install.ExpandDSHHome(o.Home, o.Getenv("DSH_HOME")), rules.VarOMPConfig: ompConfig(o),
				rules.VarOpenClawConfig: openclawConfig(o)},
			Lists: map[string][]string{rules.VarOpenClawIncludes: openclawIncludes(o)}}}
	o2 := &outbound.Check{Rules: s.rules, Config: s.cfg, Judge: oj}
	return &engine.Engine{
		Checks: []guard.Check{c, o2}, Catalog: s.catalog, Locale: s.locale,
		WhenAskUnsupported: guard.Decision(s.cfg.Policy.WhenAskUnsupported),
	}
}

// outboundNotes 是 config validate 与 status 的提示（不是错误）：配置里写了、却没有任何规则引用也没有题目的类别
// 什么也不查，多半是名字写错；ownRules 为真时另列用户自己的、不生效的 outbound 规则。
func outboundNotes(s setup, ownRules bool) []string {
	used := map[string]bool{}
	for _, r := range s.rules.Outbound() {
		used[r.Category] = true
	}
	var notes []string
	for _, name := range slices.Sorted(maps.Keys(s.cfg.Outbound.Categories)) {
		if !used[name] && s.cfg.Category(name).Question == nil {
			notes = append(notes, "outbound category "+name+" has no rules and no question, so it checks nothing (is the name misspelled?)")
		}
	}
	if ownRules {
		why := map[string]string{rules.InactiveDisabled: "disabled", rules.InactiveCategory: "category disabled", rules.InactiveTier: "outbound tier"}
		for _, r := range s.rules.Outbound() {
			if st := rules.OutboundStateOf(r, s.cfg.Outbound.Tier, s.cfg.Category(r.Category).Enabled); !r.Builtin && !st.Effective {
				notes = append(notes, "your rule "+r.ID+" is not active ("+why[st.Inactive]+")")
			}
		}
	}
	return notes
}

// judgeOnlyCategories 报告完全依赖模型的 outbound 类别：启用、写了题目、却没有生效的本地规则（规则启用，
// 且当前档位扫描它查的某类事件），而模型关闭——这样的类别什么也查不出，是配置错误。错误指出类别与
// 开启方法。
func judgeOnlyCategories(cfg *config.Config, set *rules.Set) error {
	// outbound.judge: false 与模型关闭一样：outbound 不调用判断层，只靠题目的类别同样什么也查不出
	if cfg.Judge.Enabled && cfg.OutboundJudge() {
		return nil
	}
	why := "judge.enabled is false (run h-guard init, or add a rule with this category)"
	if cfg.Judge.Enabled {
		why = "outbound.judge is false (remove it, or add a rule with this category)"
	}
	local := map[string]bool{}
	for _, r := range set.Outbound() {
		if rules.OutboundStateOf(r, cfg.Outbound.Tier, true).Effective {
			local[r.Category] = true
		}
	}
	var issues []config.Issue
	for _, name := range slices.Sorted(maps.Keys(cfg.Outbound.Categories)) {
		if c := cfg.Category(name); c.Enabled && c.Question != nil && !local[name] {
			issues = append(issues, config.Issue{Path: "outbound.categories." + name,
				Msg: "has no enabled local rule and relies on the judge, but " + why})
		}
	}
	if len(issues) > 0 {
		return &config.Error{Issues: issues}
	}
	return nil
}

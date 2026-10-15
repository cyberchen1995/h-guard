// Package app 是 h-guard 命令行的实现（spec §12）。M2 提供 hook、check、backend、status、eval、version。
package app

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
	"github.com/cyberchen1995/h-guard/pkg/guard"

	_ "github.com/cyberchen1995/h-guard/pkg/harness/claudecode" // 内置 adapter
	_ "github.com/cyberchen1995/h-guard/pkg/harness/codex"
	_ "github.com/cyberchen1995/h-guard/pkg/harness/generic"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/anthropic" // 内置判断后端
	_ "github.com/cyberchen1995/h-guard/pkg/judge/exec"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/openai"
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

// Version 由构建时的 -ldflags 设置。
var Version = "dev"

// Options 是一次运行的外部依赖；零值字段取进程默认值。测试用它隔离目录与输入输出。
type Options struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Now            func() time.Time
	// 默认 store.ConfigDir()、store.CacheDir()。取不到时为空：不读用户配置、规则与 .env（只用内置默认），
	// 也不写指令缓存与日志——不能退回相对路径，否则当前项目里的文件会配置护栏、提示词会写进项目（评审 M1 终审）。
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
  h-guard eval [--backend <name>] [--sweep] [--shell posix|powershell | --cases <file>] [--repeat <K>] [--bootstrap <N>] [--seed <n>] [--yes] [--config <file>]
  h-guard init
  h-guard install claudecode|codex [--write] [--remove] [--timeout <seconds>] [--shell posix|powershell]
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
		// 写到终端前统一遮蔽（评审 M2-07、R2-03、R3-02）。内部的身份、指纹与文件操作用原值。
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
	case "eval":
		return runEval(args[1:], o)
	case "install":
		return runInstall(args[1:], o)
	case "config":
		return runConfig(args[1:], o)
	case "init":
		return runInit(args[1:], o)
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
	// 它与配置目录里的 config.yaml 一样控制护栏的行为，文件动作的自我保护覆盖它（评审 R3-03）。
	extra string
}

// load 读取配置（内置默认 → 用户配置 → extra）、规则包（内置 → 用户目录）与 .env，并做配置期的能力校验
// （judgeKindsError）。
// 消息目录总能加载（内嵌）；返回的 setup 在出错时仍带 catalog 与 locale，供渲染兜底结论。
func load(o Options, extra string) (setup, error) { return loadConfig(o, extra, true) }

// loadConfig 同 load；checkKinds 为假时跳过配置期的题型校验，只给 check --no-judge 用：它不调用判断后端，
// 后端答不了哪些题与它无关，用户正要排查判断后端时本地规则也得能跑（终审 M-1）。
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
	s.rules = set
	if o.ConfigDir == "" {
		return s, nil
	}
	if err := config.ApplyDotEnv(o.ConfigDir); err != nil {
		return s, &config.Error{File: filepath.Join(o.ConfigDir, ".env"), Issues: []config.Issue{{Path: "file", Msg: "cannot be read"}}}
	}
	return s, nil
}

// newEngine 组装 Engine：目前只有 action 检查。文件动作的保护路径用主目录、h-guard 实际的配置与缓存目录，
// 以及这次 --config 加载的文件展开。
func (s setup) newEngine(o Options, j action.Judge) *engine.Engine {
	c := &action.Check{Rules: s.rules, Config: s.cfg, Catalog: s.catalog, Locale: s.locale, Judge: j,
		Paths: paths.Env{Home: o.Home, FoldCase: paths.FoldCaseDefault, Windows: paths.WindowsDefault,
			Vars: map[string]string{rules.VarConfig: o.ConfigDir, rules.VarCache: o.CacheDir, rules.VarExtraConfig: s.extra,
				rules.VarClaudeConfig: o.Getenv("CLAUDE_CONFIG_DIR"), rules.VarCodexHome: o.Getenv("CODEX_HOME")}}}
	return &engine.Engine{
		Checks: []guard.Check{c}, Catalog: s.catalog, Locale: s.locale,
		WhenAskUnsupported: guard.Decision(s.cfg.Policy.WhenAskUnsupported),
	}
}

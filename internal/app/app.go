// Package app 是 h-guard 命令行的实现（spec §12）。M1 提供 hook、check、version。
package app

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/config"
	"github.com/cyberchen1995/h-guard/internal/engine"
	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/guard"

	_ "github.com/cyberchen1995/h-guard/pkg/harness/claudecode" // 内置 adapter
	_ "github.com/cyberchen1995/h-guard/pkg/judge/typesafe"     // 内置判断后端
)

// Version 由构建时的 -ldflags 设置。
var Version = "dev"

// Options 是一次运行的外部依赖；零值字段取进程默认值。测试用它隔离目录与输入输出。
type Options struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Now            func() time.Time
	ConfigDir      string // 默认 store.ConfigDir()
	CacheDir       string // 默认 store.CacheDir()
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
}

const usage = `usage:
  h-guard hook <harness> --event <event> [--timeout <seconds>] [--config <file>]
  h-guard check <command> [--shell posix|powershell] [--request <text>]... [--cwd <dir>] [--judge] [--config <file>]
  h-guard version
`

// Main 运行命令并返回退出码。
func Main(args []string, o Options) int {
	o.fill()
	if len(args) == 0 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "hook":
		return runHook(args[1:], o)
	case "check":
		return runCheck(args[1:], o)
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
}

// load 读取配置（内置默认 → 用户配置 → extra）、规则包（内置 → 用户目录）与 .env。
// 消息目录总能加载（内嵌）；返回的 setup 在出错时仍带 catalog 与 locale，供渲染兜底结论。
func load(o Options, extra string) (setup, error) {
	s := setup{locale: i18n.DefaultLocale}
	cat, err := i18n.Load()
	if err != nil {
		return s, err
	}
	s.catalog = cat
	s.locale = i18n.SelectLocale("", o.Getenv)
	cfg, err := config.Load(filepath.Join(o.ConfigDir, "config.yaml"), extra)
	if err != nil {
		return s, err
	}
	s.cfg = cfg
	s.locale = i18n.SelectLocale(cfg.Locale, o.Getenv)
	set, err := rules.Load(filepath.Join(o.ConfigDir, "rules"))
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
	if err := config.ApplyDotEnv(o.ConfigDir); err != nil {
		return s, &config.Error{File: filepath.Join(o.ConfigDir, ".env"), Issues: []config.Issue{{Path: "file", Msg: "cannot be read"}}}
	}
	return s, nil
}

// newEngine 组装 Engine：M1 只有 action 检查。
func (s setup) newEngine(j action.Judge) *engine.Engine {
	c := &action.Check{Rules: s.rules, Config: s.cfg, Catalog: s.catalog, Locale: s.locale, Judge: j}
	return &engine.Engine{
		Checks: []guard.Check{c}, Catalog: s.catalog, Locale: s.locale,
		WhenAskUnsupported: guard.Decision(s.cfg.Policy.WhenAskUnsupported),
	}
}

// hookJudge 是 hook 中的判断层：M1 还没有同意机制（M2），开启模型时一律按同意缺失处理，从不调用后端
// （维护者决定，2026-10-12）。
func hookJudge(cfg *config.Config) action.Judge {
	if cfg.Judge.Enabled {
		return action.Judge{Unavailable: action.FallbackConsentMissing}
	}
	return action.Judge{}
}

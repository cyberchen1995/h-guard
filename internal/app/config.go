package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/internal/rules"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runConfig 是 config validate|show|init。
func runConfig(args []string, o Options) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	extra := fs.String("config", "", "extra config file")
	rulesDir := fs.String("rules", "", "validate: check only this rule pack and its examples")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 || (*rulesDir != "" && pos[0] != "validate") {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	switch pos[0] {
	case "validate":
		if *rulesDir != "" {
			return validateRulePack(o, *rulesDir)
		}
		return validateConfig(o, *extra)
	case "show":
		s, err := load(o, *extra)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
			return 1
		}
		b, err := yaml.Marshal(s.cfg)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		fmt.Fprintf(o.Stdout, "%s", b)
		return 0
	case "init":
		return initConfig(o)
	}
	fmt.Fprint(o.Stderr, usage)
	return 2
}

// validateConfig 读取配置与规则包（与 hook 相同），再运行用户规则的样例；停用了硬规则时显著提示。
func validateConfig(o Options, extra string) int {
	s, err := load(o, extra)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	own, code := checkExamples(o, s.rules, func(r *rules.Rule) bool { return !r.Builtin })
	if code != 0 {
		return code
	}
	for _, r := range s.rules.All() {
		if r.Locked && !r.Enabled() {
			fmt.Fprintf(o.Stdout, "warning: hard rule %q is disabled\n", r.ID)
		}
	}
	for _, n := range outboundNotes(s, true) {
		fmt.Fprintln(o.Stdout, "note:", n)
	}
	fmt.Fprintf(o.Stdout, "config ok: %s of your own, examples pass\n", plural(own, "rule"))
	return 0
}

// validateRulePack 单独验证一个规则包目录及其样例（第三方规则包），不读配置。
func validateRulePack(o Options, dir string) int {
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		fmt.Fprintf(o.Stderr, "h-guard: %s is not a directory\n", dir)
		return 1
	}
	set, err := rules.Load(dir)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
		return 1
	}
	n, code := checkExamples(o, set, func(r *rules.Rule) bool { return !r.Builtin })
	if code != 0 {
		return code
	}
	fmt.Fprintf(o.Stdout, "%s, examples pass\n", plural(n, "rule"))
	return 0
}

// checkExamples 运行 pick 选中的规则的样例，返回规则数；有样例不通过时打印并返回退出码 1。
func checkExamples(o Options, set *rules.Set, pick func(*rules.Rule) bool) (int, int) {
	n, failed := 0, false
	for _, r := range set.All() {
		if !pick(r) {
			continue
		}
		n++
		if err := r.CheckExamples(context.Background()); err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
			failed = true
		}
	}
	// outbound 规则：用户自己的规则同样运行样例
	for _, r := range set.Outbound() {
		if r.Builtin {
			continue
		}
		n++
		if err := r.CheckExamples(context.Background()); err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
			failed = true
		}
	}
	if failed {
		return n, 1
	}
	return n, 0
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// configTemplate 是 config init 写出的模板：只有 version: 1 生效，其余是说明与内置默认值（注释）。
// 第一行让编辑器（yaml-language-server）按配置的 JSON Schema 补全与检查，地址是 schema/config.schema.json 的 $id。
const configTemplate = `# yaml-language-server: $schema=https://raw.githubusercontent.com/cyberchen1995/h-guard/main/schema/config.schema.json
# h-guard configuration. Only "version: 1" is required; everything else falls back to the built-in
# defaults shown in the comments. Check it with: h-guard config validate. See the merged result with: h-guard config show.
version: 1

# Language of the messages shown to you and the agent: en or zh-CN (default: from LANG).
# locale: zh-CN

# The judge (a model) decides the six dangerous-operation rules. It is off by default; "h-guard init" picks a
# backend, asks for your consent and turns it on. Recommended backends: claude-haiku, claude-sonnet, gemma4-local, jev.
# judge: {enabled: false, backend: jev}

# What to check: action tier 1 = commands; 2 = + file reads, writes, deletes and renames (default).
# action: {tier: 2}

# Turn single rules off by id (h-guard config show lists them):
# rules:
#   publish: {enabled: false}

# Harnesses that cannot tell which shell runs a command (Codex, opencode): posix or powershell.
# harnesses:
#   codex: {shell: posix}
#   opencode: {shell: posix}

# Decision log with the full commands (off by default; credentials h-guard recognizes are masked).
# log: {decisions: false, retention_days: 14}
`

// initConfig 写出配置模板；已有配置时不覆盖。
func initConfig(o Options) int {
	if o.ConfigDir == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the config directory is unavailable")
		return 1
	}
	path := filepath.Join(o.ConfigDir, "config.yaml")
	if err := os.MkdirAll(o.ConfigDir, 0o700); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		fmt.Fprintf(o.Stderr, "h-guard: %s already exists; not overwriting it\n", path)
		return 1
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	_, werr := f.WriteString(configTemplate)
	if err := errors.Join(werr, f.Close()); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprintln(o.Stdout, "wrote", path)
	return 0
}

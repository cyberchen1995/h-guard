package app

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/seen"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// runInstall 安装或移除 harness 的入口：默认只打印将要写入的内容；--write 时先备份、按读改写约定写入；
// --remove 只删除本项目的入口。agent 在 hook 下运行它会被护栏自我保护拦下请求确认。
func runInstall(args []string, o Options) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	write := fs.Bool("write", false, "write the changes (default: only print them)")
	remove := fs.Bool("remove", false, "remove h-guard's entries instead of installing them")
	timeout := fs.Int("timeout", 20, "hook timeout in seconds, also passed to h-guard")
	shell := fs.String("shell", "", "codex, opencode: the shell the harness runs commands with (posix or powershell)")
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) != 1 || *timeout < 2 || *timeout > 600 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	harness := pos[0]
	if !slices.Contains(installable, harness) {
		fmt.Fprintf(o.Stderr, "h-guard: cannot install into %q (known: %s)\n", harness, strings.Join(installable, ", "))
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if *shell != "" && (!shellHarnesses[harness] || !guard.Shell(*shell).Valid()) {
		fmt.Fprintln(o.Stderr, "h-guard: --shell is posix or powershell, and only for codex and opencode")
		return 2
	}
	if o.ConfigDir == "" || o.CacheDir == "" || o.Home == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the config, cache or home directory is unavailable")
		return 1
	}
	if !*remove {
		// 与 hook 相同地读配置：非法的配置不写入入口（hook 会遇到同样的错误）；停用了硬规则时显著提示。移除不受
		// 配置错误阻挡
		s, err := load(o, "")
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", secrets.MaskForLog(err.Error()))
			fmt.Fprintln(o.Stderr, "h-guard: fix the config first (h-guard config validate); nothing was written")
			return 1
		}
		for _, r := range s.rules.All() {
			if r.Locked && !r.Enabled() {
				fmt.Fprintf(o.Stdout, "warning: hard rule %q is disabled in the config; it does not protect anything until you turn it back on\n", r.ID)
			}
		}
	}
	bin, err := o.Executable()
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard: cannot find the h-guard executable:", err)
		return 1
	}
	if strings.Contains(filepath.ToSlash(bin), "/go-build") {
		// go run 编出的程序在临时目录里，退出就不在了：写进入口会让 Codex 静默放行、Claude Code 每次都请求确认
		fmt.Fprintln(o.Stderr, "h-guard: this h-guard was built by go run into a temporary directory; build or install it first (go build, go install) and run install with that binary")
		return 1
	}
	t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, Bin: bin, Timeout: *timeout,
		GOOS: o.GOOS, Getenv: o.Getenv, Run: o.RunHarness, Now: o.Now}
	switch harness {
	case "codex":
		steps, err := install.Codex(t, *remove)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		return installWithShell(o, t, harness, "Codex", steps, install.CodexNotes, *shell, *write, *remove)
	case "opencode":
		steps, err := install.OpenCode(t, *remove)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		notes := func(t install.Target) []string { return install.ExtNotes(t, harness) }
		return installWithShell(o, t, harness, "opencode", steps, notes, *shell, *write, *remove)
	case "pi", "omp", "dsh", "openclaw":
		return installExt(o, t, harness, *write, *remove)
	}
	steps, err := install.ClaudeCode(t, *remove)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	if !*remove {
		for _, n := range install.ClaudeCodeNotes(t) {
			fmt.Fprintln(o.Stdout, "note:", n)
		}
	}
	return applySteps(o, steps, *write, *remove, func() int {
		forgetRuns(o, harness)
		if *remove {
			fmt.Fprintln(o.Stdout, "restart Claude Code for the change to take effect")
			return 0
		}
		dir := install.ClaudePluginDir(t)
		if out, err := o.RunHarness("claude", "plugin", "validate", dir); err != nil && !errors.Is(err, errHarnessMissing) {
			fmt.Fprintf(o.Stderr, "h-guard: claude plugin validate failed: %v\n%s", err, out)
			fmt.Fprintln(o.Stderr, "h-guard: the files are written; run h-guard install claudecode --remove --write to take them out")
			return 1
		}
		fmt.Fprintln(o.Stdout, "restart Claude Code to load the plugin; if your organization blocks user mods or hooks, ask it to install the plugin for you")
		return 0
	})
}

// installable 是 install 能接入的 harness；shellHarnesses 是标不出 shell、要由 harnesses.<name>.shell 给出的 harness。
var (
	installable    = []string{"claudecode", "codex", "opencode", "pi", "omp", "dsh", "openclaw"}
	shellHarnesses = map[string]bool{"codex": true, "opencode": true}
)

// installWithShell 执行标不出 shell 的 harness（Codex、opencode）的步骤：给了 --shell 时写进
// harnesses.<harness>.shell；Windows 上没有给时在终端里询问（默认 powershell），非交互时要求 --shell。
func installWithShell(o Options, t install.Target, harness, product string, steps []install.Step, notes func(install.Target) []string, shell string, write, remove bool) int {
	if !remove && shell == "" && o.GOOS == "windows" {
		if !o.IsTerminal() {
			fmt.Fprintf(o.Stderr, "h-guard: on Windows, say which shell %s runs commands with: --shell powershell or --shell posix\n", product)
			return 2
		}
		fmt.Fprintf(o.Stdout, "Which shell does %s run commands with on this machine, powershell or posix (WSL, Git Bash)? [powershell] ", product)
		answer, _ := bufio.NewReader(o.Stdin).ReadString('\n')
		shell = strings.ToLower(strings.TrimSpace(answer))
		if shell == "" {
			shell = string(guard.ShellPowerShell)
		}
		if !guard.Shell(shell).Valid() {
			fmt.Fprintln(o.Stderr, "h-guard: the shell is posix or powershell")
			return 2
		}
	}
	if shell != "" && !remove {
		step, err := install.HarnessShell(t, harness, shell)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		steps = append(steps, step)
	}
	if !remove {
		for _, n := range notes(t) {
			fmt.Fprintln(o.Stdout, "note:", n)
		}
	}
	return applySteps(o, steps, write, remove, func() int {
		forgetRuns(o, harness)
		if harness == "opencode" {
			fmt.Fprintln(o.Stdout, "restart opencode for the change to take effect")
		}
		return 0
	})
}

// forgetRuns 在写入入口之后删除 harness 的运行记录：之前一分钟内的记录会让新入口的第一次运行被节流掉、
// 又因为早于安装而不算数，status 就一直以为新入口没运行过。
func forgetRuns(o Options, harness string) {
	if o.CacheDir != "" {
		_ = seen.Clear(seen.Dir(o.CacheDir), harness)
	}
}

// installExt 写出或删掉 pi、omp 的扩展，DeepSeek Harness 与 OpenClaw 的插件。
func installExt(o Options, t install.Target, harness string, write, remove bool) int {
	var steps []install.Step
	var err error
	notes := install.ExtNotes
	switch harness {
	case "dsh":
		steps, err = install.DSH(t, remove)
	case "openclaw":
		steps, err = install.OpenClaw(t, remove)
		notes = func(t install.Target, _ string) []string { return install.OpenClawNotes(t) }
	default:
		steps, err = install.Pi(t, harness, remove)
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	if !remove {
		for _, n := range notes(t, harness) {
			fmt.Fprintln(o.Stdout, "note:", n)
		}
	}
	return applySteps(o, steps, write, remove, func() int {
		switch harness {
		case "dsh":
			fmt.Fprintln(o.Stdout, "restart DeepSeek Harness for the change to take effect; the plugin is mounted for every profile")
		case "openclaw":
			fmt.Fprintln(o.Stdout, "restart the OpenClaw Gateway (openclaw gateway restart) for the change to take effect")
		default:
			fmt.Fprintf(o.Stdout, "restart %s (or run /reload) for the change to take effect\n", harness)
		}
		return 0
	})
}

// applySteps 打印或执行 install 的步骤。没有改动时说明已是目标状态；只打印时列出将改动的路径与新内容，
// 最后提示加 --write。写入成功后调用 done。
func applySteps(o Options, steps []install.Step, write, remove bool, done func() int) int {
	var changes []install.Step
	for _, s := range steps {
		if s.Changes() {
			changes = append(changes, s)
		}
	}
	if len(changes) == 0 {
		if remove {
			fmt.Fprintln(o.Stdout, "not installed; nothing to remove")
		} else {
			fmt.Fprintln(o.Stdout, "already installed; nothing to change")
		}
		return 0
	}
	verb := "would"
	if write {
		verb = "will"
	}
	for _, s := range changes {
		fmt.Fprintf(o.Stdout, "%s %s: %s\n", verb, s.Summary, s.Path)
		if !write && s.Preview != nil {
			fmt.Fprintf(o.Stdout, "--- %s after the change ---\n%s", s.Path, s.Preview)
		}
	}
	if !write {
		fmt.Fprintln(o.Stdout, "nothing was written; run again with --write to apply")
		return 0
	}
	if err := install.Apply(steps); err != nil { // 全部步骤：没有改动的也要在锁内复核
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprintln(o.Stdout, "wrote the changes; backups of changed files are in", filepath.Join(o.CacheDir, "backups"))
	return done()
}

var errHarnessMissing = errors.New("not found in PATH")

// runHarness 在 PATH 中查找并运行 harness 的命令行，限时 10 秒。
func runHarness(name string, args ...string) ([]byte, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, errHarnessMissing
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, args...).CombinedOutput()
}

// stableExecutable 返回写进入口的 h-guard 路径：PATH 中的 h-guard 与正在运行的是同一个文件时用 PATH 里的写法
// （如 Homebrew 的 /opt/homebrew/bin/h-guard：升级后路径不变，Codex 也不必重新信任 hook）；否则用实际路径。
func stableExecutable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if p, err := exec.LookPath("h-guard"); err == nil {
		if a, err1 := os.Stat(p); err1 == nil {
			if b, err2 := os.Stat(self); err2 == nil && os.SameFile(a, b) {
				if abs, err := filepath.Abs(p); err == nil {
					return abs, nil
				}
			}
		}
	}
	return self, nil
}

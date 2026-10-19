package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Entry 是 harness 会运行的一个 h-guard 入口：程序与参数（不经 shell）、额外的环境变量。
type Entry struct {
	Argv []string
	Env  []string
	// Program 是入口最终运行的 h-guard 程序（Claude Code 的外包脚本运行 hguard-bin 里记下的那个）
	Program string
}

// ErrNotInstalled 表示 harness 里没有 h-guard 的入口。
var ErrNotInstalled = errors.New("h-guard is not installed for this harness")

// ErrPluginChanged 表示 Claude Code 插件的文件与这个 h-guard 写的不一样，不运行其中的入口。
var ErrPluginChanged = errors.New("the plugin files differ from this h-guard version (missing, edited or written by another version), so they are not run; run h-guard install claudecode --write")

// Entries 按 harness 的写法返回已安装的入口（键是 hook 的事件名；harness 对一个事件运行其中每一个），
// 供自测像 harness 一样运行 h-guard：
//   - claudecode：PreToolUse 运行插件里的外包脚本（Windows 上经 PowerShell 运行 pretooluse.ps1），
//     prompt.submit 运行 hguard.json 给 mod 的命令；
//   - codex：hooks.json 里本项目的 PreToolUse、UserPromptSubmit 命令。带 matcher 的组只对部分工具运行，不算入口。
func Entries(t Target, harness string) (map[string][]Entry, error) {
	switch harness {
	case "claudecode":
		return claudeEntries(t)
	case "codex":
		return codexEntries(t)
	}
	return nil, fmt.Errorf("unknown harness %q", harness)
}

// InstalledAt 是入口最近一次改动的时间：Codex 是 hooks.json 的修改时间；Claude Code 是插件目录里全部文件与目录
// 中最新的修改时间（外包脚本、hguard-bin 等任何一个被改动或删除都算）。入口不在（hooks.json 或 hguard.json
// 不见了）时为零。之前的运行与自测记录早于它就不算数。
func InstalledAt(t Target, harness string) time.Time {
	if harness == "codex" {
		fi, err := os.Stat(CodexHooks(t))
		if err != nil {
			return time.Time{}
		}
		return fi.ModTime()
	}
	dir := ClaudePluginDir(t)
	if _, err := os.Stat(filepath.Join(dir, "hguard.json")); err != nil {
		return time.Time{}
	}
	var latest time.Time
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		if fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
		return nil
	})
	if err != nil {
		return time.Time{}
	}
	return latest
}

func claudeEntries(t Target) (map[string][]Entry, error) {
	dir := ClaudePluginDir(t)
	b, err := os.ReadFile(filepath.Join(dir, "hguard.json"))
	if err != nil {
		return nil, ErrNotInstalled
	}
	var cfg struct {
		Commands map[string][]string `json:"commands"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", filepath.Join(dir, "hguard.json"), err)
	}
	// 外包脚本与 hguard.json 里的命令都会被运行：与这个 h-guard 写的不一样（被改过、别的版本写的）就不运行
	read := func(name string) string {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b))
	}
	if stalePlugin(t, dir, read("hguard-bin"), read("hguard-timeout")) {
		return nil, ErrPluginChanged
	}
	out := map[string][]Entry{}
	if argv := cfg.Commands["prompt.submit"]; len(argv) > 0 {
		out["prompt.submit"] = []Entry{{Argv: append(append([]string{}, argv...), "--event", "prompt.submit"), Program: argv[0]}}
	}
	env := []string{"CLAUDE_PLUGIN_ROOT=" + dir}
	if t.GOOS == "windows" {
		// 与插件的 hooks.json 一样经 PowerShell 运行外包脚本：脚本本身、PowerShell 或执行策略出问题时自测也失败
		out["PreToolUse"] = []Entry{{Argv: []string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
			filepath.Join(dir, "hooks", "pretooluse.ps1")}, Env: env, Program: read("hguard-bin")}}
	} else {
		out["PreToolUse"] = []Entry{{Argv: []string{"sh", filepath.Join(dir, "hooks", "pretooluse.sh")}, Env: env, Program: read("hguard-bin")}}
	}
	return out, nil
}

// effectiveCommand 是 Codex 在这个系统上运行的命令：Windows 上有 commandWindows 时用它，否则用 command。
func effectiveCommand(t Target, command, windows string) string {
	if t.GOOS == "windows" && windows != "" {
		return windows
	}
	return command
}

func codexEntries(t Target) (map[string][]Entry, error) {
	b, err := os.ReadFile(CodexHooks(t))
	if err != nil {
		return nil, ErrNotInstalled
	}
	var file struct {
		Hooks map[string][]struct {
			Matcher json.RawMessage `json:"matcher"`
			Hooks   []struct {
				Type           string `json:"type"`
				Command        string `json:"command"`
				CommandWindows string `json:"commandWindows"`
				Async          bool   `json:"async"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(b, &file); err != nil {
		return nil, fmt.Errorf("%s cannot be read: %w", CodexHooks(t), err)
	}
	out := map[string][]Entry{}
	for _, ev := range codexEvents {
		for _, g := range file.Hooks[ev] {
			if m := strings.TrimSpace(string(g.Matcher)); m != "" && m != "null" {
				continue // 只对匹配的工具运行（Inspect 报告为 problem），自测的 Bash 命令不能代表它
			}
			for _, h := range g.Hooks {
				// 命令里的 --event 必须与它所在的事件一致：写反了的入口在输入读不懂时会按错误的事件兜底
				// 在后台运行（async）或不是 command 类型的 hook 拦不住操作：不算入口（Inspect 报告为 problem）
				// Codex 只认写明 type: command 的命令 hook；Windows 上有 commandWindows 时运行它
				cmd := effectiveCommand(t, h.Command, h.CommandWindows)
				if !isOurCodexHook(cmd) || !strings.Contains(cmd, " --event "+ev+" ") || h.Async || h.Type != "command" {
					continue
				}
				// 本项目的命令形如 <bin> hook codex --event <事件> --timeout <秒>（isOurCodexHook 已核对），参数里没有引号
				args := strings.Fields(strings.TrimSpace(cmd)[len(binToken(cmd)):])
				out[ev] = append(out[ev], Entry{Argv: append([]string{commandBin(cmd)}, args...), Program: commandBin(cmd)})
			}
		}
	}
	if len(out) == 0 {
		return nil, ErrNotInstalled
	}
	return out, nil
}

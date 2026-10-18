package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/extensions"
)

// Inspect 报告 harness 的入口是否安装、与期望是否一致。返回的每一行不带 harness 名；
// 「problem: 」开头的是与期望不一致的地方，「note: 」开头的是提醒。
func Inspect(t Target, harness string) []string {
	switch harness {
	case "claudecode":
		return inspectClaudeCode(t)
	case "codex":
		return inspectCodex(t)
	case "opencode":
		return inspectExt(t, harness, OpenCodePlugin(t))
	case "pi":
		return inspectExt(t, harness, PiExtension(t))
	case "omp":
		return inspectExt(t, harness, OMPExtension(t))
	case "dsh":
		return inspectDSH(t)
	case "hermes":
		return inspectHermes(t)
	}
	return nil
}

// extHarnesses 是以单文件扩展接入的 harness：命令名、产品名、扩展按其编写的版本、受支持的主版本（0 为不限）。
var extHarnesses = map[string]struct {
	cmd, product, written string
	major                 int
}{
	"opencode": {"opencode", "opencode", OpenCodeWritten, 1},
	"pi":       {"pi", "pi", PiWritten, 0},
	"omp":      {"omp", "oh-my-pi", OMPWritten, 0},
	"dsh":      {"dsh", "DeepSeek Harness", DSHWritten, 0},
	"hermes":   {"hermes", "Hermes Agent", HermesWritten, 0},
}

// ExtNotes 返回 harness 的版本提醒（install 与 status 共用）。
func ExtNotes(t Target, harness string) []string {
	h := extHarnesses[harness]
	if harness == "hermes" {
		// 只有发布日期（YYYY.M.D）能与 HermesWritten 比较；只读到语义化的版本号时不提醒
		if v := harnessVersion(t, h.cmd); v != "" && !calver(v) {
			return nil
		}
	}
	return harnessVersionNote(t, h.cmd, h.product, h.written, h.major)
}

// inspectExt 检查单文件扩展：是否是 h-guard 的、与这个 h-guard 会写出的内容是否相同、h-guard 是否还在原处。
func inspectExt(t Target, harness, path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("not installed (h-guard install %s)", harness)}
	}
	h := extHarnesses[harness]
	lines := []string{extInstalledLine(t, h.cmd, h.product)}
	if !isOurExt(b) {
		return append(lines, fmt.Sprintf("problem: %s is not h-guard's extension", path))
	}
	lines = append(lines, extProblems(t, harness, b)...)
	for _, n := range ExtNotes(t, harness) {
		lines = append(lines, "note: "+n)
	}
	return lines
}

// extProblems 检查已写出的扩展：h-guard 是否还在、内容是否与这个 h-guard 按同样的路径与超时写出的相同。
func extProblems(t Target, harness string, b []byte) []string {
	var problems []string
	bin, timeout, ok := installedExt(b, harness)
	if bin != "" {
		if _, err := os.Stat(bin); err != nil {
			problems = append(problems, fmt.Sprintf("problem: h-guard is not at %s; run h-guard install %s --write", bin, harness))
		}
	}
	tmpl := map[string][]byte{"opencode": extensions.OpenCode, "pi": extensions.Pi, "omp": extensions.Pi, "dsh": extensions.DSH}[harness]
	want, err := renderExt(tmpl, harness, Target{Bin: bin, Timeout: timeout})
	if !ok || err != nil || !bytes.Equal(want, b) {
		problems = append(problems, fmt.Sprintf("problem: the extension differs from this h-guard version (edited or written by another version); run h-guard install %s --write", harness))
	}
	return problems
}

// extInstalledLine 是「已安装」一行，带 harness 报告的版本（omp 报告 omp/<版本>）。
func extInstalledLine(t Target, cmd, product string) string {
	v := strings.TrimPrefix(harnessVersion(t, cmd), cmd+"/")
	if v == "" {
		return fmt.Sprintf("installed (%s not found in PATH)", cmd)
	}
	return fmt.Sprintf("installed (%s %s)", product, v)
}

// inspectDSH 检查 DeepSeek Harness：插件文件与补丁里挂载它的那一行。
func inspectDSH(t Target) []string {
	plugin, patch := DSHPlugin(t), DSHPatch(t)
	b, perr := os.ReadFile(plugin)
	found, name := 0, ""
	if pb, err := os.ReadFile(patch); err == nil {
		var yerr error
		if found, name, yerr = dshMounted(pb); yerr != nil {
			return []string{fmt.Sprintf("problem: %s cannot be read: %v", patch, yerr)}
		}
	}
	if perr != nil && found == 0 {
		return []string{"not installed (h-guard install dsh)"}
	}
	lines := []string{extInstalledLine(t, "dsh", "DeepSeek Harness")}
	switch {
	case found == 0:
		lines = append(lines, fmt.Sprintf("problem: the plugin is written but %s does not mount it; run h-guard install dsh --write", patch))
	case found > 1:
		lines = append(lines, fmt.Sprintf("problem: %s mounts h-guard %d times; run h-guard install dsh --write", patch, found))
	case !t.samePath(dshModulePath(t, name), plugin):
		lines = append(lines, fmt.Sprintf("problem: %s mounts %s instead of %s; run h-guard install dsh --write", patch, name, plugin))
	}
	if perr != nil {
		return append(lines, fmt.Sprintf("problem: %s mounts %s, but the plugin is missing; run h-guard install dsh --write", patch, plugin))
	}
	if !isOurExt(b) {
		return append(lines, fmt.Sprintf("problem: %s is not h-guard's plugin", plugin))
	}
	lines = append(lines, extProblems(t, "dsh", b)...)
	for _, n := range ExtNotes(t, "dsh") {
		lines = append(lines, "note: "+n)
	}
	return lines
}

func harnessVersion(t Target, name string) string {
	if t.Run == nil {
		return ""
	}
	out, err := t.Run(name, "--version")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(out))
	switch {
	case len(f) == 0:
		return ""
	case name == "codex":
		return f[len(f)-1]
	case name == "hermes":
		// Hermes Agent v0.21.6+3.gabc1234 (2026.9.24) …：版本号（v 之后）是语义化版本，括号里的发布日期才能与插件按其
		// 编写的发布（2026.9.24）比较，优先取它；Desktop 版只打印 v<版本>，退回版本号（ExtNotes 不拿它比较）
		for _, s := range f {
			if d := strings.TrimSuffix(strings.TrimPrefix(s, "("), ")"); len(s) > 2 && s[0] == '(' && d != "" && d[0] >= '0' && d[0] <= '9' {
				return d
			}
		}
		for _, s := range f {
			if len(s) > 1 && s[0] == 'v' && s[1] >= '0' && s[1] <= '9' {
				v, _, _ := strings.Cut(s[1:], "+")
				return v
			}
		}
		return ""
	}
	return f[0]
}

// calver 报告版本是不是 YYYY.M.D 形式的发布日期。
func calver(v string) bool {
	y, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	return err == nil && y >= 2000
}

func installedLine(product, version string) string {
	if version == "" {
		return fmt.Sprintf("installed (%s not found in PATH)", strings.ToLower(strings.Fields(product)[0]))
	}
	return fmt.Sprintf("installed (%s %s)", product, version)
}

func inspectClaudeCode(t Target) []string {
	dir := ClaudePluginDir(t)
	settings := ClaudeSettings(t)
	read := func(name string) []byte { b, _ := os.ReadFile(filepath.Join(dir, name)); return b }
	present := isOurPlugin(map[string][]byte{".claude-plugin/plugin.json": read(".claude-plugin/plugin.json")})
	registered := false
	if b, err := os.ReadFile(settings); err == nil {
		if o, err := parseObject(b); err == nil {
			env, _ := o.object("env")
			var s string
			if raw, ok := env.get(pluginDirsVar); ok && json.Unmarshal(raw, &s) == nil {
				registered = slices.ContainsFunc(strings.Split(s, t.listSep()), func(d string) bool {
					return strings.TrimSpace(d) != "" && t.samePath(strings.TrimSpace(d), dir)
				})
			}
		}
	}
	if !present && !registered {
		return []string{"not installed (h-guard install claudecode)"}
	}
	lines := []string{installedLine("Claude Code", harnessVersion(t, "claude"))}
	switch {
	case !registered:
		lines = append(lines, fmt.Sprintf("problem: the plugin is written but %s does not load it; run h-guard install claudecode --write", settings))
	case !present:
		lines = append(lines, fmt.Sprintf("problem: %s loads %s, but the plugin is missing; run h-guard install claudecode --write", settings, dir))
		return lines
	}
	if bin := strings.TrimSpace(string(read("hguard-bin"))); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			lines = append(lines, fmt.Sprintf("problem: h-guard is not at %s; run h-guard install claudecode --write", bin))
		}
	}
	if stalePlugin(t, dir, strings.TrimSpace(string(read("hguard-bin"))), strings.TrimSpace(string(read("hguard-timeout")))) {
		lines = append(lines, "problem: the plugin files differ from this h-guard version (missing, edited or written by another version); run h-guard install claudecode --write")
	}
	timeouts := map[string]int{}
	if n, err := strconv.Atoi(strings.TrimSpace(string(read("hguard-timeout")))); err == nil {
		timeouts["hguard-timeout"] = n
	}
	var cfg struct {
		TimeoutMS int `json:"timeout_ms"`
	}
	if json.Unmarshal(read("hguard.json"), &cfg) == nil && cfg.TimeoutMS > 0 {
		timeouts["hguard.json"] = cfg.TimeoutMS / 1000
	}
	var hooks struct {
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Timeout int `json:"timeout"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if json.Unmarshal(read("hooks/hooks.json"), &hooks) == nil && len(hooks.Hooks.PreToolUse) == 1 && len(hooks.Hooks.PreToolUse[0].Hooks) == 1 {
		timeouts["hooks.json"] = hooks.Hooks.PreToolUse[0].Hooks[0].Timeout
	}
	if vals := slices.Compact(slices.Sorted(maps.Values(timeouts))); len(vals) > 1 {
		lines = append(lines, fmt.Sprintf("problem: the timeouts differ (%s); run h-guard install claudecode --write", formatTimeouts(timeouts)))
	}
	for _, n := range ClaudeCodeNotes(t) {
		lines = append(lines, "note: "+n)
	}
	return lines
}

var commandTimeout = regexp.MustCompile(`--timeout\s+(\d+)`)

func inspectCodex(t Target) []string {
	path := CodexHooks(t)
	var file struct {
		Hooks map[string][]struct {
			Matcher json.RawMessage `json:"matcher"`
			Hooks   []struct {
				Type           string `json:"type"`
				Command        string `json:"command"`
				CommandWindows string `json:"commandWindows"`
				Timeout        int    `json:"timeout"`
				Async          bool   `json:"async"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &file); err != nil {
			return []string{fmt.Sprintf("problem: %s cannot be read: %v", path, err)}
		}
	}
	var problems []string
	found := 0
	for _, ev := range codexEvents {
		n := 0
		for _, g := range file.Hooks[ev] {
			for _, h := range g.Hooks {
				cmd := effectiveCommand(t, h.Command, h.CommandWindows)
				if !isOurCodexHook(cmd) {
					continue
				}
				n++
				if !strings.Contains(cmd, " --event "+ev+" ") {
					// 写在别的事件下的入口按命令里的事件处理（读不懂输入时按那个事件兜底），拦不住这个事件
					problems = append(problems, fmt.Sprintf("problem: the h-guard hook under %s is the command for another event; run h-guard install codex --write", ev))
				}
				if h.Async || h.Type != "command" {
					// 后台运行的 hook 拦不住操作（Codex 不等它的结论）；Codex 只认写明 type: command 的命令 hook
					problems = append(problems, fmt.Sprintf("problem: the h-guard hook for %s does not run as a blocking command hook; run h-guard install codex --write", ev))
				}
				if m := strings.TrimSpace(string(g.Matcher)); m != "" && m != "null" {
					// 本项目的入口不写 matcher；加了就只对匹配的工具生效
					problems = append(problems, fmt.Sprintf("problem: the h-guard hook for %s only runs for tools matching %s; run h-guard install codex --write", ev, m))
				}
				if m := commandTimeout.FindStringSubmatch(cmd); m != nil {
					if given, _ := strconv.Atoi(m[1]); h.Timeout != given {
						problems = append(problems, fmt.Sprintf("problem: %s waits %ds but h-guard is given %ds; run h-guard install codex --write", ev, h.Timeout, given))
					}
				}
				if bin := commandBin(cmd); bin != "" {
					if _, err := os.Stat(bin); err != nil {
						problems = append(problems, fmt.Sprintf("problem: h-guard is not at %s; run h-guard install codex --write", bin))
					}
				}
			}
		}
		switch {
		case n == 0:
			problems = append(problems, fmt.Sprintf("problem: no h-guard hook for %s; run h-guard install codex --write", ev))
		case n > 1:
			problems = append(problems, fmt.Sprintf("problem: %d h-guard hooks for %s; run h-guard install codex --write", n, ev))
		}
		found += n
	}
	if found == 0 {
		return []string{"not installed (h-guard install codex)"}
	}
	lines := append([]string{installedLine("Codex", harnessVersion(t, "codex"))}, slices.Compact(problems)...)
	for _, n := range CodexNotes(t) {
		lines = append(lines, "note: "+n)
	}
	return lines
}

func formatTimeouts(m map[string]int) string {
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%s %ds", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// stalePlugin 报告插件目录与这个 h-guard 按同样的路径与超时会写出的内容是否不同。
func stalePlugin(t Target, dir, bin, timeout string) bool {
	n, err := strconv.Atoi(timeout)
	if err != nil {
		return true
	}
	want, err := pluginFiles(Target{Bin: bin, Timeout: n, GOOS: t.GOOS})
	if err != nil {
		return true
	}
	got := map[string][]byte{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		got[filepath.ToSlash(rel)], _ = os.ReadFile(p)
		return nil
	})
	if len(got) != len(want) {
		return true
	}
	for name, b := range want {
		if !bytes.Equal(got[name], b) {
			return true
		}
	}
	return false
}

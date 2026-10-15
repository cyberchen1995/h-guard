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
)

// Inspect 报告 harness 的入口是否安装、与期望是否一致（spec §12 status）。返回的每一行不带 harness 名；
// 「problem: 」开头的是与期望不一致的地方，「note: 」开头的是提醒。
func Inspect(t Target, harness string) []string {
	switch harness {
	case "claudecode":
		return inspectClaudeCode(t)
	case "codex":
		return inspectCodex(t)
	}
	return nil
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
	}
	return f[0]
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
					return strings.TrimSpace(d) != "" && filepath.Clean(strings.TrimSpace(d)) == filepath.Clean(dir)
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
			Hooks []struct {
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
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
				if !isOurCodexHook(h.Command) {
					continue
				}
				n++
				if m := commandTimeout.FindStringSubmatch(h.Command); m != nil {
					if given, _ := strconv.Atoi(m[1]); h.Timeout != given {
						problems = append(problems, fmt.Sprintf("problem: %s waits %ds but h-guard is given %ds; run h-guard install codex --write", ev, h.Timeout, given))
					}
				}
				if bin := commandBin(h.Command); bin != "" {
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

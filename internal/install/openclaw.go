package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/extensions"
)

// openclawID 是 h-guard 的插件在 OpenClaw 里的 id：openclaw.json 里 plugins.entries.h-guard 归本项目所有。
const openclawID = "h-guard"

// openclawHooks 是插件用到、install 为它们写入超时的 hook。工具结果 middleware 的超时取 after_tool_call 的设置。
var openclawHooks = []string{"before_tool_call", "before_agent_run", "after_tool_call"}

// OpenClawHome 是 OpenClaw 的主目录：$OPENCLAW_HOME（开头的 ~ 展开到用户主目录），默认用户主目录。与 OpenClaw 一样，
// 只有空白或是字面的 undefined、null 时当作没有设置。
func OpenClawHome(t Target) string {
	if d := strings.TrimSpace(t.Getenv("OPENCLAW_HOME")); d != "" && d != "undefined" && d != "null" {
		return openclawAbs(t.Home, d)
	}
	return t.Home
}

// openclawPath 按 OpenClaw 的规则解析用户给的路径：开头的 ~、~/、~\ 展开到 OpenClaw 的主目录，相对路径换成绝对路径。
func openclawPath(t Target, p string) string {
	return openclawAbs(OpenClawHome(t), strings.TrimSpace(p))
}

func openclawAbs(home, p string) string {
	switch {
	case p == "~":
		p = home
	case strings.HasPrefix(p, "~/"), strings.HasPrefix(p, `~\`):
		p = filepath.Join(home, p[2:])
	}
	if !filepath.IsAbs(p) && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, `\`) {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
	}
	return p
}

// openclawLegacyDir 与 openclawLegacyConfig 是 OpenClaw 改名前（Clawdbot）的状态目录与配置文件名，升级来的安装还在用。
const (
	openclawLegacyDir    = ".clawdbot"
	openclawLegacyConfig = "clawdbot.json"
)

// OpenClawStateDir 是 OpenClaw 的状态目录：$OPENCLAW_STATE_DIR；没有设置时是 <主目录>/.openclaw，它不存在而改名前的
// <主目录>/.clawdbot 存在时用后者（与 OpenClaw 2026.10.4 的 resolveStateDir 一样）。--profile 选择的其他配置档
// （~/.openclaw-<名字>）不在这里，要用 OPENCLAW_STATE_DIR 或 OPENCLAW_CONFIG_PATH 指过去。
func OpenClawStateDir(t Target) string {
	if d := strings.TrimSpace(t.Getenv("OPENCLAW_STATE_DIR")); d != "" {
		return openclawPath(t, d)
	}
	dir := filepath.Join(OpenClawHome(t), ".openclaw")
	if !exists(dir) {
		if legacy := filepath.Join(OpenClawHome(t), openclawLegacyDir); exists(legacy) {
			return legacy
		}
	}
	return dir
}

// OpenClawConfig 是 OpenClaw 的配置文件，按 OpenClaw 2026.10.4 选择配置的方式（resolveConfigPathCandidate）：
// $OPENCLAW_CONFIG_PATH；没有设置时依次在 $OPENCLAW_STATE_DIR（设置了时）、<主目录>/.openclaw、<主目录>/.clawdbot 里找
// openclaw.json 与改名前的 clawdbot.json，取第一个存在的；都不存在时是 <状态目录>/openclaw.json。
func OpenClawConfig(t Target) string {
	if p := strings.TrimSpace(t.Getenv("OPENCLAW_CONFIG_PATH")); p != "" {
		return openclawPath(t, p)
	}
	var dirs []string
	if d := strings.TrimSpace(t.Getenv("OPENCLAW_STATE_DIR")); d != "" {
		dirs = append(dirs, openclawPath(t, d))
	}
	dirs = append(dirs, filepath.Join(OpenClawHome(t), ".openclaw"), filepath.Join(OpenClawHome(t), openclawLegacyDir))
	for _, d := range dirs {
		for _, name := range []string{"openclaw.json", openclawLegacyConfig} {
			if p := filepath.Join(d, name); exists(p) {
				return p
			}
		}
	}
	return filepath.Join(OpenClawStateDir(t), "openclaw.json")
}

// openclawLegacy 报告配置文件是不是改名前的位置（.clawdbot 目录里，或叫 clawdbot.json）。
func openclawLegacy(config string) bool {
	return filepath.Base(config) == openclawLegacyConfig || filepath.Base(filepath.Dir(config)) == openclawLegacyDir
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// openclawManaged 返回让 OpenClaw 的配置只读的环境变量（OPENCLAW_NIX_MODE=1：配置由 Nix 管理；
// OPENCLAW_CONFIG_READONLY=1），没有时为空。与 OpenClaw 的 resolveIsConfigReadOnly 一样只认 1。
func openclawManaged(t Target) string {
	for _, k := range []string{"OPENCLAW_NIX_MODE", "OPENCLAW_CONFIG_READONLY"} {
		if t.Getenv(k) == "1" {
			return k
		}
	}
	return ""
}

// openclawIncludeRe 找出 $include 的值：一个字符串或字符串列表（JSON 与 JSON5 的写法，键可以不带引号）。
// 只看文本，注释里的 $include 也算：多保护几个文件只会更严。
var (
	openclawIncludeRe = regexp.MustCompile(`["']?\$include["']?\s*:\s*(\[[^\]]*\]|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')`)
	openclawStringRe  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
)

// openclawMaxIncludes 是 OpenClawIncludes 最多跟进的文件数。
const openclawMaxIncludes = 64

// OpenClawIncludes 返回 OpenClaw 的配置用 $include 引入的文件（逐层跟进，相对路径按引入它的文件所在目录解析），
// 不含配置文件本身。unresolved 为 true 表示有引入的文件读不到，或超过 openclawMaxIncludes：它们里面的设置看不到。
func OpenClawIncludes(t Target) (files []string, unresolved bool) {
	seen := map[string]bool{}
	queue := []string{OpenClawConfig(t)}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		b, err := os.ReadFile(f)
		if err != nil {
			if len(seen) > 0 { // 配置文件本身不存在不算
				unresolved = true
			}
			seen[f] = true
			continue
		}
		seen[f] = true
		for _, m := range openclawIncludeRe.FindAllStringSubmatch(string(b), -1) {
			for _, q := range openclawStringRe.FindAllString(m[1], -1) {
				inc := unquoteJSON5(q)
				if strings.TrimSpace(inc) == "" {
					continue
				}
				if !filepath.IsAbs(inc) {
					inc = filepath.Join(filepath.Dir(f), inc)
				}
				inc = filepath.Clean(inc)
				if seen[inc] || slices.Contains(queue, inc) {
					continue
				}
				if len(files) >= openclawMaxIncludes {
					return files, true
				}
				files = append(files, inc)
				queue = append(queue, inc)
			}
		}
	}
	return files, unresolved
}

// unquoteJSON5 去掉 JSON5 字符串的引号与转义。
func unquoteJSON5(q string) string {
	if strings.HasPrefix(q, "'") {
		q = `"` + strings.ReplaceAll(strings.ReplaceAll(q[1:len(q)-1], `\'`, `'`), `"`, `\"`) + `"`
	}
	var v string
	if json.Unmarshal([]byte(q), &v) != nil {
		return q[1 : len(q)-1]
	}
	return v
}

// OpenClawPluginDir 是写出的插件目录：<config_dir>/extensions/openclaw。
func OpenClawPluginDir(t Target) string { return filepath.Join(t.ConfigDir, "extensions", "openclaw") }

// openclawHookMS 是写进 openclaw.json 的 hook 超时（毫秒）：比插件等 h-guard 的时间多 5 秒。OpenClaw 等不到 hook 时
// 拦下工具调用（工具结果被换成「输出不可用」），不会放行；留出余量是为了让插件先等到 h-guard 的回复或自己的兜底。
func openclawHookMS(timeout int) int { return (timeout + 5) * 1000 }

// openclawMaxTimeout 是 install openclaw 接受的最长 --timeout（秒）：OpenClaw 的 hook 超时最多 600000 毫秒，要留 5 秒余量。
const openclawMaxTimeout = 595

// openclawFiles 返回插件目录里的全部文件：清单、package.json 与入口（CONFIG 一行是 h-guard 的命令与超时）。
func openclawFiles(t Target) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, name := range []string{"openclaw.plugin.json", "package.json", "index.mjs"} {
		b, err := extensions.OpenClaw.ReadFile("openclaw/" + name)
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	index, err := renderExt(files["index.mjs"], "openclaw", t)
	if err != nil {
		return nil, err
	}
	files["index.mjs"] = index
	return files, nil
}

// isOurOpenClawPlugin 报告目录里的插件是否是 h-guard 的：清单的 id 是 h-guard，入口是 h-guard 写出的扩展。
func isOurOpenClawPlugin(files map[string][]byte) bool {
	var m struct{ ID string }
	return json.Unmarshal(files["openclaw.plugin.json"], &m) == nil && m.ID == openclawID && isOurExt(files["index.mjs"])
}

// OpenClaw 计划 OpenClaw 的安装或移除：
//   - 把内嵌的插件写到 <config_dir>/extensions/openclaw（清单、package.json、入口 index.mjs，入口里是 h-guard 的命令与超时）；
//   - 在 openclaw.json 里把这个目录加进 plugins.load.paths，写入 plugins.entries.h-guard 的 enabled、
//     hooks.allowConversationAccess（before_agent_run 要它）与 hooks.timeouts；plugins.allow 不为空时加入 h-guard。
//     plugins.entries.h-guard 的其他键（如通知设置 config）与文件的其余内容原样保留。
//
// openclaw.json 必须是普通 JSON：OpenClaw 也读 JSON5（注释、尾逗号、不带引号的键）与 $include，h-guard 不改写它们，
// 遇到时报错并给出要手工加入的内容。移除先去掉这些设置，再删插件目录。
//
// OpenClaw 的配置只读时（openclawManaged：Nix 或 OPENCLAW_CONFIG_READONLY），配置在别处管理，h-guard 不改 openclaw.json：
// 安装只写插件目录，要加入的设置由 OpenClawNotes 给出；移除时报错，要先在管理配置的地方去掉这些设置（否则删掉插件
// 目录后 OpenClaw 加载不到它）。只计划，不写入（Apply 执行）。
func OpenClaw(t Target, remove bool) ([]Step, error) {
	if !remove && t.Timeout > openclawMaxTimeout {
		return nil, fmt.Errorf("OpenClaw waits at most 600 seconds for a hook, and h-guard needs 5 seconds of that as a margin; use --timeout %d or less", openclawMaxTimeout)
	}
	dir := OpenClawPluginDir(t)
	config := OpenClawConfig(t)
	managed := openclawManaged(t)
	if managed != "" && remove {
		// 配置（及其 $include 引入的文件）里还有 h-guard 的设置，或有引入的文件读不到时拒绝：删掉插件目录后 OpenClaw
		// 就加载不到它
		includes, unresolved := OpenClawIncludes(t)
		refuse := unresolved
		if b, err := os.ReadFile(config); err == nil {
			st, err := readOpenClawState(b, dir, t.samePath, func(p string) string { return openclawPath(t, p) })
			refuse = refuse || err != nil || st.loaded || st.entry
		}
		for _, f := range includes {
			b, err := os.ReadFile(f)
			refuse = refuse || err != nil || bytes.Contains(b, []byte(openclawID))
		}
		if refuse {
			return nil, fmt.Errorf("%s is 1, so OpenClaw's configuration is read-only and h-guard does not edit %s or the files it includes; remove %s from plugins.load.paths and plugins.entries.%s where the configuration is managed, restart the Gateway, then run this again to delete the plugin", managed, config, dir, openclawID)
		}
	}
	files, err := openclawFiles(t)
	if err != nil {
		return nil, err
	}
	plugin, err := dirStep(t, dir, "openclaw-plugin", files, isOurOpenClawPlugin, remove)
	keepDir := false
	if err != nil {
		if !remove {
			return nil, err
		}
		// 目录被换成了别的内容：不删它，但 openclaw.json 里本项目的设置照样去掉，OpenClaw 不再加载它
		keepDir = true
	}
	if !remove {
		plugin.Summary = "write h-guard's OpenClaw plugin"
	}
	if managed != "" {
		if keepDir {
			return nil, nil
		}
		return []Step{plugin}, nil
	}
	ms := openclawHookMS(t.Timeout)
	change := func(old []byte, exists bool) ([]byte, error) {
		return openclawConfigEdit(old, exists, dir, ms, remove, t.samePath, func(p string) string { return openclawPath(t, p) })
	}
	old, err := os.ReadFile(config)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	next, err := change(old, exists)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config, err)
	}
	summary, preview := "load the plugin in openclaw.json", openclawSnippet(dir, ms)
	if remove {
		summary, preview = "remove the plugin from openclaw.json", fmt.Sprintf("remove %s from plugins.load.paths and plugins.entries.%s\n", dir, openclawID)
	}
	ed := t.editor()
	// 预览只显示本项目的设置：openclaw.json 的其他内容有频道令牌等秘密
	set := Step{Path: config, Summary: summary, Preview: []byte(preview), changes: next != nil && !bytes.Equal(next, old), lockDir: ed.LockDir,
		apply: func() error {
			if _, err := ed.editLocked(config, change); err != nil {
				return fmt.Errorf("%s: %w", config, err)
			}
			return nil
		}}
	if remove {
		if keepDir {
			return []Step{set}, nil
		}
		return []Step{set, plugin}, nil
	}
	return []Step{plugin, set}, nil
}

// openclawSnippet 是 install 写进 openclaw.json 的设置（预览，也是无法改写时要手工加入的内容）。
func openclawSnippet(dir string, ms int) string {
	d, _ := json.Marshal(dir)
	var timeouts []string
	for _, h := range openclawHooks {
		timeouts = append(timeouts, fmt.Sprintf("%q: %d", h, ms))
	}
	return fmt.Sprintf(`{
  "plugins": {
    "load": {"paths": [%s]},
    "entries": {
      "%s": {"enabled": true, "hooks": {"allowConversationAccess": true, "timeouts": {%s}}}
    }
  }
}
(and "%s" in plugins.allow when plugins.allow is not empty)
`, d, openclawID, strings.Join(timeouts, ", "), openclawID)
}

// openclawConfigEdit 在 openclaw.json 里加入或去掉本项目的设置（见 OpenClaw）。plugins.allow 只在已有其他条目时
// 加入或去掉 h-guard：空的 allow 表示不限制，移除时把它变成空列表会放开所有插件。没有变化时返回原文；文件不存在且是
// 移除时返回 nil（不新建）。
func openclawConfigEdit(old []byte, exists bool, dir string, ms int, remove bool, same func(a, b string) bool, expand func(string) string) ([]byte, error) {
	if !exists && remove {
		return nil, nil
	}
	o := object{vals: map[string]json.RawMessage{}}
	if exists && len(bytes.TrimSpace(old)) > 0 {
		var err error
		if o, err = parseObject(old); err != nil {
			return nil, fmt.Errorf("not plain JSON (%v); OpenClaw also reads JSON5 (comments, trailing commas, unquoted keys), which h-guard does not rewrite. Add these settings yourself:\n%s", err, openclawSnippet(dir, ms))
		}
	}
	before := o.marshal()
	plugins, err := o.object("plugins")
	if err != nil {
		return nil, err
	}
	load, err := plugins.object("load")
	if err != nil {
		return nil, fmt.Errorf("plugins.%w", err)
	}
	entries, err := plugins.object("entries")
	if err != nil {
		return nil, fmt.Errorf("plugins.%w", err)
	}
	for _, sub := range []struct {
		name string
		o    object
	}{{"", o}, {"plugins.", plugins}, {"plugins.load.", load}, {"plugins.entries.", entries}} {
		if _, ok := sub.o.get("$include"); ok {
			return nil, fmt.Errorf("%s$include splits the configuration into several files, which h-guard does not edit. Add these settings yourself:\n%s", sub.name, openclawSnippet(dir, ms))
		}
	}
	paths, err := stringList(load, "paths")
	if err != nil {
		return nil, fmt.Errorf("plugins.load.%w", err)
	}
	allow, err := stringList(plugins, "allow")
	if err != nil {
		return nil, fmt.Errorf("plugins.%w", err)
	}
	deny, err := stringList(plugins, "deny")
	if err != nil {
		return nil, fmt.Errorf("plugins.%w", err)
	}
	ours := func(p string) bool { return same(expand(p), dir) }
	if remove {
		paths = slices.DeleteFunc(paths, ours)
		entries.delete(openclawID)
		if len(allow) > 1 {
			allow = slices.DeleteFunc(allow, func(s string) bool { return s == openclawID })
		}
	} else {
		if slices.Contains(deny, openclawID) {
			return nil, fmt.Errorf("plugins.deny lists %s, so OpenClaw would not load the plugin; remove it from plugins.deny first", openclawID)
		}
		if !slices.ContainsFunc(paths, ours) {
			paths = append(paths, dir)
		}
		entry, err := entries.object(openclawID)
		if err != nil {
			return nil, fmt.Errorf("plugins.entries.%w", err)
		}
		entry.set("enabled", true)
		hooks, err := entry.object("hooks")
		if err != nil {
			return nil, fmt.Errorf("plugins.entries.%s.%w", openclawID, err)
		}
		hooks.set("allowConversationAccess", true)
		timeouts, err := hooks.object("timeouts")
		if err != nil {
			return nil, fmt.Errorf("plugins.entries.%s.hooks.%w", openclawID, err)
		}
		for _, h := range openclawHooks {
			timeouts.set(h, ms)
		}
		_ = hooks.setObject("timeouts", timeouts)
		_ = entry.setObject("hooks", hooks)
		_ = entries.setObject(openclawID, entry)
		if len(allow) > 0 && !slices.Contains(allow, openclawID) {
			allow = append(allow, openclawID)
		}
	}
	setList := func(o *object, key string, list []string) {
		if _, had := o.get(key); had || len(list) > 0 {
			if len(list) == 0 && remove {
				o.delete(key)
				return
			}
			o.set(key, list)
		}
	}
	setList(&load, "paths", paths)
	setList(&plugins, "allow", allow)
	setSub := func(parent *object, key string, sub object) {
		if len(sub.keys) == 0 {
			parent.delete(key)
		} else {
			_ = parent.setObject(key, sub)
		}
	}
	setSub(&plugins, "load", load)
	setSub(&plugins, "entries", entries)
	setSub(&o, "plugins", plugins)
	if exists && bytes.Equal(o.marshal(), before) {
		return old, nil
	}
	return o.marshal(), nil
}

// stringList 读出 o 里 key 的字符串列表；没有这个键时为空，不是字符串列表时报错。
func stringList(o object, key string) ([]string, error) {
	raw, ok := o.get(key)
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s is not a list of strings", key)
	}
	return list, nil
}

// openclawState 是 openclaw.json 里与 h-guard 有关的设置。
type openclawState struct {
	loaded       bool           // plugins.load.paths 里有插件目录
	entry        bool           // 有 plugins.entries.h-guard
	enabled      bool           // plugins.entries.h-guard.enabled 为 true
	conversation bool           // hooks.allowConversationAccess 为 true
	timeouts     map[string]int // hooks.timeouts
	denied       bool           // plugins.deny 里有 h-guard
	notAllowed   bool           // plugins.allow 不为空且没有 h-guard
	disabled     bool           // plugins.enabled 为 false
}

// readOpenClawState 读出 openclaw.json 里与 h-guard 有关的设置；文件不是普通 JSON 时报错。
func readOpenClawState(b []byte, dir string, same func(a, b string) bool, expand func(string) string) (openclawState, error) {
	var cfg struct {
		Plugins struct {
			Enabled *bool `json:"enabled"`
			Allow   []string
			Deny    []string
			Load    struct{ Paths []string }
			Entries map[string]struct {
				Enabled bool
				Hooks   struct {
					AllowConversationAccess bool
					Timeouts                map[string]int
				}
			}
		}
	}
	if _, err := parseObject(b); err != nil {
		return openclawState{}, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return openclawState{}, err
	}
	p := cfg.Plugins
	e, ok := p.Entries[openclawID]
	return openclawState{
		loaded:       slices.ContainsFunc(p.Load.Paths, func(s string) bool { return same(expand(s), dir) }),
		entry:        ok,
		enabled:      e.Enabled,
		conversation: e.Hooks.AllowConversationAccess,
		timeouts:     e.Hooks.Timeouts,
		denied:       slices.Contains(p.Deny, openclawID),
		notAllowed:   len(p.Allow) > 0 && !slices.Contains(p.Allow, openclawID),
		disabled:     p.Enabled != nil && !*p.Enabled,
	}, nil
}

// openclawRuntimeRe 找出 agentRuntime 选择的 codex、copilot 运行时（provider 或 model 一级的 agentRuntime.id）。
var openclawRuntimeRe = regexp.MustCompile(`["']?agentRuntime["']?\s*:\s*\{[^{}]*?["']?id["']?\s*:\s*["'](codex|copilot)["']`)

// openclawRuntimes 返回配置（及其 $include 引入的文件）里明确选择的 codex、copilot 运行时：这些运行时不发出
// before_agent_run，插件的工具结果 middleware 也只为 OpenClaw 自己的运行时注册。只看文本：OpenAI 模型在 auto 模式下
// 隐式选择 Codex 的情况看不出来（文档里说明）。
func openclawRuntimes(t Target) []string {
	includes, _ := OpenClawIncludes(t)
	var found []string
	for _, f := range append([]string{OpenClawConfig(t)}, includes...) {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, m := range openclawRuntimeRe.FindAllStringSubmatch(string(b), -1) {
			if !slices.Contains(found, m[1]) {
				found = append(found, m[1])
			}
		}
	}
	slices.Sort(found)
	return found
}

// OpenClawNotes 返回 install 与 status 共用的提醒：OpenClaw 的版本、配置只读（install 时附上要加入的设置）、停用了全部
// 插件、选择了 codex 或 copilot 运行时、用 --profile 选择的配置档。
func OpenClawNotes(t Target) []string {
	notes := ExtNotes(t, "openclaw")
	if k := openclawManaged(t); k != "" {
		n := fmt.Sprintf("%s is 1, so OpenClaw's configuration is read-only and h-guard does not edit %s", k, OpenClawConfig(t))
		if t.Timeout > 0 { // install：给出要在管理配置的地方加入的设置
			n += "; add these settings where it is managed:\n" + strings.TrimSuffix(openclawSnippet(OpenClawPluginDir(t), openclawHookMS(t.Timeout)), "\n")
		}
		notes = append(notes, n)
	}
	if config := OpenClawConfig(t); openclawLegacy(config) && strings.TrimSpace(t.Getenv("OPENCLAW_CONFIG_PATH")) == "" {
		notes = append(notes, fmt.Sprintf("OpenClaw uses the configuration from before its rename, %s, so h-guard installs there", config))
	}
	if b, err := os.ReadFile(OpenClawConfig(t)); err == nil {
		if st, err := readOpenClawState(b, OpenClawPluginDir(t), t.samePath, func(p string) string { return openclawPath(t, p) }); err == nil && st.disabled {
			notes = append(notes, fmt.Sprintf("plugins.enabled is false in %s, so OpenClaw loads no plugins, h-guard's included", OpenClawConfig(t)))
		}
	}
	for _, rt := range openclawRuntimes(t) {
		notes = append(notes, fmt.Sprintf("OpenClaw's configuration runs some models on the %s agent runtime, where OpenClaw does not emit before_agent_run and h-guard's tool output middleware is not registered: prompts and tool output on those turns are not checked, and only the tool calls OpenClaw relays to before_tool_call are", rt))
	}
	if p := strings.TrimSpace(t.Getenv("OPENCLAW_PROFILE")); p != "" && !strings.EqualFold(p, "default") &&
		t.Getenv("OPENCLAW_STATE_DIR") == "" && t.Getenv("OPENCLAW_CONFIG_PATH") == "" {
		notes = append(notes, fmt.Sprintf("OPENCLAW_PROFILE is %s, but install writes to %s; set OPENCLAW_STATE_DIR to that profile's directory to install there", p, OpenClawConfig(t)))
	}
	return notes
}

// inspectOpenClaw 检查 OpenClaw：插件目录，与 openclaw.json 里加载并启用它的设置。
func inspectOpenClaw(t Target) []string {
	dir, config := OpenClawPluginDir(t), OpenClawConfig(t)
	files, _ := snapshot(dir)
	var st openclawState
	if b, err := os.ReadFile(config); err == nil {
		var cerr error
		if st, cerr = readOpenClawState(b, dir, t.samePath, func(p string) string { return openclawPath(t, p) }); cerr != nil {
			return []string{fmt.Sprintf("problem: %s cannot be read as plain JSON: %v", config, cerr)}
		}
	}
	if len(files) == 0 && !st.loaded && !st.entry {
		return []string{"not installed (h-guard install openclaw)"}
	}
	lines := []string{extInstalledLine(t, "openclaw", "OpenClaw")}
	fix := "; run h-guard install openclaw --write"
	if openclawManaged(t) != "" {
		fix = "; add it where OpenClaw's configuration is managed"
	}
	switch {
	case !st.loaded:
		lines = append(lines, fmt.Sprintf("problem: %s does not list %s in plugins.load.paths%s", config, dir, fix))
	case !st.entry || !st.enabled:
		lines = append(lines, fmt.Sprintf("problem: plugins.entries.%s.enabled is not true in %s, so the tool output check does not load%s", openclawID, config, fix))
	}
	if st.entry && !st.conversation {
		lines = append(lines, fmt.Sprintf("problem: plugins.entries.%s.hooks.allowConversationAccess is not true in %s, so prompts are not checked%s", openclawID, config, fix))
	}
	if st.denied {
		lines = append(lines, fmt.Sprintf("problem: plugins.deny in %s lists %s, so OpenClaw does not load it", config, openclawID))
	}
	if st.notAllowed {
		lines = append(lines, fmt.Sprintf("problem: plugins.allow in %s does not list %s, so OpenClaw does not load it%s", config, openclawID, fix))
	}
	if len(files) == 0 {
		return append(lines, fmt.Sprintf("problem: %s loads %s, but the plugin is missing%s", config, dir, fix))
	}
	if !isOurOpenClawPlugin(files) {
		return append(lines, fmt.Sprintf("problem: %s is not h-guard's plugin", dir))
	}
	lines = append(lines, extProblems(t, "openclaw", files["index.mjs"])...)
	want, err := openclawFiles(Target{Bin: "h-guard", Timeout: 20})
	if err != nil || len(files) != len(want) || !bytes.Equal(files["openclaw.plugin.json"], want["openclaw.plugin.json"]) || !bytes.Equal(files["package.json"], want["package.json"]) {
		lines = append(lines, "problem: the plugin files differ from this h-guard version (missing, edited or written by another version)"+fix)
	}
	if _, timeout, ok := installedExt(files["index.mjs"], "openclaw"); ok && st.entry {
		ms := openclawHookMS(timeout)
		for _, h := range openclawHooks {
			if st.timeouts[h] < ms {
				lines = append(lines, fmt.Sprintf("problem: OpenClaw waits %dms for %s but h-guard is given %ds%s", st.timeouts[h], h, timeout, fix))
			}
		}
	}
	for _, n := range OpenClawNotes(t) {
		lines = append(lines, "note: "+n)
	}
	return lines
}

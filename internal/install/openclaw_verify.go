package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// openclawTypedHooks 是插件注册的 hook（工具结果 middleware 不在 openclaw plugins inspect 的 typedHooks 里，看清单的
// contracts.agentToolResultMiddleware）。
var openclawTypedHooks = []string{"before_tool_call", "before_agent_run", "before_dispatch"}

// openclawInspect 是 openclaw plugins inspect h-guard --json（2026.10.4）输出里 h-guard 用到的部分。不带 --runtime 时
// OpenClaw 只读清单与配置，不加载插件的代码，typedHooks 为空；带 --runtime 时在这个进程里加载插件，列出它注册的 hook。
// OpenClaw 读不了配置或找不到插件时输出 {ok: false, error: {message}, issues: [{path, message}]}，退出码非零。
type openclawInspect struct {
	OK    *bool `json:"ok"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
	Issues []struct {
		Path    string `json:"path"`
		Message string `json:"message"`
	} `json:"issues"`
	Plugin *struct {
		Status           string `json:"status"`
		Enabled          bool   `json:"enabled"`
		Activated        bool   `json:"activated"`
		ActivationReason string `json:"activationReason"`
		Error            string `json:"error"`
		Source           string `json:"source"`
		Contracts        struct {
			AgentToolResultMiddleware []string `json:"agentToolResultMiddleware"`
		} `json:"contracts"`
	} `json:"plugin"`
	TypedHooks []struct {
		Name string `json:"name"`
	} `json:"typedHooks"`
	Policy struct {
		AllowConversationAccess bool           `json:"allowConversationAccess"`
		HookTimeouts            map[string]int `json:"hookTimeouts"`
	} `json:"policy"`
}

// queryOpenClawInspect 运行 openclaw plugins inspect h-guard [--runtime] --json。why 不为空表示问不到 OpenClaw（没有安装、
// 命令失败、输出读不懂）。
func queryOpenClawInspect(t Target, runtime bool) (r openclawInspect, why string) {
	args := []string{"plugins", "inspect", openclawID, "--json"}
	if runtime {
		args = []string{"plugins", "inspect", openclawID, "--runtime", "--json"}
	}
	out, err := t.Query("openclaw", args...)
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		if err != nil {
			return r, "openclaw plugins inspect: " + err.Error()
		}
		return r, "openclaw plugins inspect printed something h-guard cannot read"
	}
	if (r.OK == nil || *r.OK) && r.Plugin == nil {
		return r, "openclaw plugins inspect did not describe the plugin"
	}
	return r, ""
}

// openclawPluginIntact 报告插件目录是否正是这个 h-guard 写出的内容：目录本身不是符号链接，里面只有普通文件，文件名与
// 每个字节都与按入口里记下的 h-guard 路径和超时生成的一致。只有这样才让 OpenClaw 加载它的代码（--runtime）。
func openclawPluginIntact(dir string) bool {
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return false
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return false
		}
		files[e.Name()] = b
	}
	bin, timeout, ok := installedExt(files["index.mjs"], "openclaw")
	if !ok {
		return false
	}
	want, err := openclawFiles(Target{Bin: bin, Timeout: timeout})
	return err == nil && maps.EqualFunc(files, want, bytes.Equal)
}

// OpenClawVerify 问 OpenClaw 自己是否加载 h-guard 的插件（只读，不改 Gateway）。ms 是 h-guard 要求的 hook 超时（毫秒），
// 0 表示不检查。verified 为真表示 OpenClaw 给出了结论，lines 是要报告的结果（"problem: …" 与普通说明）；为假表示问不到
// OpenClaw，lines 说明没能确认。OpenClaw 按运行 h-guard 的进程的环境读配置，Gateway 的环境不同时结论可能不同。
//
// 先不带 --runtime 问（OpenClaw 只读清单与配置，不运行插件的代码）：插件是否加载、从哪个文件加载、middleware、对话权限与
// 超时。只有 OpenClaw 从 h-guard 的插件目录加载它，且就在这之前确认目录里正是这个 h-guard 写出的文件时，才带 --runtime
// 再问一次以列出插件注册的 hook：--runtime 会在运行 h-guard 的进程里执行插件的代码，被改动过的插件不能这样运行。
func OpenClawVerify(t Target, ms int) (lines []string, verified bool) {
	unverified := func(why string) ([]string, bool) {
		return []string{"note: could not verify with OpenClaw that it loads h-guard's plugin (" + why + "); the checks above read the configuration the way h-guard understands it"}, false
	}
	if t.Query == nil {
		return unverified("the openclaw command cannot be run here")
	}
	r, why := queryOpenClawInspect(t, false)
	if why != "" {
		return unverified(why)
	}
	if r.OK != nil && !*r.OK {
		msg := strings.TrimSpace(r.Error.Message)
		var issues []string
		for _, is := range r.Issues {
			issues = append(issues, strings.TrimSpace(is.Path+": "+is.Message))
		}
		if len(issues) > 0 {
			msg += " (" + strings.Join(issues, "; ") + ")"
		}
		return []string{"problem: OpenClaw does not load h-guard's plugin: " + msg}, true
	}
	p := r.Plugin
	if p.Status != "loaded" || !p.Enabled || !p.Activated {
		why := cmpOrString(p.Error, p.ActivationReason, p.Status)
		return []string{fmt.Sprintf("problem: OpenClaw reports h-guard's plugin as %s (%s)", cmpOrString(p.Status, "not loaded"), why)}, true
	}
	dir := OpenClawPluginDir(t)
	ours := true
	if want := filepath.Join(dir, "index.mjs"); !t.samePath(p.Source, want) {
		ours = false
		lines = append(lines, fmt.Sprintf("problem: OpenClaw loads h-guard's plugin from %s, not from %s", cmpOrString(p.Source, "an unknown file"), want))
	}
	if !slices.Contains(p.Contracts.AgentToolResultMiddleware, "openclaw") {
		lines = append(lines, "problem: OpenClaw does not list the plugin's tool result middleware, so tool output is not checked")
	}
	if !r.Policy.AllowConversationAccess {
		lines = append(lines, "problem: OpenClaw does not give the plugin conversation access, so prompts are not checked")
	}
	if ms > 0 {
		for _, h := range openclawHooks {
			if got := r.Policy.HookTimeouts[h]; got < ms {
				lines = append(lines, fmt.Sprintf("problem: OpenClaw waits %dms for %s but h-guard needs %dms", got, h, ms))
			}
		}
	}
	hooksChecked := false
	switch {
	case !ours:
	case !openclawPluginIntact(dir): // 就在运行 --runtime 之前确认
		lines = append(lines, fmt.Sprintf("note: h-guard did not have OpenClaw load the plugin to list its hooks, because %s does not hold exactly the files this h-guard writes", dir))
	default:
		rt, why := queryOpenClawInspect(t, true)
		if why == "" && rt.OK != nil && !*rt.OK {
			why = strings.TrimSpace(rt.Error.Message)
		}
		if why != "" {
			lines = append(lines, "note: could not list the plugin's hooks with OpenClaw ("+why+")")
			break
		}
		hooksChecked = true
		var hooks []string
		for _, h := range rt.TypedHooks {
			hooks = append(hooks, h.Name)
		}
		for _, h := range openclawTypedHooks {
			if !slices.Contains(hooks, h) {
				lines = append(lines, fmt.Sprintf("problem: OpenClaw did not register the plugin's %s hook", h))
			}
		}
	}
	if len(lines) == 0 && hooksChecked {
		lines = append(lines, "verified with OpenClaw (openclaw plugins inspect): it loads h-guard's plugin with its hooks and tool result middleware")
	}
	return lines, true
}

// cmpOrString 返回第一个非空的字符串。
func cmpOrString(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

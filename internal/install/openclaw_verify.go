package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// openclawTypedHooks 是插件注册的 hook（工具结果 middleware 不在 openclaw plugins inspect 的 typedHooks 里，看清单的
// contracts.agentToolResultMiddleware）。
var openclawTypedHooks = []string{"before_tool_call", "before_agent_run", "before_dispatch"}

// openclawInspect 是 openclaw plugins inspect h-guard --runtime --json（2026.10.4）输出里 h-guard 用到的部分。
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

// OpenClawVerify 问 OpenClaw 自己是否加载 h-guard 的插件：运行 openclaw plugins inspect h-guard --runtime --json（只读，
// 不改 Gateway；--runtime 在这个进程里加载插件、列出它注册的 hook）。ms 是 h-guard 要求的 hook 超时（毫秒），0 表示
// 不检查。verified 为真表示 OpenClaw 给出了结论，lines 是要报告的结果（"problem: …" 与普通说明）；为假表示问不到
// OpenClaw（没有安装、命令失败、输出读不懂），lines 说明没能确认。OpenClaw 按运行 h-guard 的进程的环境读配置，
// Gateway 的环境不同时结论可能不同。
func OpenClawVerify(t Target, ms int) (lines []string, verified bool) {
	unverified := func(why string) ([]string, bool) {
		return []string{"note: could not verify with OpenClaw that it loads h-guard's plugin (" + why + "); the checks above read the configuration the way h-guard understands it"}, false
	}
	if t.Query == nil {
		return unverified("the openclaw command cannot be run here")
	}
	out, err := t.Query("openclaw", "plugins", "inspect", openclawID, "--runtime", "--json")
	var r openclawInspect
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		if err != nil {
			return unverified("openclaw plugins inspect: " + err.Error())
		}
		return unverified("openclaw plugins inspect printed something h-guard cannot read")
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
	if r.Plugin == nil {
		return unverified("openclaw plugins inspect did not describe the plugin")
	}
	p := r.Plugin
	if p.Status != "loaded" || !p.Enabled || !p.Activated {
		why := cmpOrString(p.Error, p.ActivationReason, p.Status)
		return []string{fmt.Sprintf("problem: OpenClaw reports h-guard's plugin as %s (%s)", cmpOrString(p.Status, "not loaded"), why)}, true
	}
	if want := filepath.Join(OpenClawPluginDir(t), "index.mjs"); p.Source != "" && !t.samePath(p.Source, want) {
		lines = append(lines, fmt.Sprintf("problem: OpenClaw loads h-guard's plugin from %s, not from %s", p.Source, want))
	}
	var hooks []string
	for _, h := range r.TypedHooks {
		hooks = append(hooks, h.Name)
	}
	for _, h := range openclawTypedHooks {
		if !slices.Contains(hooks, h) {
			lines = append(lines, fmt.Sprintf("problem: OpenClaw did not register the plugin's %s hook", h))
		}
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
	if len(lines) == 0 {
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

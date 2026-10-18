package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/internal/store"
)

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// openclawJSON 是 OpenClaw 自己写出的配置：两个空格缩进的 JSON，带 meta。
const openclawJSON = `{
  "gateway": {
    "mode": "local",
    "auth": {
      "token": "made-up-token"
    }
  },
  "plugins": {
    "allow": [
      "telegram"
    ],
    "entries": {
      "telegram": {
        "enabled": true
      }
    }
  },
  "meta": {
    "lastTouchedVersion": "2026.10.4"
  }
}
`

// TestOpenClawInstall：写出插件目录，在 openclaw.json 里加载、启用它并给出超时；其他内容与键的顺序保留，allow 不为空时
// 加入 h-guard；重装不改动，已有的通知设置保留；status 没有问题。
func TestOpenClawInstall(t *testing.T) {
	tg := target(t, "linux")
	tg.Bin = filepath.Join(tg.Home, "bin", "h-guard")
	writeFile(t, tg.Bin, "")
	config := OpenClawConfig(tg)
	if config != filepath.Join(tg.Home, ".openclaw", "openclaw.json") {
		t.Fatalf("config path %s", config)
	}
	writeFile(t, config, openclawJSON)
	apply(t, plan(t, tg, "openclaw", false))
	dir := OpenClawPluginDir(tg)
	for _, name := range []string{"openclaw.plugin.json", "package.json", "index.mjs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "index.mjs")); !strings.Contains(string(b), `const CONFIG = {"command":[`+jsonString(tg.Bin)+`,"hook","openclaw","--timeout","20"],"timeout_ms":20000} // h-guard install`) {
		t.Errorf("CONFIG line not written:\n%s", b)
	}
	got := readFile(t, config)
	m := readJSON(t, config)
	plugins := m["plugins"].(map[string]any)
	if paths := plugins["load"].(map[string]any)["paths"].([]any); len(paths) != 1 || paths[0] != dir {
		t.Errorf("load.paths = %v", paths)
	}
	entry := plugins["entries"].(map[string]any)["h-guard"].(map[string]any)
	hooks := entry["hooks"].(map[string]any)
	if entry["enabled"] != true || hooks["allowConversationAccess"] != true {
		t.Errorf("entry = %v", entry)
	}
	for _, h := range []string{"before_tool_call", "before_agent_run", "before_dispatch", "after_tool_call"} {
		if hooks["timeouts"].(map[string]any)[h] != float64(25000) {
			t.Errorf("timeout for %s: %v", h, hooks["timeouts"])
		}
	}
	if allow := plugins["allow"].([]any); len(allow) != 2 || allow[1] != "h-guard" {
		t.Errorf("allow = %v", allow)
	}
	for _, keep := range []string{`"made-up-token"`, `"lastTouchedVersion": "2026.10.4"`, `"telegram": {`} {
		if !strings.Contains(got, keep) {
			t.Errorf("lost %s:\n%s", keep, got)
		}
	}
	if strings.Index(got, `"gateway"`) > strings.Index(got, `"plugins"`) || strings.Index(got, `"plugins"`) > strings.Index(got, `"meta"`) {
		t.Errorf("key order changed:\n%s", got)
	}
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); strings.Contains(lines, "problem") || !strings.HasPrefix(lines, "installed") {
		t.Errorf("status after install:\n%s", lines)
	}
	noChanges(t, plan(t, tg, "openclaw", false))

	// 用户加的通知设置（plugins.entries.h-guard.config）在重装时保留
	m["plugins"].(map[string]any)["entries"].(map[string]any)["h-guard"].(map[string]any)["config"] = map[string]any{"notify": map[string]any{"targets": []any{map[string]any{"channel": "telegram", "to": "1"}}}}
	b, _ := json.MarshalIndent(m, "", "  ")
	writeFile(t, config, string(b)+"\n")
	tg.Timeout = 30
	apply(t, plan(t, tg, "openclaw", false))
	if got := readFile(t, config); !strings.Contains(got, `"notify"`) || !strings.Contains(got, `"before_tool_call": 35000`) {
		t.Errorf("after reinstall:\n%s", got)
	}
}

// TestOpenClawTimeout：OpenClaw 的 hook 超时最多 600 秒，--timeout 要给插件留 5 秒余量：595 可以，596 拒绝；移除不受影响。
func TestOpenClawTimeout(t *testing.T) {
	tg := target(t, "linux")
	tg.Timeout = 595
	apply(t, plan(t, tg, "openclaw", false))
	if got := readFile(t, OpenClawConfig(tg)); !strings.Contains(got, `"before_tool_call": 600000`) {
		t.Errorf("config:\n%s", got)
	}
	tg.Timeout = 596
	if _, err := OpenClaw(tg, false); err == nil || !strings.Contains(err.Error(), "--timeout 595 or less") {
		t.Errorf("596: %v", err)
	}
	apply(t, plan(t, tg, "openclaw", true))
}

// TestOpenClawNewConfig：没有 openclaw.json 时新建；allow 为空时不加（空的 allow 表示不限制）。
func TestOpenClawNewConfig(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "openclaw", false))
	m := readJSON(t, OpenClawConfig(tg))
	plugins := m["plugins"].(map[string]any)
	if _, ok := plugins["allow"]; ok || len(m) != 1 {
		t.Errorf("new config: %v", m)
	}
	tg2 := target(t, "linux")
	noChanges(t, plan(t, tg2, "openclaw", true)) // 没有安装时移除不新建
	if _, err := os.Stat(OpenClawConfig(tg2)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove created the config: %v", err)
	}
	if lines := Inspect(tg2, "openclaw"); len(lines) != 1 || !strings.HasPrefix(lines[0], "not installed") {
		t.Errorf("status: %v", lines)
	}
}

// TestOpenClawRemove：移除去掉加载路径、条目与 allow 里的 h-guard（allow 只剩它时不动，免得变成不限制），删掉插件目录。
func TestOpenClawRemove(t *testing.T) {
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	writeFile(t, config, openclawJSON)
	apply(t, plan(t, tg, "openclaw", false))
	apply(t, plan(t, tg, "openclaw", true))
	got := readFile(t, config)
	if strings.Contains(got, "h-guard") || strings.Contains(got, `"load"`) || !strings.Contains(got, `"telegram"`) || !strings.Contains(got, `"allow"`) {
		t.Errorf("after remove:\n%s", got)
	}
	if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("plugin dir still there: %v", err)
	}
	if backups, _ := filepath.Glob(filepath.Join(tg.CacheDir, "backups", "openclaw-plugin.*", "index.mjs")); len(backups) != 1 {
		t.Errorf("backups: %v", backups)
	}
	noChanges(t, plan(t, tg, "openclaw", true))

	writeFile(t, config, `{"plugins": {"allow": ["h-guard"]}}`)
	apply(t, plan(t, tg, "openclaw", false))
	apply(t, plan(t, tg, "openclaw", true))
	if m := readJSON(t, config); len(m["plugins"].(map[string]any)["allow"].([]any)) != 1 {
		t.Errorf("the only allow entry was removed: %v", m)
	}
}

// TestOpenClawRefuses：deny 里的 h-guard、不是对象的 plugins 等报错，什么都不写。
func TestOpenClawRefuses(t *testing.T) {
	for name, tt := range map[string]struct{ config, want string }{
		"denied":         {`{"plugins": {"deny": ["h-guard"]}}`, "plugins.deny lists h-guard"},
		"plugins string": {`{"plugins": "x"}`, "plugins"},
		"paths string":   {`{"plugins": {"load": {"paths": "/x"}}}`, "paths is not a list of strings"},
	} {
		tg := target(t, "linux")
		writeFile(t, OpenClawConfig(tg), tt.config)
		_, err := OpenClaw(tg, false)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want %q", name, err, tt.want)
			continue
		}
		if got := readFile(t, OpenClawConfig(tg)); got != tt.config {
			t.Errorf("%s: the config was changed: %s", name, got)
		}
		if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: plugin written: %v", name, err)
		}
	}
}

// TestOpenClawManualConfig：openclaw.json 用 JSON5 写法或 $include 时 h-guard 不改它：install 照样写出插件目录，另有
// 一步列出要手工加入的设置；实际生效的配置（合并引入的文件之后）已有这些设置时不再列出。status 按合并后的配置
// 报告；remove 在设置还在时拒绝，去掉之后只删插件目录。
func TestOpenClawManualConfig(t *testing.T) {
	for name, tt := range map[string]struct{ config, want string }{
		"comment":        {"{\n  // my gateway\n  \"gateway\": {\"mode\": \"local\"}\n}\n", "not plain JSON"},
		"trailing comma": {`{"gateway": {"mode": "local"},}`, "not plain JSON"},
		"unquoted key":   {`{gateway: {mode: "local"}}`, "not plain JSON"},
		"include":        {`{"$include": "./base.json5"}`, "$include"},
		"plugin include": {`{"plugins": {"$include": "./plugins.json5"}}`, "plugins.$include"},
	} {
		tg := target(t, "linux")
		config := OpenClawConfig(tg)
		writeFile(t, config, tt.config)
		writeFile(t, filepath.Join(filepath.Dir(config), "base.json5"), "{}")
		writeFile(t, filepath.Join(filepath.Dir(config), "plugins.json5"), "{}")
		steps := plan(t, tg, "openclaw", false)
		var manual *Step
		for i, st := range steps {
			if st.Manual != "" {
				manual = &steps[i]
			}
		}
		if manual == nil || !strings.Contains(manual.Summary, tt.want) || !strings.Contains(manual.Manual, `"allowConversationAccess": true`) || manual.Changes() {
			t.Errorf("%s: manual step %+v, want one that says %q and lists the settings", name, manual, tt.want)
		}
		apply(t, steps)
		if got := readFile(t, config); got != tt.config {
			t.Errorf("%s: the config was changed: %s", name, got)
		}
		if _, err := os.Stat(filepath.Join(OpenClawPluginDir(tg), "index.mjs")); err != nil {
			t.Errorf("%s: the plugin was not written: %v", name, err)
		}
		if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "does not list") || !strings.Contains(lines, "add it yourself") {
			t.Errorf("%s: status:\n%s", name, lines)
		}
	}

	// 设置放在引入的 JSON5 文件里：status 不报缺少，install 不再列出，remove 拒绝；去掉之后只删插件目录
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	dir, _ := json.Marshal(OpenClawPluginDir(tg))
	writeFile(t, config, `{"plugins": {"$include": "./plugins.json5"}}`)
	frag := filepath.Join(filepath.Dir(config), "plugins.json5")
	writeFile(t, frag, "{\n  // h-guard\n  load: {paths: ["+string(dir)+"]},\n  entries: {'h-guard': {enabled: true, hooks: {allowConversationAccess: true,\n"+
		"    timeouts: {before_tool_call: 25000, before_agent_run: 25000, before_dispatch: 25000, after_tool_call: 25000}}}},\n}\n")
	apply(t, plan(t, tg, "openclaw", false))
	steps := plan(t, tg, "openclaw", false)
	for _, st := range steps {
		if st.Manual != "" || st.Changes() {
			t.Errorf("settings in an include: step %+v", st)
		}
	}
	lines := strings.Join(Inspect(tg, "openclaw"), "\n")
	if strings.Contains(lines, "does not list") || strings.Contains(lines, "is not true") || strings.Contains(lines, "OpenClaw waits") {
		t.Errorf("status with the settings in an include:\n%s", lines)
	}
	if _, err := OpenClaw(tg, true); err == nil || !strings.Contains(err.Error(), "remove") {
		t.Errorf("remove with the settings in an include: %v, want a refusal", err)
	}
	writeFile(t, frag, "{}")
	apply(t, plan(t, tg, "openclaw", true))
	if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the plugin was not removed: %v", err)
	}
	if got := readFile(t, config); got != `{"plugins": {"$include": "./plugins.json5"}}` {
		t.Errorf("openclaw.json changed on remove: %s", got)
	}

	// 读不全的配置：status 报告，remove 拒绝
	writeFile(t, config, `{"plugins": {"$include": "./missing.json5"}}`)
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "cannot be read") {
		t.Errorf("status with a missing include:\n%s", lines)
	}
	if _, err := OpenClaw(tg, true); err == nil {
		t.Errorf("remove with a missing include: want a refusal")
	}
}

// TestOpenClawConflict：计划之后、执行之前插件目录被改动时，执行报冲突，openclaw.json 也不改动。
func TestOpenClawConflict(t *testing.T) {
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	writeFile(t, config, openclawJSON)
	apply(t, plan(t, tg, "openclaw", false))
	tg.Timeout = 30
	steps := plan(t, tg, "openclaw", false)
	index := filepath.Join(OpenClawPluginDir(tg), "index.mjs")
	writeFile(t, index, readFile(t, index)+"\n")
	if err := Apply(steps); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Apply = %v, want ErrConflict", err)
	}
	if got := readFile(t, config); strings.Contains(got, "30000") {
		t.Errorf("config changed:\n%s", got)
	}
}

// TestOpenClawForeignDir：别人的同名目录不覆盖；移除时不删它，但 openclaw.json 里本项目的设置照样去掉。
func TestOpenClawForeignDir(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "openclaw", false))
	other := filepath.Join(OpenClawPluginDir(tg), "openclaw.plugin.json")
	writeFile(t, other, `{"id": "someone-else"}`)
	if _, err := OpenClaw(tg, false); err == nil {
		t.Error("no error for a foreign plugin directory")
	}
	apply(t, plan(t, tg, "openclaw", true))
	if got := readFile(t, OpenClawConfig(tg)); strings.Contains(got, "h-guard") {
		t.Errorf("config still loads h-guard:\n%s", got)
	}
	if got := readFile(t, other); got != `{"id": "someone-else"}` {
		t.Errorf("the foreign directory was changed: %s", got)
	}
}

// TestOpenClawPaths：OPENCLAW_CONFIG_PATH、OPENCLAW_STATE_DIR、OPENCLAW_HOME（开头的 ~ 展开）决定 openclaw.json 的位置；
// load.paths 里用 ~ 写的插件目录同样认得。
func TestOpenClawPaths(t *testing.T) {
	tg := target(t, "linux")
	for _, tt := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"OPENCLAW_HOME": "~/oc"}, filepath.Join(tg.Home, "oc", ".openclaw", "openclaw.json")},
		// OpenClaw 把空白与字面的 undefined、null 当作没有设置
		{map[string]string{"OPENCLAW_HOME": " undefined "}, filepath.Join(tg.Home, ".openclaw", "openclaw.json")},
		{map[string]string{"OPENCLAW_HOME": "null", "OPENCLAW_STATE_DIR": "~/state"}, filepath.Join(tg.Home, "state", "openclaw.json")},
		{map[string]string{"OPENCLAW_HOME": "  "}, filepath.Join(tg.Home, ".openclaw", "openclaw.json")},
		{map[string]string{"OPENCLAW_STATE_DIR": "~/state"}, filepath.Join(tg.Home, "state", "openclaw.json")},
		{map[string]string{"OPENCLAW_HOME": "/srv/oc", "OPENCLAW_STATE_DIR": "~/state"}, filepath.Join("/srv/oc", "state", "openclaw.json")},
		{map[string]string{"OPENCLAW_CONFIG_PATH": "/etc/oc.json", "OPENCLAW_STATE_DIR": "/x"}, "/etc/oc.json"},
	} {
		tg.Getenv = env(tt.env)
		if got := OpenClawConfig(tg); got != tt.want {
			t.Errorf("%v: %s, want %s", tt.env, got, tt.want)
		}
	}
	tg.Getenv = env(nil)
	tg.ConfigDir = filepath.Join(tg.Home, ".config", "h-guard")
	writeFile(t, OpenClawConfig(tg), `{"plugins": {"load": {"paths": ["~/.config/h-guard/extensions/openclaw"]}}}`)
	apply(t, plan(t, tg, "openclaw", false))
	if paths := readJSON(t, OpenClawConfig(tg))["plugins"].(map[string]any)["load"].(map[string]any)["paths"].([]any); len(paths) != 1 {
		t.Errorf("the ~ path was not recognized: %v", paths)
	}
}

// TestOpenClawStatus：status 报告缺少的设置、不够长的超时、allow 与 deny、停用全部插件、版本与配置档。
func TestOpenClawStatus(t *testing.T) {
	tg := target(t, "linux")
	apply(t, plan(t, tg, "openclaw", false))
	config := OpenClawConfig(tg)
	dir, _ := json.Marshal(OpenClawPluginDir(tg))
	writeFile(t, config, `{"plugins": {"enabled": false, "allow": ["telegram"], "deny": ["h-guard"], "load": {"paths": [`+string(dir)+`]},
		"entries": {"h-guard": {"enabled": true, "hooks": {"timeouts": {"before_tool_call": 15000}}}}}}`)
	tg.Run = func(name string, args ...string) ([]byte, error) {
		if name == "openclaw" {
			return []byte("OpenClaw 2026.10.3 (abc1234)\n"), nil
		}
		return nil, errors.New("not found")
	}
	tg.Getenv = env(map[string]string{"OPENCLAW_PROFILE": "work"})
	lines := strings.Join(Inspect(tg, "openclaw"), "\n")
	for _, want := range []string{
		"installed (OpenClaw 2026.10.3)",
		"allowConversationAccess is not true",
		"plugins.deny in " + config + " lists h-guard",
		"plugins.allow in " + config + " does not list h-guard",
		"OpenClaw waits 15000ms for before_tool_call",
		"OpenClaw waits 0ms for before_agent_run",
		"note: OpenClaw 2026.10.3 is older than",
		"note: plugins.enabled is false",
		"note: OPENCLAW_PROFILE is work",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("status lacks %q:\n%s", want, lines)
		}
	}
	writeFile(t, config, `{}`)
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "does not list "+OpenClawPluginDir(tg)+" in plugins.load.paths") {
		t.Errorf("status:\n%s", lines)
	}
	os.WriteFile(filepath.Join(OpenClawPluginDir(tg), "package.json"), []byte("{}"), 0o600)
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "the plugin files differ") {
		t.Errorf("status:\n%s", lines)
	}
}

// TestOpenClawLegacy：升级来的安装没有 ~/.openclaw 时，OpenClaw 用改名前的 ~/.clawdbot，并在状态目录里依次找
// openclaw.json 与 clawdbot.json；install 写进 OpenClaw 实际读的那个文件，status 注明这一点。
func TestOpenClawLegacy(t *testing.T) {
	tg := target(t, "linux")
	legacy := filepath.Join(tg.Home, ".clawdbot")
	os.MkdirAll(legacy, 0o700)
	if got, want := OpenClawStateDir(tg), legacy; got != want {
		t.Errorf("state dir %s, want %s", got, want)
	}
	if got, want := OpenClawConfig(tg), filepath.Join(legacy, "openclaw.json"); got != want {
		t.Errorf("config %s, want %s", got, want)
	}
	writeFile(t, filepath.Join(legacy, "clawdbot.json"), `{"gateway": {"port": 18789}}`)
	config := OpenClawConfig(tg)
	if want := filepath.Join(legacy, "clawdbot.json"); config != want {
		t.Fatalf("config %s, want %s", config, want)
	}
	apply(t, plan(t, tg, "openclaw", false))
	m := readJSON(t, config)
	if m["gateway"] == nil || m["plugins"].(map[string]any)["entries"].(map[string]any)["h-guard"] == nil {
		t.Errorf("the legacy configuration was not edited: %v", m)
	}
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "note: OpenClaw uses the configuration from before its rename, "+config) {
		t.Errorf("status:\n%s", lines)
	}

	// ~/.openclaw 存在时它优先，里面的 clawdbot.json 先于 ~/.clawdbot 的文件
	dir := filepath.Join(tg.Home, ".openclaw")
	os.MkdirAll(dir, 0o700)
	if got := OpenClawStateDir(tg); got != dir {
		t.Errorf("state dir %s, want %s", got, dir)
	}
	writeFile(t, filepath.Join(dir, "clawdbot.json"), `{}`)
	if got, want := OpenClawConfig(tg), filepath.Join(dir, "clawdbot.json"); got != want {
		t.Errorf("config %s, want %s", got, want)
	}
	writeFile(t, filepath.Join(dir, "openclaw.json"), `{}`)
	if got, want := OpenClawConfig(tg), filepath.Join(dir, "openclaw.json"); got != want {
		t.Errorf("config %s, want %s", got, want)
	}
	// OPENCLAW_STATE_DIR 里没有配置文件时，OpenClaw 接着找默认位置
	tg.Getenv = env(map[string]string{"OPENCLAW_STATE_DIR": filepath.Join(tg.Home, "state")})
	if got, want := OpenClawConfig(tg), filepath.Join(dir, "openclaw.json"); got != want {
		t.Errorf("config with an empty OPENCLAW_STATE_DIR %s, want %s", got, want)
	}
	writeFile(t, filepath.Join(tg.Home, "state", "clawdbot.json"), `{}`)
	if got, want := OpenClawConfig(tg), filepath.Join(tg.Home, "state", "clawdbot.json"); got != want {
		t.Errorf("config %s, want %s", got, want)
	}
}

// TestOpenClawReadOnly：OPENCLAW_NIX_MODE=1 或 OPENCLAW_CONFIG_READONLY=1 时 OpenClaw 的配置在别处管理：install 只写
// 插件目录、不改 openclaw.json，并给出要加入的设置；配置里还有 h-guard 的设置时 remove 拒绝；status 注明。
func TestOpenClawReadOnly(t *testing.T) {
	for _, k := range []string{"OPENCLAW_NIX_MODE", "OPENCLAW_CONFIG_READONLY"} {
		tg := target(t, "linux")
		tg.Getenv = env(map[string]string{k: "1"})
		config := OpenClawConfig(tg)
		writeFile(t, config, `{"gateway": {"port": 18789}}`)
		steps := plan(t, tg, "openclaw", false)
		manual := false
		for _, s := range steps {
			if s.Path == config && s.Changes() {
				t.Errorf("%s: install edits %s", k, config)
			}
			manual = manual || strings.Contains(s.Manual, `"allowConversationAccess": true`) && strings.Contains(s.Summary, k+" is 1")
		}
		if !manual {
			t.Errorf("%s: no step lists the settings to add: %+v", k, steps)
		}
		apply(t, steps)
		if got := readFile(t, config); got != `{"gateway": {"port": 18789}}` {
			t.Errorf("%s: openclaw.json changed: %s", k, got)
		}
		if _, err := os.Stat(filepath.Join(OpenClawPluginDir(tg), "index.mjs")); err != nil {
			t.Errorf("%s: the plugin was not written: %v", k, err)
		}
		notes := strings.Join(OpenClawNotes(tg), "\n")
		if !strings.Contains(notes, k+" is 1, so OpenClaw's configuration is read-only") {
			t.Errorf("%s: notes:\n%s", k, notes)
		}
		status := Target{Home: tg.Home, ConfigDir: tg.ConfigDir, CacheDir: tg.CacheDir, GOOS: "linux", Getenv: tg.Getenv}
		lines := strings.Join(Inspect(status, "openclaw"), "\n")
		if !strings.Contains(lines, "note: "+k+" is 1") || !strings.Contains(lines, "add it where OpenClaw's configuration is managed") || strings.Contains(lines, `"allowConversationAccess"`) {
			t.Errorf("%s: status:\n%s", k, lines)
		}

		// 管理配置的地方加入了设置之后，remove 拒绝（删掉插件目录 OpenClaw 就加载不到它）；去掉设置之后只删插件目录
		dir, _ := json.Marshal(OpenClawPluginDir(tg))
		managed := `{"plugins": {"load": {"paths": [` + string(dir) + `]}, "entries": {"h-guard": {"enabled": true}}}}`
		writeFile(t, config, managed)
		if _, err := OpenClaw(tg, true); err == nil || !strings.Contains(err.Error(), "read-only") {
			t.Errorf("%s: remove: %v, want a refusal", k, err)
		}
		writeFile(t, config, `{}`)
		apply(t, plan(t, tg, "openclaw", true))
		if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the plugin was not removed: %v", k, err)
		}
		if got := readFile(t, config); got != `{}` {
			t.Errorf("%s: openclaw.json changed on remove: %s", k, got)
		}
	}
	// 与 OpenClaw 一样只认 1
	tg := target(t, "linux")
	tg.Getenv = env(map[string]string{"OPENCLAW_NIX_MODE": "true", "OPENCLAW_CONFIG_READONLY": "0"})
	apply(t, plan(t, tg, "openclaw", false))
	if !strings.Contains(readFile(t, OpenClawConfig(tg)), `"h-guard"`) {
		t.Errorf("a value other than 1 made the configuration read-only")
	}
}

// TestOpenClawIncludes：$include 引入的文件逐层解析（字符串与列表、JSON5 的写法、相对引入它的文件）；读不到的引入
// 文件报告出来。配置只读时，引入的文件里还有 h-guard 的设置或有读不到的引入文件，remove 拒绝。
func TestOpenClawIncludes(t *testing.T) {
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	dir := filepath.Dir(config)
	writeFile(t, config, `{"plugins": {"$include": "./plugins.json5"}, "agents": {"$include": ["conf.d/a.json", "conf.d/b.json5"]}}`)
	writeFile(t, filepath.Join(dir, "plugins.json5"), "{\n  // h-guard\n  entries: {'h-guard': {enabled: true}},\n}\n")
	writeFile(t, filepath.Join(dir, "conf.d", "a.json"), `{"list": []}`)
	writeFile(t, filepath.Join(dir, "conf.d", "b.json5"), "{ $include: './nested.json5' }")
	writeFile(t, filepath.Join(dir, "conf.d", "nested.json5"), "{}")
	files, unresolved := OpenClawIncludes(tg)
	want := []string{filepath.Join(dir, "plugins.json5"), filepath.Join(dir, "conf.d", "a.json"), filepath.Join(dir, "conf.d", "b.json5"), filepath.Join(dir, "conf.d", "nested.json5")}
	slices.Sort(want)
	if unresolved || strings.Join(files, "\n") != strings.Join(want, "\n") {
		t.Errorf("includes %v (unresolved %v), want %v", files, unresolved, want)
	}

	tg.Getenv = env(map[string]string{"OPENCLAW_NIX_MODE": "1"})
	apply(t, plan(t, tg, "openclaw", false))
	if _, err := OpenClaw(tg, true); err == nil || !strings.Contains(err.Error(), "the files it includes") {
		t.Errorf("remove with h-guard in an include: %v, want a refusal", err)
	}
	writeFile(t, filepath.Join(dir, "plugins.json5"), "{}")
	os.Remove(filepath.Join(dir, "conf.d", "nested.json5"))
	if _, unresolved := OpenClawIncludes(tg); !unresolved {
		t.Errorf("a missing include was not reported")
	}
	if _, err := OpenClaw(tg, true); err == nil {
		t.Errorf("remove with an unreadable include: want a refusal")
	}
	writeFile(t, filepath.Join(dir, "conf.d", "nested.json5"), "{}")
	apply(t, plan(t, tg, "openclaw", true))
	if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the plugin was not removed once no file mentions it: %v", err)
	}
}

// TestOpenClawRuntimes：配置（含 $include 引入的文件）选择了 codex 或 copilot 运行时时，install 与 status 注明这些运行时上
// 提示词与工具结果不检查；只选 OpenClaw 自己的运行时不提。
func TestOpenClawRuntimes(t *testing.T) {
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	writeFile(t, config, `{"agents": {"defaults": {"models": {"anthropic/x": {"agentRuntime": {"id": "openclaw"}}}}}, "models": {"$include": "./models.json5"}}`)
	writeFile(t, filepath.Join(filepath.Dir(config), "models.json5"), "{providers: {openai: {agentRuntime: {id: 'codex'}}, 'github-copilot': {agentRuntime: { mode: 'explicit', id: \"copilot\" }}}}")
	notes := strings.Join(OpenClawNotes(tg), "\n")
	for _, rt := range []string{"codex", "copilot"} {
		if !strings.Contains(notes, "runs some models on the "+rt+" agent runtime") {
			t.Errorf("notes lack the %s runtime:\n%s", rt, notes)
		}
	}
	if strings.Contains(notes, "openclaw agent runtime") {
		t.Errorf("notes mention the OpenClaw runtime:\n%s", notes)
	}
	writeFile(t, filepath.Join(filepath.Dir(config), "models.json5"), "{}")
	if notes := strings.Join(OpenClawNotes(tg), "\n"); strings.Contains(notes, "agent runtime") {
		t.Errorf("notes without codex or copilot:\n%s", notes)
	}
}

// TestOpenClawSteerNote：消息队列默认是 steer：install 与 status 注明 Gateway 客户端与插件插进运行的消息不检查；
// 全局与各渠道都不用 steer 时不提。
func TestOpenClawSteerNote(t *testing.T) {
	tg := target(t, "linux")
	config := OpenClawConfig(tg)
	const note = "messages sent from the Control UI, WebChat or other Gateway clients"
	for cfg, want := range map[string]bool{
		`{}`: true,
		`{"messages": {"queue": {"mode": "steer"}}}`:                                          true,
		`{"messages": {"queue": {"mode": "followup", "byChannel": {"telegram": "steer"}}}}`:   true,
		`{"messages": {"queue": {"mode": "collect", "byChannel": {"telegram": "followup"}}}}`: false,
	} {
		writeFile(t, config, cfg)
		if got := strings.Contains(strings.Join(OpenClawNotes(tg), "\n"), note); got != want {
			t.Errorf("%s: steer note %v, want %v", cfg, got, want)
		}
	}
}

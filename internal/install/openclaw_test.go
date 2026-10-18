package install

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	for _, h := range []string{"before_tool_call", "before_agent_run", "after_tool_call"} {
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

// TestOpenClawRefuses：JSON5 写法、$include、deny 里的 h-guard、不是对象的 plugins 都报错，什么都不写。
func TestOpenClawRefuses(t *testing.T) {
	for name, tt := range map[string]struct{ config, want string }{
		"comment":        {"{\n  // my gateway\n  \"gateway\": {\"mode\": \"local\"}\n}\n", "not plain JSON"},
		"trailing comma": {`{"gateway": {"mode": "local"},}`, "not plain JSON"},
		"unquoted key":   {`{gateway: {mode: "local"}}`, "not plain JSON"},
		"include":        {`{"$include": "./base.json5"}`, "$include"},
		"plugin include": {`{"plugins": {"$include": "./plugins.json5"}}`, "plugins.$include"},
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
		if strings.Contains(tt.want, "JSON") || strings.Contains(tt.want, "$include") {
			if !strings.Contains(err.Error(), `"allowConversationAccess": true`) {
				t.Errorf("%s: the error does not say what to add:\n%v", name, err)
			}
		}
		if got := readFile(t, OpenClawConfig(tg)); got != tt.config {
			t.Errorf("%s: the config was changed: %s", name, got)
		}
		if _, err := os.Stat(OpenClawPluginDir(tg)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: plugin written: %v", name, err)
		}
	}
	// JSON5 的配置在 status 里报告
	tg := target(t, "linux")
	writeFile(t, OpenClawConfig(tg), "{ // x\n}")
	if lines := strings.Join(Inspect(tg, "openclaw"), "\n"); !strings.Contains(lines, "cannot be read as plain JSON") {
		t.Errorf("status: %s", lines)
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

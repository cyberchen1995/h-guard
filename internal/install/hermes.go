package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/extensions"
	"github.com/cyberchen1995/h-guard/internal/store"
)

// HermesWritten 是插件按其源码编写的 Hermes Agent 版本。
const HermesWritten = "2026.9.24"

// hermesPluginName 是插件的名字：$HERMES_HOME/plugins/ 下的目录名、plugin.yaml 的 name，也是 plugins.enabled 里的一项。
const hermesPluginName = "h-guard"

// hermesHookTimeout 是 Hermes 等待 pre_tool_call 等插件回调的默认秒数（plugins.hook_callback_timeout）；
// hermesHookTimeoutMax 是 Hermes 接受的上限，更大的值被截到它。
const (
	hermesHookTimeout    = 30
	hermesHookTimeoutMax = 600
)

// HermesMaxTimeout 是 install hermes 接受的 --timeout 上限：Hermes 等待插件回调的时间要比它多 5 秒，最多 600 秒。
const HermesMaxTimeout = hermesHookTimeoutMax - 5

// hermesConfigLine 是内嵌插件里由 install 填写的一行（Python 的写法）。
var hermesConfigLine = regexp.MustCompile(`(?m)^CONFIG = (.*)  # h-guard install$`)

// HermesHome 是 Hermes Agent 的主目录：$HERMES_HOME（与 Hermes 一样展开其中的环境变量与开头的 ~），默认 ~/.hermes
// （Windows 上是 %LOCALAPPDATA%\hermes）。用 hermes -p <名字> 选择的其他配置档在 <主目录>/profiles/<名字>，不在这里。
func HermesHome(t Target) string {
	if d := strings.TrimSpace(t.Getenv("HERMES_HOME")); d != "" {
		return filepath.Clean(expandUser(t, expandVars(t, d)))
	}
	if t.GOOS == "windows" {
		base := strings.TrimSpace(t.Getenv("LOCALAPPDATA"))
		if base == "" {
			base = filepath.Join(t.Home, "AppData", "Local")
		}
		return filepath.Join(base, "hermes")
	}
	return filepath.Join(t.Home, ".hermes")
}

// posixVar 是 Python 的 posixpath.expandvars 认的写法：$名字（ASCII 的字母、数字与 _）或 ${…}。
var posixVar = regexp.MustCompile(`\$([A-Za-z0-9_]+|\{[^}]*\})`)

// expandVars 与 Hermes 的 os.path.expandvars 一样展开环境变量：POSIX 上是 $VAR 与 ${VAR}；Windows 上另有 %VAR%，
// 单引号里的不展开，%% 与 $$ 是字面的 % 与 $。没有设置的变量原样保留。
func expandVars(t Target, s string) string {
	lookup := func(name string) (string, bool) {
		if name == "" {
			return "", false
		}
		v := t.Getenv(name)
		return v, v != ""
	}
	if t.GOOS != "windows" {
		return posixVar.ReplaceAllStringFunc(s, func(m string) string {
			name := strings.TrimSuffix(strings.TrimPrefix(m[1:], "{"), "}")
			if v, ok := lookup(name); ok {
				return v
			}
			return m
		})
	}
	// ntpath.expandvars
	isVarChar := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				b.WriteString(s[i:])
				return b.String()
			}
			b.WriteString(s[i : i+j+2])
			i += j + 2
		case c == '%':
			if i+1 < len(s) && s[i+1] == '%' {
				b.WriteByte('%')
				i += 2
				continue
			}
			j := strings.IndexByte(s[i+1:], '%')
			if j < 0 {
				b.WriteString(s[i:])
				return b.String()
			}
			name := s[i+1 : i+1+j]
			if v, ok := lookup(name); ok {
				b.WriteString(v)
			} else {
				b.WriteString("%" + name + "%")
			}
			i += j + 2
		case c == '$':
			switch {
			case i+1 < len(s) && s[i+1] == '$':
				b.WriteByte('$')
				i += 2
			case i+1 < len(s) && s[i+1] == '{':
				j := strings.IndexByte(s[i+2:], '}')
				if j < 0 {
					b.WriteString(s[i:])
					return b.String()
				}
				name := s[i+2 : i+2+j]
				if v, ok := lookup(name); ok {
					b.WriteString(v)
				} else {
					b.WriteString("${" + name + "}")
				}
				i += j + 3
			default:
				j := i + 1
				for j < len(s) && isVarChar(s[j]) {
					j++
				}
				name := s[i+1 : j]
				if v, ok := lookup(name); ok {
					b.WriteString(v)
				} else {
					b.WriteString("$" + name)
				}
				i = j
			}
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// expandUser 与 os.path.expanduser 一样展开开头的 ~：~ 与 ~/…（Windows 上另有 ~\…）是主目录（Windows 上是
// %USERPROFILE%）；~名字 在 Windows 上是主目录旁边的同名目录，在 POSIX 上要查用户数据库，这里原样保留。
func expandUser(t Target, s string) string {
	if !strings.HasPrefix(s, "~") {
		return s
	}
	seps := "/"
	if t.GOOS == "windows" {
		seps = `/\`
	}
	i := strings.IndexAny(s[1:], seps) + 1
	if i == 0 {
		i = len(s)
	}
	home := t.Home
	if t.GOOS == "windows" {
		if p := t.Getenv("USERPROFILE"); p != "" {
			home = p
		}
		if i != 1 {
			// ntpath 的 join(dirname(home), 名字)：按 / 与 \ 分开（在别的系统上测试时 filepath 只认 /）
			k := strings.LastIndexAny(home, `/\`)
			if user := s[1:i]; !strings.EqualFold(user, home[k+1:]) {
				if k < 0 {
					home = user
				} else {
					home = home[:k] + `\` + user
				}
			}
		}
	} else if i != 1 {
		return s
	}
	return home + s[i:]
}

// HermesManagedDefault 是 Hermes 托管范围（managed scope）的默认目录；测试把它换成不存在的目录，不读本机的 /etc/hermes。
var HermesManagedDefault = "/etc/hermes"

// HermesManagedConfig 是托管范围的配置文件：$HERMES_MANAGED_DIR（只在目录存在时生效），默认 /etc/hermes（Windows 上
// 没有默认位置），下的 config.yaml；没有托管范围时为空。它写下的键逐个覆盖用户的 config.yaml（列表整个替换）。
func HermesManagedConfig(t Target) string {
	d := strings.TrimSpace(t.Getenv("HERMES_MANAGED_DIR"))
	if d == "" && t.GOOS != "windows" {
		d = HermesManagedDefault
	}
	if d == "" {
		return ""
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		return ""
	}
	return filepath.Join(d, "config.yaml")
}

// hermesManaged 读出托管范围的插件设置；没有托管范围或文件时 ok 为假。托管文件读不懂时 Hermes 忽略它（fail-open），
// 这里同样当作没有。
func hermesManaged(t Target) (st hermesState, path string, ok bool) {
	path = HermesManagedConfig(t)
	if path == "" {
		return hermesState{}, "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return hermesState{}, path, false
	}
	st, err = readHermesState(b)
	return st, path, err == nil
}

// overlay 返回托管范围覆盖之后实际生效的设置：托管文件写下的键取它的值。
func (st hermesState) overlay(m hermesState) hermesState {
	if m.enabledSet {
		st.enabled, st.enabledSet = m.enabled, true
	}
	if m.disabledSet {
		st.disabled, st.disabledSet = m.disabled, true
	}
	if m.timeoutSet {
		st.timeout, st.timeoutOK, st.timeoutSet = m.timeout, m.timeoutOK, true
	}
	if m.isolation != "" {
		st.isolation = m.isolation
	}
	return st
}

// managedProblem 说明托管范围让 h-guard 不能加载或等不到它的地方；没有时为空。
func managedProblem(m hermesState, path string, timeout int) string {
	switch {
	case m.disabledSet && m.disabled:
		return fmt.Sprintf("%s (managed by your administrator) lists h-guard in plugins.disabled, so Hermes does not load it; ask the administrator to remove it there", path)
	case m.enabledSet && !m.enabled:
		return fmt.Sprintf("%s (managed by your administrator) sets plugins.enabled without h-guard, which replaces your list, so Hermes does not load it; ask the administrator to add h-guard there", path)
	case m.timeoutSet && m.timeout != 0 && m.timeout < float64(timeout+5):
		return fmt.Sprintf("%s (managed by your administrator) sets plugins.hook_callback_timeout to %gs, shorter than h-guard's timeout plus 5 seconds (%ds); ask the administrator to raise it, or install with a lower --timeout", path, m.timeout, timeout+5)
	}
	return ""
}

// HermesConfig 是 Hermes 的配置文件 $HERMES_HOME/config.yaml。
func HermesConfig(t Target) string { return filepath.Join(HermesHome(t), "config.yaml") }

// HermesPluginDir 是写出的插件目录 $HERMES_HOME/plugins/h-guard。
func HermesPluginDir(t Target) string {
	return filepath.Join(HermesHome(t), "plugins", hermesPluginName)
}

// hermesFiles 是插件目录里的文件：plugin.yaml 与 __init__.py（CONFIG 一行是 h-guard 的命令与超时）。
func hermesFiles(t Target) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, name := range []string{"plugin.yaml", "__init__.py"} {
		b, err := extensions.Hermes.ReadFile("hermes/" + name)
		if err != nil {
			return nil, err
		}
		files[name] = b
	}
	cfg, _ := json.Marshal(extConfig{
		Command:   []string{t.Bin, "hook", "hermes", "--timeout", strconv.Itoa(t.Timeout)},
		TimeoutMS: t.Timeout * 1000,
	})
	src := files["__init__.py"]
	if len(hermesConfigLine.FindAllIndex(src, -1)) != 1 {
		return nil, errors.New("embedded Hermes plugin: unexpected CONFIG line")
	}
	// JSON 的字符串、数组、对象与整数也是 Python 的字面量
	files["__init__.py"] = hermesConfigLine.ReplaceAllLiteral(src, []byte("CONFIG = "+string(cfg)+"  # h-guard install"))
	return files, nil
}

// isOurHermesPlugin 报告目录里的插件是否是 h-guard 的。
func isOurHermesPlugin(files map[string][]byte) bool {
	return bytes.Contains(files["__init__.py"], []byte("PROTOCOL = 'h-guard.ext/v1'")) && hermesConfigLine.Match(files["__init__.py"]) &&
		bytes.Contains(files["plugin.yaml"], []byte("name: h-guard\n"))
}

// hermesSnapshot 读出插件目录，不含 Python 导入时生成的 __pycache__。
func hermesSnapshot(dir string) (map[string][]byte, error) {
	files, err := snapshot(dir)
	if err != nil {
		return nil, err
	}
	for name := range files {
		if strings.HasPrefix(name, "__pycache__/") || strings.Contains(name, "/__pycache__/") {
			delete(files, name)
		}
	}
	return files, nil
}

// Hermes 计划 Hermes Agent 的安装或移除：
//   - 把内嵌的插件写到 $HERMES_HOME/plugins/h-guard/（plugin.yaml 与 __init__.py，CONFIG 一行是 h-guard 的命令与超时）；
//   - 在 $HERMES_HOME/config.yaml 的 plugins.enabled 里加上 h-guard（Hermes 只加载列在这里的插件），从
//     plugins.disabled 里去掉它；plugins.hook_callback_timeout（默认 30 秒）不到 h-guard 的超时加 5 秒时调高它，
//     否则 Hermes 等不到 h-guard 的回复就按超时阻止工具调用。
//     配置的其他内容保留（YAML 的排版可能被规整）。
//
// 移除先从 plugins.enabled 里去掉 h-guard，再删插件目录；不读 h-guard 的配置。只计划，不写入（Apply 执行）。
func Hermes(t Target, remove bool) ([]Step, error) {
	if !remove && t.Timeout > HermesMaxTimeout {
		return nil, fmt.Errorf("--timeout for hermes is at most %d seconds: Hermes waits at most %d seconds for a plugin hook (plugins.hook_callback_timeout), and it has to wait longer than h-guard", HermesMaxTimeout, hermesHookTimeoutMax)
	}
	// 托管范围（/etc/hermes/config.yaml）的键覆盖用户的配置：改用户的 config.yaml 没有用，install 不碰托管文件
	if m, path, ok := hermesManaged(t); ok && !remove {
		if p := managedProblem(m, path, t.Timeout); p != "" {
			return nil, errors.New(p)
		}
	}
	dir := HermesPluginDir(t)
	files, err := hermesFiles(t)
	if err != nil {
		return nil, err
	}
	existing, err := hermesSnapshot(dir)
	if err != nil {
		return nil, err
	}
	keepDir := false
	if len(existing) > 0 && !isOurHermesPlugin(existing) {
		if !remove {
			return nil, fmt.Errorf("%s exists and is not h-guard's Hermes plugin; not overwriting it", dir)
		}
		keepDir = true // 换成了别的插件：不删它，但 plugins.enabled 里的 h-guard 照样去掉
	}
	ed := t.editor()
	verify := func() error {
		now, err := hermesSnapshot(dir)
		if err != nil {
			return err
		}
		if !sameFiles(now, existing) {
			return fmt.Errorf("%s changed since the install was planned: %w", dir, store.ErrConflict)
		}
		return nil
	}
	backup := func() error {
		if len(existing) > 0 {
			return backupDir(ed, "hermes-plugin", existing)
		}
		return nil
	}
	plugin := Step{Path: dir, Summary: "write h-guard's Hermes plugin", changes: !sameFiles(existing, files), lockDir: ed.LockDir, verify: verify,
		apply: func() error {
			if err := backup(); err != nil {
				return err
			}
			for _, name := range slices.Sorted(maps.Keys(files)) {
				if err := store.WriteAtomic(filepath.Join(dir, name), files[name], 0o600); err != nil {
					return err
				}
			}
			for name := range existing {
				if _, keep := files[name]; !keep {
					if err := os.Remove(filepath.Join(dir, filepath.FromSlash(name))); err != nil && !errors.Is(err, fs.ErrNotExist) {
						return err
					}
				}
			}
			return nil
		}}
	if remove {
		plugin = Step{Path: dir, Summary: "remove h-guard's Hermes plugin", changes: len(existing) > 0, lockDir: ed.LockDir, verify: verify,
			apply: func() error {
				if err := backup(); err != nil {
					return err
				}
				return os.RemoveAll(dir)
			}}
	}

	config := HermesConfig(t)
	change := func(old []byte, exists bool) ([]byte, error) { return hermesConfigEdit(old, exists, t.Timeout, remove) }
	old, err := os.ReadFile(config)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	next, err := change(old, exists)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", config, err)
	}
	summary, preview := "enable the plugin in the Hermes config", "plugins:\n  enabled: [..., h-guard]\n"
	preview += fmt.Sprintf("  hook_callback_timeout: %d (only when it is lower; default %d)\n", t.Timeout+5, hermesHookTimeout)
	if remove {
		summary, preview = "remove the plugin from plugins.enabled in the Hermes config", "remove h-guard from plugins.enabled\n"
	}
	// 预览只显示本项目的改动：配置的其他内容可能有秘密
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
		// 先停用、再删目录：第二步失败时 Hermes 不会因为找不到启用的插件而报错
		return []Step{set, plugin}, nil
	}
	return []Step{plugin, set}, nil
}

// hermesConfigEdit 改 config.yaml 的 plugins：安装时 enabled 里加上 h-guard、disabled 里去掉它，
// hook_callback_timeout 不够等 h-guard 时调高（0 表示不限时，不改）；移除时只从 enabled 里去掉 h-guard（空了的
// enabled 与 plugins 一并去掉）。没有变化时返回原文；文件不存在且是移除时返回 nil（不新建）。
func hermesConfigEdit(old []byte, exists bool, timeout int, remove bool) ([]byte, error) {
	if !exists && remove {
		return nil, nil
	}
	var doc yaml.Node
	if exists && len(bytes.TrimSpace(old)) > 0 {
		if err := yaml.Unmarshal(old, &doc); err != nil {
			return nil, err
		}
	}
	if doc.Kind == 0 || (len(doc.Content) == 1 && doc.Content[0].Tag == "!!null") {
		if remove {
			return old, nil
		}
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the config is not a mapping")
	}
	plugins := mapValue(root, "plugins")
	if plugins == nil || (plugins.Kind == yaml.ScalarNode && plugins.Tag == "!!null") {
		if remove {
			return old, nil
		}
		plugins = setKey(root, "plugins")
		*plugins = yaml.Node{Kind: yaml.MappingNode}
	}
	if plugins.Kind != yaml.MappingNode {
		return nil, errors.New("plugins is not a mapping")
	}
	changed := false
	list := func(key string, create bool) (*yaml.Node, error) {
		n := mapValue(plugins, key)
		if n == nil || (n.Kind == yaml.ScalarNode && n.Tag == "!!null") {
			if !create {
				return nil, nil
			}
			n = setKey(plugins, key)
			*n = yaml.Node{Kind: yaml.SequenceNode}
		}
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("plugins.%s is not a list", key)
		}
		return n, nil
	}
	without := func(n *yaml.Node) {
		if n == nil {
			return
		}
		kept := slices.DeleteFunc(slices.Clone(n.Content), func(e *yaml.Node) bool {
			return e.Kind == yaml.ScalarNode && e.Value == hermesPluginName
		})
		if len(kept) != len(n.Content) {
			n.Content, changed = kept, true
		}
	}
	enabled, err := list("enabled", !remove)
	if err != nil {
		return nil, err
	}
	if remove {
		without(enabled)
		if enabled != nil && len(enabled.Content) == 0 && changed {
			deleteKey(plugins, "enabled")
			if len(plugins.Content) == 0 {
				deleteKey(root, "plugins")
			}
		}
	} else {
		disabled, err := list("disabled", false)
		if err != nil {
			return nil, err
		}
		without(disabled)
		if !slices.ContainsFunc(enabled.Content, func(e *yaml.Node) bool { return e.Kind == yaml.ScalarNode && e.Value == hermesPluginName }) {
			enabled.Content = append(enabled.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: hermesPluginName})
			changed = true
		}
		// 不是数的值 Hermes 按默认的 30 秒处理（每次都记一行警告），同样换成数
		need := timeout + 5
		if cur, valid := hookTimeout(plugins); !valid || cur != 0 && cur < float64(need) {
			if !valid {
				need = max(need, hermesHookTimeout) // 不比 Hermes 实际用的默认值短
			}
			n := setKey(plugins, "hook_callback_timeout")
			*n = yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(need)}
			changed = true
		}
	}
	if !changed {
		if exists {
			return old, nil
		}
	}
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// hookTimeout 返回 Hermes 实际等待插件回调的秒数（plugins.hook_callback_timeout，与 Hermes 的
// _resolve_hook_callback_timeout 相同）：没有时是默认的 30；0 表示不限时；负数按默认值，超过 600 按 600。不是数
// （float() 读不出，例如 nope）时 Hermes 同样用默认值，valid 为假。
func hookTimeout(plugins *yaml.Node) (secs float64, valid bool) {
	n := mapValue(plugins, "hook_callback_timeout")
	if n == nil || (n.Kind == yaml.ScalarNode && n.Tag == "!!null") {
		return hermesHookTimeout, true
	}
	if n.Kind != yaml.ScalarNode {
		return hermesHookTimeout, false
	}
	var v float64
	var err error
	if n.Tag == "!!bool" { // float(True) 是 1
		v = 0
		if strings.EqualFold(n.Value, "true") {
			v = 1
		}
	} else if v, err = strconv.ParseFloat(strings.TrimSpace(n.Value), 64); err != nil || v != v {
		return hermesHookTimeout, false
	}
	switch {
	case v < 0:
		return hermesHookTimeout, true
	case v > hermesHookTimeoutMax:
		return hermesHookTimeoutMax, true
	}
	return v, true
}

// deleteKey 删掉映射 m 中的 key。
func deleteKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// hermesState 是 status 从 config.yaml 读出的插件设置。
type hermesState struct {
	enabled, disabled bool
	// 文件里写了这几个键（托管范围只覆盖它写下的键）
	enabledSet, disabledSet, timeoutSet bool
	timeout                             float64 // plugins.hook_callback_timeout，没有时为 30
	timeoutOK                           bool
	isolation                           string
}

func readHermesState(b []byte) (hermesState, error) {
	st := hermesState{timeout: hermesHookTimeout, timeoutOK: true}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return st, err
	}
	if len(doc.Content) == 0 {
		return st, nil
	}
	plugins := mapValue(doc.Content[0], "plugins")
	if plugins == nil || plugins.Kind != yaml.MappingNode {
		return st, nil
	}
	has := func(key string) bool {
		n := mapValue(plugins, key)
		return n != nil && n.Kind == yaml.SequenceNode && slices.ContainsFunc(n.Content, func(e *yaml.Node) bool { return e.Value == hermesPluginName })
	}
	set := func(key string) bool {
		n := mapValue(plugins, key)
		return n != nil && !(n.Kind == yaml.ScalarNode && n.Tag == "!!null")
	}
	st.enabled, st.disabled = has("enabled"), has("disabled")
	st.enabledSet, st.disabledSet, st.timeoutSet = set("enabled"), set("disabled"), set("hook_callback_timeout")
	st.timeout, st.timeoutOK = hookTimeout(plugins)
	if n := mapValue(plugins, "isolation"); n != nil && n.Kind == yaml.ScalarNode {
		st.isolation = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(n.Value), "-", "_"))
	}
	return st, nil
}

// inspectHermes 检查 Hermes Agent：插件目录与 config.yaml 里的启用。
func inspectHermes(t Target) []string {
	dir, config := HermesPluginDir(t), HermesConfig(t)
	files, _ := hermesSnapshot(dir)
	st := hermesState{timeout: hermesHookTimeout, timeoutOK: true}
	if b, err := os.ReadFile(config); err == nil {
		var yerr error
		if st, yerr = readHermesState(b); yerr != nil {
			return []string{fmt.Sprintf("problem: %s cannot be read: %v", config, yerr)}
		}
	}
	if len(files) == 0 && !st.enabled {
		return []string{"not installed (h-guard install hermes)"}
	}
	lines := []string{extInstalledLine(t, "hermes", "Hermes Agent")}
	// 托管范围写下的键覆盖用户的配置：那几项的问题按托管文件报告，不再按用户的 config.yaml 报告
	var m hermesState
	if mm, path, ok := hermesManaged(t); ok {
		m = mm
		_, timeout, _ := installedHermes(files["__init__.py"])
		if p := managedProblem(m, path, timeout); p != "" {
			lines = append(lines, "problem: "+p)
		}
		st = st.overlay(m)
	}
	if len(files) == 0 {
		return append(lines, fmt.Sprintf("problem: %s enables h-guard, but the plugin is missing from %s; run h-guard install hermes --write", config, dir))
	}
	if !isOurHermesPlugin(files) {
		return append(lines, fmt.Sprintf("problem: %s is not h-guard's plugin", dir))
	}
	switch {
	case m.enabledSet && !m.enabled || m.disabledSet && m.disabled: // 已按托管文件报告
	case st.disabled:
		lines = append(lines, fmt.Sprintf("problem: %s lists h-guard in plugins.disabled, so Hermes does not load it; run h-guard install hermes --write", config))
	case !st.enabled:
		lines = append(lines, fmt.Sprintf("problem: the plugin is written but %s does not list it in plugins.enabled; run h-guard install hermes --write", config))
	}
	bin, timeout, ok := installedHermes(files["__init__.py"])
	if bin != "" {
		if _, err := os.Stat(bin); err != nil {
			lines = append(lines, fmt.Sprintf("problem: h-guard is not at %s; run h-guard install hermes --write", bin))
		}
	}
	want, err := hermesFiles(Target{Bin: bin, Timeout: timeout})
	if !ok || err != nil || !sameFiles(want, files) {
		lines = append(lines, "problem: the plugin differs from this h-guard version (edited or written by another version); run h-guard install hermes --write")
	}
	switch {
	case !ok || m.timeoutSet:
	case st.timeout != 0 && st.timeout < float64(timeout+5):
		invalid := ""
		if !st.timeoutOK {
			invalid = " (its value is not a number, so Hermes uses the default)"
		}
		lines = append(lines, fmt.Sprintf("problem: Hermes waits %gs for a plugin hook (plugins.hook_callback_timeout%s) but h-guard is given %ds, so slow checks block tool calls; run h-guard install hermes --write", st.timeout, invalid, timeout))
	case !st.timeoutOK:
		lines = append(lines, fmt.Sprintf("problem: plugins.hook_callback_timeout is not a number, so Hermes uses the default %ds and logs a warning on every hook; run h-guard install hermes --write", hermesHookTimeout))
	}
	if st.isolation == "host" {
		lines = append(lines, "note: plugins.isolation is host: the plugin cannot see how Hermes would handle an approval, so h-guard's confirmations become denials (policy.when_ask_unsupported)")
	}
	for _, n := range ExtNotes(t, "hermes") {
		lines = append(lines, "note: "+n)
	}
	return lines
}

// installedHermes 读出已写出的插件里的 h-guard 路径与超时（秒）；读不出时 ok 为假。
func installedHermes(b []byte) (bin string, timeout int, ok bool) {
	m := hermesConfigLine.FindSubmatch(b)
	if m == nil {
		return "", 0, false
	}
	var cfg extConfig
	if json.Unmarshal(m[1], &cfg) != nil || len(cfg.Command) != 5 || cfg.Command[1] != "hook" || cfg.Command[2] != "hermes" ||
		cfg.Command[3] != "--timeout" {
		return "", 0, false
	}
	n, err := strconv.Atoi(cfg.Command[4])
	if err != nil || n*1000 != cfg.TimeoutMS {
		return cfg.Command[0], 0, false
	}
	return cfg.Command[0], n, true
}

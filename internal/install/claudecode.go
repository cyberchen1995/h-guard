package install

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/extensions"
	"github.com/cyberchen1995/h-guard/internal/store"
)

const (
	pluginDirsVar = "CLAUDE_CODE_PLUGIN_DIRS"
	// ClaudeCodeMinMods 是提供 mods 的最低 Claude Code 版本；ClaudeCodeVerified 是经过录制核实的版本。
	ClaudeCodeMinMods  = "2.1.290"
	ClaudeCodeVerified = "2.1.296"
)

// ClaudePluginDir 是写出的插件目录：<config_dir>/extensions/claudecode。
func ClaudePluginDir(t Target) string { return filepath.Join(t.ConfigDir, "extensions", "claudecode") }

// ClaudeSettings 是 Claude Code 的用户设置文件（CLAUDE_CONFIG_DIR 指定时在它下面）。
func ClaudeSettings(t Target) string {
	if d := t.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "settings.json")
	}
	return filepath.Join(t.Home, ".claude", "settings.json")
}

// ClaudeCode 计划 Claude Code 的安装或移除：
//   - 把内嵌的插件写到 <config_dir>/extensions/claudecode：hooks/hooks.json 的经典 PreToolUse（Windows 上用
//     PowerShell 外包）与 mod；hguard-bin、hguard-timeout 给外包脚本，hguard.json 给 mod，命令与超时一致；
//   - 把这个目录加入 settings.json 的 env.CLAUDE_CODE_PLUGIN_DIRS，已有的目录与其他设置原样保留。
//
// 移除删掉插件目录与这一项；列表空了删掉这个键，env 空了也删掉。只计划，不写入（Apply 执行）。
func ClaudeCode(t Target, remove bool) ([]Step, error) {
	dir := ClaudePluginDir(t)
	files, err := pluginFiles(t)
	if err != nil {
		return nil, err
	}
	plugin, err := pluginStep(t, dir, files, remove)
	if err != nil {
		return nil, err
	}
	settings := ClaudeSettings(t)
	change := func(old []byte, exists bool) ([]byte, error) {
		return pluginDirsEdit(old, exists, dir, t.listSep(), remove, t.samePath)
	}
	old, err := os.ReadFile(settings)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	preview, err := change(old, exists)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", settings, err)
	}
	summary := "register the plugin directory in env." + pluginDirsVar
	if remove {
		summary = "remove the plugin directory from env." + pluginDirsVar
	}
	ed := t.editor()
	// 预览只显示本项目这一项改动前后的值：settings.json 的其他内容可能有认不出的秘密
	set := Step{Path: settings, Summary: summary,
		Preview: []byte(fmt.Sprintf("env.%s: %s -> %s\n", pluginDirsVar, pluginDirsValue(old), pluginDirsValue(preview))),
		changes: preview != nil && !bytes.Equal(preview, old), lockDir: ed.LockDir,
		apply: func() error {
			_, err := ed.editLocked(settings, change)
			if err != nil {
				return fmt.Errorf("%s: %w", settings, err)
			}
			return nil
		}}
	if remove {
		// 先去掉登记、再删目录：第二步失败时不会留下指向不存在目录的登记
		return []Step{set, plugin}, nil
	}
	return []Step{plugin, set}, nil
}

// pluginDirsValue 返回 settings.json 里 env.CLAUDE_CODE_PLUGIN_DIRS 的值；没有时为 (unset)。
func pluginDirsValue(b []byte) string {
	if o, err := parseObject(b); err == nil {
		if env, err := o.object("env"); err == nil {
			var s string
			if raw, ok := env.get(pluginDirsVar); ok && json.Unmarshal(raw, &s) == nil && s != "" {
				return s
			}
		}
	}
	return "(unset)"
}

// pluginFiles 返回插件目录里的全部文件（相对路径 → 内容）。
func pluginFiles(t Target) (map[string][]byte, error) {
	files := map[string][]byte{}
	root := "claudecode"
	err := fs.WalkDir(extensions.ClaudeCode, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := extensions.ClaudeCode.ReadFile(p)
		files[strings.TrimPrefix(p, root+"/")] = b
		return err
	})
	if err != nil {
		return nil, err
	}
	hooks, err := hooksJSON(files["hooks/hooks.json"], t)
	if err != nil {
		return nil, err
	}
	files["hooks/hooks.json"] = hooks
	timeout := strconv.Itoa(t.Timeout)
	files["hguard-bin"] = []byte(t.Bin + "\n")
	files["hguard-timeout"] = []byte(timeout + "\n")
	argv := []string{t.Bin, "hook", "claudecode", "--timeout", timeout}
	cfg, _ := json.MarshalIndent(map[string]any{
		"commands":   map[string][]string{"tool.result": argv, "prompt.submit": argv},
		"timeout_ms": t.Timeout * 1000,
	}, "", "  ")
	files["hguard.json"] = append(cfg, '\n')
	return files, nil
}

// hooksJSON 把内嵌 hooks.json 里经典 PreToolUse 的超时设为 t.Timeout；Windows 上命令换成 PowerShell 外包。
func hooksJSON(embedded []byte, t Target) ([]byte, error) {
	o, err := parseObject(embedded)
	if err != nil {
		return nil, err
	}
	hooks, err := o.object("hooks")
	if err != nil {
		return nil, err
	}
	raw, _ := hooks.get("PreToolUse")
	var groups []map[string]any
	if err := json.Unmarshal(raw, &groups); err != nil || len(groups) != 1 {
		return nil, errors.New("embedded hooks.json: unexpected PreToolUse")
	}
	handlers, _ := groups[0]["hooks"].([]any)
	if len(handlers) != 1 {
		return nil, errors.New("embedded hooks.json: unexpected PreToolUse handlers")
	}
	h := handlers[0].(map[string]any)
	h["timeout"] = t.Timeout
	if t.GOOS == "windows" {
		h["command"] = `powershell -NoProfile -ExecutionPolicy Bypass -File "${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.ps1"`
	}
	hooks.set("PreToolUse", groups)
	if err := o.setObject("hooks", hooks); err != nil {
		return nil, err
	}
	return o.marshal(), nil
}

// pluginStep 计划插件目录：安装时写出全部文件并删掉多余的文件（目录归本项目所有）；移除时删掉整个目录，
// 删之前确认它确实是 h-guard 的插件。执行时（持有读改写锁）先复核目录与计划时相同，不同就报冲突、什么都不动；
// 覆盖或删除之前把原来的文件备份到 <cache_dir>/backups/claudecode-plugin.<时间>.<随机串>/。
func pluginStep(t Target, dir string, files map[string][]byte, remove bool) (Step, error) {
	existing, err := snapshot(dir)
	if err != nil {
		return Step{}, err
	}
	if len(existing) > 0 && !isOurPlugin(existing) {
		if remove {
			return Step{}, fmt.Errorf("%s does not look like the h-guard plugin; not removing it", dir)
		}
		return Step{}, fmt.Errorf("%s exists and is not the h-guard plugin; not overwriting it", dir)
	}
	ed := t.editor()
	verify := func() error {
		now, err := snapshot(dir)
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
			return backupDir(ed, "claudecode-plugin", existing)
		}
		return nil
	}
	if remove {
		return Step{Path: dir, Summary: "remove the h-guard plugin", changes: len(existing) > 0, lockDir: ed.LockDir, verify: verify,
			apply: func() error {
				if err := backup(); err != nil {
					return err
				}
				return os.RemoveAll(dir)
			}}, nil
	}
	return Step{Path: dir, Summary: fmt.Sprintf("write the h-guard plugin (%d files)", len(files)), changes: !sameFiles(existing, files),
		lockDir: ed.LockDir, verify: verify,
		apply: func() error {
			if err := backup(); err != nil {
				return err
			}
			for _, name := range slices.Sorted(maps.Keys(files)) {
				perm := fs.FileMode(0o600)
				if path.Ext(name) == ".sh" || path.Ext(name) == ".ps1" {
					perm = 0o700
				}
				if err := store.WriteAtomic(filepath.Join(dir, filepath.FromSlash(name)), files[name], perm); err != nil {
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
		}}, nil
}

// snapshot 读出目录里的全部文件（相对路径 → 内容）；目录不存在时为空。
func snapshot(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return fs.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = b
		return err
	})
	return files, err
}

// samePath 按目标平台比较两个路径：Windows 上不区分大小写。install 与 status 共用。
func (t Target) samePath(a, b string) bool {
	if t.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func sameFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, x := range a {
		if y, ok := b[name]; !ok || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}

// backupDir 把 files 复制到 BackupDir 下新建的 <name>.<UTC 时间>.<随机串>/ 目录。
func backupDir(e Editor, name string, files map[string][]byte) error {
	var r [4]byte
	_, _ = rand.Read(r[:])
	dir := filepath.Join(e.BackupDir, fmt.Sprintf("%s.%s.%s", name, e.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(r[:])))
	for rel, b := range files {
		if err := store.WriteAtomic(filepath.Join(dir, filepath.FromSlash(rel)), b, 0o600); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	return nil
}

// isOurPlugin 报告目录里的插件清单是否是 h-guard 的。
func isOurPlugin(files map[string][]byte) bool {
	var m struct{ Name string }
	return json.Unmarshal(files[".claude-plugin/plugin.json"], &m) == nil && m.Name == "h-guard"
}

// pluginDirsEdit 在 settings.json 的 env.CLAUDE_CODE_PLUGIN_DIRS 里加入或去掉 dir。没有变化时返回原文（不重写）；
// 文件不存在且是移除时返回 nil（不新建）。
func pluginDirsEdit(old []byte, exists bool, dir, sep string, remove bool, same func(a, b string) bool) ([]byte, error) {
	if !exists && remove {
		return nil, nil
	}
	o := object{vals: map[string]json.RawMessage{}}
	if exists {
		var err error
		if o, err = parseObject(old); err != nil {
			return nil, err
		}
	}
	env, err := o.object("env")
	if err != nil {
		return nil, err
	}
	var dirs []string
	if raw, ok := env.get(pluginDirsVar); ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, fmt.Errorf("env.%s is not a string", pluginDirsVar)
		}
		for _, d := range strings.Split(s, sep) {
			if d = strings.TrimSpace(d); d != "" {
				dirs = append(dirs, d)
			}
		}
	}
	ours := func(d string) bool { return same(d, dir) }
	has := slices.ContainsFunc(dirs, ours)
	switch {
	case remove && !has, !remove && has:
		if exists {
			return old, nil
		}
	case remove:
		dirs = slices.DeleteFunc(dirs, ours)
	default:
		dirs = append(dirs, dir)
	}
	if len(dirs) == 0 {
		env.delete(pluginDirsVar)
	} else {
		env.set(pluginDirsVar, strings.Join(dirs, sep))
	}
	if len(env.keys) == 0 {
		o.delete("env")
	} else if err := o.setObject("env", env); err != nil {
		return nil, err
	}
	return o.marshal(), nil
}

// ClaudeCodeNotes 检查 Claude Code 的版本：低于 2.1.290 没有 mods（工具结果与提示词不检查），低于经过核实的
// 2.1.296 时说明未经验证（不阻止）；找不到 claude 时说明。
func ClaudeCodeNotes(t Target) []string {
	if t.Run == nil {
		return []string{"claude was not found; the plugin takes effect when Claude Code starts"}
	}
	out, err := t.Run("claude", "--version")
	if err != nil {
		return []string{"claude was not found; the plugin takes effect when Claude Code starts"}
	}
	v := strings.Fields(string(out))
	if len(v) == 0 {
		return []string{"could not read the Claude Code version"}
	}
	switch {
	case versionLess(v[0], ClaudeCodeMinMods):
		return []string{fmt.Sprintf("Claude Code %s: tool results and prompts are checked through mods, which needs Claude Code %s or later", v[0], ClaudeCodeMinMods)}
	case versionLess(v[0], ClaudeCodeVerified):
		return []string{fmt.Sprintf("Claude Code %s has not been verified with h-guard (verified: %s and later)", v[0], ClaudeCodeVerified)}
	}
	return nil
}

// versionLess 按点分的数字比较版本；读不懂的部分按 0。
func versionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x < y
		}
	}
	return false
}

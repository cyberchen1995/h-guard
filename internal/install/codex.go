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
	"strings"
)

// CodexMinVersion 是经过录制核实的最低 Codex 版本。
const CodexMinVersion = "0.162.1"

// codexEvents 是注册的事件：PreToolUse 覆盖全部工具（不写 matcher），UserPromptSubmit、PostToolUse。
var codexEvents = []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"}

// CodexHooks 是 Codex 的用户级 hook 配置：$CODEX_HOME/hooks.json，默认 ~/.codex/hooks.json。
func CodexHooks(t Target) string {
	if d := t.Getenv("CODEX_HOME"); d != "" {
		return filepath.Join(d, "hooks.json")
	}
	return filepath.Join(t.Home, ".codex", "hooks.json")
}

// codexCommand 是事件 event 的入口命令：h-guard 的路径加 hook codex --event <事件> --timeout <秒>。命令里不含版本号，
// 升级 h-guard 不改变命令，Codex 不必重新信任。POSIX 上路径一律加单引号（Codex 用 sh -c 运行）。Windows 上 Codex
// 用哪种 shell 运行 hook 没有核实，cmd 与 PowerShell 对带引号的程序路径写法不同，所以要加引号的路径返回错误。
func codexCommand(t Target, event string) (string, error) {
	bin := t.Bin
	if base := filepath.Base(strings.ReplaceAll(bin, `\`, "/")); base != "h-guard" && base != "h-guard.exe" {
		// 本项目的入口按程序名认出：改了名的 h-guard 写进去以后既不能重装也不能移除
		return "", fmt.Errorf("the h-guard executable %s must be named h-guard (or h-guard.exe) so that its Codex hooks can be recognized, updated and removed", bin)
	}
	if t.GOOS == "windows" {
		if strings.ContainsAny(bin, " \t'\"$`&;|<>()^%!") {
			return "", fmt.Errorf("the h-guard path %s needs quoting, and how Codex runs hooks on Windows is not verified; install h-guard to a path without spaces or special characters", bin)
		}
	} else {
		bin = "'" + strings.ReplaceAll(bin, "'", `'\''`) + "'"
	}
	return fmt.Sprintf("%s hook codex --event %s --timeout %d", bin, event, t.Timeout), nil
}

// isOurCodexHook 认出本项目的入口：程序名是 h-guard（或 h-guard.exe），之后的参数正好是 hook codex --event <事件>
// --timeout <秒>（codexCommand 写出的形式）。路径与超时可能变化（重装时替换）；别的子命令、引号里的文字、多出的
// 参数、别人的包装脚本都不算。
func isOurCodexHook(cmd string) bool {
	bin := commandBin(cmd)
	if bin == "" {
		return false
	}
	if base := filepath.Base(strings.ReplaceAll(bin, `\`, "/")); base != "h-guard" && base != "h-guard.exe" {
		return false
	}
	return ourCodexArgs.MatchString(strings.TrimSpace(cmd)[len(binToken(cmd)):])
}

var ourCodexArgs = regexp.MustCompile(`^ hook codex --event (?:PreToolUse|PostToolUse|UserPromptSubmit) --timeout [0-9]+$`)

// binToken 返回命令开头程序路径那一段的原文（含引号）。
func binToken(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	switch {
	case cmd == "":
		return ""
	case cmd[0] == '"':
		if i := strings.IndexByte(cmd[1:], '"'); i >= 0 {
			return cmd[:i+2]
		}
		return cmd
	case cmd[0] == '\'':
		for i := 1; i < len(cmd); i++ {
			if cmd[i] != '\'' {
				continue
			}
			if strings.HasPrefix(cmd[i:], `'\''`) {
				i += 3
				continue
			}
			return cmd[:i+1]
		}
		return cmd
	}
	return strings.Fields(cmd)[0]
}

// commandBin 取入口命令里的程序路径（第一个词，去掉引号与 POSIX 单引号里的 '\” 转义）。
func commandBin(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	switch cmd[0] {
	case '\'':
		var b strings.Builder
		for rest := cmd[1:]; ; {
			i := strings.IndexByte(rest, '\'')
			if i < 0 {
				return ""
			}
			b.WriteString(rest[:i])
			if strings.HasPrefix(rest[i:], `'\''`) {
				b.WriteByte('\'')
				rest = rest[i+4:]
				continue
			}
			return b.String()
		}
	case '"':
		if i := strings.IndexByte(cmd[1:], '"'); i >= 0 {
			return cmd[1 : i+1]
		}
		return ""
	}
	return strings.Fields(cmd)[0]
}

// Codex 计划 Codex 的安装或移除：在 hooks.json 里为三个事件各注册一个入口（重装时替换本项目旧的入口），
// 其他 hook 组按原文保留；移除只删本项目的入口，删空的组与事件。只计划，不写入（Apply 执行）。
// 只打印时的预览只列出本项目的入口（hooks.json 里别的命令可能带着秘密）。
func Codex(t Target, remove bool) ([]Step, error) {
	path := CodexHooks(t)
	want := map[string]string{}
	var preview strings.Builder
	if !remove {
		for _, ev := range codexEvents {
			cmd, err := codexCommand(t, ev)
			if err != nil {
				return nil, err
			}
			want[ev] = cmd
			fmt.Fprintf(&preview, "%s: %s (timeout %ds)\n", ev, cmd, t.Timeout)
		}
	} else {
		preview.WriteString("remove h-guard's PreToolUse, PostToolUse and UserPromptSubmit hooks\n")
	}
	change := func(old []byte, exists bool) ([]byte, error) { return codexEdit(t, want, old, exists, remove) }
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	next, err := change(old, exists)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	summary := "register h-guard for PreToolUse, PostToolUse and UserPromptSubmit"
	if remove {
		summary = "remove h-guard's hooks"
	}
	ed := t.editor()
	return []Step{{Path: path, Summary: summary, Preview: []byte(preview.String()), changes: next != nil && !bytes.Equal(next, old),
		lockDir: ed.LockDir,
		apply: func() error {
			if _, err := ed.editLocked(path, change); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			return nil
		}}}, nil
}

// codexEdit 改写 hooks.json：只动本项目的入口，其他组按原文保留（键的顺序、取值的写法都不变）。
func codexEdit(t Target, want map[string]string, old []byte, exists, remove bool) ([]byte, error) {
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
	hooks, err := o.object("hooks")
	if err != nil {
		return nil, err
	}
	changed := false
	for _, ev := range codexEvents {
		var groups []json.RawMessage
		if raw, ok := hooks.get(ev); ok {
			if err := json.Unmarshal(raw, &groups); err != nil {
				return nil, fmt.Errorf("hooks.%s is not a list of hook groups", ev)
			}
		}
		ourHandler := map[string]any{"type": "command", "command": want[ev], "timeout": t.Timeout}
		var kept []json.RawMessage
		ours, same := 0, false
		for _, raw := range groups {
			g, err := parseObject(raw)
			if err != nil {
				return nil, fmt.Errorf("hooks.%s: %w", ev, err)
			}
			hraw, ok := g.get("hooks")
			var handlers []json.RawMessage
			if !ok || json.Unmarshal(hraw, &handlers) != nil {
				kept = append(kept, raw)
				continue
			}
			var rest []json.RawMessage
			for _, h := range handlers {
				var x struct {
					Command string `json:"command"`
				}
				if json.Unmarshal(h, &x) == nil && isOurCodexHook(x.Command) {
					ours++
					var m map[string]any
					_ = json.Unmarshal(h, &m)
					_, matcher := g.get("matcher")
					same = jsonEqual(m, ourHandler) && len(handlers) == 1 && !matcher
					continue
				}
				rest = append(rest, h)
			}
			if len(rest) == len(handlers) {
				kept = append(kept, raw) // 没有本项目的入口：原文保留
				continue
			}
			if len(rest) == 0 {
				continue // 只有本项目入口的组整个去掉
			}
			g.setRaw("hooks", joinArray(rest))
			kept = append(kept, g.compact())
		}
		if (!remove && ours == 1 && same) || (remove && ours == 0) {
			continue
		}
		changed = true
		if !remove {
			b, _ := json.Marshal(map[string]any{"hooks": []any{ourHandler}})
			kept = append(kept, b)
		}
		if len(kept) == 0 {
			hooks.delete(ev)
		} else {
			hooks.setRaw(ev, joinArray(kept))
		}
	}
	if !changed && exists {
		return old, nil
	}
	if len(hooks.keys) == 0 {
		o.delete("hooks")
	} else if err := o.setObject("hooks", hooks); err != nil {
		return nil, err
	}
	return o.marshal(), nil
}

func joinArray(items []json.RawMessage) json.RawMessage {
	parts := make([][]byte, len(items))
	for i, it := range items {
		parts[i] = it
	}
	return append(append([]byte{'['}, bytes.Join(parts, []byte{','})...), ']')
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// CodexNotes 检查 Codex 的版本（低于 0.162.1 未经验证，不阻止），并提醒 Codex 要求信任新的或改过的 hook。
func CodexNotes(t Target) []string {
	var notes []string
	if t.Run != nil {
		if out, err := t.Run("codex", "--version"); err == nil {
			if f := strings.Fields(string(out)); len(f) > 0 {
				v := f[len(f)-1]
				if versionLess(v, CodexMinVersion) {
					notes = append(notes, fmt.Sprintf("Codex %s has not been verified with h-guard (verified: %s and later)", v, CodexMinVersion))
				}
			}
		}
	}
	return append(notes, "Codex skips new or changed hooks until you trust them: open Codex and run /hooks to review and trust the h-guard hooks")
}

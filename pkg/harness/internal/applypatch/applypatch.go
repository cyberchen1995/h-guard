// Package applypatch 解析 apply_patch 的补丁格式（*** Begin Patch … *** End Patch），Codex 与 opencode 的
// apply_patch 工具都用它。
package applypatch

import (
	"errors"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// ErrUnparsed 表示 apply_patch 的内容读不懂：不能当作「没有动作」，调用方按 harness.TargetUnparsedError 请求确认。
var ErrUnparsed = errors.New("apply_patch input cannot be parsed")

// BeginPatch、EndPatch 是补丁的开头与结尾行。
const (
	BeginPatch = "*** Begin Patch"
	EndPatch   = "*** End Patch"
)

const (
	addFile    = "*** Add File:"
	deleteFile = "*** Delete File:"
	updateFile = "*** Update File:"
	moveTo     = "*** Move to:"
	endOfFile  = "*** End of File"
)

// Actions 把 apply_patch 的补丁转成动作：Add File、Update File → file_write；Delete File →
// file_delete；Update File 加 Move to → file_rename（源与目标都检查）。路径照原样（相对路径由检查按 cwd 解析）。
//
// 只认 Codex 的补丁格式：*** Begin Patch 之前可以有不以 "*** " 开头的行（如 apply_patch <<'EOF' 这样的 heredoc
// 开头），*** End Patch 之后同样如此（如 heredoc 的结束行）。其余任何读不懂的地方（缺开头或结尾、不认识的
// "*** " 行、空路径、正文行不合格式、一个操作都没有）都返回 ErrUnparsed：多问一次，不能漏掉文件。
func Actions(patch string) ([]guard.Action, error) {
	lines := strings.Split(strings.ReplaceAll(patch, "\r\n", "\n"), "\n")
	i := 0
	for ; i < len(lines) && strings.TrimSpace(lines[i]) != BeginPatch; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "*** ") {
			return nil, ErrUnparsed
		}
	}
	if i == len(lines) {
		return nil, ErrUnparsed
	}
	var out []guard.Action
	body := byte(0) // 当前操作的正文行允许的形状：'+' Add File，'@' Update File，0 不允许正文
	for i++; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		header := strings.TrimSpace(line)
		path := func(prefix string) string { return strings.TrimSpace(strings.TrimPrefix(header, prefix)) }
		switch {
		case header == EndPatch:
			if len(out) == 0 {
				return nil, ErrUnparsed
			}
			for _, rest := range lines[i+1:] {
				if strings.HasPrefix(strings.TrimSpace(rest), "*** ") {
					return nil, ErrUnparsed
				}
			}
			return out, nil
		case strings.HasPrefix(header, addFile):
			out, body = appendFile(out, guard.ActionFileWrite, path(addFile)), '+'
		case strings.HasPrefix(header, deleteFile):
			out, body = appendFile(out, guard.ActionFileDelete, path(deleteFile)), 0
		case strings.HasPrefix(header, updateFile):
			out, body = appendFile(out, guard.ActionFileWrite, path(updateFile)), '@'
		case strings.HasPrefix(header, moveTo):
			// 只能紧跟在 Update File 之后、第一个 @@ 之前
			if len(out) == 0 || body != '@' || out[len(out)-1].Kind != guard.ActionFileWrite || !strings.HasPrefix(strings.TrimSpace(lines[i-1]), updateFile) {
				return nil, ErrUnparsed
			}
			last := &out[len(out)-1]
			last.Kind, last.File.To = guard.ActionFileRename, path(moveTo)
			if last.File.To == "" {
				return nil, ErrUnparsed
			}
		case header == endOfFile && body == '@':
		case strings.HasPrefix(header, "*** "):
			return nil, ErrUnparsed
		case line == "":
			// 空行：Add File 的正文里是空行，Update 的上下文里是空的上下文行；操作之间的空行不影响目标
		case body == '+' && line[0] == '+':
		case body == '@' && (strings.HasPrefix(line, "@@") || strings.ContainsRune(" +-", rune(line[0]))):
		default:
			return nil, ErrUnparsed
		}
		if len(out) > 0 && out[len(out)-1].File.Path == "" {
			return nil, ErrUnparsed
		}
	}
	return nil, ErrUnparsed // 没有 *** End Patch
}

func appendFile(out []guard.Action, kind guard.ActionKind, path string) []guard.Action {
	return append(out, guard.Action{Kind: kind, File: &guard.FileAction{Path: path}})
}

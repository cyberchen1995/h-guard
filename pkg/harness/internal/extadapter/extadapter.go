// Package extadapter 是按扩展接入协议 v1 接入的 adapter 共用的部分：读请求、拼工具输出文本、组装动作、渲染回复。
// 扩展只转交 harness 的事件，判断与 harness 特有字段的解析都在各自的 adapter 里。
package extadapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

// Request 解析扩展请求，并确认它是发给 harness 的。
func Request(raw []byte, harness string) (extproto.Request, error) {
	req, err := extproto.ParseRequest(raw)
	if err != nil {
		return extproto.Request{}, err
	}
	if req.Harness != harness {
		return extproto.Request{}, fmt.Errorf("%s: request is for harness %q", harness, req.Harness)
	}
	return req, nil
}

// Exec 返回一条命令的 exec 动作；空命令返回 false。
func Exec(command string, shell guard.Shell) (guard.Action, bool) {
	if strings.TrimSpace(command) == "" {
		return guard.Action{}, false
	}
	return guard.Action{Kind: guard.ActionExec, Exec: &guard.ExecAction{Command: command, Shell: shell}}, true
}

// File 返回一个文件动作；空路径返回 false。
func File(kind guard.ActionKind, path string) (guard.Action, bool) {
	if strings.TrimSpace(path) == "" {
		return guard.Action{}, false
	}
	return guard.Action{Kind: kind, File: &guard.FileAction{Path: path}}, true
}

// Text 从工具结果中抽取文本：字符串原样；内容块数组（[{type: "text", text}, …]，或带这样一个 content 数组的
// 对象）取各文本块按顺序以换行连接；其余 JSON 原样（紧凑写法），图片等非文本块不参与。
func Text(raw json.RawMessage) string {
	if IsNull(raw) {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	type block struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	var blocks []block
	if json.Unmarshal(raw, &blocks) != nil {
		var obj struct {
			Content *[]block `json:"content"`
		}
		if json.Unmarshal(raw, &obj) != nil || obj.Content == nil {
			return Compact(raw)
		}
		blocks = *obj.Content
	}
	var parts []string
	for _, b := range blocks {
		if b.Type == "text" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// IsNull 报告 JSON 值是否缺失或为 null。
func IsNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// Compact 返回 JSON 的紧凑写法；不是合法 JSON 时原样返回。
func Compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// Relative 报告路径是否相对于 cwd（不以 /、~、盘符或 \\ 开头）。
func Relative(p string) bool {
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, `\\`) {
		return false
	}
	return !(len(p) >= 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/'))
}

// Under 返回 cwd 下的相对路径 p；cwd 用反斜杠时按 Windows 写法拼接。
func Under(cwd, p string) string {
	sep := "/"
	if strings.Contains(cwd, `\`) && !strings.Contains(cwd, "/") {
		sep = `\`
	}
	return strings.TrimRight(cwd, `/\`) + sep + p
}

// Workdir 返回命令实际的工作目录：没有给 workdir 时是 cwd；相对的 workdir 按 cwd 解析。
func Workdir(cwd, workdir string) string {
	switch {
	case strings.TrimSpace(workdir) == "":
		return cwd
	case Relative(workdir) && cwd != "":
		return Under(cwd, workdir)
	}
	return workdir
}

// Render 渲染扩展接入协议的回复：pass 不带说明；其余结论必须带说明，缺失时用固定文本。
func Render(out guard.Outcome) []byte {
	d := out.Verdict.Decision
	if d == guard.DecisionPass {
		b, _ := json.Marshal(extproto.NewReply(extproto.ActionPass, "", ""))
		return b
	}
	msg := out.Message
	if strings.TrimSpace(msg) == "" {
		msg = "h-guard" // 非 pass 的回复必须带说明
	}
	b, _ := json.Marshal(extproto.NewReply(extproto.Action(d), msg, out.Hint))
	return b
}

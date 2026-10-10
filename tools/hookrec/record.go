package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

type options struct {
	Out    string
	Event  string
	Format string
	Mode   string
	Canary string
	Now    func() time.Time
}

const (
	reasonText   = "h-guard M0 test"    // 回复原因的前缀，脚本据此判断原因是否显示出来
	replacedText = "[h-guard replaced]" // 拦下工具输出时的标记，脚本据此在 transcript 中查找
)

// modes 是各回复格式支持的模式。codex 为 Codex 原生 hook 的输出（record 不输出）；
// ext 为扩展接入协议 v1 的回复（每次都回复，record 回复 pass）。
var modes = map[string][]string{
	"codex": {"record", "deny", "ask", "block-prompt", "block-output"},
	"ext":   {"record", "deny", "ask", "warn"},
}

// checkMode 检查格式与模式的组合。
func checkMode(opt options) error {
	allowed, ok := modes[opt.Format]
	if !ok {
		return fmt.Errorf("unknown format %q", opt.Format)
	}
	if !slices.Contains(allowed, opt.Mode) {
		return fmt.Errorf("mode %q is not available for format %q", opt.Mode, opt.Format)
	}
	return nil
}

// handle 把 stdin 记到 opt.Out 下，并按模式返回要写到 stdout 的回复。
func handle(stdin []byte, opt options) ([]byte, error) {
	reply, err := buildReply(stdin, opt)
	if err != nil {
		return nil, err
	}
	rec := fixtures.RawRecord{Event: opt.Event, ReceivedAt: opt.Now().UTC(), Stdin: rawOrString(stdin), Reply: reply}
	b, err := encodeCompact(rec)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(opt.Out, 0o755); err != nil {
		return nil, err
	}
	name := fmt.Sprintf("%020d-%d-%s-%s.json", rec.ReceivedAt.UnixNano(), os.Getpid(), randHex(4), opt.Event)
	if err := os.WriteFile(filepath.Join(opt.Out, name), b, 0o644); err != nil {
		return nil, err
	}
	return reply, nil
}

// buildReply 按格式与模式构造回复。只有 stdin 含 opt.Canary 时才按模式回复。
func buildReply(stdin []byte, opt options) ([]byte, error) {
	if err := checkMode(opt); err != nil {
		return nil, err
	}
	triggered := opt.Mode != "record" && opt.Canary != "" && bytes.Contains(stdin, []byte(opt.Canary))
	if opt.Format == "ext" {
		if !triggered {
			return json.Marshal(extproto.NewReply(extproto.ActionPass, "", ""))
		}
		message := reasonText + ": " + opt.Mode
		if opt.Mode == "deny" {
			message = replacedText + " " + message
		}
		return json.Marshal(extproto.NewReply(extproto.Action(opt.Mode), message, ""))
	}
	if !triggered {
		return nil, nil
	}
	switch opt.Mode {
	case "deny", "ask":
		return json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       opt.Mode,
			"permissionDecisionReason": reasonText + ": " + opt.Mode,
		}})
	case "block-prompt":
		return json.Marshal(map[string]any{"decision": "block", "reason": reasonText + ": prompt blocked"})
	default: // block-output
		return json.Marshal(map[string]any{"decision": "block", "reason": replacedText + " " + reasonText + ": output blocked"})
	}
}

// rawOrString 合法 JSON 原样保留，否则存为 JSON 字符串。
func rawOrString(b []byte) json.RawMessage {
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, _ := json.Marshal(string(b))
	return s
}

// encodeCompact 紧凑编码且不转义 <、>、&；录制脚本用 jq 读取这些记录。
func encodeCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

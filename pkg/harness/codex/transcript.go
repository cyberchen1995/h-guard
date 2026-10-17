package codex

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/internal/jsonl"
)

// transcriptTail 是从会话记录末尾读取的字节数上限：只需要最近几条指令。
const transcriptTail = 4 << 20

type rolloutRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	Payload   struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Text *string `json:"text"`
		} `json:"content"`
	} `json:"payload"`
}

// ReadRequests 从 Codex 的会话记录（hook 输入的 transcript_path，rollout-*.jsonl）回退读取最近的至多 limit 条
// 指令，按时间先后排列。用户消息是 type 为 response_item、payload 为 role user 的 message，每个文本块
// 一条；来源按 sourceOf 判定（注入的上下文块是自动的）。被 UserPromptSubmit 拦下的提示词不写进会话记录。
// 只读末尾 4 MiB；残行、读不懂的行与空文本跳过。
func (Adapter) ReadRequests(path string, limit int) ([]guard.Request, error) {
	if path == "" || limit <= 0 {
		return nil, nil
	}
	var all []guard.Request
	err := jsonl.Tail(path, transcriptTail, func(line []byte) {
		var rec rolloutRecord
		if json.Unmarshal(line, &rec) != nil || rec.Type != "response_item" || rec.Payload.Type != "message" || rec.Payload.Role != "user" {
			return
		}
		for _, c := range rec.Payload.Content {
			if c.Text == nil || strings.TrimSpace(*c.Text) == "" {
				continue
			}
			all = append(all, guard.Request{Text: *c.Text, Source: sourceOf(*c.Text), At: rec.Timestamp})
		}
	})
	if err != nil {
		return nil, err
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}

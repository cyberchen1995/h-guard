package claudecode

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// transcriptTail 是从 transcript 末尾读取的字节数上限：只需要最近几条指令。
const transcriptTail = 4 << 20

// metaPrefixes 是 Claude Code 写进 user 记录、但不是人说的话的内容（沿用 Python 版）。
var metaPrefixes = []string{"<local-command", "<command-name", "<command-message", "<command-args"}

type transcriptRecord struct {
	Type                      string    `json:"type"`
	IsMeta                    bool      `json:"isMeta"`
	IsSidechain               bool      `json:"isSidechain"`
	IsCompactSummary          bool      `json:"isCompactSummary"`
	IsVisibleInTranscriptOnly bool      `json:"isVisibleInTranscriptOnly"`
	Timestamp                 time.Time `json:"timestamp"`
	Message                   struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	Origin *struct {
		Kind string `json:"kind"`
	} `json:"origin"`
}

// ReadRequests 从 transcript 回退读取最近的至多 limit 条指令，按时间先后排列（spec §5.4）。
// 来源按 transcript 的 origin.kind 判定（用户输入记为 human）；没有 origin 的旧记录按用户本人处理，
// 但以 <task-notification 开头的内容是自动消息。跳过元信息、压缩摘要、子 agent 侧链与 tool_result。
// 只读末尾 4 MiB；残行与读不懂的行跳过。
func (Adapter) ReadRequests(path string, limit int) ([]guard.Request, error) {
	if path == "" || limit <= 0 {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := max(0, info.Size()-transcriptTail)
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if start > 0 { // 第一行可能不完整
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	var all []guard.Request
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), transcriptTail)
	for sc.Scan() {
		var rec transcriptRecord
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if req, ok := requestOf(rec); ok {
			all = append(all, req)
		}
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}

func requestOf(rec transcriptRecord) (guard.Request, bool) {
	if rec.Type != "user" || rec.IsMeta || rec.IsSidechain || rec.IsCompactSummary || rec.IsVisibleInTranscriptOnly {
		return guard.Request{}, false
	}
	var text string
	if json.Unmarshal(rec.Message.Content, &text) != nil {
		return guard.Request{}, false // 数组形式的 user 记录是 tool_result，不是人说的话
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return guard.Request{}, false
	}
	for _, p := range metaPrefixes {
		if strings.HasPrefix(text, p) {
			return guard.Request{}, false
		}
	}
	src := guard.SourceUser
	switch {
	case rec.Origin != nil:
		src = SourceOf(rec.Origin.Kind)
	case strings.HasPrefix(text, "<task-notification"):
		src = guard.SourceAutomated
	}
	return guard.Request{Text: text, Source: src, At: rec.Timestamp}, true
}

// Package log 写健康记录与决策日志（spec §10.2–10.4）。
//
//   - 健康记录默认开启，只在出现降级原因、能力降级、配置非法或内部异常时写，只含原因码，
//     不含任何内容（命令、路径、提示词、工具输出、会话 ID）。
//   - 决策日志默认关闭，开启后每次 hook 调用写一条，记原文；唯一处理是用 pkg/detect/secrets
//     把凭据值换成描述形状的占位符（本地检测、无开关）。单条上限 64 KiB。
//
// 提示词与工具输出的正文不进决策日志，只记长度（outbound 的命中摘录在 M4 加入）。
// 每条记录一次 O_APPEND 写入，不加锁；写入失败一律忽略，不影响结论。
package log

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// HealthRetention 是健康记录的保留时间（spec §10.2）。
const HealthRetention = 7 * 24 * time.Hour

// MaxDecisionBytes 是一条决策日志的上限（spec §10.3）。
const MaxDecisionBytes = 64 << 10

// Health 是一条健康记录。字段固定，没有任何内容字段。
type Health struct {
	TS      time.Time `json:"ts"`
	Version string    `json:"version"`
	Harness string    `json:"harness"`
	Event   string    `json:"event"`
	Check   string    `json:"check"`           // 产生该原因码的 Check；Engine 的能力降级为 engine，入口兜底为 app
	Code    string    `json:"code"`            // 降级原因码
	Where   string    `json:"where,omitempty"` // 内部异常时 panic 所在的函数与行号
}

// Writer 写两类记录。Dir 为 <cache_dir>/h-guard；为空（缓存目录取不到）时什么都不写。
type Writer struct {
	Dir           string
	Decisions     bool // log.decisions
	RetentionDays int  // log.retention_days
	Now           func() time.Time
}

func (w *Writer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Health 追加健康记录（每个原因码一条），并清理 7 天前的文件。失败忽略。
func (w *Writer) Health(recs []Health) {
	if w.Dir == "" || len(recs) == 0 { // 缓存目录取不到时不写（不能退回相对路径）
		return
	}
	now := w.now()
	dir := filepath.Join(w.Dir, "health")
	for _, r := range recs {
		if r.TS.IsZero() {
			r.TS = now.UTC()
		}
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		_ = store.AppendLine(filepath.Join(dir, now.Format("2006-01-02")+".jsonl"), b)
	}
	store.RemoveOlder(dir, now.Add(-HealthRetention))
}

// Decision 是一条决策日志。
type Decision struct {
	TS          time.Time       `json:"ts"`
	Version     string          `json:"version"`
	Harness     string          `json:"harness"`
	SessionID   string          `json:"session_id"`
	CallID      string          `json:"call_id"`
	Cwd         string          `json:"cwd"`
	Event       guard.EventKind `json:"event"`
	Tool        string          `json:"tool,omitempty"`
	Decision    guard.Decision  `json:"decision"`
	RawDecision guard.Decision  `json:"raw_decision"`
	Findings    []guard.Finding `json:"findings,omitempty"`
	Signals     map[string]any  `json:"signals,omitempty"`
	Fallbacks   []string        `json:"fallbacks,omitempty"`
	Backend     string          `json:"backend,omitempty"`
	Profile     string          `json:"profile,omitempty"`
	LatencyMS   Latency         `json:"latency_ms"`
	Actions     []guard.Action  `json:"actions,omitempty"`
	Requests    []guard.Request `json:"requests,omitempty"`
	TextBytes   int             `json:"text_bytes,omitempty"` // 提示词或工具输出的长度；正文不记录
	Truncated   bool            `json:"truncated,omitempty"`
	Note        string          `json:"note,omitempty"` // 超过上限被截断时的标注
}

// Latency 是总耗时与判断层耗时。
type Latency struct {
	Total int64 `json:"total"`
	Judge int64 `json:"judge,omitempty"`
}

// Decision 追加一条决策日志（log.decisions 关闭时什么都不做），并按 retention_days 清理。
func (w *Writer) Decision(d Decision) {
	if w.Dir == "" || !w.Decisions {
		return
	}
	now := w.now()
	if d.TS.IsZero() {
		d.TS = now.UTC()
	}
	b, err := json.Marshal(mask(d))
	if err != nil {
		return
	}
	if len(b) > MaxDecisionBytes {
		b = shrink(mask(d))
	}
	dir := filepath.Join(w.Dir, "logs")
	_ = store.AppendLine(filepath.Join(dir, "decisions-"+now.Format("2006-01-02")+".jsonl"), b)
	store.RemoveOlder(dir, now.AddDate(0, 0, -max(1, w.RetentionDays)))
}

// mask 遮蔽所有自由文本字段中的凭据值（spec §10.3）。
func mask(d Decision) Decision {
	d.Cwd = secrets.MaskForLog(d.Cwd)
	acts := make([]guard.Action, len(d.Actions))
	for i, a := range d.Actions {
		if a.Exec != nil {
			e := *a.Exec
			e.Command = secrets.MaskForLog(e.Command)
			a.Exec = &e
		}
		if a.File != nil {
			f := *a.File
			f.Path, f.To = secrets.MaskForLog(f.Path), secrets.MaskForLog(f.To)
			a.File = &f
		}
		a.Raw = nil // tool_call 等预留动作的原始载荷不记录
		acts[i] = a
	}
	d.Actions = acts
	reqs := make([]guard.Request, len(d.Requests))
	for i, r := range d.Requests {
		r.Text = secrets.MaskForLog(r.Text)
		reqs[i] = r
	}
	d.Requests = reqs
	return d
}

// shrink 反复对最长的文本字段做中间截断，直到整条不超过上限。
func shrink(d Decision) []byte {
	for range 64 {
		b, err := json.Marshal(d)
		if err != nil || len(b) <= MaxDecisionBytes {
			return b
		}
		field := longest(&d)
		over := len(b) - MaxDecisionBytes + 64
		*field = cutMiddle(*field, len(*field)-over)
		d.Note = "truncated to fit 64 KiB"
	}
	b, _ := json.Marshal(Decision{TS: d.TS, Version: d.Version, Harness: d.Harness, Event: d.Event,
		Decision: d.Decision, RawDecision: d.RawDecision, Fallbacks: d.Fallbacks, Note: "record dropped: too large"})
	return b
}

func longest(d *Decision) *string {
	best := &d.Cwd
	consider := func(s *string) {
		if len(*s) > len(*best) {
			best = s
		}
	}
	for i := range d.Actions {
		if d.Actions[i].Exec != nil {
			consider(&d.Actions[i].Exec.Command)
		}
	}
	for i := range d.Requests {
		consider(&d.Requests[i].Text)
	}
	return best
}

func cutMiddle(s string, keep int) string {
	if keep < 0 {
		keep = 0
	}
	if len(s) <= keep {
		return s
	}
	head := keep * 2 / 3
	tail := keep - head
	// 不切断 UTF-8 字符
	for head > 0 && head < len(s) && s[head]&0xC0 == 0x80 {
		head--
	}
	start := len(s) - tail
	for start < len(s) && s[start]&0xC0 == 0x80 {
		start++
	}
	return s[:head] + fmt.Sprintf("…[%d bytes cut]…", start-head) + s[start:]
}

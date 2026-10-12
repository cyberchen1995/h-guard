package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Summary 是一个 harness 的统计结果。只含计数、标签名、字段名，以及白名单字段的短取值与布尔值；
// 不含消息内容、路径、ID 或未知字段的取值（评审 H01）。
type Summary struct {
	Harness      string         `json:"harness"`
	Files        int            `json:"files"`
	Lines        int            `json:"lines"`
	SkippedLines int            `json:"skipped_lines"` // 不是 JSON 的行
	UserRecords  int            `json:"user_records"`
	LeadingTags  map[string]int `json:"leading_tags"` // 每段用户文本的开头标签，如 "<task-notification"
	RecordKeys   map[string]int `json:"record_keys"`  // 用户消息记录的字段名；nestedKeys 中的对象展开一层，如 origin.kind
	EnumValues   map[string]int `json:"enum_values"`  // "字段=值"：enumKeys 中字段的短取值，以及任意字段的布尔值
}

// extractor 从一条记录中取出用户消息的各段文本，以及要统计的字段；不是用户消息时 ok 为 false。
type extractor func(rec map[string]any) (texts []string, fields map[string]any, ok bool)

var (
	// 只认闭合的标签（<name> 或 <name attr…>）：没闭合的尖括号后面可能是用户内容（评审 M4）
	tagRe  = regexp.MustCompile(`^<([A-Za-z][A-Za-z0-9_-]{0,40})(?:\s[^<>]{0,200})?/?>`)
	enumRe = regexp.MustCompile(`^[A-Za-z_-]{1,32}$`)
)

// enumKeys 是允许输出取值的字段：取值是 harness 定义的类型或来源标记，不是用户内容。其他字段只统计
// 字段名，因为未知字段即使取值很短也可能是 key、名字或标签（评审 H01）。
var enumKeys = map[string]bool{
	"type": true, "userType": true, "isMeta": true, "isSidechain": true, "isCompactSummary": true,
	"isVisibleInTranscriptOnly": true, "entrypoint": true, "origin.kind": true,
	"payload.type": true, "payload.role": true,
}

// nestedKeys 是展开一层统计的对象，其字段名由 harness 定义。
var nestedKeys = map[string]bool{"origin": true, "payload": true}

func scanDir(harness, root string, ex extractor) Summary {
	s := Summary{Harness: harness, LeadingTags: map[string]int{}, RecordKeys: map[string]int{}, EnumValues: map[string]int{}}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 目录不存在或不可读：跳过
		}
		if d.IsDir() || filepath.Ext(p) != ".jsonl" {
			return nil
		}
		s.Files++
		_ = scanFile(&s, p, ex)
		return nil
	})
	return s
}

func scanFile(s *Summary, path string, ex extractor) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	for {
		line, err := r.ReadBytes('\n') // 不限行长：会话记录里单行可达数 MB
		if len(bytes.TrimSpace(line)) > 0 {
			s.Lines++
			countLine(s, line, ex)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func countLine(s *Summary, line []byte, ex extractor) {
	var rec map[string]any
	if err := json.Unmarshal(line, &rec); err != nil {
		s.SkippedLines++
		return
	}
	texts, fields, ok := ex(rec)
	if !ok {
		return
	}
	s.UserRecords++
	if len(texts) == 0 {
		s.LeadingTags["(empty)"]++
	}
	for _, t := range texts {
		s.LeadingTags[leadingTag(t)]++
	}
	for k, v := range flatten(fields) {
		s.RecordKeys[k]++
		if ev, ok := enumValue(k, v); ok {
			s.EnumValues[ev]++
		}
	}
}

func leadingTag(text string) string {
	t := strings.TrimSpace(text)
	if m := tagRe.FindStringSubmatch(t); m != nil {
		return "<" + strings.ToLower(m[1])
	}
	switch {
	case strings.HasPrefix(t, "<"):
		return "(lt)"
	case t == "":
		return "(empty)"
	case strings.HasPrefix(t, "["):
		return "(bracket)"
	case strings.HasPrefix(t, "/"):
		return "(slash)"
	}
	return "(plain)"
}

// flatten 返回记录的顶层字段，并把 nestedKeys 中的对象展开一层。
func flatten(fields map[string]any) map[string]any {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		out[k] = v
		if obj, ok := v.(map[string]any); ok && nestedKeys[k] {
			for k2, v2 := range obj {
				out[k+"."+k2] = v2
			}
		}
	}
	return out
}

// enumValue 只对布尔值与 enumKeys 中字段的短标识符返回 "字段=值"。
func enumValue(key string, v any) (string, bool) {
	switch x := v.(type) {
	case bool:
		return key + "=" + strconv.FormatBool(x), true
	case string:
		if enumKeys[key] && enumRe.MatchString(x) {
			return key + "=" + x, true
		}
	}
	return "", false
}

// claudeUser 识别 Claude Code transcript 里的用户消息；工具结果不算用户消息。
func claudeUser(rec map[string]any) ([]string, map[string]any, bool) {
	if rec["type"] != "user" {
		return nil, nil, false
	}
	msg, _ := rec["message"].(map[string]any)
	switch c := msg["content"].(type) {
	case string:
		return []string{c}, rec, true
	case []any:
		var texts []string
		for _, item := range c {
			m, _ := item.(map[string]any)
			if m["type"] == "tool_result" {
				return nil, nil, false
			}
			if s, ok := m["text"].(string); ok && m["type"] == "text" {
				texts = append(texts, s)
			}
		}
		return texts, rec, true
	}
	return nil, nil, false
}

// codexUser 识别 Codex 会话记录里的用户消息（response_item / message / role=user）。
func codexUser(rec map[string]any) ([]string, map[string]any, bool) {
	payload, _ := rec["payload"].(map[string]any)
	if rec["type"] != "response_item" || payload["type"] != "message" || payload["role"] != "user" {
		return nil, nil, false
	}
	var texts []string
	items, _ := payload["content"].([]any)
	for _, item := range items {
		m, _ := item.(map[string]any)
		if s, ok := m["text"].(string); ok {
			texts = append(texts, s)
		}
	}
	return texts, rec, true
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

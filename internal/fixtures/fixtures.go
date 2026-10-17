// Package fixtures 管理从真实 harness 录制的 hook 样本（testdata/fixtures）。
package fixtures

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// RawRecord 是录制工具写下的一条原始记录（录制工具不在公开仓库中）。
type RawRecord struct {
	Event      string          `json:"event"`
	ReceivedAt time.Time       `json:"received_at"`
	Stdin      json.RawMessage `json:"stdin"`           // hook 收到的输入；不是 JSON 时存为 JSON 字符串
	Reply      json.RawMessage `json:"reply,omitempty"` // hook 写到 stdout 的回复
}

// ManifestFile 是录制脚本在每个场景的原始记录目录中写下的批次信息。
const ManifestFile = "manifest.json"

// Manifest 是一个场景一次录制的批次信息。导入只用它的版本，不用导入时 CLI 报告的版本。
type Manifest struct {
	RunID      string    `json:"run_id"`
	Harness    string    `json:"harness"`
	Version    string    `json:"version"`
	Platform   string    `json:"platform"`
	Scenario   string    `json:"scenario"`
	RecordedAt time.Time `json:"recorded_at"`
}

// ReadManifest 读取 rawDir 中的 manifest 并检查必填字段。
func ReadManifest(rawDir string) (Manifest, error) {
	b, err := os.ReadFile(filepath.Join(rawDir, ManifestFile))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Manifest{}, fmt.Errorf("fixtures: %s: %w", ManifestFile, err)
	}
	if m.RunID == "" || m.Harness == "" || m.Version == "" || m.Platform == "" || m.Scenario == "" {
		return Manifest{}, fmt.Errorf("fixtures: %s needs run_id, harness, version, platform and scenario", ManifestFile)
	}
	return m, nil
}

// Meta 返回导入用的样本信息。
func (m Manifest) Meta() Meta {
	return Meta{Harness: m.Harness, Version: m.Version, Scenario: m.Scenario, Platform: m.Platform, RunID: m.RunID}
}

// Meta 是导入时附加的样本信息。
type Meta struct{ Harness, Version, Scenario, Platform, RunID string }

// Fixture 是一条整理后的样本。
type Fixture struct {
	Harness  string          `json:"harness"`  // claudecode | codex
	Version  string          `json:"version"`  // 录制时的 harness 版本
	Scenario string          `json:"scenario"` // 场景名，如 bash-echo
	Platform string          `json:"platform,omitempty"`
	RunID    string          `json:"run_id,omitempty"`
	Event    string          `json:"event"` // 事件或 hook 名，如 PreToolUse、tool.check
	Stdin    json.RawMessage `json:"stdin"`
	Reply    json.RawMessage `json:"reply,omitempty"`
	Notes    string          `json:"notes,omitempty"`
	Path     string          `json:"-"` // Load 时填入
}

// Replacement 把样本中的本机信息替换为占位符。
type Replacement struct{ Old, New string }

// 样本中替换本机路径用的占位符。
const (
	HomePlaceholder    = "/home/user"
	WorkdirPlaceholder = "/tmp/hg-m0"
)

// Sanitize 应用替换规则。每条规则也替换其在 JSON 字符串中的转义写法（如 Windows 路径的反斜杠）；
// 更长的 Old 先替换，避免 /private/var/x 先被 /var/x 截断。Old 为空的规则被忽略。
func Sanitize(b []byte, rules []Replacement) []byte {
	var all []Replacement
	for _, r := range rules {
		if r.Old == "" {
			continue
		}
		all = append(all, r)
		if esc := jsonEscape(r.Old); esc != r.Old {
			all = append(all, Replacement{Old: esc, New: jsonEscape(r.New)})
		}
	}
	slices.SortStableFunc(all, func(a, b Replacement) int { return len(b.Old) - len(a.Old) })
	for _, r := range all {
		b = bytes.ReplaceAll(b, []byte(r.Old), []byte(r.New))
	}
	return b
}

// jsonEscape 返回 s 在 JSON 字符串中的写法（不含两侧引号）。
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := strings.TrimSuffix(buf.String(), "\n")
	return out[1 : len(out)-1]
}

var slugRe = regexp.MustCompile(`[^A-Za-z0-9]`)

// ClaudeSlug 返回 Claude Code 为某个目录生成的项目目录名（~/.claude/projects/<slug>）。
func ClaudeSlug(path string) string { return slugRe.ReplaceAllString(path, "-") }

// LocalPathRules 返回把本机路径换成占位符的规则。workdirs 应同时给出录制目录及其解析符号链接后的写法
// （macOS 的 /var/folders 实际位于 /private/var/folders）。每个路径同时替换其 Claude Code 项目目录名。
func LocalPathRules(home string, workdirs []string) []Replacement {
	var rules []Replacement
	for _, wd := range workdirs {
		if wd == "" {
			continue
		}
		for _, p := range pathAliases(wd) {
			rules = append(rules,
				Replacement{Old: p, New: WorkdirPlaceholder},
				Replacement{Old: ClaudeSlug(p), New: ClaudeSlug(WorkdirPlaceholder)},
			)
		}
	}
	if home != "" {
		rules = append(rules,
			Replacement{Old: home, New: HomePlaceholder},
			Replacement{Old: ClaudeSlug(home), New: ClaudeSlug(HomePlaceholder)},
		)
	}
	return rules
}

// pathAliases 返回 p 本身，以及 macOS 上同一位置的另一种写法：/var、/tmp 是 /private/var、/private/tmp 的
// 符号链接，记录里两种写法都可能出现。
func pathAliases(p string) []string {
	out := []string{p}
	for _, pre := range []string{"/var/", "/tmp/"} {
		switch {
		case strings.HasPrefix(p, "/private"+pre):
			out = append(out, strings.TrimPrefix(p, "/private"))
		case strings.HasPrefix(p, pre):
			out = append(out, "/private"+p)
		}
	}
	return out
}

// leakPatterns 是样本中不应出现的本机路径写法：macOS 临时目录及其 Claude Code 项目目录名、
// /private/tmp、macOS 与 Windows 的用户目录（JSON 中 Windows 路径的反斜杠是转义后的写法）。
var leakPatterns = []string{
	"/var/folders/", "-var-folders-", "/private/var/", "-private-var-", "/private/tmp/", "-private-tmp-",
	"/Users/", "-Users-", `\\Users\\`,
}

// LeakCheck 检查样本内容中是否残留本机路径。home 是本机家目录，它和它的 Claude Code 项目目录名也算泄露。
// 返回的错误只说明类别，不含路径本身。
func LeakCheck(b []byte, home string) error {
	if home != "" && home != HomePlaceholder {
		if bytes.Contains(b, []byte(home)) || bytes.Contains(b, []byte(ClaudeSlug(home))) {
			return errors.New("fixtures: contains the local home directory or its Claude Code project name")
		}
	}
	for _, p := range leakPatterns {
		if bytes.Contains(b, []byte(p)) {
			return fmt.Errorf("fixtures: contains a local path (%s)", strings.Trim(p, `-/\`))
		}
	}
	return nil
}

const lockFile = ".import.lock"

// Import 把 rawDir 下的原始记录整理为一组样本，写到 destRoot/<harness>/<version>/，并整组替换该场景
// 原有的样本：新的一组全部写好之后才移走旧的，任何一步失败都保留旧的完整一组。
// 文件名为 <scenario>-<序号>-<事件>.json，序号按记录的接收时间排列。同一目录同一时间只允许一个导入。
func Import(rawDir, destRoot string, meta Meta, rules []Replacement) ([]string, error) {
	if meta.Harness == "" || meta.Version == "" || meta.Scenario == "" {
		return nil, errors.New("fixtures: harness, version and scenario are required")
	}
	recs, err := readRaw(rawDir)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(destRoot, meta.Harness, meta.Version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	names := make([]string, 0, len(recs))
	for i, r := range recs {
		b, err := encodeIndent(Fixture{
			Harness: meta.Harness, Version: meta.Version, Scenario: meta.Scenario,
			Platform: meta.Platform, RunID: meta.RunID, Event: r.Event, Stdin: r.Stdin, Reply: r.Reply,
		})
		if err != nil {
			return nil, err
		}
		name := fmt.Sprintf("%s-%02d-%s.json", meta.Scenario, i+1, r.Event)
		if err := os.WriteFile(filepath.Join(stage, name), Sanitize(b, rules), 0o644); err != nil {
			return nil, err
		}
		names = append(names, name)
	}

	old, err := scenarioFiles(dir, meta.Scenario)
	if err != nil {
		return nil, err
	}
	trash, err := os.MkdirTemp(dir, ".old-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(trash)
	var moved, placed []string
	rollback := func() {
		for _, n := range placed {
			_ = os.Remove(filepath.Join(dir, n))
		}
		for _, n := range moved {
			_ = os.Rename(filepath.Join(trash, n), filepath.Join(dir, n))
		}
	}
	for _, n := range old {
		if err := os.Rename(filepath.Join(dir, n), filepath.Join(trash, n)); err != nil {
			rollback()
			return nil, err
		}
		moved = append(moved, n)
	}
	for _, n := range names {
		if err := os.Rename(filepath.Join(stage, n), filepath.Join(dir, n)); err != nil {
			rollback()
			return nil, err
		}
		placed = append(placed, n)
	}
	written := make([]string, len(names))
	for i, n := range names {
		written[i] = filepath.Join(dir, n)
	}
	return written, nil
}

// readRaw 读取 rawDir 下的原始记录（跳过 manifest），按接收时间排序。
func readRaw(rawDir string) ([]RawRecord, error) {
	paths, err := filepath.Glob(filepath.Join(rawDir, "*.json"))
	if err != nil {
		return nil, err
	}
	var recs []RawRecord
	for _, p := range paths {
		if filepath.Base(p) == ManifestFile {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var r RawRecord
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("fixtures: %s: %w", p, err)
		}
		recs = append(recs, r)
	}
	if len(recs) == 0 {
		return nil, fmt.Errorf("fixtures: no raw records in %s", rawDir)
	}
	slices.SortStableFunc(recs, func(a, b RawRecord) int { return a.ReceivedAt.Compare(b.ReceivedAt) })
	return recs, nil
}

// scenarioFiles 返回 dir 中属于该场景的样本文件名。按文件内容的 scenario 字段判断，
// 不按文件名前缀，避免 a 与 a-b 两个场景互相误伤。
func scenarioFiles(dir, scenario string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var f struct {
			Scenario string `json:"scenario"`
		}
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("fixtures: cannot read existing fixture %s: %w", e.Name(), err)
		}
		if f.Scenario == scenario {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// lockDir 以 O_EXCL 创建锁文件。锁已存在说明另一个导入正在进行，或上次导入异常退出（此时需要人工删除）。
func lockDir(dir string) (func(), error) {
	p := filepath.Join(dir, lockFile)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("fixtures: another import holds %s; remove it if no import is running", p)
		}
		return nil, err
	}
	_ = f.Close()
	return func() { _ = os.Remove(p) }, nil
}

// encodeIndent 缩进编码，不转义 <、>、&，样本里的标签保持原样便于阅读和搜索。
func encodeIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Load 读取 root 下所有样本，跳过以点开头的目录（导入时的临时目录）。root 不存在时返回 nil, nil。
func Load(root string) ([]Fixture, error) {
	var out []Fixture
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(p) != ".json" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var f Fixture
		if err := json.Unmarshal(b, &f); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		f.Path = p
		out = append(out, f)
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return out, err
}

// harnessSpec 是一个 harness 的样本必备字段。字段名用点号表示嵌套。
type harnessSpec struct {
	nameKey  string              // 事件名所在的字段
	protocol string              // 非空时 protocol 字段必须等于它
	common   []string            // 每条样本都要有的字段
	events   map[string][]string // 各事件额外要有的字段
}

// 必备字段来自 Claude Code 扩展请求与 Codex 官方文档（2026-10-09）。真实载荷与之不符时
// TestRecordedFixtures 失败，应同时更新本表。
var specs = map[string]harnessSpec{
	"claudecode": {
		nameKey:  "hook",
		protocol: "h-guard.ext/v1",
		common:   []string{"protocol", "harness", "harness_version", "hook", "session.id", "session.cwd", "data"},
		events: map[string][]string{
			"tool.check":    {"decided", "data.tool"},
			"tool.result":   {"result", "data.tool"},
			"prompt.submit": {"data.text", "data.origin"},
		},
	},
	// Claude Code 插件内经典 PreToolUse 的原生输入
	"claudecode-native": {
		nameKey: "hook_event_name",
		common:  []string{"session_id", "transcript_path", "cwd", "hook_event_name", "permission_mode"},
		events:  map[string][]string{"PreToolUse": {"tool_name", "tool_input", "tool_use_id"}},
	},
	"codex": {
		nameKey: "hook_event_name",
		common:  []string{"session_id", "cwd", "hook_event_name", "transcript_path"},
		events: map[string][]string{
			"PreToolUse":       {"tool_name", "tool_input", "tool_use_id", "turn_id"},
			"PostToolUse":      {"tool_name", "tool_input", "tool_response", "tool_use_id", "turn_id"},
			"UserPromptSubmit": {"prompt", "turn_id"},
		},
	},
}

// Validate 检查样本的元信息与必备字段，并确认事件名与 Event 一致。
func Validate(f Fixture) error {
	spec, ok := specs[specName(f)]
	if !ok {
		return fmt.Errorf("unknown harness %q", f.Harness)
	}
	if f.Version == "" || f.Scenario == "" || f.Event == "" {
		return errors.New("version, scenario and event are required")
	}
	var stdin map[string]any
	if err := json.Unmarshal(f.Stdin, &stdin); err != nil {
		return fmt.Errorf("stdin is not a JSON object: %w", err)
	}
	for _, k := range append(slices.Clone(spec.common), spec.events[f.Event]...) {
		if _, ok := lookup(stdin, k); !ok {
			return fmt.Errorf("stdin lacks %q", k)
		}
	}
	if name, _ := lookup(stdin, spec.nameKey); name != f.Event {
		return fmt.Errorf("%s = %v, want %q", spec.nameKey, name, f.Event)
	}
	if spec.protocol != "" {
		if proto, _ := lookup(stdin, "protocol"); proto != spec.protocol {
			return fmt.Errorf("protocol = %v, want %q", proto, spec.protocol)
		}
	}
	return nil
}

// specName 返回样本适用的字段表：Claude Code 的 PreToolUse 是经典 hook 的原生输入，其余是扩展请求。
func specName(f Fixture) string {
	if f.Harness == "claudecode" && f.Event == "PreToolUse" {
		return "claudecode-native"
	}
	return f.Harness
}

// cwdKeys 是各类记录中工作目录所在的字段。
var cwdKeys = map[string]string{"claudecode": "session.cwd", "claudecode-native": "cwd", "codex": "cwd"}

// CwdOf 返回样本记录的工作目录；harness 未知或没有该字段时返回空串。
func CwdOf(f Fixture) string {
	key, ok := cwdKeys[specName(f)]
	if !ok {
		return ""
	}
	var stdin map[string]any
	if json.Unmarshal(f.Stdin, &stdin) != nil {
		return ""
	}
	v, _ := lookup(stdin, key)
	s, _ := v.(string)
	return s
}

// lookup 按点号路径取值。
func lookup(m map[string]any, path string) (any, bool) {
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

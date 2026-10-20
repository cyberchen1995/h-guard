package eval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/cyberchen1995/h-guard/corpus"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// Scenario 是一步（或一个任务）所处的用户意图场景。
type Scenario string

const (
	ScenarioKeepWork    Scenario = "keep_work"   // 用户要保住进行中的工作
	ScenarioNoPublish   Scenario = "no_publish"  // 用户没有要求对外发布
	ScenarioCredentials Scenario = "credentials" // 凭据不该外露
	ScenarioNormal      Scenario = "normal"      // 普通的日常操作
)

func (s Scenario) valid() bool {
	switch s {
	case ScenarioKeepWork, ScenarioNoPublish, ScenarioCredentials, ScenarioNormal:
		return true
	}
	return false
}

// HarmIDs 是步骤可以标注的危害类别。
var HarmIDs = []string{"destructive_git", "branch_ops", "recursive_delete", "publish", "sensitive_read", "verify_bypass", "catastrophic"}

// 步骤可用的工具：前两个执行命令，其余是文件工具。
var (
	execTools = []string{"Bash", "PowerShell"}
	fileTools = []string{"Read", "Grep", "Write", "Edit"}
)

// Step 是一步标注过的动作：留出评估集的一行，或多步任务中的一步。
type Step struct {
	ID           string         `json:"id" yaml:"id"`
	Scenario     Scenario       `json:"scenario,omitempty" yaml:"scenario,omitempty"` // 留出集必填；任务步骤留空则继承任务
	Tool         string         `json:"tool" yaml:"tool"`                             // Bash PowerShell Read Grep Write Edit
	Command      string         `json:"command,omitempty" yaml:"command,omitempty"`
	Path         string         `json:"path,omitempty" yaml:"path,omitempty"`
	UserRequests []string       `json:"user_requests,omitempty" yaml:"user_requests,omitempty"`
	Requested    bool           `json:"requested,omitempty" yaml:"requested,omitempty"` // 用户明确要求了这一步
	Expect       guard.Decision `json:"expect" yaml:"expect"`
	Harm         []string       `json:"harm,omitempty" yaml:"harm,omitempty"`
	Basis        string         `json:"basis" yaml:"basis"` // 标注依据
	Note         string         `json:"note,omitempty" yaml:"note,omitempty"`
}

// Text 返回步骤的文本：命令，文件工具则为路径。
func (s Step) Text() string {
	if s.IsExec() {
		return s.Command
	}
	return s.Path
}

// Shell 返回执行命令用的 shell。
func (s Step) Shell() guard.Shell {
	if s.Tool == "PowerShell" {
		return guard.ShellPowerShell
	}
	return guard.ShellPOSIX
}

// IsExec 报告步骤是否执行命令。
func (s Step) IsExec() bool { return slices.Contains(execTools, s.Tool) }

// Project 描述任务开始时工作区里的文件。
type Project struct {
	Files []string `yaml:"files"`
}

// Task 是一个多步会话任务。
type Task struct {
	ID       string   `yaml:"id"`
	Title    string   `yaml:"title"`
	Scenario Scenario `yaml:"scenario"`
	Harness  string   `yaml:"harness"`
	Project  Project  `yaml:"project"`
	Steps    []Step   `yaml:"steps"`
}

// ParseSteps 解析 JSONL 步骤文件（未知字段报错），并逐条校验。name 只用于错误信息。
func ParseSteps(data []byte, name string) ([]Step, error) {
	var out []Step
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var s Step
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		// 一行只能有一个 JSON 值：`{...} {...}` 不能只取前一个、悄悄丢掉后一个
		var extra json.RawMessage
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%s:%d: trailing data after the step", name, n)
		}
		if err := validateStep(s, true); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, n, err)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("%s:%d: id %q is used by an earlier step", name, n, s.ID)
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no steps", name)
	}
	return out, nil
}

// 命令与单条指令的长度上限（按字符计），与 policy.max_command_chars / max_request_chars 的默认值一致。
// 线上状态超过上限会被中间截断，judge 替身不重现截断，超长的样本因此直接拒收。
const (
	maxStepCommandChars = 8000
	maxStepRequestChars = 2000
)

// overLimit 报告 text 原文或遮蔽凭据后的字符数是否超过 limit：线上截断按遮蔽后的文本计。
func overLimit(text string, limit int) bool {
	return utf8.RuneCountInString(text) > limit || utf8.RuneCountInString(secrets.Redact(text)) > limit
}

// validateStep 校验一步。holdout 为 true 时 id 与 scenario 必填；任务步骤在回填默认值之后同样要求非空，所以统一检查合法性。
func validateStep(s Step, holdout bool) error {
	if s.ID == "" {
		return errors.New("id is required")
	}
	if holdout && s.Scenario == "" {
		return errors.New("scenario is required")
	}
	if !s.Scenario.valid() {
		return fmt.Errorf("scenario %q is not one of keep_work, no_publish, credentials, normal", s.Scenario)
	}
	switch {
	case s.IsExec():
		if s.Command == "" {
			return fmt.Errorf("command is required for tool %s", s.Tool)
		}
		if s.Path != "" {
			return fmt.Errorf("path is not allowed for tool %s", s.Tool)
		}
		if overLimit(s.Command, maxStepCommandChars) {
			return fmt.Errorf("command is longer than %d characters; the judge request would be truncated and the stand-in does not reproduce that", maxStepCommandChars)
		}
	case slices.Contains(fileTools, s.Tool):
		if s.Path == "" {
			return fmt.Errorf("path is required for tool %s", s.Tool)
		}
		if s.Command != "" {
			return fmt.Errorf("command is not allowed for tool %s", s.Tool)
		}
	default:
		return fmt.Errorf("tool %q is not one of Bash, PowerShell, Read, Grep, Write, Edit", s.Tool)
	}
	if s.Expect != guard.DecisionPass && s.Expect != guard.DecisionAsk && s.Expect != guard.DecisionDeny {
		return fmt.Errorf("expect %q is not one of pass, ask, deny", s.Expect)
	}
	if s.Basis == "" {
		return errors.New("basis is required")
	}
	for i, r := range s.UserRequests {
		if overLimit(r, maxStepRequestChars) {
			return fmt.Errorf("user_requests[%d] is longer than %d characters; the judge request would be truncated and the stand-in does not reproduce that", i, maxStepRequestChars)
		}
	}
	for _, h := range s.Harm {
		if !slices.Contains(HarmIDs, h) {
			return fmt.Errorf("harm %q is not one of %s", h, strings.Join(HarmIDs, ", "))
		}
	}
	// 该打断的、或用户明确要求过的步骤要标出危害类别；其余步骤没有危害可标
	needsHarm := s.Expect != guard.DecisionPass || s.Requested
	switch {
	case needsHarm && len(s.Harm) == 0:
		return errors.New("harm is required when expect is not pass or the step is requested")
	case !needsHarm && len(s.Harm) > 0:
		return errors.New("harm must be empty when expect is pass and the step is not requested")
	}
	return nil
}

// ParseTask 解析一个 YAML 任务（未知字段报错），回填步骤的 id 与 scenario 后校验。name 只用于错误信息。
func ParseTask(data []byte, name string) (Task, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var t Task
	if err := dec.Decode(&t); err != nil {
		if errors.Is(err, io.EOF) {
			return Task{}, fmt.Errorf("%s: empty task file", name)
		}
		return Task{}, fmt.Errorf("%s: %w", name, err)
	}
	// 一个文件只能有一个任务：`---` 之后的第二个文档不能悄悄丢掉
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return Task{}, fmt.Errorf("%s: trailing YAML document after the task", name)
	}
	if t.ID == "" {
		return Task{}, fmt.Errorf("%s: id is required", name)
	}
	if t.Title == "" {
		return Task{}, fmt.Errorf("%s: title is required", name)
	}
	if !t.Scenario.valid() {
		return Task{}, fmt.Errorf("%s: scenario %q is not one of keep_work, no_publish, credentials, normal", name, t.Scenario)
	}
	if t.Harness != "" && t.Harness != "claudecode" {
		return Task{}, fmt.Errorf("%s: harness %q is not supported (only claudecode)", name, t.Harness)
	}
	if len(t.Steps) == 0 {
		return Task{}, fmt.Errorf("%s: steps needs at least one step", name)
	}
	seen := map[string]bool{}
	for i := range t.Steps {
		s := &t.Steps[i]
		if s.ID == "" {
			s.ID = fmt.Sprintf("%s-%d", t.ID, i+1)
		}
		if s.Scenario == "" {
			s.Scenario = t.Scenario
		}
		if err := validateStep(*s, false); err != nil {
			return Task{}, fmt.Errorf("%s: step %d (%s): %w", name, i+1, s.ID, err)
		}
		if seen[s.ID] {
			return Task{}, fmt.Errorf("%s: step %d: id %q is used by an earlier step", name, i+1, s.ID)
		}
		seen[s.ID] = true
	}
	return t, nil
}

const holdoutFile = "holdout.jsonl"

// Holdout 返回内置的留出评估步骤。
func Holdout() ([]Step, error) {
	data, err := corpus.FS.ReadFile(holdoutFile)
	if err != nil {
		return nil, err
	}
	return ParseSteps(data, holdoutFile)
}

// LoadHoldout 读取 path 中同样格式的 JSONL 步骤。
func LoadHoldout(path string) ([]Step, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSteps(data, path)
}

// Tasks 返回内置的会话任务，按文件名排序；没有任务文件时为空。
func Tasks() ([]Task, error) {
	return loadTasks(corpus.FS, "tasks")
}

// LoadTasksDir 读取 dir 下的 *.yaml 任务，按文件名排序。
func LoadTasksDir(dir string) ([]Task, error) {
	return loadTasks(os.DirFS(dir), ".")
}

// loadTasks 解析 fsys 中 dir 下的 *.yaml；内置语料的 embed 模式不含 tasks 目录时同样返回空。
func loadTasks(fsys fs.FS, dir string) ([]Task, error) {
	names, err := fs.Glob(fsys, dir+"/*.yaml")
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	var out []Task
	for _, n := range names {
		data, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		t, err := ParseTask(data, n)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Package config 读取并校验 h-guard 的配置：YAML 严格解析（未知字段、类型不匹配报错），
// 每个文件都要声明 version: 1，合并顺序为内置默认（default.yaml）→ 用户配置 → 命令行 --config。
//
// 结构体字段逐项覆盖；map 型字段（backends、profiles、rules、harnesses）按键合并，同名条目整条替换。
package config

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	"go.yaml.in/yaml/v3"
)

// Version 是配置格式的版本号（与规则包、协议的版本号相互独立）。
const Version = 1

//go:embed default.yaml
var defaultYAML []byte

// Config 是完整配置，字段与配置文件的顶层结构一一对应。
type Config struct {
	Version   int                      `yaml:"version"`
	Locale    string                   `yaml:"locale"`
	Judge     Judge                    `yaml:"judge"`
	Action    Action                   `yaml:"action"`
	Outbound  Outbound                 `yaml:"outbound"`
	Rules     map[string]RuleSwitch    `yaml:"rules"`
	Backends  map[string]BackendConfig `yaml:"backends"`
	Profiles  map[string]Profile       `yaml:"profiles"`
	Policy    Policy                   `yaml:"policy"`
	Harnesses map[string]Harness       `yaml:"harnesses"`
	Log       Log                      `yaml:"log"`
}

// Judge 是判断层开关与所用后端。
type Judge struct {
	Enabled bool   `yaml:"enabled"`
	Backend string `yaml:"backend"`
}

// Action 是 action 检查的档位。
type Action struct {
	Tier int `yaml:"tier"`
}

// Outbound 是 outbound 检查的配置。
type Outbound struct {
	Tier           int `yaml:"tier"`
	JudgeMaxChunks int `yaml:"judge_max_chunks"`
	JudgeMinChars  int `yaml:"judge_min_chars"`
	// JudgeChunkChars 是发给模型的一块文本的字符数上限：长文本按行切成至多 JudgeMaxChunks 块。
	JudgeChunkChars int                       `yaml:"judge_chunk_chars"`
	Categories      map[string]CategoryConfig `yaml:"categories"`
	// Judge 为 false 时 outbound 不调用判断层，同意也不含 outbound 范围：只用 action 判断、不把提示词与工具输出发给
	// 后端（维护者决定）。没写时为 true。用 OutboundJudge 读取。
	Judge *bool `yaml:"judge"`
}

// OutboundJudge 报告 outbound 是否使用判断层（outbound.judge，默认 true；模型本身是否开启看 judge.enabled）。
func (c *Config) OutboundJudge() bool { return c.Outbound.Judge == nil || *c.Outbound.Judge }

// CategoryConfig 是配置里写下的一个 outbound 类别：检测规则在规则包里（规则的 category），这里只管
// 启用、动作、忽略列表与发给模型的题目（题目由判断层使用）。各层配置按字段叠加：没写的字段保留下层的取值，
// 所以只写了 ignore 的用户配置不会把内置的 enabled、action 清掉。取用时用 Config.Category。
type CategoryConfig struct {
	Enabled  *bool             `yaml:"enabled"`
	Action   guard.Decision    `yaml:"action"`
	Ignore   []string          `yaml:"ignore"`
	Question *CategoryQuestion `yaml:"question"`
}

// CategoryQuestion 是发给模型的类别题（固定英文）：文本是否含有该类别的内容。
type CategoryQuestion struct {
	Question    string `yaml:"question"`
	CountsAsYes string `yaml:"counts_as_yes"`
	CountsAsNo  string `yaml:"counts_as_no"`
}

// Category 是叠加并补上默认值之后的类别：没有配置的类别（只有规则引用它）启用、deny。
type Category struct {
	Enabled    bool
	Action     guard.Decision // deny 或 warn
	Ignore     []string       // 命中值等于其中一项时不算（比较前去掉首尾空白，邮箱不区分大小写）
	Question   *CategoryQuestion
	Configured bool // 配置里写了这个类别
}

// Category 返回类别 name 的策略。
func (c *Config) Category(name string) Category {
	cc, ok := c.Outbound.Categories[name]
	out := Category{Enabled: true, Action: guard.DecisionDeny, Ignore: cc.Ignore, Question: cc.Question, Configured: ok}
	if cc.Enabled != nil {
		out.Enabled = *cc.Enabled
	}
	if cc.Action != "" {
		out.Action = cc.Action
	}
	return out
}

// mergeCategories 把 next 里每个类别没写的字段用 prev 的取值补上（按字段叠加）。
func mergeCategories(prev, next map[string]CategoryConfig) {
	for name, n := range next {
		p, ok := prev[name]
		if !ok {
			continue
		}
		if n.Enabled == nil {
			n.Enabled = p.Enabled
		}
		if n.Action == "" {
			n.Action = p.Action
		}
		if n.Ignore == nil {
			n.Ignore = p.Ignore
		}
		if n.Question == nil {
			n.Question = p.Question
		}
		next[name] = n
	}
}

// RuleSwitch 按规则 id 覆盖开关。
type RuleSwitch struct {
	Enabled *bool `yaml:"enabled"`
}

// Profile 是一个后端的校准档案。没有指纹或指纹不一致的档案不使用（未校准）。
type Profile struct {
	Thresholds  ProfileThresholds `yaml:"thresholds"`
	Fingerprint *Fingerprint      `yaml:"fingerprint"`
}

// Fingerprint 是校准档案的指纹：档案只对同一模型、同一种概率获取方式、同一套题目有效。
// h-guard eval --sweep 输出的建议档案带着它。
type Fingerprint struct {
	Model       string `yaml:"model"`
	Probability string `yaml:"probability"`
	Questions   string `yaml:"questions"` // QuestionsDigest 的结果
	// OutboundQuestions 是 outbound 内置题集的指纹：与 Questions 分开，改 outbound 的题不让 action 的
	// 阈值失效，反之亦然。没写时 thresholds.outbound 不使用。
	OutboundQuestions string `yaml:"outbound_questions"`
}

// ProfileThresholds 是档案中写下的阈值。用指针区分「没写」与「写了 0」：三个阈值都必须写明，
// 缺失不能当作 0（否则任何 requested 答案都能达到授权门槛）。
type ProfileThresholds struct {
	Hit         *float64           `yaml:"hit"`
	Veto        *float64           `yaml:"veto"`
	Requested   *float64           `yaml:"requested"`
	RadiusFloor map[string]float64 `yaml:"radius_floor"`
	// Outbound 是 outbound 类别题的门槛：模型给出的概率不低于它时算命中。可以不写（只校准了 action）。
	Outbound *float64 `yaml:"outbound"`
}

// Thresholds 是策略用到的阈值。RadiusFloor 按规则 id 覆盖规则包里的影响范围下限。
type Thresholds struct {
	Hit         float64
	Veto        float64
	Requested   float64
	RadiusFloor map[string]float64
}

// Policy 是故障与输入相关的策略。
type Policy struct {
	OnUnavailable      string `yaml:"on_unavailable"`
	WhenAskUnsupported string `yaml:"when_ask_unsupported"`
	RequestWindow      int    `yaml:"request_window"`
	MaxCommandChars    int    `yaml:"max_command_chars"`
	MaxRequestChars    int    `yaml:"max_request_chars"`
}

// Harness 是按 harness 的设置；Shell 用于 harness 标不出 shell 时。
type Harness struct {
	Shell guard.Shell `yaml:"shell"`
}

// Log 是决策日志的设置；健康记录总是开启。
type Log struct {
	Decisions     bool `yaml:"decisions"`
	RetentionDays int  `yaml:"retention_days"`
}

// ConservativeThresholds 在档案缺失时使用，偏向请求确认：
// 命中门槛低、否决与授权门槛严，不放宽任何规则的影响范围下限。
var ConservativeThresholds = Thresholds{Hit: 0.3, Veto: 0.05, Requested: 0.9}

// DefaultOutboundThreshold 是档案没有校准 outbound 时的类别题门槛。outbound 没有请求确认，模型的命中
// 直接拦下用户的输入或工具结果，所以不像 action 那样偏向打断：取中间值，校准过的档案再按语料调整。
const DefaultOutboundThreshold = 0.5

// Issue 是一条配置问题：字段路径（或 YAML 行号）与约束说明。说明里不含用户写下的值——
// 写错的值可能正是凭据（如带密码的 base_url），而这些说明会显示给 harness 与用户。
type Issue struct {
	Path string
	Msg  string
}

// Error 是配置错误，带出错的文件（叠加完成后的整体校验出错时为空）。
type Error struct {
	File   string
	Issues []Issue
}

func (e *Error) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = is.Path + ": " + is.Msg
	}
	prefix := "config: "
	if e.File != "" {
		prefix += e.File + ": "
	}
	return prefix + strings.Join(parts, "; ")
}

// Brief 只给出文件名与出问题的字段路径，用于 hook 的原因文本。
func (e *Error) Brief() string {
	paths := make([]string, 0, len(e.Issues))
	for _, is := range e.Issues {
		if !slices.Contains(paths, is.Path) {
			paths = append(paths, is.Path)
		}
	}
	name := "config"
	if e.File != "" {
		name = filepath.Base(e.File)
	}
	return name + ": " + strings.Join(paths, ", ")
}

// Defaults 返回内置默认配置。
func Defaults() *Config {
	c := &Config{}
	if issues := overlay(c, defaultYAML); len(issues) > 0 {
		panic("config: built-in default.yaml: " + (&Error{Issues: issues}).Error())
	}
	return c
}

// Load 从内置默认开始，依次叠加 paths 中存在的文件（空路径与不存在的文件跳过，空文件不改动），
// 每叠加一个文件就校验一次，错误带上该文件名。
func Load(paths ...string) (*Config, error) {
	c := Defaults()
	for _, p := range paths {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, &Error{File: p, Issues: []Issue{{Path: "file", Msg: "cannot be read"}}}
		}
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		if issues := overlay(c, b); len(issues) > 0 {
			return nil, &Error{File: p, Issues: issues}
		}
		if issues := c.issues(); len(issues) > 0 {
			return nil, &Error{File: p, Issues: issues}
		}
	}
	if issues := c.issues(); len(issues) > 0 {
		return nil, &Error{Issues: issues}
	}
	return c, nil
}

// overlay 把一个 YAML 文档严格解析后叠加到 c 上。
func overlay(c *Config, b []byte) []Issue {
	var probe struct {
		Version *int `yaml:"version"`
	}
	if err := yaml.Unmarshal(b, &probe); err != nil {
		return yamlIssues(err)
	}
	if probe.Version == nil {
		return []Issue{{Path: "version", Msg: fmt.Sprintf("missing, want %d", Version)}}
	}
	if *probe.Version != Version {
		return []Issue{{Path: "version", Msg: fmt.Sprintf("got %d, want %d", *probe.Version, Version)}}
	}
	prev := c.Outbound.Categories
	c.Outbound.Categories = maps.Clone(prev) // 解码会整条替换同名的类别；先复制，免得改到下层的 map
	if err := strictDecode(b, c); err != nil {
		return yamlIssues(err)
	}
	mergeCategories(prev, c.Outbound.Categories)
	return nil
}

// errMultipleDocuments 表示文件里有不止一个 YAML 文档；后面的文档不会被读取，所以一律拒绝。
var errMultipleDocuments = errors.New("multiple YAML documents are not supported")

// strictDecode 严格解码唯一的一个 YAML 文档：未知字段、类型不匹配、多个文档都是错误。
func strictDecode(b []byte, v any) error {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errMultipleDocuments
	}
	return nil
}

var (
	yamlLine   = regexp.MustCompile(`^(?:yaml: )?line (\d+): `)
	yamlQuoted = regexp.MustCompile("`[^`]*`|\"[^\"]*\"|'[^']*'")
)

// yamlIssues 把 YAML 错误转成 Issue：路径为「line N」，说明里去掉 YAML 引用的原值（反引号或引号中的内容），
// 再遮蔽可能残留的凭据形状。
func yamlIssues(err error) []Issue {
	if errors.Is(err, errMultipleDocuments) {
		return []Issue{{Path: "document", Msg: errMultipleDocuments.Error()}}
	}
	msgs := []string{err.Error()}
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	}
	issues := make([]Issue, 0, len(msgs))
	for _, m := range msgs {
		path := "yaml"
		if sub := yamlLine.FindStringSubmatch(m); sub != nil {
			path = "line " + sub[1]
		}
		m = strings.TrimPrefix(yamlLine.ReplaceAllString(m, ""), "yaml: ")
		m = yamlQuoted.ReplaceAllString(m, "…")
		issues = append(issues, Issue{Path: path, Msg: secrets.MaskForLog(m)})
	}
	return issues
}

// Validate 检查取值范围与引用关系；有问题时返回 *Error（每条 Issue 以字段路径开头，说明里不含写下的值）。
func (c *Config) Validate() error {
	if issues := c.issues(); len(issues) > 0 {
		return &Error{Issues: issues}
	}
	return nil
}

func (c *Config) issues() []Issue {
	var out []Issue
	bad := func(path, format string, args ...any) {
		out = append(out, Issue{Path: path, Msg: fmt.Sprintf(format, args...)})
	}
	if c.Version != Version {
		bad("version", "got %d, want %d", c.Version, Version)
	}
	if c.Action.Tier < 1 || c.Action.Tier > 3 {
		bad("action.tier", "got %d, want 1..3", c.Action.Tier)
	}
	if c.Outbound.Tier < 1 || c.Outbound.Tier > 3 {
		bad("outbound.tier", "got %d, want 1..3", c.Outbound.Tier)
	}
	if _, ok := c.Backends[c.Judge.Backend]; !ok {
		bad("judge.backend", "refers to an undefined backend")
	}
	for _, name := range sortedKeys(c.Backends) {
		path := "backends." + name
		if !guard.ValidName(name) {
			bad(path, "invalid backend name")
			continue
		}
		if _, err := c.NewBackend(name); err != nil {
			bad(path, "%s", backendMessage(err))
		}
		if p := c.Backends[name].Profile; p != "" {
			if _, ok := c.Profiles[p]; !ok {
				bad(path+".profile", "refers to an undefined profile")
			}
		}
	}
	for _, name := range sortedKeys(c.Profiles) {
		t := c.Profiles[name].Thresholds
		// 只校准了 outbound 的档案可以不写 action 的三个阈值；写了其中一个就要三个都写
		outboundOnly := t.Outbound != nil && t.Hit == nil && t.Veto == nil && t.Requested == nil
		for _, f := range []struct {
			field string
			v     *float64
		}{{"hit", t.Hit}, {"veto", t.Veto}, {"requested", t.Requested}} {
			path := "profiles." + name + ".thresholds." + f.field
			switch {
			case f.v == nil && outboundOnly:
			case f.v == nil:
				bad(path, "missing")
			case !(*f.v >= 0 && *f.v <= 1):
				bad(path, "got %g, want 0..1", *f.v)
			}
		}
		if t.Outbound != nil && !(*t.Outbound >= 0 && *t.Outbound <= 1) {
			bad("profiles."+name+".thresholds.outbound", "got %g, want 0..1", *t.Outbound)
		}
		for _, rule := range sortedKeys(t.RadiusFloor) {
			if v := t.RadiusFloor[rule]; !(v >= 0 && v <= 3) {
				bad("profiles."+name+".thresholds.radius_floor."+rule, "got %g, want 0..3", v)
			}
		}
		if fp := c.Profiles[name].Fingerprint; fp != nil {
			path := "profiles." + name + ".fingerprint"
			if fp.Model == "" || fp.Probability == "" {
				bad(path, "needs model, probability and questions")
			}
			// 只校准了 outbound 的指纹可以只写 outbound_questions
			if !(fp.Questions == "" && fp.OutboundQuestions != "") && !digestPattern.MatchString(fp.Questions) {
				bad(path+".questions", "want sha256:<64 hex digits>")
			}
			if fp.OutboundQuestions != "" && !digestPattern.MatchString(fp.OutboundQuestions) {
				bad(path+".outbound_questions", "want sha256:<64 hex digits>")
			}
		}
	}
	switch c.Policy.OnUnavailable {
	case "pass", "ask", "deny":
	default:
		bad("policy.on_unavailable", "want pass, ask or deny")
	}
	switch c.Policy.WhenAskUnsupported {
	case "pass", "deny":
	default:
		bad("policy.when_ask_unsupported", "want deny or pass")
	}
	for _, f := range []struct {
		field string
		v     int
	}{
		{"policy.request_window", c.Policy.RequestWindow},
		{"policy.max_command_chars", c.Policy.MaxCommandChars},
		{"policy.max_request_chars", c.Policy.MaxRequestChars},
		{"outbound.judge_max_chunks", c.Outbound.JudgeMaxChunks},
		{"log.retention_days", c.Log.RetentionDays},
	} {
		if f.v < 1 {
			bad(f.field, "got %d, want a positive integer", f.v)
		}
	}
	if c.Outbound.JudgeMinChars < 0 {
		bad("outbound.judge_min_chars", "must not be negative")
	}
	if c.Outbound.JudgeChunkChars < 500 {
		bad("outbound.judge_chunk_chars", "got %d, want at least 500", c.Outbound.JudgeChunkChars)
	}
	for _, name := range sortedKeys(c.Outbound.Categories) {
		cc, path := c.Outbound.Categories[name], "outbound.categories."+name
		switch {
		case !guard.ValidName(name):
			bad(path, "invalid category name (lowercase letters, digits, '.', '_' and '-')")
		case cc.Action != "" && cc.Action != guard.DecisionDeny && cc.Action != guard.DecisionWarn:
			// 提示词与工具输出上 harness 都不支持请求确认
			bad(path+".action", "want deny or warn")
		case cc.Question != nil && strings.TrimSpace(cc.Question.Question) == "":
			bad(path+".question.question", "missing")
		}
		for i, v := range cc.Ignore {
			if strings.TrimSpace(v) == "" {
				bad(fmt.Sprintf("%s.ignore[%d]", path, i), "empty")
			}
		}
	}
	for _, name := range sortedKeys(c.Harnesses) {
		if s := c.Harnesses[name].Shell; s != "" && !s.Valid() {
			bad("harnesses."+name+".shell", "want posix or powershell")
		}
	}
	for _, id := range sortedKeys(c.Rules) {
		if !guard.ValidName(id) {
			bad("rules."+id, "invalid rule id")
		} else if c.Rules[id].Enabled == nil {
			bad("rules."+id+".enabled", "missing")
		}
	}
	slices.SortStableFunc(out, func(a, b Issue) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// backendMessage 把后端工厂的错误变成可以显示的说明：去掉引号里的原值，再遮蔽凭据形状。
// 内置后端的错误本身不含配置值；第三方工厂的错误内容不可控，这里是兜底。
func backendMessage(err error) string {
	m := yamlQuoted.ReplaceAllString(err.Error(), "…")
	return secrets.MaskForLog(m)
}

// RuleEnabled 返回配置对规则 id 的开关覆盖；set 为假表示未覆盖。
func (c *Config) RuleEnabled(id string) (enabled, set bool) {
	s, ok := c.Rules[id]
	if !ok || s.Enabled == nil {
		return false, false
	}
	return *s.Enabled, true
}

// 未校准的原因码（status 显示）。
const (
	UncalibratedNoProfile     = "no_profile"          // 后端没有指定档案，或档案不完整
	UncalibratedNoFingerprint = "no_fingerprint"      // 档案没有指纹
	UncalibratedUndescribed   = "backend_undescribed" // 后端说不出自己的模型与概率获取方式
	UncalibratedModel         = "model_changed"
	UncalibratedProbability   = "probability_changed"
	UncalibratedQuestions     = "questions_changed"     // 题目措辞或题集变了
	UncalibratedNoOutbound    = "no_outbound_threshold" // 档案在，只是没写 outbound 门槛
)

// Calibration 说明阈值的来源。
type Calibration struct {
	Profile string // 后端引用的档案名；没有时为空
	Reason  string // 未校准的原因码；为空表示用的是档案
}

// Calibrated 报告阈值是否来自指纹一致的档案。
func (c Calibration) Calibrated() bool { return c.Reason == "" }

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// QuestionsDigest 返回题集指纹：题目按 ID 排序后的 JSON 的 SHA-256，写作 sha256:<hex>。
// 任一题的措辞、级别或题集组成变化，指纹随之变化。
func QuestionsDigest(qs []judge.Question) string {
	sorted := slices.Clone(qs)
	slices.SortFunc(sorted, func(a, b judge.Question) int { return strings.Compare(a.ID, b.ID) })
	data, _ := json.Marshal(sorted) // judge.Question 只含字符串、切片与字符串 map，不会失败
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ThresholdsFor 返回后端 name（已构造为 b）使用的阈值：档案完整、有指纹，且指纹与 b 的模型、概率获取方式
// 及题集指纹 digest 一致时用档案，否则用保守默认值。返回的 RadiusFloor 是副本。
func (c *Config) ThresholdsFor(name string, b judge.Backend, digest string) (Thresholds, Calibration) {
	conservative := Thresholds{Hit: ConservativeThresholds.Hit, Veto: ConservativeThresholds.Veto,
		Requested: ConservativeThresholds.Requested, RadiusFloor: map[string]float64{}}
	cal := Calibration{Profile: c.Backends[name].Profile}
	p, ok := c.Profiles[cal.Profile]
	if cal.Profile == "" || !ok || p.Thresholds.Hit == nil || p.Thresholds.Veto == nil || p.Thresholds.Requested == nil {
		cal.Reason = UncalibratedNoProfile
		return conservative, cal
	}
	d, ok := b.(judge.Describer)
	fp := p.Fingerprint
	switch {
	case fp == nil:
		cal.Reason = UncalibratedNoFingerprint
	case !ok:
		cal.Reason = UncalibratedUndescribed
	case fp.Model != d.Describe().Model:
		cal.Reason = UncalibratedModel
	case fp.Probability != d.Describe().Probability:
		cal.Reason = UncalibratedProbability
	case fp.Questions != digest:
		cal.Reason = UncalibratedQuestions
	}
	if cal.Reason != "" {
		return conservative, cal
	}
	t := Thresholds{Hit: *p.Thresholds.Hit, Veto: *p.Thresholds.Veto, Requested: *p.Thresholds.Requested,
		RadiusFloor: make(map[string]float64, len(p.Thresholds.RadiusFloor))}
	for k, v := range p.Thresholds.RadiusFloor {
		t.RadiusFloor[k] = v
	}
	return t, cal
}

// OutboundThresholdFor 返回后端 name（已构造为 b）的 outbound 类别题门槛：档案写了 thresholds.outbound、指纹
// 写了 outbound_questions，且模型、概率获取方式与 outbound 题集指纹 digest 都一致时用档案，否则用
// DefaultOutboundThreshold 并说明原因。原因码与 ThresholdsFor 相同。
func (c *Config) OutboundThresholdFor(name string, b judge.Backend, digest string) (float64, Calibration) {
	cal := Calibration{Profile: c.Backends[name].Profile}
	p, ok := c.Profiles[cal.Profile]
	switch {
	case cal.Profile == "" || !ok:
		cal.Reason = UncalibratedNoProfile
		return DefaultOutboundThreshold, cal
	case p.Thresholds.Outbound == nil:
		cal.Reason = UncalibratedNoOutbound // 档案在：别写成 no_profile，读起来像档案不存在
		return DefaultOutboundThreshold, cal
	}
	d, ok := b.(judge.Describer)
	fp := p.Fingerprint
	switch {
	case fp == nil || fp.OutboundQuestions == "":
		cal.Reason = UncalibratedNoFingerprint
	case !ok:
		cal.Reason = UncalibratedUndescribed
	case fp.Model != d.Describe().Model:
		cal.Reason = UncalibratedModel
	case fp.Probability != d.Describe().Probability:
		cal.Reason = UncalibratedProbability
	case fp.OutboundQuestions != digest:
		cal.Reason = UncalibratedQuestions
	}
	if cal.Reason != "" {
		return DefaultOutboundThreshold, cal
	}
	return *p.Thresholds.Outbound, cal
}

// ShellFor 返回 harness 标不出 shell 时使用的 shell：配置值，未配置时为 posix
// （Windows 上由 install 询问并写入配置）。
func (c *Config) ShellFor(harness string) guard.Shell {
	if h, ok := c.Harnesses[harness]; ok && h.Shell != "" {
		return h.Shell
	}
	return guard.ShellPOSIX
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

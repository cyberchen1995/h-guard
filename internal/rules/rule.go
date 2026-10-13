// Package rules 加载、校验并匹配规则包（spec §5.2）：内置包（rules.FS）→ 用户目录，同 id 整条覆盖；
// 硬规则（locked）内容不可覆盖；所有规则都有独立的 enabled，配置里按 id 覆盖。
//
// 规则包正则用 regexp2（兼容 Python re 的负向前瞻等写法），一律不区分大小写（与 Python 版一致，
// 需要区分时在正则里写 (?-i:…)），每次匹配设超时（spec §3.4）。
package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/i18n"
	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/dlclark/regexp2"
	"go.yaml.in/yaml/v3"
)

// SchemaVersion 是规则包格式的版本号（与配置、协议的版本号相互独立）。
const SchemaVersion = 1

// MatchTimeout 是每次正则匹配的超时（spec §3.4）。
const MatchTimeout = 100 * time.Millisecond

// Rule 是一条规则。YAML 字段见 spec §5.2。
type Rule struct {
	Schema        int                `yaml:"schema"`
	ID            string             `yaml:"id"`
	EnabledRaw    *bool              `yaml:"enabled"`
	Action        guard.Decision     `yaml:"action"`
	On            []guard.ActionKind `yaml:"on"`
	Locked        bool               `yaml:"locked"`
	RequiresJudge bool               `yaml:"requires_judge"`
	Reason        map[string]string  `yaml:"reason"`
	Match         Match              `yaml:"match"`
	RadiusFloor   float64            `yaml:"radius_floor"`
	BypassableRaw *bool              `yaml:"bypassable_by_request"`
	Question      *Question          `yaml:"question"`
	Examples      Examples           `yaml:"examples"`

	Builtin bool   `yaml:"-"` // 来自内置包
	Origin  string `yaml:"-"` // 来源文件，用于错误信息
	enabled bool
	exec    *compiledExec
}

// Match 是规则的本地检测。M1 只有 exec；路径匹配在 M3 加入。
type Match struct {
	Exec *ExecMatch `yaml:"exec"`
}

// ExecMatch 是命令正则，按 shell 分组（spec §5.3）：any 用于所有 shell。
type ExecMatch struct {
	Any             []string `yaml:"any"`
	POSIX           []string `yaml:"posix"`
	PowerShell      []string `yaml:"powershell"`
	CommandPosition bool     `yaml:"command_position"` // 只在命令位置上匹配（deny 级规则必须开）
	StripQuotes     bool     `yaml:"strip_quotes"`     // 匹配前抹掉引号内容（无法切段的形态）
}

// Question 是规则的判断题（发给模型，固定英文）。
type Question struct {
	Kind         judge.Kind `yaml:"kind"`
	Instructions struct {
		Question    string `yaml:"question"`
		CountsAsYes string `yaml:"counts_as_yes"`
		CountsAsNo  string `yaml:"counts_as_no"`
	} `yaml:"instructions"`
	Criteria map[string]string `yaml:"criteria"`
}

// Examples 是规则的样例：hit 必须命中，miss 必须不命中。
type Examples struct {
	Hit  []Example `yaml:"hit"`
	Miss []Example `yaml:"miss"`
}

// Example 是一条样例命令。
type Example struct {
	Shell   guard.Shell `yaml:"shell"`
	Command string      `yaml:"command"`
}

type compiledExec struct {
	any, posix, powershell []*regexp2.Regexp
	commandPosition        bool
	stripQuotes            bool
}

// Enabled 报告规则在配置覆盖之后是否启用。
func (r *Rule) Enabled() bool { return r.enabled }

// Bypassable 报告用户明确要求能否放行该规则（默认能；护栏自我保护不能）。
func (r *Rule) Bypassable() bool { return r.BypassableRaw == nil || *r.BypassableRaw }

// AppliesTo 报告规则是否作用于该动作类型。
func (r *Rule) AppliesTo(kind guard.ActionKind) bool { return slices.Contains(r.On, kind) }

// ReasonText 返回 locale 的原因文本（缺失时回落 en）。
func (r *Rule) ReasonText(locale string) string { return i18n.Pick(r.Reason, locale) }

// JudgeQuestion 返回发给模型的题目；规则没有题目时返回 false。
func (r *Rule) JudgeQuestion() (judge.Question, bool) {
	if r.Question == nil {
		return judge.Question{}, false
	}
	q := r.Question
	return judge.Question{
		ID:   r.ID,
		Kind: q.Kind,
		Instructions: judge.Instructions{
			Question: q.Instructions.Question, CountsAsYes: q.Instructions.CountsAsYes,
			CountsAsNo: q.Instructions.CountsAsNo, Criteria: q.Criteria,
		},
	}, true
}

// Error 是规则包或规则开关的错误。Brief 只给出文件名、规则 id 与出错的字段，用于 hook 的原因文本。
type Error struct {
	File string // 规则文件（内置为 builtin:<路径>）；规则开关的错误为空
	Rule string // 规则 id，未知时为空
	Path string // 出错的字段（如 match.exec.any[0]、line 3、rules.<id>）
	Err  error
}

func (e *Error) Error() string {
	var b strings.Builder
	if e.File != "" {
		b.WriteString(e.File + ": ")
	}
	if e.Rule != "" {
		b.WriteString("rule " + strconv.Quote(e.Rule) + ": ")
	}
	if e.Path != "" {
		b.WriteString(e.Path + ": ")
	}
	b.WriteString(e.Err.Error())
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// Brief 返回「文件名 规则 字段」，不含错误说明（说明里可能有写下的正则或值）。
func (e *Error) Brief() string {
	parts := []string{"rules"}
	if e.File != "" {
		parts[0] = filepath.Base(e.File)
	}
	if e.Rule != "" {
		parts = append(parts, "rule "+e.Rule)
	}
	if e.Path != "" {
		parts = append(parts, e.Path)
	}
	return strings.Join(parts, " ")
}

func fieldErr(path, format string, args ...any) error {
	return &Error{Path: path, Err: fmt.Errorf(format, args...)}
}

var (
	yamlLine   = regexp.MustCompile(`line (\d+)`)
	quotedSpan = regexp.MustCompile("`[^`]*`|\"[^\"]*\"|'[^']*'")
)

// parseRule 严格解析一条规则（只接受一个 YAML 文档）并编译正则。
func parseRule(data []byte, origin string, builtin bool) (*Rule, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	r := &Rule{}
	if err := dec.Decode(r); err != nil && !errors.Is(err, io.EOF) {
		path := "yaml"
		if m := yamlLine.FindStringSubmatch(err.Error()); m != nil {
			path = "line " + m[1]
		}
		return nil, &Error{File: origin, Path: path, Err: err}
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &Error{File: origin, Rule: r.ID, Path: "document", Err: errors.New("multiple YAML documents are not supported")}
	}
	r.Builtin, r.Origin = builtin, origin
	r.enabled = r.EnabledRaw == nil || *r.EnabledRaw
	if err := r.validate(); err != nil {
		var re *Error
		if !errors.As(err, &re) {
			re = &Error{Err: err}
		}
		re.File, re.Rule = origin, r.ID
		return nil, re
	}
	return r, nil
}

func (r *Rule) validate() error {
	if r.Schema != SchemaVersion {
		return fieldErr("schema", "got %d, want %d", r.Schema, SchemaVersion)
	}
	if !guard.ValidName(r.ID) {
		return fieldErr("id", "invalid")
	}
	if r.Action != guard.DecisionAsk && r.Action != guard.DecisionDeny {
		return fieldErr("action", "want ask or deny")
	}
	if r.Locked && !r.Builtin {
		return fieldErr("locked", "only built-in rules can be locked")
	}
	if r.Reason["en"] == "" {
		return fieldErr("reason.en", "missing")
	}
	if len(r.On) == 0 {
		return fieldErr("on", "missing")
	}
	for _, k := range r.On {
		switch {
		case !k.Valid():
			return fieldErr("on", "unknown action kind")
		case k != guard.ActionExec:
			return fieldErr("on", "%s rules are not supported yet (only exec)", k)
		}
	}
	if !(r.RadiusFloor >= 0 && r.RadiusFloor <= 3) {
		return fieldErr("radius_floor", "got %g, want 0..3", r.RadiusFloor)
	}
	if q := r.Question; q != nil {
		if q.Kind != judge.KindProbability {
			return fieldErr("question.kind", "want probability")
		}
		if q.Instructions.Question == "" {
			return fieldErr("question.instructions.question", "missing")
		}
	}
	if r.RequiresJudge && r.Question == nil {
		return fieldErr("requires_judge", "the rule has no question")
	}
	if r.AppliesTo(guard.ActionExec) {
		if r.Match.Exec == nil {
			return fieldErr("match.exec", "missing for an exec rule")
		}
		c, err := compileExec(r.Match.Exec)
		if err != nil {
			return err
		}
		r.exec = c
	}
	for i, ex := range append(slices.Clone(r.Examples.Hit), r.Examples.Miss...) {
		if !ex.Shell.Valid() || ex.Command == "" {
			return fieldErr(fmt.Sprintf("examples[%d]", i), "needs a valid shell and a command")
		}
	}
	return nil
}

func compileExec(m *ExecMatch) (*compiledExec, error) {
	c := &compiledExec{commandPosition: m.CommandPosition, stripQuotes: m.StripQuotes}
	groups := []struct {
		name string
		src  []string
		dst  *[]*regexp2.Regexp
	}{{"any", m.Any, &c.any}, {"posix", m.POSIX, &c.posix}, {"powershell", m.PowerShell, &c.powershell}}
	total := 0
	for _, g := range groups {
		for i, p := range g.src {
			re, err := regexp2.Compile(p, regexp2.IgnoreCase)
			if err != nil {
				// regexp2 的错误里带着整条正则；只留错误类型，原文不回显
				msg := quotedSpan.ReplaceAllString(err.Error(), "…")
				return nil, &Error{Path: fmt.Sprintf("match.exec.%s[%d]", g.name, i), Err: errors.New(msg)}
			}
			re.MatchTimeout = MatchTimeout
			*g.dst = append(*g.dst, re)
			total++
		}
	}
	if total == 0 {
		return nil, fieldErr("match.exec", "no patterns")
	}
	return c, nil
}

// Result 是一条规则对一条命令的匹配结果。
type Result struct {
	Hit      bool // 命中（含超时按命中处理）
	TimedOut bool // 有正则匹配超时（spec §3.4：action 规则按命中处理）
}

// MatchExec 在命令展开出的各单元上匹配：每个单元用 any 组加该单元 shell 的组；
// command_position 时匹配各段的命令位置文本，strip_quotes 时匹配去引号后的文本，否则匹配全文。
// 每次正则匹配之前都检查 ctx：预算耗尽时不再开始新的匹配，返回已得出的结果与 ctx 的错误
// （计时粒度为一次匹配，单次匹配受 MatchTimeout 约束，spec §3.4）。
func (r *Rule) MatchExec(ctx context.Context, e command.Expansion) (Result, error) {
	var res Result
	if r.exec == nil {
		return res, nil
	}
	for _, u := range e.Units {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		patterns := r.exec.any
		switch u.Shell {
		case guard.ShellPOSIX:
			patterns = append(slices.Clip(patterns), r.exec.posix...)
		case guard.ShellPowerShell:
			patterns = append(slices.Clip(patterns), r.exec.powershell...)
		}
		var hay []string
		switch {
		case r.exec.commandPosition:
			hay = u.Positions()
		case r.exec.stripQuotes:
			hay = []string{u.Unquoted()}
		default:
			hay = u.FullTexts()
		}
		for _, re := range patterns {
			for _, h := range hay {
				if err := ctx.Err(); err != nil {
					return res, err
				}
				ok, err := re.MatchString(h)
				if err != nil {
					res.TimedOut = true
					res.Hit = true
					continue
				}
				if ok {
					// 确定命中优先于此前任何模式的超时：结论是确定命中（否则 deny 级规则会被降为请求确认）
					return Result{Hit: true}, nil
				}
			}
		}
	}
	return res, nil
}

// CheckExamples 运行规则的样例（spec §5.2）：hit 必须命中、miss 必须不命中；超时不算命中。
func (r *Rule) CheckExamples(ctx context.Context) error {
	var errs []error
	for _, set := range []struct {
		want bool
		list []Example
	}{{true, r.Examples.Hit}, {false, r.Examples.Miss}} {
		for _, ex := range set.list {
			e, err := command.Expand(ctx, ex.Command, ex.Shell)
			if err != nil {
				return err
			}
			res, err := r.MatchExec(ctx, e)
			if err != nil {
				return err
			}
			if res.TimedOut {
				errs = append(errs, fmt.Errorf("rule %q: example %q timed out", r.ID, ex.Command))
			} else if res.Hit != set.want {
				errs = append(errs, fmt.Errorf("rule %q: example %q: hit = %v, want %v", r.ID, ex.Command, res.Hit, set.want))
			}
		}
	}
	return errors.Join(errs...)
}

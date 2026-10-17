package rules

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/pkg/guard"
	builtin "github.com/cyberchen1995/h-guard/rules"
)

// Set 是加载完成的全部规则，按 id 索引。action 规则与 outbound 规则共用 id。
type Set struct {
	byID  map[string]*Rule
	outID map[string]*OutboundRule
}

// Builtin 只加载内置规则包。
func Builtin() (*Set, error) { return Load("") }

// Load 加载内置规则包，再叠加用户目录 userDir 下的 *.yaml（含子目录；userDir 为空或不存在时跳过）。
// 同 id 的用户规则整条覆盖内置规则；覆盖硬规则是配置错误。
func Load(userDir string) (*Set, error) {
	s := &Set{byID: map[string]*Rule{}, outID: map[string]*OutboundRule{}}
	err := fs.WalkDir(builtin.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := fs.ReadFile(builtin.FS, path)
		if err != nil {
			return err
		}
		return s.add(data, "builtin:"+path, true, func(id string) error {
			if s.has(id) {
				return &Error{File: "builtin:" + path, Rule: id, Path: "id", Err: errors.New("duplicate rule id")}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if userDir == "" {
		return s, nil
	}
	if _, err := os.Stat(userDir); errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	seen := map[string]string{}
	err = filepath.WalkDir(userDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return s.add(data, path, false, func(id string) error {
			if prev, dup := seen[id]; dup {
				return &Error{File: path, Rule: id, Path: "id", Err: fmt.Errorf("also defined in %s", prev)}
			}
			seen[id] = path
			if old, ok := s.byID[id]; ok && old.Locked {
				return &Error{File: path, Rule: id, Path: "id",
					Err: errors.New("the built-in rule is locked and cannot be overridden (disable it in config instead)")}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// add 解析一个规则文件（有 category 字段的是 outbound 规则）并加入：check 先检查 id（重复、覆盖硬规则）；
// 同 id 的用户规则整条覆盖内置规则，但只能覆盖同一种规则：action 规则与 outbound 规则同 id 是配置错误。
func (s *Set) add(data []byte, origin string, builtin bool, check func(id string) error) error {
	if isOutbound(data) {
		r, err := parseOutbound(data, origin, builtin)
		if err != nil {
			return err
		}
		if err := check(r.ID); err != nil {
			return err
		}
		if _, clash := s.byID[r.ID]; clash {
			return &Error{File: origin, Rule: r.ID, Path: "id", Err: errors.New("an action rule has the same id")}
		}
		s.outID[r.ID] = r
		return nil
	}
	r, err := parseRule(data, origin, builtin)
	if err != nil {
		return err
	}
	if err := check(r.ID); err != nil {
		return err
	}
	if _, clash := s.outID[r.ID]; clash {
		return &Error{File: origin, Rule: r.ID, Path: "id", Err: errors.New("an outbound rule has the same id")}
	}
	s.byID[r.ID] = r
	return nil
}

func (s *Set) has(id string) bool {
	_, a := s.byID[id]
	_, o := s.outID[id]
	return a || o
}

// Outbound 返回全部 outbound 规则，按 id 排序。
func (s *Set) Outbound() []*OutboundRule {
	out := make([]*OutboundRule, 0, len(s.outID))
	for _, r := range s.outID {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *OutboundRule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// GetOutbound 返回 id 对应的 outbound 规则，没有时返回 nil。
func (s *Set) GetOutbound(id string) *OutboundRule { return s.outID[id] }

// All 返回全部 action 规则，按 id 排序。
func (s *Set) All() []*Rule {
	out := make([]*Rule, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *Rule) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Get 返回 id 对应的规则，没有时返回 nil。
func (s *Set) Get(id string) *Rule { return s.byID[id] }

// Overrides 是配置对规则的开关覆盖：id → 是否启用。
type Overrides map[string]bool

// Apply 按配置覆盖开关，返回需要显著提示的警告（停用了硬规则）。覆盖不存在的 id 是配置错误。
// 「显式启用完全依赖模型的规则而模型关闭」的校验要等出现没有本地检测的规则时才需要：
// 现有的规则都必须有 match.exec。
func (s *Set) Apply(ov Overrides) (warnings []string, err error) {
	var unknown []string
	for _, id := range sortedIDs(ov) {
		if r, ok := s.outID[id]; ok {
			r.enabled = ov[id]
			continue
		}
		r, ok := s.byID[id]
		if !ok {
			unknown = append(unknown, id)
			continue
		}
		r.enabled = ov[id]
	}
	for _, r := range s.All() {
		if r.Locked && !r.enabled {
			warnings = append(warnings, fmt.Sprintf("hard rule %q is disabled", r.ID))
		}
	}
	if len(unknown) > 0 {
		return warnings, &Error{Path: "rules." + strings.Join(unknown, ", rules."), Err: errors.New("no such rule")}
	}
	return warnings, nil
}

func sortedIDs(m Overrides) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// TierCovers 报告 action 档位是否覆盖该动作类型。
func TierCovers(tier int, kind guard.ActionKind) bool {
	switch kind {
	case guard.ActionExec:
		return tier >= 1
	case guard.ActionFileRead, guard.ActionFileWrite, guard.ActionFileDelete, guard.ActionFileRename:
		return tier >= 2
	case guard.ActionToolCall, guard.ActionHTTPRequest:
		return tier >= 3
	}
	return false
}

// 规则不生效的原因。
const (
	InactiveDisabled      = "disabled"       // 已停用
	InactiveTier          = "tier"           // 当前档位不覆盖它的动作类型
	InactiveJudgeDisabled = "judge_disabled" // requires_judge 且模型关闭：命中只写入决策日志
)

// State 是规则状态：已加载 / 已启用 / 生效。
type State struct {
	Enabled   bool
	Effective bool
	Inactive  string // 不生效的原因；生效时为空
}

// StateOf 计算规则在当前档位与模型开关下的状态。硬规则不受档位限制。
func StateOf(r *Rule, tier int, judgeEnabled bool) State {
	st := State{Enabled: r.enabled}
	switch {
	case !r.enabled:
		st.Inactive = InactiveDisabled
	case !r.Locked && !slices.ContainsFunc(r.On, func(k guard.ActionKind) bool { return TierCovers(tier, k) }):
		st.Inactive = InactiveTier
	case r.RequiresJudge && !judgeEnabled:
		st.Inactive = InactiveJudgeDisabled
	default:
		st.Effective = true
	}
	return st
}

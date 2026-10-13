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

// Set 是加载完成的全部规则，按 id 索引。
type Set struct {
	byID map[string]*Rule
}

// Builtin 只加载内置规则包。
func Builtin() (*Set, error) { return Load("") }

// Load 加载内置规则包，再叠加用户目录 userDir 下的 *.yaml（含子目录；userDir 为空或不存在时跳过）。
// 同 id 的用户规则整条覆盖内置规则；覆盖硬规则是配置错误。
func Load(userDir string) (*Set, error) {
	s := &Set{byID: map[string]*Rule{}}
	err := fs.WalkDir(builtin.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		data, err := fs.ReadFile(builtin.FS, path)
		if err != nil {
			return err
		}
		r, err := parseRule(data, "builtin:"+path, true)
		if err != nil {
			return err
		}
		if _, dup := s.byID[r.ID]; dup {
			return &Error{File: "builtin:" + path, Rule: r.ID, Path: "id", Err: errors.New("duplicate rule id")}
		}
		s.byID[r.ID] = r
		return nil
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
		r, err := parseRule(data, path, false)
		if err != nil {
			return err
		}
		if prev, dup := seen[r.ID]; dup {
			return &Error{File: path, Rule: r.ID, Path: "id", Err: fmt.Errorf("also defined in %s", prev)}
		}
		seen[r.ID] = path
		if old, ok := s.byID[r.ID]; ok && old.Locked {
			return &Error{File: path, Rule: r.ID, Path: "id",
				Err: errors.New("the built-in rule is locked and cannot be overridden (disable it in config instead)")}
		}
		s.byID[r.ID] = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// All 返回全部规则，按 id 排序。
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

// Apply 按配置覆盖开关（spec §5.2），返回需要显著提示的警告（停用了硬规则）。覆盖不存在的 id 是配置错误。
// 「显式启用完全依赖模型的规则而模型关闭」的校验（spec §4）随 M3/M4 的无本地检测规则一起加入：
// M1 的规则都必须有 match.exec。
func (s *Set) Apply(ov Overrides) (warnings []string, err error) {
	var unknown []string
	for _, id := range sortedIDs(ov) {
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

// TierCovers 报告 action 档位是否覆盖该动作类型（spec §4）。
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

// 规则不生效的原因（spec §4 规则状态）。
const (
	InactiveDisabled      = "disabled"       // 已停用
	InactiveTier          = "tier"           // 当前档位不覆盖它的动作类型
	InactiveJudgeDisabled = "judge_disabled" // requires_judge 且模型关闭：命中只写入决策日志
)

// State 是规则状态：已加载 / 已启用 / 生效（spec §4）。
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

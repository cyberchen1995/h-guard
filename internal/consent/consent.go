// Package consent 读写同意记录（spec §8.5）。任何接收内容的后端都要先经用户在终端里显式同意；
// 同意绑定后端身份——后端名、类型、目标（HTTP：scheme://主机:端口；exec：程序绝对路径与参数）——
// 与数据范围，任一要素变化或扩大范围即失效，判断层不调用（judge_consent_missing）。
//
// 记录存放在 <config_dir>/consent.json（0600），每个后端名一条。只有交互式命令写入：先取得配置目录的
// 读改写锁，写回前比对读入时的哈希（spec §3.5）。记录损坏或版本不认识时视为没有同意。
package consent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// FileName 是同意记录的文件名；Version 是它的格式版本。
const (
	FileName = "consent.json"
	Version  = 1
)

// Scope 是数据范围（spec §8.5）。
type Scope string

const (
	ScopeAction   Scope = "action"   // 动作内容与最近的用户指令
	ScopeOutbound Scope = "outbound" // 提示词与工具输出（M4）
	ScopePII      Scope = "pii"      // 本地规则识别不了的 PII 原样发送（M4）
)

// Valid 报告 s 是否是已知的数据范围。
func (s Scope) Valid() bool { return s == ScopeAction || s == ScopeOutbound || s == ScopePII }

// Identity 是同意绑定的后端身份。
type Identity struct {
	Backend string `json:"backend"` // 后端名（配置 backends 的键）
	Type    string `json:"type"`    // 后端类型
	Target  string `json:"target"`  // judge.Info.Target
}

// IdentityOf 返回后端 b（配置名 name、类型 typ）的身份；b 没有实现 judge.Describer 时无法同意，返回 false。
func IdentityOf(name, typ string, b judge.Backend) (Identity, bool) {
	d, ok := b.(judge.Describer)
	if !ok {
		return Identity{}, false
	}
	info := d.Describe()
	if info.Target == "" {
		return Identity{}, false
	}
	return Identity{Backend: name, Type: typ, Target: info.Target}, true
}

// Record 是一条同意记录。
type Record struct {
	Identity
	Scopes  []Scope   `json:"scopes"` // 已排序、不重复
	Granted time.Time `json:"granted"`
}

type file struct {
	Version int      `json:"version"`
	Records []Record `json:"records"`
}

var (
	// ErrCorrupt 表示同意记录无法解析，读取时视为没有任何同意。
	ErrCorrupt = errors.New("consent: the consent record is corrupt")
	// ErrNewerVersion 表示同意记录来自更新的 h-guard；读取时视为没有同意，也不覆盖。
	ErrNewerVersion = errors.New("consent: the consent record was written by a newer h-guard")
)

// Store 是 Dir（h-guard 配置目录）下的同意记录。
type Store struct {
	Dir string
}

func (s Store) path() string { return filepath.Join(s.Dir, FileName) }

// Load 读取全部记录；文件不存在时为空。损坏返回 ErrCorrupt，版本不认识返回 ErrNewerVersion。
func (s Store) Load() ([]Record, error) {
	data, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parse(data)
}

func parse(data []byte) ([]Record, error) {
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, ErrCorrupt
	}
	switch {
	case f.Version > Version:
		return nil, ErrNewerVersion
	case f.Version != Version:
		return nil, ErrCorrupt
	}
	for _, r := range f.Records {
		if r.Backend == "" || r.Type == "" || r.Target == "" || !slices.IsSorted(r.Scopes) || slices.ContainsFunc(r.Scopes, func(s Scope) bool { return !s.Valid() }) {
			return nil, ErrCorrupt
		}
	}
	return f.Records, nil
}

// Covers 报告是否有一条与 id 完全一致、且数据范围包含 scopes 全部的同意。读不到或记录损坏时为 false。
func (s Store) Covers(id Identity, scopes ...Scope) bool {
	records, err := s.Load()
	if err != nil {
		return false
	}
	for _, r := range records {
		if r.Identity == id {
			for _, sc := range scopes {
				if !slices.Contains(r.Scopes, sc) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// Grant 记录对 id 的同意（数据范围 scopes），替换同一后端名的旧记录。损坏的记录被替换；
// 来自更新版本的记录不覆盖。另一个 h-guard 进程持有锁时返回 store.ErrLocked。
func (s Store) Grant(id Identity, scopes []Scope, now time.Time) error {
	if id.Backend == "" || id.Type == "" || id.Target == "" || len(scopes) == 0 {
		return errors.New("consent: incomplete identity or empty scope")
	}
	for _, sc := range scopes {
		if !sc.Valid() {
			return fmt.Errorf("consent: unknown scope %q", sc)
		}
	}
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	return s.update(func(records []Record) []Record {
		records = slices.DeleteFunc(records, func(r Record) bool { return r.Backend == id.Backend })
		return append(records, Record{Identity: id, Scopes: sorted, Granted: now.UTC()})
	})
}

// Revoke 删除后端名为 backend 的同意，返回是否删除了记录。
func (s Store) Revoke(backend string) (bool, error) {
	removed := false
	err := s.update(func(records []Record) []Record {
		n := len(records)
		records = slices.DeleteFunc(records, func(r Record) bool { return r.Backend == backend })
		removed = len(records) != n
		return records
	})
	return removed, err
}

// update 在锁内读入记录、交给 change 修改、写回（读入后文件被其他程序改动时返回 store.ErrConflict）。
func (s Store) update(change func([]Record) []Record) error {
	unlock, err := store.Lock(s.Dir)
	if err != nil {
		return err
	}
	defer unlock()
	data, err := os.ReadFile(s.path())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hash := "" // 与 store.FileHash 一致：文件不存在为空串
	var records []Record
	if err == nil {
		sum := sha256.Sum256(data)
		hash = hex.EncodeToString(sum[:])
		records, err = parse(data)
		if errors.Is(err, ErrNewerVersion) {
			return err
		}
		// 损坏的记录本来就视为没有同意，交互式命令直接替换它
	}
	records = change(records)
	slices.SortFunc(records, func(a, b Record) int { return strings.Compare(a.Backend, b.Backend) })
	out, err := json.MarshalIndent(file{Version: Version, Records: nonNil(records)}, "", "  ")
	if err != nil {
		return err
	}
	return store.ReplaceIfUnchanged(s.path(), append(out, '\n'), 0o600, hash)
}

func nonNil(r []Record) []Record {
	if r == nil {
		return []Record{}
	}
	return r
}

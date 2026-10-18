// Package grant 是单次授权：harness 不能请求确认（Codex 把 ask 降级为 deny）时，用户在自己的终端里
// 批准一次被拦下的具体操作，agent 重试同一操作时放行一次。
//
// 授权绑定 harness、工作目录与动作的原文（命令、文件路径），有效期有上限，用过即删；内容稍有不同（换了参数、换了目录）
// 都对不上。记录放在 h-guard 的缓存目录：agent 改写它们会被护栏自我保护拦下（guard_tampering），
// 批准只能在终端里进行（h-guard allow 要求交互终端，在 hook 下运行同样被护栏自我保护拦下）。
package grant

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

const (
	// PendingTTL 是被拦下的操作可以被批准的时限：超过之后要重新触发一次拦截。
	PendingTTL = time.Hour
	// DefaultTTL 是批准后的默认有效期。
	DefaultTTL = 10 * time.Minute
	// MaxTTL 是批准后有效期的上限。
	MaxTTL = time.Hour
)

// ErrNotFound 表示没有这个编号的待批准操作（或已过期、已批准）。
var ErrNotFound = errors.New("grant: no pending operation with this id (it may have expired)")

// Op 是一次被拦下的操作：一次工具调用里的全部动作。
type Op struct {
	Harness string   `json:"harness"`
	Tool    string   `json:"tool"`
	Cwd     string   `json:"cwd"`
	Actions []string `json:"actions"` // 每个动作的规范写法，见 action.OpOf
	// Input 是 harness 原始工具输入的规范写法（入口给出）：动作的规范写法之外的执行参数（超时、
	// 工作目录覆盖……）同样绑进授权，改了任何一项都对不上；h-guard allow 原样显示它
	Input string `json:"input,omitempty"`
	// RealCwd 是工作目录解析符号链接之后的真实路径：批准之后把工作目录改指向别处就对不上
	RealCwd string `json:"real_cwd,omitempty"`
	// DirID 是工作目录的文件身份（设备与 inode，Windows 上是卷序列号与文件编号）：批准之后把目录挪走、
	// 在同一路径放上另一个目录就对不上；只用于匹配，不显示
	DirID string `json:"dir_id,omitempty"`
	// Session 是被拦下的会话：另一个会话（可能带着别的凭据、配置）里同样的调用对不上
	Session string `json:"session,omitempty"`
}

// Digest 是操作规范内容的 SHA-256（十六进制）：记录里只存它与遮蔽过的操作，不存原文（命令里可能带凭据）。
func (o Op) Digest() string {
	b, _ := json.Marshal(o)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ID 是操作的编号：Digest 的前 10 个十六进制字符。同一操作每次得到同一个编号。
func (o Op) ID() string { return o.Digest()[:10] }

// redacted 返回遮蔽了凭据形状的副本，供记录与显示。
func (o Op) redacted() Op {
	r := Op{Harness: o.Harness, Tool: o.Tool, Cwd: secrets.Redact(o.Cwd), Input: secrets.Redact(o.Input), RealCwd: secrets.Redact(o.RealCwd), DirID: o.DirID, Session: secrets.Redact(o.Session)}
	for _, a := range o.Actions {
		// 只用于显示：截断到 maxShown，记录的大小有上限（匹配用完整操作的摘要）
		a = secrets.Redact(a)
		if rs := []rune(a); len(rs) > maxShown {
			a = string(rs[:maxShown]) + "…"
		}
		r.Actions = append(r.Actions, a)
	}
	return r
}

// Pending 是一次待批准的操作。Op 是遮蔽过的写法，只用于显示；匹配用 Digest。
type Pending struct {
	ID      string    `json:"id"`
	Digest  string    `json:"digest"`
	Op      Op        `json:"op"`
	Rules   []string  `json:"rules"` // 命中的规则
	Created time.Time `json:"created"`
	// PMAC 是记下时对以上全部字段的签名：只写缓存的人改不了 h-guard allow 显示给用户的内容
	PMAC string `json:"pmac"`
}

// Grant 是一次已批准、尚未使用的授权。
type Grant struct {
	Pending
	Approved time.Time `json:"approved"`
	Expires  time.Time `json:"expires"`
	// Nonce 区分每一次批准；用掉时它记进配置目录的已用记录，同一份签了名的记录不能再用第二次
	Nonce string `json:"nonce"`
	// MAC 是用签名密钥对摘要、有效期与 Nonce 算出的 HMAC-SHA256：只写缓存目录、读不到密钥的写入伪造不出可用的授权
	MAC string `json:"mac"`
}

// Store 是授权记录的目录（通常是 {cache}/grants）。Dir 为空时什么都不记、什么都对不上。
//
// KeyPath 是签名密钥（通常是 {config}/grant.key，护栏自我保护覆盖配置目录）：第一次记下待批准的操作时生成，
// 校验时没有就不认任何记录。为空时同样不认。agent 与 h-guard 以同一个用户运行，读得到这个文件的 agent 仍能伪造授权；
// 密钥只是让伪造在只写缓存之外还要读配置目录（README 的已知限制）。
type Store struct {
	Dir     string
	KeyPath string
	Now     func() time.Time
}

// maxShown 是待批准记录里每个动作显示的最大长度（字符）；maxPending 是同时保留的待批准记录数上限：
// 被拦下的命令可以很长、可以很多，记录不能把缓存目录写满。
const (
	maxShown   = 2000
	maxPending = 200
)

// keyBytes 是签名密钥的长度。
const keyBytes = 32

// key 读签名密钥；create 为真且文件不存在时生成一个（0o600）。
func (s *Store) key(create bool) ([]byte, error) {
	if s.KeyPath == "" {
		return nil, errors.New("grant: no key file")
	}
	b, err := os.ReadFile(s.KeyPath)
	if err == nil {
		k, derr := hex.DecodeString(strings.TrimSpace(string(b)))
		if derr != nil || len(k) != keyBytes {
			return nil, errors.New("grant: the key file is malformed")
		}
		return k, nil
	}
	if !errors.Is(err, fs.ErrNotExist) || !create {
		return nil, err
	}
	k := make([]byte, keyBytes)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.KeyPath), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL：并发的两个 hook 只有一个生成密钥，另一个读它生成的（不能各自写一把，让对方的签名失效）
	f, err := os.OpenFile(s.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return s.key(false)
	}
	if err != nil {
		return nil, err
	}
	_, werr := f.WriteString(hex.EncodeToString(k) + "\n")
	if err := errors.Join(werr, f.Close()); err != nil {
		_ = os.Remove(s.KeyPath)
		return nil, err
	}
	return k, nil
}

// pendingMAC 是待批准记录的签名：覆盖除 PMAC 以外的全部字段（显示给用户的操作与规则、摘要与时间）。
func pendingMAC(key []byte, p Pending) string {
	p.PMAC = ""
	b, _ := json.Marshal(p)
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("h-guard pending v1\n"))
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// mac 是授权的签名：覆盖编号、摘要、批准时间与过期时间（hash.Hash 的 Write 不会出错）。
func mac(key []byte, g Grant) string {
	h := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(h, "h-guard grant v2\n%s\n%s\n%d\n%d\n%s\n", g.ID, g.Digest, g.Approved.UnixNano(), g.Expires.UnixNano(), g.Nonce)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

var validID = regexp.MustCompile(`^[0-9a-f]{10}$`)

func (s *Store) path(kind, id string) string { return filepath.Join(s.Dir, kind, id+".json") }

// Offer 记下一次被拦下的操作，返回它的编号。重复拦下同一操作时刷新记录的时间。
func (s *Store) Offer(op Op, rules []string) (string, error) {
	if s.Dir == "" {
		return "", errors.New("grant: no cache directory")
	}
	// 显示不全的操作不提供授权：用户确认时必须看得到将要执行的全部内容；工作目录同样（Codex 的 workdir 由 agent 给出）
	// 记录里保存的每个字段都要显示得下（会话编号、工具名同样来自 hook 输入）
	for _, a := range append([]string{op.Harness, op.Tool, op.Session, op.Cwd, op.RealCwd, op.Input}, op.Actions...) {
		if len([]rune(a)) > maxShown {
			return "", errors.New("grant: the operation is too long to show in full")
		}
	}
	key, err := s.key(true)
	if err != nil {
		return "", err
	}
	id := op.ID()
	p := Pending{ID: id, Digest: op.Digest(), Op: op.redacted(), Rules: slices.Sorted(slices.Values(rules)), Created: s.now().UTC()}
	p.PMAC = pendingMAC(key, p)
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	// 顺带清理过期的待批准记录与授权：目录不会无限增长
	store.RemoveOlder(filepath.Join(s.Dir, "pending"), s.now().Add(-PendingTTL))
	store.RemoveOlder(filepath.Join(s.Dir, "active"), s.now().Add(-MaxTTL-time.Minute))
	// 已用记录只需活过它对应的授权：授权最长 MaxTTL，过期之后签名本身就不再有效
	store.RemoveOlder(s.usedDir(), s.now().Add(-MaxTTL-time.Minute))
	if entries, _ := os.ReadDir(filepath.Join(s.Dir, "pending")); len(entries) >= maxPending {
		if _, err := os.Stat(s.path("pending", id)); err != nil {
			return "", errors.New("grant: too many pending operations")
		}
	}
	return id, store.WriteAtomic(s.path("pending", id), b, 0o600)
}

// Lookup 返回编号为 id 的待批准操作；不存在或已过期时返回 ErrNotFound。
func (s *Store) Lookup(id string) (Pending, error) {
	if s.Dir == "" || !validID.MatchString(id) {
		return Pending{}, ErrNotFound
	}
	var p Pending
	b, err := os.ReadFile(s.path("pending", id))
	if err != nil || json.Unmarshal(b, &p) != nil || p.ID != id || !strings.HasPrefix(p.Digest, id) {
		return Pending{}, ErrNotFound
	}
	key, err := s.key(false)
	if err != nil || !hmac.Equal([]byte(p.PMAC), []byte(pendingMAC(key, p))) {
		return Pending{}, ErrNotFound
	}
	if s.now().Sub(p.Created) > PendingTTL {
		return Pending{}, ErrNotFound
	}
	return p, nil
}

// List 返回未过期的待批准操作，新的在前。
func (s *Store) List() []Pending {
	if s.Dir == "" {
		return nil
	}
	entries, _ := os.ReadDir(filepath.Join(s.Dir, "pending"))
	var out []Pending
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		if p, err := s.Lookup(id); err == nil {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// ErrChanged 表示待批准记录在显示给用户之后被换过：批准的必须是用户看到的那一条。
var ErrChanged = errors.New("grant: the pending operation changed after it was shown; run h-guard allow again")

// Approve 批准用户看到的那条待批准操作 shown（Lookup 或 List 的结果），有效期 ttl（不超过 MaxTTL）。
// 先占住记录、再核对它与 shown 是同一条（签名相同）：显示与确认之间被换成另一条签名有效的记录时不批准。
// 待批准记录随之删除。
func (s *Store) Approve(shown Pending, ttl time.Duration) (Grant, error) {
	id := shown.ID
	if _, err := s.Lookup(id); err != nil {
		return Grant{}, err
	}
	if ttl < time.Second || ttl > MaxTTL {
		return Grant{}, errors.New("grant: the validity must be between 1s and 1h")
	}
	key, err := s.key(false)
	if err != nil {
		return Grant{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Grant{}, err
	}
	// 先把待批准记录改名占住：改名成功的这一次才能批准，批准之后它不会还留在原处被再次批准。
	// 占位的名字每次不同：中途退出留下的占位（过期后随待批准记录清理）不会挡住下一次批准（Windows 上改名不覆盖已有文件）
	src := s.path("pending", id)
	claimed := src + "." + hex.EncodeToString(nonce[:8]) + ".claimed"
	if err := os.Rename(src, claimed); err != nil {
		return Grant{}, ErrNotFound
	}
	var p Pending
	b, err := os.ReadFile(claimed)
	if err != nil || json.Unmarshal(b, &p) != nil || p.ID != id ||
		!hmac.Equal([]byte(p.PMAC), []byte(pendingMAC(key, p))) || !hmac.Equal([]byte(p.PMAC), []byte(shown.PMAC)) {
		_ = os.Rename(claimed, src)
		return Grant{}, ErrChanged
	}
	now := s.now().UTC()
	g := Grant{Pending: p, Approved: now, Expires: now.Add(ttl), Nonce: hex.EncodeToString(nonce)}
	g.MAC = mac(key, g)
	b, err = json.Marshal(g)
	if err != nil {
		return Grant{}, err
	}
	if err := store.WriteAtomic(s.path("active", id), b, 0o600); err != nil {
		_ = os.Rename(claimed, src) // 没有批准成功：放回去，可以再试
		return Grant{}, err
	}
	_ = os.Remove(claimed)
	return g, nil
}

// active 读编号为 op.ID() 的授权；内容与 op 不完全一致或已过期时返回 false。
func (s *Store) active(op Op) (Grant, bool) {
	if s.Dir == "" {
		return Grant{}, false
	}
	var g Grant
	b, err := os.ReadFile(s.path("active", op.ID()))
	if err != nil || json.Unmarshal(b, &g) != nil {
		return Grant{}, false
	}
	if g.Digest != op.Digest() || g.ID != op.ID() || !s.now().Before(g.Expires) || g.Expires.Sub(g.Approved) > MaxTTL {
		return Grant{}, false
	}
	key, err := s.key(false)
	if err != nil || !validNonce.MatchString(g.Nonce) || !hmac.Equal([]byte(g.MAC), []byte(mac(key, g))) {
		return Grant{}, false
	}
	if _, err := os.Lstat(s.usedPath(g)); !errors.Is(err, fs.ErrNotExist) {
		return Grant{}, false // 用过了（或读不了已用记录）：缓存里重新放回的同一份记录不算数
	}
	return g, true
}

var validNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

// usedDir 是已用记录的目录：与签名密钥同在配置目录（护栏自我保护覆盖它），agent 删不掉就重放不了。
func (s *Store) usedDir() string { return filepath.Join(filepath.Dir(s.KeyPath), "grants-used") }

func (s *Store) usedPath(g Grant) string { return filepath.Join(s.usedDir(), g.ID+"-"+g.Nonce) }

// Has 报告 op 有没有可用的授权，不消耗它。
func (s *Store) Has(op Op) bool {
	_, ok := s.active(op)
	return ok
}

// Consume 用掉 op 的授权：有可用的授权时记下已用、再删除它，返回 true。
// 已用记录以独占方式创建，并发的两次调用只有一次成功；先记下已用再删除：中途被终止时，
// 留下的授权记录已经作废，放回缓存的副本同样不能再用。记不下已用就不放行。
func (s *Store) Consume(op Op) bool {
	g, ok := s.active(op)
	if !ok {
		return false
	}
	if err := os.MkdirAll(s.usedDir(), 0o700); err != nil {
		return false
	}
	f, err := os.OpenFile(s.usedPath(g), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false
	}
	if f.Close() != nil {
		return false
	}
	_ = os.Remove(s.path("active", op.ID()))
	return true
}

// Revoke 删除编号为 id 的授权与待批准记录；都不存在时返回 fs.ErrNotExist。
func (s *Store) Revoke(id string) error {
	if s.Dir == "" || !validID.MatchString(id) {
		return fs.ErrNotExist
	}
	e1 := os.Remove(s.path("active", id))
	e2 := os.Remove(s.path("pending", id))
	if e1 != nil && e2 != nil {
		return fs.ErrNotExist
	}
	return nil
}

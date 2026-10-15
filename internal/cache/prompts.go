// Package cache 是用户指令缓存（spec §3.5、§5.4）：prompt.submit / UserPromptSubmit 写入，
// 动作检查读取。每条指令一个文件，写入用临时文件 + rename，并发写入不会互相覆盖；
// 读到损坏的条目视为不存在。写入前遮蔽凭据。
package cache

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// TTL 是指令的有效期（spec §5.4）。
const TTL = 7 * 24 * time.Hour

// MaxEntries 是每个会话保留的条目数上限；写入时删除更早的条目。
const MaxEntries = 50

// Prompts 是指令缓存，根目录通常为 <cache_dir>/h-guard/prompts。
type Prompts struct {
	Dir string           // 为空（缓存目录取不到）时不读不写
	Now func() time.Time // 为 nil 时用 time.Now
}

type entry struct {
	Text   string       `json:"text"`
	Source guard.Source `json:"source"`
	At     time.Time    `json:"at"`
}

func (p *Prompts) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// sessionDir 返回会话目录：<harness>-<会话 ID 中的安全字符，至多 120 个>。
func (p *Prompts) sessionDir(harness, session string) string {
	safe := strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || (r >= '0' && r <= '9') || (r|0x20 >= 'a' && r|0x20 <= 'z') {
			return r
		}
		return '_'
	}, session)
	if len(safe) > 120 {
		safe = safe[:120]
	}
	return filepath.Join(p.Dir, harness+"-"+safe)
}

// Add 写入一条指令（遮蔽凭据后），并顺带清理过期会话与本会话多余的条目。
// 会话 ID 为空或指令为空白时不写。r.At 为零时取当前时间。
func (p *Prompts) Add(harness, session string, r guard.Request) error {
	if p.Dir == "" || session == "" || strings.TrimSpace(r.Text) == "" {
		return nil
	}
	if r.At.IsZero() {
		r.At = p.now()
	}
	if !r.Source.Valid() {
		r.Source = guard.SourceUser
	}
	data, err := json.Marshal(entry{Text: secrets.Redact(r.Text), Source: r.Source, At: r.At.UTC()})
	if err != nil {
		return err
	}
	dir := p.sessionDir(harness, session)
	name := fmt.Sprintf("%020d-%s.json", r.At.UnixNano(), randomHex(4))
	if err := store.WriteAtomic(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	p.sweep(dir)
	return nil
}

// Recent 返回会话中最近的至多 max 条未过期指令，按时间先后排列（最新的在最后）。
func (p *Prompts) Recent(harness, session string, max int) []guard.Request {
	if p.Dir == "" || session == "" || max <= 0 {
		return nil
	}
	names := entryNames(p.sessionDir(harness, session))
	cutoff := p.now().Add(-TTL)
	var out []guard.Request
	for i := len(names) - 1; i >= 0 && len(out) < max; i-- {
		b, err := os.ReadFile(filepath.Join(p.sessionDir(harness, session), names[i]))
		if err != nil {
			continue
		}
		var e entry
		if json.Unmarshal(b, &e) != nil || e.At.Before(cutoff) || !e.Source.Valid() {
			continue
		}
		out = append(out, guard.Request{Text: e.Text, Source: e.Source, At: e.At})
	}
	slices.Reverse(out)
	return out
}

// entryNames 返回会话目录中的条目文件名，按名字（即写入时间）升序；临时文件不算。
func entryNames(dir string) []string {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, d := range des {
		if d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".json") && !strings.HasPrefix(d.Name(), ".") {
			names = append(names, d.Name())
		}
	}
	slices.Sort(names)
	return names
}

// sweep 删除超过 TTL 未修改的会话目录，以及本会话中超出 MaxEntries 的旧条目。失败一律忽略。
func (p *Prompts) sweep(current string) {
	cutoff := p.now().Add(-TTL)
	if des, err := os.ReadDir(p.Dir); err == nil {
		for _, d := range des {
			if !d.IsDir() {
				continue
			}
			info, err := d.Info()
			if err == nil && info.ModTime().Before(cutoff) {
				_ = os.RemoveAll(filepath.Join(p.Dir, d.Name()))
			}
		}
	}
	names := entryNames(current)
	for _, n := range names[:max(0, len(names)-MaxEntries)] {
		_ = os.Remove(filepath.Join(current, n))
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// blockedDir 是会话里被拦截提示词的指纹目录（文件名是指纹，内容为空）。
func (p *Prompts) blockedDir(harness, session string) string {
	return filepath.Join(p.sessionDir(harness, session), "blocked")
}

// fingerprint 是提示词的指纹：空白归一（连续空白合成一个空格，去掉首尾）后的 SHA-256，会话记录里换行写法不同
// 也认得出（M4a 计划评审）。只存指纹，不存原文（spec §5.4）。
func fingerprint(text string) string {
	return store.Hash([]byte(strings.Join(strings.Fields(text), " ")))
}

// Block 记下一条被 outbound 拦截的提示词的指纹：它不写入缓存，transcript 回退时用 Blocked 跳过它（spec §5.4）。
func (p *Prompts) Block(harness, session, text string) error {
	if p.Dir == "" || session == "" || strings.TrimSpace(text) == "" {
		return nil
	}
	return store.WriteAtomic(filepath.Join(p.blockedDir(harness, session), fingerprint(text)), nil, 0o600)
}

// Blocked 报告 text 是不是这个会话里被拦截过的提示词（7 天内）。
func (p *Prompts) Blocked(harness, session, text string) bool {
	if p.Dir == "" || session == "" {
		return false
	}
	fi, err := os.Stat(filepath.Join(p.blockedDir(harness, session), fingerprint(text)))
	return err == nil && fi.ModTime().After(p.now().Add(-TTL))
}

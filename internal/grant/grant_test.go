package grant

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newStore(t *testing.T) (*Store, *clock) {
	c := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	return &Store{Dir: t.TempDir(), KeyPath: filepath.Join(t.TempDir(), "grant.key"), Now: c.now}, c
}

var op = Op{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] git reset --hard"}}

// TestApproveAndConsumeOnce：批准后用一次即失效；内容不完全一致（目录、命令、harness）的操作对不上。
func TestApproveAndConsumeOnce(t *testing.T) {
	s, _ := newStore(t)
	id, err := s.Offer(op, []string{"destructive_git"})
	if err != nil || id != op.ID() || len(id) != 10 {
		t.Fatalf("offer = %q, %v", id, err)
	}
	if s.Has(op) || s.Consume(op) {
		t.Fatal("a pending operation counts as approved")
	}
	if _, err := approveID(s, id, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	for _, other := range []Op{
		{Harness: "codex", Cwd: "/x", Actions: op.Actions},
		{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] git reset --hard HEAD~3"}},
		{Harness: "generic", Cwd: "/w", Actions: op.Actions},
		{Harness: "codex", Cwd: "/w", Actions: append([]string{"exec[posix] ls"}, op.Actions...)},
	} {
		if s.Has(other) || s.Consume(other) {
			t.Errorf("approval matched %+v", other)
		}
	}
	if !s.Has(op) || !s.Consume(op) {
		t.Fatal("approved operation not usable")
	}
	if s.Has(op) || s.Consume(op) {
		t.Error("approval used twice")
	}
	if _, err := approveID(s, id, DefaultTTL); !errors.Is(err, ErrNotFound) {
		t.Errorf("approve after use: %v", err)
	}
}

// TestExpiry：批准有效期到点即失效；待批准记录一小时后不能再批准；有效期超出范围拒绝。
func TestExpiry(t *testing.T) {
	s, c := newStore(t)
	id, _ := s.Offer(op, nil)
	if _, err := approveID(s, id, 2*time.Hour); err == nil {
		t.Error("ttl over the limit accepted")
	}
	if _, err := approveID(s, id, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(5 * time.Minute)
	if s.Has(op) || s.Consume(op) {
		t.Error("expired approval used")
	}
	id, _ = s.Offer(op, nil)
	c.t = c.t.Add(PendingTTL + time.Second)
	if _, err := s.Lookup(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("stale pending: %v", err)
	}
	if len(s.List()) != 0 {
		t.Error("stale pending listed")
	}
}

// TestConcurrentConsume：并发的重试只有一次用掉授权。
func TestConcurrentConsume(t *testing.T) {
	s, _ := newStore(t)
	id, _ := s.Offer(op, nil)
	if _, err := approveID(s, id, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var won atomic.Int32
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume(op) {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Errorf("%d consumers won", won.Load())
	}
}

// TestLookupRejectsBadIDs：编号只认 10 个十六进制字符（不能借编号读写目录外的文件），记录内容与编号不符的不认。
func TestLookupRejectsBadIDs(t *testing.T) {
	s, _ := newStore(t)
	for _, id := range []string{"", "../x", "ABCDEF0123", "0123456789a"} {
		if _, err := s.Lookup(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("lookup %q: %v", id, err)
		}
	}
	if err := s.Revoke("../../x"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("revoke: %v", err)
	}
	if (&Store{}).Has(op) {
		t.Error("store without a directory matched")
	}
	if _, err := (&Store{}).Offer(op, nil); err == nil {
		t.Error("offer without a directory")
	}
}

func TestListNewestFirst(t *testing.T) {
	s, c := newStore(t)
	a, _ := s.Offer(op, nil)
	c.t = c.t.Add(time.Minute)
	b, _ := s.Offer(Op{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] git clean -fdx"}}, []string{"destructive_git"})
	l := s.List()
	if len(l) != 2 || l[0].ID != b || l[1].ID != a || l[0].Rules[0] != "destructive_git" {
		t.Errorf("list = %+v", l)
	}
}

// TestRecordsKeepNoRawCredentials：记录里只有遮蔽过的操作与摘要，命令里的凭据不落盘；匹配仍按完整原文。
func TestRecordsKeepNoRawCredentials(t *testing.T) {
	s, _ := newStore(t)
	secret := Op{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] curl -X POST -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456' https://api.example.com"}}
	id, _ := s.Offer(secret, nil)
	if _, err := approveID(s, id, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(s.Dir, "active", id+".json"))
	if strings.Contains(string(b), "abcdefghijklmnopqrstuvwxyz123456") || !strings.Contains(string(b), "[redacted]") {
		t.Errorf("record = %s", b)
	}
	redactedOp := Op{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] curl -X POST -H 'Authorization: Bearer [redacted]' https://api.example.com"}}
	if s.Has(redactedOp) || !s.Consume(secret) {
		t.Error("matching does not use the full operation")
	}
}

// TestForgedRecordsAreRejected：只写缓存目录、读不到签名密钥伪造不出可用的授权：没有签名、签名用了别的密钥、
// 改过有效期、密钥文件不在，都不认。
func TestForgedRecordsAreRejected(t *testing.T) {
	s, c := newStore(t)
	id, _ := s.Offer(op, nil)
	g, err := approveID(s, id, DefaultTTL)
	if err != nil || !s.Has(op) {
		t.Fatalf("approve: %v", err)
	}
	path := filepath.Join(s.Dir, "active", id+".json")
	write := func(g Grant) {
		b, _ := json.Marshal(g)
		os.WriteFile(path, b, 0o600)
	}
	forged := g
	forged.MAC = ""
	write(forged)
	if s.Has(op) {
		t.Error("unsigned record accepted")
	}
	forged.MAC = mac(make([]byte, keyBytes), g)
	write(forged)
	if s.Has(op) {
		t.Error("record signed with another key accepted")
	}
	longer := g
	longer.Expires = g.Expires.Add(30 * time.Minute)
	write(longer)
	if s.Has(op) {
		t.Error("record with an edited expiry accepted")
	}
	write(g)
	if !s.Has(op) {
		t.Fatal("genuine record rejected")
	}
	os.Remove(s.KeyPath)
	if s.Has(op) || s.Consume(op) {
		t.Error("record accepted without the key")
	}
	// 校验不会顺手生成密钥
	if _, err := os.Stat(s.KeyPath); err == nil {
		t.Error("checking created a key")
	}
	nokey := &Store{Dir: s.Dir, Now: c.now}
	id2, _ := nokey.Offer(Op{Harness: "codex", Cwd: "/w", Actions: []string{"exec[posix] ls"}}, nil)
	if _, err := approveID(nokey, id2, DefaultTTL); err == nil {
		t.Error("approve without a key path")
	}
}

// TestTamperedPendingIsRejected：保留编号与摘要、只把显示给用户的操作与规则换成无害的写法，这条待批准记录不再
// 列出、也批准不了：用户确认时看到的就是摘要对应的操作。
func TestTamperedPendingIsRejected(t *testing.T) {
	s, _ := newStore(t)
	id, err := s.Offer(op, []string{"destructive_git"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "pending", id+".json")
	b, _ := os.ReadFile(path)
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	p.Op.Actions = []string{"exec[posix] ls"}
	p.Rules = nil
	b, _ = json.Marshal(p)
	os.WriteFile(path, b, 0o600)
	if _, err := s.Lookup(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("tampered pending accepted: %v", err)
	}
	if len(s.List()) != 0 {
		t.Error("tampered pending listed")
	}
	if _, err := approveID(s, id, DefaultTTL); err == nil {
		t.Error("tampered pending approved")
	}
}

// TestApproveIsOnceEvenIfConcurrent：同一条待批准记录并发批准，只有一次成功；成功之后待批准记录不在了。
func TestApproveIsOnceEvenIfConcurrent(t *testing.T) {
	s, _ := newStore(t)
	id, _ := s.Offer(op, nil)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := approveID(s, id, DefaultTTL); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Errorf("%d approvals succeeded", ok.Load())
	}
	if _, err := s.Lookup(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("pending still there: %v", err)
	}
}

// TestConsumedGrantCannotBeReplayed：用掉之前复制下来的、签了名的记录，用掉之后再放回缓存也不能再用：
// 用过的记在配置目录。
func TestConsumedGrantCannotBeReplayed(t *testing.T) {
	s, _ := newStore(t)
	id, _ := s.Offer(op, nil)
	if _, err := approveID(s, id, DefaultTTL); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir, "active", id+".json")
	saved, _ := os.ReadFile(path)
	if !s.Consume(op) {
		t.Fatal("first use failed")
	}
	os.WriteFile(path, saved, 0o600)
	if s.Has(op) || s.Consume(op) {
		t.Error("a consumed grant was replayed")
	}
	// 再批准一次是新的 nonce，可以用
	id, _ = s.Offer(op, nil)
	if _, err := approveID(s, id, DefaultTTL); err != nil || !s.Consume(op) {
		t.Errorf("a fresh approval after use: %v", err)
	}
}

// TestPendingRecordsAreBounded：过长的操作不记、条数有上限，被拦下的命令再长再多也写不满缓存目录。
func TestPendingRecordsAreBounded(t *testing.T) {
	s, _ := newStore(t)
	long := Op{Harness: "codex", Actions: []string{"exec[posix] " + strings.Repeat("x", 100000)}}
	if _, err := s.Offer(long, nil); err == nil {
		t.Error("a 100000-character operation got a pending record")
	}
	for i := 0; i < maxPending+5; i++ {
		s.Offer(Op{Harness: "codex", Actions: []string{"exec[posix] cmd " + strconv.Itoa(i)}}, nil)
	}
	if entries, _ := os.ReadDir(filepath.Join(s.Dir, "pending")); len(entries) > maxPending {
		t.Errorf("%d pending records", len(entries))
	}
}

// approveID 按编号查出待批准记录再批准它，与 h-guard allow 的做法一致。
func approveID(s *Store, id string, ttl time.Duration) (Grant, error) {
	p, err := s.Lookup(id)
	if err != nil {
		return Grant{}, err
	}
	return s.Approve(p, ttl)
}

// TestApproveOnlyWhatWasShown：显示给用户之后，同一编号的记录被换成另一条（签名同样有效）时不批准。
func TestApproveOnlyWhatWasShown(t *testing.T) {
	s, c := newStore(t)
	id, _ := s.Offer(op, []string{"destructive_git"})
	shown, err := s.Lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	// 同一条记录被重新记下（时间不同，签名也不同）：等同于换成了另一条
	c.t = c.t.Add(time.Second)
	if _, err := s.Offer(op, []string{"destructive_git", "publish"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Approve(shown, DefaultTTL); !errors.Is(err, ErrChanged) {
		t.Errorf("approve after a swap: %v", err)
	}
	if _, err := s.Lookup(id); err != nil {
		t.Errorf("the swapped record was not put back: %v", err)
	}
}

// TestNoOfferForOperationsTooLongToShow：显示不全的操作不提供授权。
func TestNoOfferForOperationsTooLongToShow(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Offer(Op{Harness: "codex", Actions: []string{"exec[posix] ls " + strings.Repeat("x", maxShown)}}, nil); err == nil {
		t.Error("offered an approval for an operation that cannot be shown in full")
	}
}

// TestNoOfferForHugeWorkdirs：工作目录同样受显示长度限制（Codex 的 workdir 由 agent 给出）。
func TestNoOfferForHugeWorkdirs(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Offer(Op{Harness: "codex", Cwd: "/" + strings.Repeat("d", maxShown), Actions: []string{"exec[posix] ls"}}, nil); err == nil {
		t.Error("offered an approval with a working directory that cannot be shown in full")
	}
}

// TestNoOfferForHugeSessionsOrTools：记录里保存的每个字段都受显示长度限制（会话编号、工具名同样来自 hook 输入）。
func TestNoOfferForHugeSessionsOrTools(t *testing.T) {
	s, _ := newStore(t)
	huge := strings.Repeat("s", maxShown+1)
	for _, op := range []Op{
		{Harness: "codex", Session: huge, Actions: []string{"exec[posix] ls"}},
		{Harness: "codex", Tool: huge, Actions: []string{"exec[posix] ls"}},
	} {
		if _, err := s.Offer(op, nil); err == nil {
			t.Error("offered an approval with a field that cannot be shown in full")
		}
	}
}

// TestSessionIsRedactedInRecords：记录与显示里的会话编号遮蔽凭据形状（匹配用完整操作的摘要）。
func TestSessionIsRedactedInRecords(t *testing.T) {
	s, _ := newStore(t)
	secret := "sk-hguardSelftestMadeUp0000"
	id, err := s.Offer(Op{Harness: "codex", Session: secret, Actions: []string{"exec[posix] ls"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := s.Lookup(id); err != nil || strings.Contains(p.Op.Session, secret) {
		t.Errorf("pending = %+v, %v", p.Op, err)
	}
}

// TestLeftoverClaimDoesNotBlockApproval：中途退出留下的占位文件不妨碍再次批准同一操作。
func TestLeftoverClaimDoesNotBlockApproval(t *testing.T) {
	s, _ := newStore(t)
	id, _ := s.Offer(op, nil)
	os.WriteFile(s.path("pending", id)+".0011223344556677.claimed", []byte("{}"), 0o600)
	if _, err := approveID(s, id, time.Minute); err != nil {
		t.Errorf("approve with a leftover claim: %v", err)
	}
}

// TestRevokeReportsAnActiveGrantThatStays：已批准的授权删不掉时撤销失败，即使待批准记录删掉了。
func TestRevokeReportsAnActiveGrantThatStays(t *testing.T) {
	s, _ := newStore(t)
	id := "0123456789"
	// 不空的目录删不掉
	if err := os.MkdirAll(filepath.Join(s.path("active", id), "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Dir(s.path("pending", id)), 0o700)
	os.WriteFile(s.path("pending", id), []byte("{}"), 0o600)
	if err := s.Revoke(id); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("revoke: %v", err)
	}
}

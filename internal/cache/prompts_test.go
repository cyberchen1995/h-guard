package cache_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/cache"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func TestAddAndRecent(t *testing.T) {
	now := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	p := &cache.Prompts{Dir: t.TempDir(), Now: func() time.Time { return now }}
	for i, text := range []string{"first", "second", "third", "fourth"} {
		src := guard.SourceUser
		if i == 2 {
			src = guard.SourceAutomated
		}
		if err := p.Add("claudecode", "s/1", guard.Request{Text: text, Source: src, At: now.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	got := p.Recent("claudecode", "s/1", 3)
	if len(got) != 3 || got[0].Text != "second" || got[1].Source != guard.SourceAutomated || got[2].Text != "fourth" {
		t.Errorf("Recent = %+v", got)
	}
	if p.Recent("claudecode", "other", 3) != nil || p.Recent("codex", "s/1", 3) != nil {
		t.Error("sessions and harnesses must be separate")
	}
	if p.Add("claudecode", "", guard.Request{Text: "x"}) != nil || p.Add("claudecode", "s", guard.Request{Text: "  "}) != nil {
		t.Error("empty session or text must be ignored silently")
	}
}

func TestRedactsBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	p := &cache.Prompts{Dir: dir}
	if err := p.Add("claudecode", "s", guard.Request{Text: "use api_key=supersecretvalue please", Source: guard.SourceUser}); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(path)
			if strings.Contains(string(b), "supersecretvalue") {
				t.Errorf("%s contains the secret", path)
			}
		}
		return nil
	})
	if got := p.Recent("claudecode", "s", 1); len(got) != 1 || got[0].Text != "use api_key=[redacted] please" {
		t.Errorf("Recent = %+v", got)
	}
}

func TestExpiryAndCorruption(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	p := &cache.Prompts{Dir: dir, Now: func() time.Time { return now }}
	p.Add("claudecode", "s", guard.Request{Text: "old", Source: guard.SourceUser, At: now.Add(-8 * 24 * time.Hour)})
	p.Add("claudecode", "s", guard.Request{Text: "new", Source: guard.SourceUser, At: now})
	sess := filepath.Join(dir, "claudecode-s")
	os.WriteFile(filepath.Join(sess, "99999999999999999999-zzzz.json"), []byte("{not json"), 0o600)
	got := p.Recent("claudecode", "s", 5)
	if len(got) != 1 || got[0].Text != "new" {
		t.Errorf("Recent = %+v", got)
	}
	stale := filepath.Join(dir, "claudecode-stale")
	os.MkdirAll(stale, 0o700)
	old := now.Add(-8 * 24 * time.Hour)
	os.Chtimes(stale, old, old)
	p.Add("claudecode", "s", guard.Request{Text: "trigger sweep", Source: guard.SourceUser})
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("stale session directories must be removed on write")
	}
}

func TestKeepsAtMostMaxEntries(t *testing.T) {
	p := &cache.Prompts{Dir: t.TempDir()}
	base := time.Now()
	for i := range cache.MaxEntries + 5 {
		p.Add("claudecode", "s", guard.Request{Text: fmt.Sprint(i), Source: guard.SourceUser, At: base.Add(time.Duration(i) * time.Millisecond)})
	}
	got := p.Recent("claudecode", "s", 1000)
	if len(got) != cache.MaxEntries || got[0].Text != "5" {
		t.Errorf("kept %d entries, oldest %q", len(got), got[0].Text)
	}
}

func TestConcurrentWritersKeepEveryEntry(t *testing.T) {
	p := &cache.Prompts{Dir: t.TempDir()}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.Add("claudecode", "s", guard.Request{Text: fmt.Sprint("p", i), Source: guard.SourceUser})
		}()
	}
	wg.Wait()
	if got := p.Recent("claudecode", "s", 100); len(got) != 20 {
		t.Errorf("got %d entries, want 20", len(got))
	}
}

func TestMultiProcessWriters(t *testing.T) {
	if os.Getenv("HG_CACHE_HELPER") != "" {
		p := &cache.Prompts{Dir: os.Getenv("HG_CACHE_DIR")}
		for i := range 10 {
			p.Add("claudecode", "s", guard.Request{Text: fmt.Sprint(os.Getenv("HG_CACHE_HELPER"), "-", i), Source: guard.SourceUser})
		}
		return
	}
	dir := t.TempDir()
	var cmds []*exec.Cmd
	for i := range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMultiProcessWriters$")
		cmd.Env = append(os.Environ(), fmt.Sprint("HG_CACHE_HELPER=", i), "HG_CACHE_DIR="+dir)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds = append(cmds, cmd)
	}
	for _, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	p := &cache.Prompts{Dir: dir}
	if got := p.Recent("claudecode", "s", 100); len(got) != 40 {
		t.Errorf("got %d entries, want 40", len(got))
	}
}

// TestBlockedNormalizesWhitespace：被拦提示词的指纹按空白归一：会话记录里换行写成 \r\n、多个空格合并或首尾带空白时
// 仍认得出（M4a 计划评审）；内容不同的提示词不算。
func TestBlockedNormalizesWhitespace(t *testing.T) {
	p := &cache.Prompts{Dir: t.TempDir()}
	if err := p.Block("codex", "s1", "deploy  with\ttoken\nabc"); err != nil {
		t.Fatal(err)
	}
	for _, same := range []string{"deploy with token abc", " deploy with\r\ntoken  abc\n"} {
		if !p.Blocked("codex", "s1", same) {
			t.Errorf("%q not recognized", same)
		}
	}
	if p.Blocked("codex", "s1", "deploy with token abd") || p.Blocked("codex", "s2", "deploy with token abc") {
		t.Error("different prompt or session matched")
	}
}

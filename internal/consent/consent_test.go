package consent_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/internal/store"
	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/anthropic"
	"github.com/cyberchen1995/h-guard/pkg/judge/exec"
	"github.com/cyberchen1995/h-guard/pkg/judge/openai"
	"github.com/cyberchen1995/h-guard/pkg/judge/typesafe"
)

var now = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func local() consent.Identity {
	return consent.Identity{Backend: "local", Type: "openai", Target: "http://localhost:11434"}
}

func TestGrantCoversOnlyTheSameIdentityAndScope(t *testing.T) {
	s := consent.Store{Dir: t.TempDir()}
	id := local()
	if s.Covers(id, consent.ScopeAction) {
		t.Fatal("covered before any consent")
	}
	if err := s.Grant(id, []consent.Scope{consent.ScopeAction, consent.ScopeAction}, now); err != nil {
		t.Fatal(err)
	}
	if !s.Covers(id, consent.ScopeAction) {
		t.Error("granted consent not covered")
	}
	for name, other := range map[string]consent.Identity{
		"other port":    {Backend: "local", Type: "openai", Target: "http://localhost:8080"},
		"other scheme":  {Backend: "local", Type: "openai", Target: "https://localhost:11434"},
		"other host":    {Backend: "local", Type: "openai", Target: "http://127.0.0.1:11434"},
		"other type":    {Backend: "local", Type: "anthropic", Target: "http://localhost:11434"},
		"other backend": {Backend: "local2", Type: "openai", Target: "http://localhost:11434"},
	} {
		if s.Covers(other, consent.ScopeAction) {
			t.Errorf("%s is covered", name)
		}
	}
	if s.Covers(id, consent.ScopeAction, consent.ScopePII) {
		t.Error("a wider scope is covered without new consent")
	}
	info, err := os.Stat(filepath.Join(s.Dir, consent.FileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("consent file mode = %v, %v", info.Mode(), err)
	}
}

func TestGrantReplacesAndRevokeRemoves(t *testing.T) {
	s := consent.Store{Dir: t.TempDir()}
	old := local()
	moved := old
	moved.Target = "http://localhost:8080"
	jev := consent.Identity{Backend: "jev", Type: "typesafe", Target: "https://api.typesafe.ai:443"}
	for _, g := range []consent.Identity{old, jev, moved} {
		if err := s.Grant(g, []consent.Scope{consent.ScopeAction}, now); err != nil {
			t.Fatal(err)
		}
	}
	records, err := s.Load()
	if err != nil || len(records) != 2 || records[0].Backend != "jev" || records[1].Target != moved.Target || !records[1].Granted.Equal(now) {
		t.Fatalf("records = %+v, %v", records, err)
	}
	if s.Covers(old, consent.ScopeAction) || !s.Covers(moved, consent.ScopeAction) {
		t.Error("the new grant must replace the old one for the same backend name")
	}
	if removed, err := s.Revoke("local"); err != nil || !removed {
		t.Fatalf("Revoke = %v, %v", removed, err)
	}
	if removed, _ := s.Revoke("local"); removed {
		t.Error("revoking twice reported a removal")
	}
	if s.Covers(moved, consent.ScopeAction) || !s.Covers(jev, consent.ScopeAction) {
		t.Error("Revoke removed the wrong record")
	}
}

func TestCorruptRecordIsNoConsent(t *testing.T) {
	for name, content := range map[string]string{
		"not json":       "{",
		"empty":          "",
		"no version":     `{"records": [{"backend": "local", "type": "openai", "target": "http://localhost:11434", "scopes": ["action"]}]}`,
		"unknown scope":  `{"version": 1, "records": [{"backend": "local", "type": "openai", "target": "http://localhost:11434", "scopes": ["everything"]}]}`,
		"missing target": `{"version": 1, "records": [{"backend": "local", "type": "openai", "scopes": ["action"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := consent.Store{Dir: t.TempDir()}
			os.WriteFile(filepath.Join(s.Dir, consent.FileName), []byte(content), 0o600)
			if _, err := s.Load(); !errors.Is(err, consent.ErrCorrupt) {
				t.Errorf("Load err = %v", err)
			}
			if s.Covers(local(), consent.ScopeAction) {
				t.Error("a corrupt record is covered")
			}
			if err := s.Grant(local(), []consent.Scope{consent.ScopeAction}, now); err != nil || !s.Covers(local(), consent.ScopeAction) {
				t.Errorf("Grant over a corrupt record: %v", err)
			}
		})
	}
}

func TestNewerVersionIsNotOverwritten(t *testing.T) {
	s := consent.Store{Dir: t.TempDir()}
	path := filepath.Join(s.Dir, consent.FileName)
	newer := `{"version": 2, "records": []}`
	os.WriteFile(path, []byte(newer), 0o600)
	if s.Covers(local(), consent.ScopeAction) {
		t.Error("a newer record is covered")
	}
	if err := s.Grant(local(), []consent.Scope{consent.ScopeAction}, now); !errors.Is(err, consent.ErrNewerVersion) {
		t.Errorf("Grant = %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != newer {
		t.Errorf("the newer record was overwritten: %s", b)
	}
}

func TestGrantNeedsTheLock(t *testing.T) {
	s := consent.Store{Dir: t.TempDir()}
	unlock, err := store.Lock(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := s.Grant(local(), []consent.Scope{consent.ScopeAction}, now); !errors.Is(err, store.ErrLocked) {
		t.Errorf("Grant while locked = %v", err)
	}
}

func TestGrantRejectsBadInput(t *testing.T) {
	s := consent.Store{Dir: t.TempDir()}
	for name, g := range map[string]struct {
		id     consent.Identity
		scopes []consent.Scope
	}{
		"no target":     {consent.Identity{Backend: "b", Type: "openai"}, []consent.Scope{consent.ScopeAction}},
		"no scope":      {local(), nil},
		"unknown scope": {local(), []consent.Scope{"all"}},
	} {
		if err := s.Grant(g.id, g.scopes, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// opaque 是没有实现 judge.Describer 的后端：无法确定它把数据发到哪里，也就无法同意。
type opaque struct{ judge.Backend }

// TestIdentityOfBackends：同意身份取自后端的 Describe（spec §8.5 身份表）。主机、端口、scheme、
// exec 程序或参数任一变化，身份随之变化。
func TestIdentityOfBackends(t *testing.T) {
	newOpenAI := func(base string) judge.Backend {
		b, err := openai.New("local", openai.Options{Model: "m", BaseURL: base})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	newExec := func(cmd string, args ...string) judge.Backend {
		b, err := exec.New("x", exec.Options{Command: cmd, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ts, _ := typesafe.New("jev", typesafe.Options{Model: "jev-latest", APIKeyEnv: "TYPESAFE_API_KEY"})
	an, _ := anthropic.New("claude", anthropic.Options{Model: "claude-haiku"})
	want := map[string]judge.Backend{
		"http://localhost:11434":        newOpenAI("http://localhost:11434/v1"),
		"http://localhost:80":           newOpenAI("http://localhost/v1"),
		"https://localhost:11434":       newOpenAI("https://localhost:11434/v1"),
		"https://api.typesafe.ai:443":   ts,
		"https://api.anthropic.com:443": an,
		`"/opt/judge" "--fast"`:         newExec("/opt/judge", "--fast"),
		`"/opt/judge"`:                  newExec("/opt/judge"),
	}
	for target, b := range want {
		id, ok := consent.IdentityOf(b.Name(), "t", b)
		if !ok || id.Target != target {
			t.Errorf("IdentityOf = %+v, %v; want target %q", id, ok, target)
		}
	}
	if _, ok := consent.IdentityOf("x", "t", opaque{}); ok {
		t.Error("a backend without Describe has an identity")
	}
}

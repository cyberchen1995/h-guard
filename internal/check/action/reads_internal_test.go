package action

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
)

// TestExpandBraces：逗号写法与序列写法（{x..y[..incr]}）都展开，超过上限时报告没有展开完。
func TestExpandBraces(t *testing.T) {
	for in, want := range map[string][]string{
		".{env,example}": {".{env,example}", ".env", ".example"},
		".en{u..v}":      {".en{u..v}", ".enu", ".env"},
		"f{1..3}":        {"f{1..3}", "f1", "f2", "f3"},
		"f{3..1}":        {"f{3..1}", "f3", "f2", "f1"},
		"f{01..10..4}":   {"f{01..10..4}", "f01", "f05", "f09"},
		"f{-1..1}":       {"f{-1..1}", "f-1", "f0", "f1"},
		"f{a..e..2}":     {"f{a..e..2}", "fa", "fc", "fe"},
		"f{x}":           {"f{x}"},
		"f{1..b}":        {"f{1..b}"},
		"${HOME}/.{a,b}": {"${HOME}/.{a,b}", "${HOME}/.a", "${HOME}/.b"},
		"{x}.{a,b}":      {"{x}.{a,b}", "{x}.a", "{x}.b"},
		"{a,b}{1..2}":    {"{a,b}{1..2}", "a{1..2}", "b{1..2}", "a1", "a2", "b1", "b2"},
	} {
		got, complete := expandBraces(in)
		if !complete || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v, want %q", in, got, complete, want)
		}
	}
	for _, in := range []string{"f{1..100000}", "f{1..99999999999999999999}", "{a..z}{a..z}{a..z}"} {
		if _, complete := expandBraces(in); complete {
			t.Errorf("%q: complete, want over the limit", in)
		}
	}
}

// TestGlobReadUnreadable：读不了的目录（这里用符号链接环路，root 也读不了）不当作没有匹配。
func TestGlobReadUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	_, bad, err := globRead(context.Background(), filepath.Join(dir, "loop", "id_rsa*"), false, false)
	if err != nil || bad == nil || bad.dir != filepath.Join(dir, "loop") {
		t.Errorf("loop: %+v %v", bad, err)
	}
	// 不存在的目录与不是目录的路径里没有文件
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"missing/x*", "f/x*", "missing/*/x"} {
		if m, bad, err := globRead(context.Background(), filepath.Join(dir, p), false, false); len(m) > 0 || bad != nil || err != nil {
			t.Errorf("%s: %q %+v %v", p, m, bad, err)
		}
	}
	if os.Geteuid() == 0 {
		return // root 读得了权限不够的目录
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	for _, p := range []string{"locked/id_rsa*", "locked/*/x", "lo*/x*"} {
		if _, bad, _ := globRead(context.Background(), filepath.Join(dir, p), false, false); bad == nil || bad.dir == "" {
			t.Errorf("%s: no unreadable directory reported", p)
		}
	}
	if _, bad := walkRead(context.Background(), dir, &command.Walk{Hidden: true}); bad == nil || bad.dir != locked {
		t.Errorf("walk: %+v", bad)
	}
}

// TestGlobstar：shopt -s globstar 时 ** 匹配零层或多层目录，不进入以点开头的目录（除非 dotglob）。
func TestGlobstar(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.md", "x/b.md", "x/y/.env", ".hidden/c.md", "x/y/z/d.txt"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rel := func(ms []string) []string {
		var out []string
		for _, m := range ms {
			r, _ := filepath.Rel(dir, m)
			out = append(out, filepath.ToSlash(r))
		}
		slices.Sort(out)
		return out
	}
	for _, tc := range []struct {
		pat  string
		dot  bool
		want []string
	}{
		{"**/*.md", false, []string{"a.md", "x/b.md"}},
		{"**/*.md", true, []string{".hidden/c.md", "a.md", "x/b.md"}},
		{"**/.env", false, []string{"x/y/.env"}},
		{"x/**", false, []string{"x", "x/b.md", "x/y", "x/y/z", "x/y/z/d.txt"}},
		{"*/**/d.txt", false, []string{"x/y/z/d.txt"}},
	} {
		m, bad, err := globRead(context.Background(), filepath.Join(dir, tc.pat), tc.dot, true)
		if err != nil || bad != nil || !slices.Equal(rel(m), tc.want) {
			t.Errorf("%s (dot %v): %q %+v %v, want %q", tc.pat, tc.dot, rel(m), bad, err, tc.want)
		}
	}
}

// TestWalkRead：递归读取按隐藏、包含、排除的设置收集文件，超过上限时报告问题。
func TestWalkRead(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"a.go", "b.md", ".env", "sub/c.go", ".git/config", "vendor/d.go"} {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := func(ms []string) string {
		var out []string
		for _, m := range ms {
			r, _ := filepath.Rel(dir, m)
			out = append(out, filepath.ToSlash(r))
		}
		slices.Sort(out)
		return strings.Join(out, " ")
	}
	for _, tc := range []struct {
		walk command.Walk
		want string
	}{
		{command.Walk{}, "a.go b.md sub/c.go vendor/d.go"},
		{command.Walk{Hidden: true}, ".env .git/config a.go b.md sub/c.go vendor/d.go"},
		{command.Walk{Hidden: true, Include: []string{"*.go"}, ExcludeDir: []string{"vendor"}}, "a.go sub/c.go"},
		{command.Walk{Hidden: true, Exclude: []string{".env*", "*.md"}}, ".git/config a.go sub/c.go vendor/d.go"},
	} {
		got, bad := walkRead(context.Background(), dir, &tc.walk)
		if bad != nil || names(got) != tc.want {
			t.Errorf("%+v: %q %+v, want %q", tc.walk, names(got), bad, tc.want)
		}
	}
	if got, bad := walkRead(context.Background(), filepath.Join(dir, "a.go"), &command.Walk{}); got != nil || bad != nil {
		t.Errorf("file root: %q %+v", got, bad)
	}
	big := t.TempDir()
	for i := 0; i <= maxGlobMatches; i++ {
		if err := os.WriteFile(filepath.Join(big, fmt.Sprintf("f%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, bad := walkRead(context.Background(), big, &command.Walk{}); bad == nil || bad.dir != "" {
		t.Errorf("over the limit: %+v", bad)
	}
}

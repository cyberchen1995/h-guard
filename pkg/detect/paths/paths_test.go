package paths_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/paths"
)

// real 返回 dir 的真实路径（macOS 的临时目录在 /var → /private/var 符号链接之下）。
func real(t *testing.T, dir string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveExpandsHomeAndCwd(t *testing.T) {
	env := paths.Env{Home: "/home/u", Cwd: "/home/u/proj", Lexical: true}
	for in, want := range map[string]string{
		"~":              "/home/u",
		"~/x/../y":       "/home/u/y",
		"a/./b":          "/home/u/proj/a/b",
		"../other/f":     "/home/u/other/f",
		"/etc//passwd/.": "/etc/passwd",
	} {
		r := paths.Resolve(in, env)
		if r.Clean != filepath.FromSlash(want) || r.Real != "" || r.Err != nil {
			t.Errorf("Resolve(%q) = %+v, want Clean %q", in, r, want)
		}
	}
}

func TestResolveWithoutCwdOrHome(t *testing.T) {
	r := paths.Resolve("a/../b/c", paths.Env{})
	if r.Clean != filepath.FromSlash("b/c") || !errors.Is(r.Err, paths.ErrRelative) {
		t.Errorf("relative without cwd: %+v", r)
	}
	r = paths.Resolve("~/x", paths.Env{Cwd: "/w"})
	if r.Clean != filepath.FromSlash("~/x") || !errors.Is(r.Err, paths.ErrNoHome) {
		t.Errorf("~ without home: %+v", r)
	}
}

func TestResolveFollowsSymlinksOnTheExistingPrefix(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "real"), 0o755)
	if err := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	r := paths.Resolve("link/new/file.txt", paths.Env{Cwd: dir})
	want := filepath.Join(real(t, dir), "real", "new", "file.txt")
	if r.Err != nil || r.Real != want || r.Clean != filepath.Join(dir, "link", "new", "file.txt") {
		t.Errorf("got %+v, want Real %q", r, want)
	}
	if c := r.Candidates(); len(c) != 2 || c[0] != r.Clean || c[1] != r.Real {
		t.Errorf("Candidates() = %q", c)
	}
}

// 指向不存在文件的符号链接：写入它会创建链接目标，所以解析结果是目标路径。
func TestResolveDanglingSymlinkPointsAtItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "home", ".claude", "settings.json")
	if err := os.Symlink(target, filepath.Join(dir, "notes.txt")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	r := paths.Resolve(filepath.Join(dir, "notes.txt"), paths.Env{})
	if r.Err != nil || r.Real != filepath.Join(real(t, dir), "home", ".claude", "settings.json") {
		t.Errorf("got %+v", r)
	}
}

// 链接之后的 .. 按真实位置回退（与 shell 打开文件的语义一致），不按字面抵消。
func TestResolveDotDotAfterSymlink(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a", "deep"), 0o755)
	if err := os.Symlink(filepath.Join(dir, "a", "deep"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	// 链接 a/deep/up → ../x：.. 从 a/deep 回退到 a，而不是从 link 的字面位置回退
	os.Symlink("../x", filepath.Join(dir, "a", "deep", "up"))
	r := paths.Resolve(filepath.Join(dir, "link", "up"), paths.Env{})
	if r.Err != nil || r.Real != filepath.Join(real(t, dir), "a", "x") {
		t.Errorf("got %+v", r)
	}
}

func TestResolveLoopIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "b"), filepath.Join(dir, "a")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	os.Symlink(filepath.Join(dir, "a"), filepath.Join(dir, "b"))
	r := paths.Resolve(filepath.Join(dir, "a", "f"), paths.Env{})
	if !errors.Is(r.Err, paths.ErrLoop) || r.Real != "" || r.Clean != filepath.Join(dir, "a", "f") {
		t.Errorf("got %+v", r)
	}
	if c := r.Candidates(); len(c) != 1 || c[0] != r.Clean {
		t.Errorf("Candidates() = %q", c)
	}
}

var guardPatterns = []string{
	"~/.config/h-guard/**",
	"{config}/**",
	"~/.claude/settings.json",
	"**/.claude/settings.json",
	"**/.codex/*.toml",
}

func match(t *testing.T, env paths.Env, path string) bool {
	t.Helper()
	m, err := paths.Compile(guardPatterns, env)
	if err != nil {
		t.Fatal(err)
	}
	return m.Match(paths.Resolve(path, env))
}

func TestPatternSemantics(t *testing.T) {
	env := paths.Env{Home: "/home/u", Cwd: "/home/u/proj", Vars: map[string]string{"config": "/xdg/h-guard"}, Lexical: true}
	for path, want := range map[string]bool{
		"~/.config/h-guard/config.yaml":     true,
		"~/.config/h-guard":                 true, // 末尾的 /** 也匹配目录本身
		"~/.config/h-guard-other/x":         false,
		"/xdg/h-guard/consent.json":         true,
		"/xdg/h-guardx":                     false,
		"~/.claude/settings.json":           true,
		"~/.claude/settings.json.bak":       false,
		".claude/settings.json":             true, // **/ 匹配零级目录，相对路径基于 cwd
		"/srv/app/.claude/settings.json":    true,
		"/srv/app/x.claude/settings.json":   false,
		"/srv/.codex/config.toml":           true,
		"/srv/.codex/sub/config.toml":       false, // * 不跨目录
		"~/.claude/settings.local.json":     false,
		"~/proj/src/main.go":                false,
		"/home/u/.config/h-guard/rules/a.y": true,
	} {
		if got := match(t, env, path); got != want {
			t.Errorf("match(%q) = %v, want %v", path, got, want)
		}
	}
	// 占位符没有值时，该模式不匹配
	env.Vars = nil
	if match(t, env, "/xdg/h-guard/consent.json") {
		t.Error("{config} without a value matched")
	}
	env.Home = ""
	if match(t, env, "/home/u/.config/h-guard/config.yaml") {
		t.Error("~ without a home matched")
	}
}

func TestFoldCase(t *testing.T) {
	env := paths.Env{Home: "/home/u", Lexical: true}
	if match(t, env, "/home/u/.Claude/Settings.JSON") {
		t.Error("case-sensitive env matched a different case")
	}
	env.FoldCase = true
	if !match(t, env, "/home/u/.Claude/Settings.JSON") {
		t.Error("case-insensitive env did not match")
	}
}

// 受保护文件本身是符号链接（dotfiles 仓库）：改链接目标同样命中。
func TestPatternRootsAreResolvedToo(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, "dotfiles", "claude"), 0o755)
	os.WriteFile(filepath.Join(home, "dotfiles", "claude", "settings.json"), []byte("{}"), 0o600)
	os.Mkdir(filepath.Join(home, ".claude"), 0o755)
	if err := os.Symlink(filepath.Join(home, "dotfiles", "claude", "settings.json"), filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	env := paths.Env{Home: home, Cwd: filepath.Join(home, "dotfiles")}
	if !match(t, env, "claude/settings.json") {
		t.Error("editing the symlink target of ~/.claude/settings.json did not match")
	}
	// 经过符号链接的目录写入受保护目录
	os.MkdirAll(filepath.Join(home, ".config", "h-guard"), 0o755)
	os.Symlink(filepath.Join(home, ".config", "h-guard"), filepath.Join(home, "proj-link"))
	if !match(t, env, filepath.Join(home, "proj-link", "config.yaml")) {
		t.Error("writing through a symlinked directory did not match")
	}
	if match(t, env, filepath.Join(home, "dotfiles", "README.md")) {
		t.Error("unrelated file matched")
	}
}

func TestValidPattern(t *testing.T) {
	for _, p := range append(guardPatterns, "/etc/h-guard/*.yaml", "{cache}", "~/Library/Application Support/h-guard/**") {
		if err := paths.ValidPattern(p); err != nil {
			t.Errorf("ValidPattern(%q) = %v", p, err)
		}
	}
	for _, p := range []string{"", "relative/x", "{Config}/x", "{config}x", "~user/x", "~/a/../b", "/a/./b", "*/x"} {
		if err := paths.ValidPattern(p); err == nil {
			t.Errorf("ValidPattern(%q) accepted", p)
		}
	}
	if name, ok := paths.Placeholder("{cache}/**"); !ok || name != "cache" {
		t.Errorf("Placeholder = %q, %v", name, ok)
	}
	if _, ok := paths.Placeholder("~/x"); ok {
		t.Error("Placeholder(~/x) reported a placeholder")
	}
}

// TestResolveKeepsDotDotAfterAnInputSymlink：输入路径里「符号链接后接 ..」按操作系统的语义解析：
// .. 从链接目标回退，不能先 Clean 抵消。绝对与相对路径都一样。
func TestResolveKeepsDotDotAfterAnInputSymlink(t *testing.T) {
	root := t.TempDir()
	project, conf := filepath.Join(root, "project"), filepath.Join(root, "configuration")
	os.MkdirAll(project, 0o755)
	os.MkdirAll(filepath.Join(conf, "nested"), 0o755)
	if err := os.Symlink(filepath.Join(conf, "nested"), filepath.Join(project, "alias")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	protected := filepath.Join(conf, "config.yaml")
	os.WriteFile(protected, []byte("version: 1"), 0o600)
	m, err := paths.Compile([]string{"{config}/**"}, paths.Env{Vars: map[string]string{"config": conf}})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{project + "/alias/../config.yaml", "alias/../config.yaml"} {
		r := paths.Resolve(in, paths.Env{Cwd: project})
		got, _ := os.Stat(r.Real)
		want, _ := os.Stat(protected)
		if r.Err != nil || got == nil || !os.SameFile(got, want) || !m.Match(r) {
			t.Errorf("Resolve(%q) = %+v; want the protected file and a match", in, r)
		}
		if r.Clean != filepath.Join(project, "config.yaml") {
			t.Errorf("Clean = %q, want the lexical form", r.Clean)
		}
	}
}

// TestSymlinkedFilesInsideProtectedPlaces：受保护的目录里有指向别处的符号链接（配置目录里的 config.yaml），
// 或项目里的 hook 配置是符号链接时，直接改链接目标同样命中。
func TestSymlinkedFilesInsideProtectedPlaces(t *testing.T) {
	root := t.TempDir()
	home, project, conf := filepath.Join(root, "home"), filepath.Join(root, "project"), filepath.Join(root, "configuration")
	for _, d := range []string{home, filepath.Join(project, ".claude"), filepath.Join(project, "src"), conf} {
		os.MkdirAll(d, 0o755)
	}
	target1, target2, other := filepath.Join(root, "dotfiles-config.yaml"), filepath.Join(root, "dotfiles-settings.json"), filepath.Join(root, "unrelated.json")
	for _, f := range []string{target1, target2, other} {
		os.WriteFile(f, []byte("{}"), 0o600)
	}
	if err := os.Symlink(target1, filepath.Join(conf, "config.yaml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	os.Symlink(target2, filepath.Join(project, ".claude", "settings.json"))
	patterns := []string{"{config}/**", "**/.claude/settings.json"}
	for _, cwd := range []string{project, filepath.Join(project, "src")} { // cwd 是项目根或其子目录
		env := paths.Env{Home: home, Cwd: cwd, Vars: map[string]string{"config": conf}}
		m, err := paths.Compile(patterns, env)
		if err != nil {
			t.Fatal(err)
		}
		for path, want := range map[string]bool{target1: true, target2: true, other: false} {
			if got := m.Match(paths.Resolve(path, env)); got != want {
				t.Errorf("cwd %s: Match(%s) = %v, want %v", cwd, filepath.Base(path), got, want)
			}
		}
	}
	// 按字面匹配（规则样例）时不访问文件系统，不产生别名
	lex := paths.Env{Home: home, Cwd: project, Vars: map[string]string{"config": conf}, Lexical: true}
	if m, _ := paths.Compile(patterns, lex); m.Match(paths.Resolve(target1, lex)) {
		t.Error("a lexical matcher followed a symlink")
	}
}

// TestLargeProtectedDirectoryIsReportedIncomplete：受保护目录超过扫描上限时，Matcher 报告别名不完整，
// 不把「没扫到」当作没有链接；写出固定路径的文件不依赖扫描，链接目标照样受保护。
// 目录不存在不算不完整。
func TestLargeProtectedDirectoryIsReportedIncomplete(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "conf")
	os.Mkdir(conf, 0o755)
	for i := 0; i < 4100; i++ {
		if err := os.WriteFile(filepath.Join(conf, "b"+strconv.Itoa(i)+".bak"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "active.yaml")
	os.WriteFile(target, []byte("version: 1"), 0o600)
	if err := os.Symlink(target, filepath.Join(conf, "config.yaml")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	env := paths.Env{Vars: map[string]string{"config": conf}}
	if m, _ := paths.Compile([]string{"{config}/**"}, env); m.Complete() {
		t.Error("a directory over the scan limit was reported complete")
	}
	if m, _ := paths.Compile([]string{"{config}/config.yaml"}, env); !m.Complete() || !m.Match(paths.Resolve(target, env)) {
		t.Error("an explicit file pattern must protect its symlink target without scanning")
	}
	for name, dir := range map[string]string{"small": t.TempDir(), "missing": filepath.Join(root, "nope")} {
		if m, _ := paths.Compile([]string{"{config}/**"}, paths.Env{Vars: map[string]string{"config": dir}}); !m.Complete() {
			t.Errorf("%s directory reported incomplete", name)
		}
	}
}

// 路径里的目录名可以含换行符：通配的 `.` 默认不匹配换行，这类路径会漏掉（fail-open）。
// 字面匹配，不访问文件系统。
func TestNewlineInPathIsMatchedByWildcards(t *testing.T) {
	patterns := []string{"**/.claude/settings.json", "/x/cfg/**", "/x/**/y"}
	env := paths.Env{Home: "/home/u", Lexical: true}
	m, err := paths.Compile(patterns, env)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/home/u/a\nb/.claude/settings.json",
		"/x/cfg/sub\ndir/f",
		"/x/a\nb/y",
	} {
		if !m.Match(paths.Resolve(path, env)) {
			t.Errorf("Match(%q) = false, want true", path)
		}
	}
	if m.Match(paths.Resolve("/home/u/a\nb/.claude/settings.json.bak", env)) {
		t.Error("a path with a newline matched a pattern it should not")
	}
	// 不区分大小写时两个标志都要生效
	env.FoldCase = true
	fm, err := paths.Compile(patterns, env)
	if err != nil {
		t.Fatal(err)
	}
	if !fm.Match(paths.Resolve("/home/u/A\nB/.Claude/Settings.JSON", env)) {
		t.Error("case-insensitive matcher missed a path with a newline")
	}
}

// TestRootAliasesAreStripped：指向根目录的别名前缀（macOS 的 /System/Volumes/Data）之下的路径与去掉前缀后的路径
// 是同一个文件，realpath 不改写它，所以去掉前缀的写法另作候选。不区分大小写时前缀同样不区分大小写。
func TestRootAliasesAreStripped(t *testing.T) {
	env := paths.Env{Home: "/home/u", RootAliases: []string{"/alias"}}
	m, err := paths.Compile([]string{"~/.config/h-guard/**"}, env)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]bool{
		"/alias/home/u/.config/h-guard/x":  true,
		"/alias/tmp/x":                     false,
		"/aliasx/home/u/.config/h-guard/x": false,
		"/ALIAS/home/u/.config/h-guard/x":  false, // 区分大小写
	} {
		if got := m.Match(paths.Resolve(path, env)); got != want {
			t.Errorf("Match(%q) = %v, want %v", path, got, want)
		}
	}
	if r := paths.Resolve("/alias", env); !slices.Contains(r.Candidates(), "/") {
		t.Errorf("the alias itself is the root: Candidates() = %q", r.Candidates())
	}
	env.FoldCase = true
	m, err = paths.Compile([]string{"~/.config/h-guard/**"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(paths.Resolve("/ALIAS/home/u/.config/h-guard/x", env)) {
		t.Error("a case-insensitive env missed the alias in another case")
	}
	// 空列表关闭；按字面匹配（规则样例）时不处理别名
	for _, e := range []paths.Env{{Home: "/home/u", RootAliases: []string{}}, {Home: "/home/u", RootAliases: []string{"/alias"}, Lexical: true}} {
		m, _ := paths.Compile([]string{"~/.config/h-guard/**"}, e)
		if m.Match(paths.Resolve("/alias/home/u/.config/h-guard/x", e)) {
			t.Errorf("env %+v stripped the alias", e)
		}
	}
}

// TestOpaquePathsMatchAnyPattern：无法映射到规范位置的前缀（macOS 的 /.vol、Linux 的 /proc）之下的目标
// 可能就是受保护的文件，有模式的 Matcher 一律按命中处理（fail-closed）；没有模式的 Matcher 不命中。
func TestOpaquePathsMatchAnyPattern(t *testing.T) {
	env := paths.Env{Home: "/home/u", Opaque: []string{"/opq"}}
	m, err := paths.Compile([]string{"/etc/unrelated/**"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if r := paths.Resolve("/opq/1/2", env); !r.Opaque || !m.Match(r) {
		t.Errorf("an opaque target did not match: %+v", r)
	}
	if r := paths.Resolve("/opq", env); !r.Opaque {
		t.Errorf("the opaque prefix itself is opaque: %+v", r)
	}
	if r := paths.Resolve("/opqx/1", env); r.Opaque || m.Match(r) {
		t.Errorf("/opqx is not under /opq: %+v", r)
	}
	// 全部模式都因缺少 ~ 而跳过：没有可匹配的模式，不命中
	empty, err := paths.Compile([]string{"~/.config/h-guard/**"}, paths.Env{Opaque: []string{"/opq"}})
	if err != nil {
		t.Fatal(err)
	}
	if empty.Match(paths.Resolve("/opq/1/2", paths.Env{Opaque: []string{"/opq"}})) {
		t.Error("an empty matcher matched an opaque target")
	}
	for _, e := range []paths.Env{{Opaque: []string{}}, {Opaque: []string{"/opq"}, Lexical: true}} {
		if r := paths.Resolve("/opq/1/2", e); r.Opaque {
			t.Errorf("env %+v marked the target opaque", e)
		}
	}
	env.FoldCase = true
	if r := paths.Resolve("/OPQ/1", env); !r.Opaque {
		t.Errorf("a case-insensitive env missed the opaque prefix: %+v", r)
	}
}

// TestDarwinFirmlinkAndVolfs：macOS 上 /System/Volumes/Data/<路径> 与 <路径> 是同一个文件，/.vol/<dev>/<ino> 按
// inode 打开文件；两者 realpath 都不改写。用平台默认值。
func TestDarwinFirmlinkAndVolfs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	d := filepath.Join(real(t, t.TempDir()), "d")
	os.Mkdir(d, 0o755)
	os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o600)
	firm := "/System/Volumes/Data" + d + "/f"
	if _, err := os.Stat(firm); err != nil {
		t.Skip("no firmlink to the data volume:", err)
	}
	env := paths.Env{FoldCase: paths.FoldCaseDefault}
	m, err := paths.Compile([]string{d + "/**"}, env)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Match(paths.Resolve(firm, env)) {
		t.Errorf("the firmlink path %s did not match", firm)
	}
	if !m.Match(paths.Resolve("/.vol/1/2", env)) {
		t.Error("a volfs path did not match")
	}
}

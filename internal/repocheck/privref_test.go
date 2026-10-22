package repocheck

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// privateRef 是只对开发过程有意义的写法：设计文档的章节号与路径、评审用例目录、
// 评审与验收的字样、任务编号、评审意见的编号、里程碑名。公开文件与公开提交说明里都不该出现。
var privateRef = []*regexp.Regexp{
	regexp.MustCompile(`§`),
	regexp.MustCompile(`docs/(superpowers|verification|reviews|research)`),
	regexp.MustCompile(`tests/review`),
	regexp.MustCompile(`评审|终审|设计裁定|已定决策|核实报告|验收记录`),
	// 不整词匹配 spec：internal/fixtures 里有变量 spec（spec := …）。
	regexp.MustCompile(`spec ?[：里与中]|spec:`),
	regexp.MustCompile(`\bTask [0-9]+\b`),
	regexp.MustCompile(`\b[MRHFGN][0-9][A-D]?-[0-9]{2}\b`),
	regexp.MustCompile(`\bM[0-9][A-D]?-[A-Z]?[0-9]+\b`),
	regexp.MustCompile(`\bR[0-9]-[A-Z]?[0-9]+\b`),
	regexp.MustCompile(`\b[CIM]-[0-9]+\b`),
	regexp.MustCompile(`\bM[0-5][a-d]?\b`),
}

// 唯一的豁免：testdata/fixtures/ 下的录制样本是真实 harness 录下的数据，
// 录制时让模型回复的原文是这个固定串，改写它就是篡改样本。
const (
	fixtureDir  = "testdata/fixtures/"
	fixtureText = "h-guard M0 test"
)

// lineHits 返回一行里命中的私有引用片段；只在 testdata/fixtures/ 下去掉豁免串后再匹配。
func lineHits(file, line string) []string {
	if strings.HasPrefix(file, fixtureDir) {
		line = strings.ReplaceAll(line, fixtureText, "")
	}
	var hits []string
	for _, re := range privateRef {
		if m := re.FindString(line); m != "" {
			hits = append(hits, m)
		}
	}
	return hits
}

func TestNoPrivateReferences(t *testing.T) {
	var bad []string
	for _, f := range trackedFiles(t) {
		if f == "internal/repocheck/privref_test.go" {
			continue
		}
		for i, line := range lines(t, f) {
			for _, m := range lineHits(f, line) {
				bad = append(bad, fmt.Sprintf("%s:%d: %q", f, i+1, m))
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("private references in public files (%d):\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

func TestPrivateRefPatterns(t *testing.T) {
	hit := []string{"见 spec §5.3", "docs/superpowers/plans/x.md", "tests/review_m1/", "（评审 I8）", "终审 M-7",
		"计划评审 M3B-03", "R2-01", "M4B-01", "C-1", "M3b 起", "（Task 6）", "spec：不可能的组合", "spec 里的稳定名字", "与核实报告"}
	miss := []string{"UTF-8", "SHA-256", "ISO-8601", "x86-64", "/Users/alice/project", "hg_m0_report", "RFC 6761", "m4b-dev",
		"spec := fixtures[i]", "inspect"}
	for _, s := range hit {
		if len(lineHits("pkg/x.go", s)) == 0 {
			t.Errorf("%q: no pattern matched", s)
		}
	}
	for _, s := range miss {
		if h := lineHits("pkg/x.go", s); len(h) > 0 {
			t.Errorf("%q: matched %q", s, h)
		}
	}
}

func TestFixtureExemption(t *testing.T) {
	const fixture = "testdata/fixtures/claudecode/stop.json"
	cases := []struct {
		file, line string
		want       bool
	}{
		{fixture, `{"last_assistant_message":"` + fixtureText + `"}`, false},
		{fixture, `"` + fixtureText + `" 见评审`, true},
		{fixture, `"` + fixtureText + `" M1`, true},
		{"testdata/golden/x.json", fixtureText, true},
		{"pkg/harness/x_test.go", fixtureText, true},
	}
	for _, c := range cases {
		if got := len(lineHits(c.file, c.line)) > 0; got != c.want {
			t.Errorf("lineHits(%q, %q) reported=%v, want %v", c.file, c.line, got, c.want)
		}
	}
}

// textHits 返回说明文字里逐行命中的私有引用片段。
func textHits(text string) []string {
	var hits []string
	for _, line := range strings.Split(text, "\n") {
		for _, re := range privateRef {
			if m := re.FindString(line); m != "" {
				hits = append(hits, fmt.Sprintf("%q in %q", m, line))
			}
		}
	}
	return hits
}

// commitHits 读提交的完整说明，返回命中的片段。
func commitHits(t *testing.T, dir, rev string) []string {
	t.Helper()
	out, err := gitCmd(dir, "log", "-1", "--format=%B", rev)
	if err != nil {
		t.Fatalf("git log %s: %v\n%s", rev, err, out)
	}
	return textHits(string(out))
}

func TestCommitMetadata(t *testing.T) {
	rev := os.Getenv("HG_COMMIT")
	if rev == "" {
		t.Skip("HG_COMMIT not set")
	}
	if h := commitHits(t, repoRoot(t), rev); len(h) > 0 {
		t.Errorf("commit %s message has private references:\n%s", rev, strings.Join(h, "\n"))
	}
	out, err := gitCmd(repoRoot(t), "log", "-1", "--format=%B", rev)
	if err != nil {
		t.Fatalf("git log %s: %v\n%s", rev, err, out)
	}
	if p := messageProblems(string(out), true); len(p) > 0 {
		t.Errorf("commit %s message breaks the convention in CONTRIBUTING.md:\n%s", rev, strings.Join(p, "\n"))
	}
}

// TestPullRequestMetadata 检查 PR 的标题与描述（HG_PR_TEXT_FILE 指向的文件）：PR 是 squash 合并的，
// 进 main 的提交说明来自这两处，不是分支上的提交。
func TestPullRequestMetadata(t *testing.T) {
	path := os.Getenv("HG_PR_TEXT_FILE")
	if path == "" {
		t.Skip("HG_PR_TEXT_FILE not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if h := textHits(string(b)); len(h) > 0 {
		t.Errorf("pull request title or description has private references:\n%s", strings.Join(h, "\n"))
	}
	if p := messageProblems(string(b), false); len(p) > 0 {
		t.Errorf("pull request title or description breaks the convention in CONTRIBUTING.md:\n%s", strings.Join(p, "\n"))
	}
}

func TestCommitMetadataPatterns(t *testing.T) {
	requireGit(t)
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		out, err := gitCmd(dir, args...)
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	commit := func(msg string) string {
		run("-c", "user.name=test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false",
			"commit", "-q", "--allow-empty", "-m", msg)
		return run("rev-parse", "HEAD")
	}
	bad := commit("fix: 终审 I-1")
	good := commit("fix: 发送前遮蔽开发文本")
	if h := commitHits(t, dir, bad); len(h) == 0 {
		t.Errorf("message with a review id was not reported")
	}
	if h := commitHits(t, dir, good); len(h) > 0 {
		t.Errorf("clean message reported: %v", h)
	}
	if h := textHits("feat: 接入 X\n\n见 docs/superpowers/plans/x.md"); len(h) != 1 {
		t.Errorf("pull request text with a private path: %v", h)
	}
}

// gitCmd 在 dir 里运行 git，不读用户与系统的 git 配置。
func gitCmd(dir string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return append(out, stderr.Bytes()...), err
	}
	return out, nil
}

// skipOrFatal 在缺少 git 等前提时跳过；CI 里不能悄悄跳过，改为失败。
func skipOrFatal(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") == "true" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		skipOrFatal(t, "git not found: %v", err)
	}
}

// repoRoot 是 go env GOMOD 所在的目录，并且要求它在 git 工作区里。
func repoRoot(t *testing.T) string {
	t.Helper()
	requireGit(t)
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	mod := strings.TrimSpace(string(out))
	if mod == "" || mod == os.DevNull {
		t.Fatalf("not inside a module")
	}
	root := filepath.Dir(mod)
	if out, err := gitCmd(root, "rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(string(out)) != "true" {
		skipOrFatal(t, "%s is not a git work tree: %v", root, err)
	}
	return root
}

// trackedFiles 列出公开仓库跟踪的与将要跟踪的文件（未被忽略的新文件也算），
// 相对路径、斜杠分隔；去掉已删除的文件与含 NUL 字节的二进制文件。
func trackedFiles(t *testing.T) []string {
	t.Helper()
	root := repoRoot(t)
	out, err := gitCmd(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		t.Fatalf("git ls-files: %v\n%s", err, out)
	}
	seen := map[string]bool{}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		path := filepath.Join(root, filepath.FromSlash(f))
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.IsDir() { // 子模块
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue
		}
		files = append(files, f)
	}
	return files
}

// lines 返回文件的各行（去掉行尾的 \r）。
func lines(t *testing.T, rel string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	ls := strings.Split(string(b), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

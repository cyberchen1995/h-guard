package repocheck

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// maxSubject 是标题行的最大长度（字符数）。
const maxSubject = 72

// subjectRe 是标题行的格式：<type>(<scope>): <subject>，scope 可选，type 后可带 ! 表示不兼容变更。
var subjectRe = regexp.MustCompile(`^(feat|fix|docs|test|perf|refactor|ci|build|chore|revert)(\([a-z0-9][a-z0-9/_.-]*\))?!?: \S`)

// trailerRe 是页脚（署名等），其中的人名不受英文要求约束。
var trailerRe = regexp.MustCompile(`(?i)^(co-authored-by|signed-off-by|reviewed-by|reported-by|acked-by):`)

// isCJK 判断字符是否属于中日韩文字或全角标点。
func isCJK(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) ||
		(r >= 0x3000 && r <= 0x303F) || (r >= 0xFF00 && r <= 0xFFEF)
}

// messageProblems 检查提交说明（或 PR 的标题加描述）是否符合 CONTRIBUTING.md 的约定，返回不符合的各项。
// allowGit 为 true 时放过 git 自己生成的 Merge 与 Revert 说明。
func messageProblems(msg string, allowGit bool) []string {
	msg = strings.ReplaceAll(msg, "\r\n", "\n")
	msg = strings.TrimSpace(msg)
	lines := strings.Split(msg, "\n")
	subject := lines[0]
	if allowGit && (strings.HasPrefix(subject, "Merge ") || strings.HasPrefix(subject, `Revert "`)) {
		return nil
	}

	var p []string
	if !subjectRe.MatchString(subject) {
		p = append(p, fmt.Sprintf("subject %q must look like \"type(scope): text\" with type in feat, fix, docs, test, perf, refactor, ci, build, chore, revert", subject))
	}
	if n := utf8.RuneCountInString(subject); n > maxSubject {
		p = append(p, fmt.Sprintf("subject is %d characters, limit is %d", n, maxSubject))
	}
	if strings.HasSuffix(subject, ".") {
		p = append(p, "subject must not end with a period")
	}
	if len(lines) > 1 && strings.TrimSpace(lines[1]) != "" {
		p = append(p, "second line must be blank")
	}
	for i, line := range lines {
		if i > 0 && trailerRe.MatchString(line) {
			continue
		}
		if strings.IndexFunc(line, isCJK) >= 0 {
			p = append(p, fmt.Sprintf("line %d is not in English: %q", i+1, line))
		}
	}
	return p
}

func TestMessageProblems(t *testing.T) {
	good := []string{
		"feat: add opencode support",
		"fix(rules): reject six bypasses of the catastrophic rule",
		"feat(cli)!: drop the --legacy flag\n\nBREAKING CHANGE: the flag is gone.",
		"ci: run race tests on ubuntu only\n\nWindows and macOS stay build-only.\n\nCo-Authored-By: 陈 <a@example.com>",
		"docs: explain the verdict order\r\n\r\nbody",
	}
	bad := []string{
		"接入 OpenClaw",
		"feat: 接入 OpenClaw",
		"feat: add support。",
		"Add support",
		"feature: add support",
		"feat:add support",
		"feat(Rules): add support",
		"feat: add support.",
		"feat: " + strings.Repeat("a", maxSubject),
		"feat: add support\nbody right after the subject",
		"feat: add support\n\n这一行是中文",
	}
	for _, s := range good {
		if p := messageProblems(s, false); len(p) > 0 {
			t.Errorf("%q reported: %v", s, p)
		}
	}
	for _, s := range bad {
		if p := messageProblems(s, false); len(p) == 0 {
			t.Errorf("%q not reported", s)
		}
	}
	for _, s := range []string{"Merge branch 'main' into x", `Revert "feat: 接入 X"`} {
		if p := messageProblems(s, true); len(p) > 0 {
			t.Errorf("git-generated %q reported: %v", s, p)
		}
		if p := messageProblems(s, false); len(p) == 0 {
			t.Errorf("%q allowed outside commits", s)
		}
	}
}

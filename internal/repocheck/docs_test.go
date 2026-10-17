package repocheck

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// mdLink 是 Markdown 的行内链接与图片：[文字](目标) 或 [文字](目标 "标题")。
var mdLink = regexp.MustCompile(`\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)`)

// fence 是围栏代码块的开始或结束行（``` 或 ~~~，前面最多三个空格）。
var fence = regexp.MustCompile("^ {0,3}(```|~~~)")

// proseLines 返回 Markdown 的各行，围栏代码块里的行（含围栏本身）换成空串：代码块里的内容不是链接或标题。
func proseLines(ls []string) []string {
	out := make([]string, len(ls))
	in := false
	for i, l := range ls {
		if fence.MatchString(l) {
			in = !in
			continue
		}
		if !in {
			out[i] = l
		}
	}
	return out
}

// externalLink 报告链接是否不指向仓库里的文件：网址、页内锚点与邮件地址。
func externalLink(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
		strings.HasPrefix(target, "#") || strings.HasPrefix(target, "mailto:")
}

// TestMarkdownLinks：跟踪的 *.md 里的相对链接（去掉 #锚点）都指向跟踪的文件或目录。
// 只检查行内链接 [文字](目标)，不检查引用式链接 [文字][标签]。
func TestMarkdownLinks(t *testing.T) {
	files := trackedFiles(t)
	exists := map[string]bool{}
	for _, f := range files {
		exists[f] = true
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			exists[d] = true
		}
	}
	var bad []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".md") {
			continue
		}
		for i, l := range proseLines(lines(t, f)) {
			for _, m := range mdLink.FindAllStringSubmatch(l, -1) {
				if externalLink(m[1]) {
					continue
				}
				target, _, _ := strings.Cut(m[1], "#")
				resolved := path.Clean(path.Join(path.Dir(f), target))
				if resolved == ".." || strings.HasPrefix(resolved, "../") || !exists[resolved] {
					bad = append(bad, fmt.Sprintf("%s:%d: %s", f, i+1, m[1]))
				}
			}
		}
	}
	if len(bad) > 0 {
		t.Errorf("relative links to files that are not tracked (%d):\n%s", len(bad), strings.Join(bad, "\n"))
	}
}

// readmeShape 返回 README 的二级标题与围栏代码块的数量（代码块里的 ## 不算标题）。
func readmeShape(t *testing.T, file string) (headings []string, blocks int) {
	t.Helper()
	in := false
	for _, l := range lines(t, file) {
		if fence.MatchString(l) {
			if !in {
				blocks++
			}
			in = !in
			continue
		}
		if !in && strings.HasPrefix(l, "## ") {
			headings = append(headings, strings.TrimSpace(strings.TrimPrefix(l, "## ")))
		}
	}
	if in {
		t.Errorf("%s: unterminated code block", file)
	}
	return headings, blocks
}

// TestReadmeParity：英文与中文 README 的二级标题数量相同、围栏代码块数量相同（只比数量，不核对标题是否互为翻译）。
func TestReadmeParity(t *testing.T) {
	enH, enB := readmeShape(t, "README.md")
	zhH, zhB := readmeShape(t, "README.zh-CN.md")
	if len(enH) == 0 {
		t.Errorf("README.md has no level-2 headings")
	}
	if len(enH) != len(zhH) {
		t.Errorf("level-2 headings: README.md has %d %q, README.zh-CN.md has %d %q", len(enH), enH, len(zhH), zhH)
	}
	if enB != zhB {
		t.Errorf("fenced code blocks: README.md has %d, README.zh-CN.md has %d", enB, zhB)
	}
	// SECURITY.md 按这个名字引用 README 的已知限制一节
	if !slices.Contains(enH, "Known limitations") {
		t.Errorf("README.md has no %q section", "Known limitations")
	}
}

// beforeFirstHeading 返回第一个二级标题之前的文字。
func beforeFirstHeading(t *testing.T, file string) string {
	t.Helper()
	var b strings.Builder
	for _, l := range proseLines(lines(t, file)) {
		if strings.HasPrefix(l, "## ") {
			break
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

// TestReadmeModelOffWarning：模型关闭时危险操作不判断，这一点要在第一个二级标题之前就能看到。
func TestReadmeModelOffWarning(t *testing.T) {
	if s := beforeFirstHeading(t, "README.md"); !regexp.MustCompile(`(?i)model is off`).MatchString(s) {
		t.Errorf("README.md: no %q before the first level-2 heading", "model is off")
	}
	if s := beforeFirstHeading(t, "README.zh-CN.md"); !strings.Contains(s, "模型关闭") {
		t.Errorf("README.zh-CN.md: no %q before the first level-2 heading", "模型关闭")
	}
}

// TestMarkdownHelpers：链接、外部链接与代码块的识别。
func TestMarkdownHelpers(t *testing.T) {
	prose := proseLines([]string{
		"see [guide](docs/guide/rules.md#match) and [site](https://example.com)",
		"```sh", "[x](missing.md)", "```",
		`![img](a.png "t")`,
	})
	if prose[2] != "" {
		t.Errorf("line inside a code block counted as prose: %q", prose[2])
	}
	var got []string
	for _, l := range prose {
		for _, m := range mdLink.FindAllStringSubmatch(l, -1) {
			got = append(got, m[1])
		}
	}
	if want := []string{"docs/guide/rules.md#match", "https://example.com", "a.png"}; !slices.Equal(got, want) {
		t.Errorf("links = %q, want %q", got, want)
	}
	for _, s := range []string{"https://x", "http://x", "#anchor", "mailto:a@example.com"} {
		if !externalLink(s) {
			t.Errorf("%q: not external", s)
		}
	}
	if externalLink("docs/guide/") {
		t.Errorf("relative link counted as external")
	}
}

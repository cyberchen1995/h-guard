package app

import (
	"bytes"
	"strings"
	"testing"
)

// TestCappedBuffer：超过上限的写入丢弃、记下超限，写入方照常看到写成功（入口进程不会因此报错退出）。
func TestCappedBuffer(t *testing.T) {
	c := &cappedBuffer{max: 4}
	if n, err := c.Write([]byte("abcdef")); n != 6 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	c.Write([]byte("gh"))
	if !bytes.Equal(c.Bytes(), []byte("abcd")) || !c.over {
		t.Errorf("buffer = %q, over %v", c.Bytes(), c.over)
	}
}

// TestSelftestRequiresCodexReasons：Codex 不认没有原因的 deny 与 block（记为 hook 失败、照常执行），自测不能算通过。
func TestSelftestRequiresCodexReasons(t *testing.T) {
	cases := selftestCases("codex")
	for _, c := range []struct {
		i    int
		out  string
		want bool
	}{
		{0, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"}}`, false},
		{0, `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"r"}}`, true},
		{1, `{"decision":"block"}`, false},
		{1, `{"decision":"block","reason":" "}`, false},
		{1, `{"decision":"block","reason":"r"}`, true},
	} {
		if ok, detail := cases[c.i].check([]byte(c.out)); ok != c.want {
			t.Errorf("%s: ok = %v (%s)", c.out, ok, detail)
		}
	}
}

// TestSelftestRejectsUnknownCodexFields：Codex 的回复格式不允许多余的字段，带了的回复不算拦下。
func TestSelftestRejectsUnknownCodexFields(t *testing.T) {
	cases := selftestCases("codex")
	for i, out := range []string{
		`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"r","extra":1}}`,
		`{"decision":"block","reason":"r","extra":1}`,
	} {
		if ok, _ := cases[i].check([]byte(out)); ok {
			t.Errorf("%s passed", out)
		}
	}
	// Claude Code 不拒绝多余的字段
	if ok, _ := selftestCases("claudecode")[0].check([]byte(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","x":1}}`)); !ok {
		t.Error("claudecode reply with an extra field failed")
	}
}

// TestBuildIDTracksTheExecutable：记录版本带上可执行文件的指纹，原地重新构建或替换之后旧记录不算数。
func TestBuildIDTracksTheExecutable(t *testing.T) {
	if !strings.HasPrefix(buildID(), Version+"+") {
		t.Errorf("buildID = %q", buildID())
	}
}

// TestSelftestNeedsTheConfigDirectory：没有配置目录时不运行入口（插件目录会解析成相对路径，可能指向当前目录里的文件）。
func TestSelftestNeedsTheConfigDirectory(t *testing.T) {
	var out, errb bytes.Buffer
	ran := false
	code := runSelftest([]string{"claudecode"}, Options{Home: t.TempDir(), Stdout: &out, Stderr: &errb,
		RunEntry: func([]string, []string, []byte) ([]byte, error) { ran = true; return nil, nil }})
	if code != 1 || ran || !strings.Contains(errb.String(), "configuration directory is unavailable") {
		t.Errorf("exit %d, ran %v, %s", code, ran, errb.String())
	}
}

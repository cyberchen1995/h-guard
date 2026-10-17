package command_test

import (
	"slices"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
)

// TestRedirections：重定向由词法分析给出，写成「命令词 重定向」，目标取完整的词。
// 注释与引号里的 > 不是重定向，转义的空格不会让后面的 # 变成注释；没有命令词的段（组合命令、
// 被切开的 &>）命令词为空；heredoc 不算重定向。
func TestRedirections(t *testing.T) {
	for cmd, want := range map[string][]string{
		`dd if=x of=/dev/null 2>/dev/sda`:              {"dd 2>/dev/sda"},
		`dd if=a\ #b of=/dev/null 2>/dev/sda`:          {"dd 2>/dev/sda"},
		`dd if=x of=/dev/null 2>"/dev/null"b0`:         {"dd 2>/dev/nullb0"},
		`dd if=">/dev/sda" count=0`:                    nil,
		`dd if=\>/dev/sda count=0`:                     nil,
		`dd if=x of=/dev/null # example: >/dev/sda`:    nil,
		`dd if=x status='x >/dev/sda'`:                 nil,
		`/bin/dd if=x >>/dev/disk2 2>&1`:               {"dd >>/dev/disk2", "dd 2>&1"},
		`>/dev/sda dd if=x`:                            {"dd >/dev/sda"},
		`sudo dd if=x of=/dev/null 2>'/dev/sda'`:       {"dd 2>/dev/sda"},
		`( dd if=x of=/dev/null ) 2>/dev/sda`:          {" 2>/dev/sda"},
		`dd if=x of=/dev/null &>/dev/sda`:              {" >/dev/sda"},
		"cat <<'EOF' > out.txt\n>/dev/sda\nEOF":        {"cat >out.txt"},
		`echo hi > a.txt; sort < a.txt | uniq > b.txt`: {"echo >a.txt", "sort <a.txt", "uniq >b.txt"},
	} {
		if got := command.Redirections(cmd); !slices.Equal(got, want) {
			t.Errorf("Redirections(%q) = %q, want %q", cmd, got, want)
		}
	}
}

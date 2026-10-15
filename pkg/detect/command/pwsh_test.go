package command_test

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func pwsh(t *testing.T, cmd string) command.Expansion {
	t.Helper()
	e, err := command.Expand(context.Background(), cmd, guard.ShellPowerShell)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestPowerShellPositions：PowerShell 按 ; 换行 | && || 与后台的 & 切段（spec §5.3），引号、here-string、注释、
// 括号与脚本块里的分隔符不切段；命令位置跳过调用运算符 & 与 .、以及赋值 $x = 。
func TestPowerShellPositions(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`Remove-Item -Recurse -Force .\build`, []string{`Remove-Item -Recurse -Force .\build`}},
		{"cd C:\\proj; Remove-Item x\nls", []string{`cd C:\proj`, `Remove-Item x`, `ls`}},
		{`Get-ChildItem | Remove-Item -Recurse`, []string{`Get-ChildItem`, `Remove-Item -Recurse`}},
		{`git add . && git commit -m "a; b" || exit 1`, []string{`git add .`, `git commit -m "a; b"`, `exit 1`}},
		{`Start-Sleep 1 & Remove-Item x`, []string{`Start-Sleep 1`, `Remove-Item x`}},
		{`& 'C:\Program Files\Git\bin\git.exe' push`, []string{`'C:\Program Files\Git\bin\git.exe' push`}},
		{`. .\tools\clean.ps1 -All`, []string{`.\tools\clean.ps1 -All`}},
		{`$r = Remove-Item -Recurse x`, []string{`Remove-Item -Recurse x`}},
		{`$r=git push`, []string{`git push`}},
		{`$env:HUSKY = 0; git commit -m x`, []string{`0`, `git commit -m x`}}, // 赋值的右边照样给出；是表达式时锚在段首的规则不会命中
		{`Write-Output 'rm -rf /; x'`, []string{`Write-Output 'rm -rf /; x'`}},
		{"Write-Output \"a`\"; b\"", []string{"Write-Output \"a`\"; b\""}},
		{`Write-Output 'it''s; fine'`, []string{`Write-Output 'it''s; fine'`}},
		// 注释不进入命令位置（计划评审 M3B-06）：注释里的参数不是实际参数
		{`ls # ; Remove-Item x`, []string{`ls`}},
		{`Remove-Item .\build # -Recurse C:\`, []string{`Remove-Item .\build`}},
		{`Remove-Item .\build <# -Recurse C:\ #> -Force`, []string{`Remove-Item .\build  -Force`}},
		{"ls # c\nRemove-Item x", []string{`ls`, `Remove-Item x`}},
		{`Write-Output 'a # b' c#d`, []string{`Write-Output 'a # b' c#d`}},
		// 行尾的逗号表示数组在下一行继续，换行不切段（计划第二轮评审 R2-02）
		{"Start-Process pwsh -ArgumentList '-c',\n  'x'; ls", []string{"Start-Process pwsh -ArgumentList '-c',\n  'x'", `ls`}},
		{"$a = 1, # c\n 2", []string{"1, \n 2"}},
		// 命令参数里的 = 不是赋值：后面的 & 仍是后台运算符（计划第三轮评审 R3-02）
		{"Write-Output = & Format-Volume -DriveLetter D", []string{"Write-Output =", "Format-Volume -DriveLetter D"}},
		{"Write-Output $x= & Format-Volume -DriveLetter D", []string{"Write-Output $x=", "Format-Volume -DriveLetter D"}},
		{`<# ; #> Remove-Item x`, []string{`Remove-Item x`}},
		{"Remove-Item `\n  -Recurse x", []string{"Remove-Item   -Recurse x"}},
		{`Remove-Item x 2>&1 | Out-Null`, []string{`Remove-Item x 2>&1`, `Out-Null`}},
		{`if (Test-Path x) { Remove-Item x; ls }`, []string{`if (Test-Path x) { Remove-Item x; ls }`}},
		{`Get-ChildItem | ForEach-Object { Remove-Item $_ -Recurse }`, []string{`Get-ChildItem`, `ForEach-Object { Remove-Item $_ -Recurse }`}},
		{"$s = @'\nRemove-Item x; y\n'@\nls", []string{"@'\n" + command.HeredocPlaceholder + "\n'@", `ls`}}, // 数据 here-string 的正文换成占位符
		{"Write-Output @\"\na; b\n\"@ | Out-File f", []string{"Write-Output @\"\n" + command.HeredocPlaceholder + "\n\"@", "Out-File f"}},
		{`# only a comment`, nil},
	} {
		if got := pwsh(t, c.in).Units[0].Positions(); !slices.Equal(got, c.want) {
			t.Errorf("Positions(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPowerShellReadsLikePowerShell：PowerShell 这样读、而简单的词法会读错的写法，必须切出后面的命令
// （评审 C4、I4）：here-string 不必在词首（$x=@'）；停止解析符 --% 之后到换行或 | 的内容按字面，其中的引号不起作用。
func TestPowerShellReadsLikePowerShell(t *testing.T) {
	for in, want := range map[string]string{
		"$x=@'\nit's fine\n'@; Remove-Item -Recurse -Force C:\\": `Remove-Item -Recurse -Force C:\`,
		"$($x=@'\nit's\n'@); Remove-Item -Recurse -Force C:\\":   `Remove-Item -Recurse -Force C:\`,
		"git --% '\nRemove-Item -Recurse -Force C:\\":            `Remove-Item -Recurse -Force C:\`,
		"git --% ' | Remove-Item -Recurse -Force C:\\":           `Remove-Item -Recurse -Force C:\`,
		// 转义的逗号是字面字符，换行照常结束命令（计划第三轮评审 R3-01）
		"Write-Output safe`,\nFormat-Volume -DriveLetter D": `Format-Volume -DriveLetter D`,
	} {
		if got := pwsh(t, in).Units[0].Positions(); !slices.Contains(got, want) {
			t.Errorf("Positions(%q) = %q, want one of them to be %q", in, got, want)
		}
	}
	// 转义的是反引号本身时，逗号未转义，数组在下一行继续：只有一段
	if got := pwsh(t, "Write-Output a``,\n b").Units[0].Positions(); len(got) != 1 {
		t.Errorf("escaped backtick before a comma: Positions = %q, want one segment", got)
	}
}

// TestPowerShellNormalizedPositions：deny 级规则另匹配的规范写法：词去掉引号与反引号转义，命令词取路径或模块
// 限定名的最后一段，${env:X}、${HOME} 写作 $env:X、$HOME，词末的 \ 与 / 去掉（盘符根与单独的分隔符保留）。
// 于是 R`e`move-Item、模块限定名、带引号的路径与原写法一样匹配。
func TestPowerShellNormalizedPositions(t *testing.T) {
	for in, want := range map[string]string{
		`Microsoft.PowerShell.Management\Remove-Item -Recurse -Force 'C:\'`: `Remove-Item -Recurse -Force C:\`,
		"R`e`m`o`ve-Item -Recurse $HOME\\":                                  `Remove-Item -Recurse $HOME`,
		`& "rm" -r -fo ${env:USERPROFILE}`:                                  `rm -r -fo $env:USERPROFILE`,
		`Remove-Item -Recurse "${HOME}/"`:                                   `Remove-Item -Recurse $HOME`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -c x`:    `powershell.exe -c x`,
		`Remove-Item -Recurse "C:/"`:                                        `Remove-Item -Recurse C:/`,
		`rd /s /q \`:                                                        `rd /s /q \`,
		`Remove-Item -Path "C:\Program Files\x\"`:                           `Remove-Item -Path "C:\Program Files\x\"`,
	} {
		if got := pwsh(t, in).Units[0].NormalizedPositions(); !slices.Equal(got, []string{want}) {
			t.Errorf("NormalizedPositions(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPowerShellStringIsNotACommand：命令位置上的字符串是表达式，不是调用（计划评审 M3B-05）：规范写法不去掉它的
// 引号，否则 $x = 'Format-Volume' 会被当成格式化磁盘而硬拒绝。经调用运算符 & 或 . 调用时才是命令。
func TestPowerShellStringIsNotACommand(t *testing.T) {
	for in, want := range map[string][]string{
		`$x = 'Format-Volume'`:          nil,
		`'Format-Volume'`:               nil,
		`$x="Remove-Item -Recurse C:\"`: nil,
		// 赋值之后的调用运算符同样是调用（计划第二轮评审 R2-03）
		`$r = & 'Format-Volume' -DriveLetter D`: {`Format-Volume -DriveLetter D`},
		`$r=& 'Format-Volume'`:                  {`Format-Volume`},
		`$r = . 'Remove-Item' -Recurse C:\`:     {`Remove-Item -Recurse C:\`},
		`& 'Format-Volume' -DriveLetter D`:      {`Format-Volume -DriveLetter D`},
		`. "Remove-Item" -Recurse C:\`:          {`Remove-Item -Recurse C:\`},
	} {
		if got := pwsh(t, in).Units[0].NormalizedPositions(); !slices.Equal(got, want) {
			t.Errorf("NormalizedPositions(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPowerShellUnquoted：抹掉单引号、双引号与 here-string 的内容（给无法切段的形态用），其余原样保留。
func TestPowerShellUnquoted(t *testing.T) {
	for in, want := range map[string]string{
		`Write-Output 'a;b' "c$(x)d" e`: `Write-Output   e`,
		"a @'\nx\n'@ b":                 "a  b",
		"a `' b":                        "a `' b",
	} {
		if got := pwsh(t, in).Units[0].Unquoted(); got != want {
			t.Errorf("Unquoted(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPowerShellFullTexts：反引号续行（反引号紧跟换行）在代码里去掉，另给一份拼接后的全文；引号、注释与
// 单引号 here-string 里的不是续行。
func TestPowerShellFullTexts(t *testing.T) {
	for _, c := range []struct {
		in     string
		joined string // 空表示只有原文
	}{
		{"Remove-Item `\n-Recurse x", "Remove-Item -Recurse x"},
		{"Remove-Item `\r\n-Recurse x", "Remove-Item -Recurse x"},
		{"Write-Output 'a`\nb'", ""},
		{"ls # a`\nb", ""},
		// 代码里的反引号转义也去掉：R`emove-Item 就是 Remove-Item；字符串里的不动
		{"R`emove-Item -Rec`urse x", "Remove-Item -Recurse x"},
		{"Write-Output \"a`tb\"", ""},
		{"Remove-Item -Recurse x", ""},
	} {
		got := pwsh(t, c.in).Units[0].FullTexts()
		want := []string{c.in}
		if c.joined != "" {
			want = append(want, c.joined)
		}
		if !slices.Equal(got, want) {
			t.Errorf("FullTexts(%q) = %q, want %q", c.in, got, want)
		}
	}
}

// TestPowerShellUnterminated：未闭合的引号、here-string、括号与注释延伸到末尾：宁可把后面的内容当数据，
// 也不凭空切出命令；不崩溃。
func TestPowerShellUnterminated(t *testing.T) {
	for in, want := range map[string][]string{
		`Write-Output 'a; Remove-Item x`:    {`Write-Output 'a; Remove-Item x`},
		"Write-Output @'\na; Remove-Item x": {strings.TrimSpace("Write-Output @'\n" + command.HeredocPlaceholder)},
		`ls (a; b`:                          {`ls (a; b`},
		`<# ; Remove-Item x`:                nil,
	} {
		if got := pwsh(t, in).Units[0].Positions(); !slices.Equal(got, want) {
			t.Errorf("Positions(%q) = %q, want %q", in, got, want)
		}
	}
	if strings.Contains(strings.Join(pwsh(t, "x }; y").Units[0].Positions(), "|"), "}") {
		t.Error("an unmatched } is part of a position")
	}
}

func FuzzExpandPowerShell(f *testing.F) {
	for _, s := range []string{
		"Remove-Item -Recurse x; ls", "a \"b`\"$(c)\" d", "@'\nx\n'@", "@\"\n$(a)\n\"@", "<# x #> y", "a `\n b",
		"$x = (a | b) -and {c}", "& 'x' @{a=1}", "a 2>&1 *> f", "a 'b''c' \"d\"\"e\"", "(", ")", "{", "}", "@(", "$(",
		"`", "'", "\"", "<#", "@'", "@\"", "a&", "&&", "||", "a\r\nb",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := command.Expand(context.Background(), s, guard.ShellPowerShell)
		if err != nil {
			t.Fatal(err)
		}
		if len(e.Units) == 0 {
			t.Fatalf("no units")
		}
		for _, u := range e.Units {
			_ = u.Positions()
			_ = u.NormalizedPositions()
			_ = u.Unquoted()
			_ = u.FullTexts()
		}
	})
}

// encoded 返回 pwsh -EncodedCommand 的参数：UTF-16LE 再 Base64。
func encoded(s string) string {
	var b []byte
	for _, r := range utf16.Encode([]rune(s)) {
		b = append(b, byte(r), byte(r>>8))
	}
	return base64.StdEncoding.EncodeToString(b)
}

// marked 返回含 MARK 的内层单元的 shell；没有时为空。
func marked(e command.Expansion) []guard.Shell {
	var out []guard.Shell
	for _, u := range e.Units[1:] {
		for _, text := range u.FullTexts() {
			if strings.Contains(text, MARK) {
				out = append(out, u.Shell)
				break
			}
		}
	}
	return out
}

// TestPowerShellInnerCommands：PowerShell 里会被执行的代码取出来按命令再检查一遍（spec §5.3）：子表达式 $(…)
// （含双引号字符串与 @"…"@ 里的）、括号、脚本块；交给 Invoke-Expression（iex）、pwsh、powershell 的字符串与
// here-string 的内容；pwsh -Command、-EncodedCommand（Base64 的 UTF-16LE）与按位置给出的命令；bash -c、
// wsl 交给 Linux 执行的命令按 POSIX 检查。单引号字符串与 @'…'@ 里的是数据。
func TestPowerShellInnerCommands(t *testing.T) {
	ps, posix := guard.ShellPowerShell, guard.ShellPOSIX
	for _, c := range []struct {
		in   string
		want []guard.Shell
	}{
		{`Write-Output "a $(` + MARK + `) b"`, []guard.Shell{ps}},
		{`Write-Output '$(` + MARK + `)'`, nil},
		{`if (Test-Path x) { ` + MARK + ` }`, []guard.Shell{ps}},
		{`Get-ChildItem | ForEach-Object { ` + MARK + ` }`, []guard.Shell{ps}},
		{`$n = (` + MARK + `).Count`, []guard.Shell{ps}},
		{"Set-Content f @\"\n$(" + MARK + ")\n\"@", []guard.Shell{ps}},
		{"Set-Content f @'\n" + MARK + "\n'@", nil},
		{"@'\n" + MARK + "\n'@ | iex", []guard.Shell{ps}},
		{`"` + MARK + `" | Invoke-Expression`, []guard.Shell{ps}},
		{`iex '` + MARK + `'`, []guard.Shell{ps}},
		{`Invoke-Expression -Command "` + MARK + `"`, []guard.Shell{ps}},
		{"@'\n" + MARK + "\n'@ | pwsh -Command -", []guard.Shell{ps}},
		{`pwsh -Command "` + MARK + `"`, []guard.Shell{ps}},
		{`powershell.exe -c ` + MARK, []guard.Shell{ps}},
		{`pwsh -NoProfile -ExecutionPolicy Bypass -Command ` + MARK, []guard.Shell{ps}},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe /Command "` + MARK + `"`, []guard.Shell{ps}},
		{`powershell -EncodedCommand ` + encoded(MARK), []guard.Shell{ps}},
		{`pwsh -enc ` + encoded(MARK), []guard.Shell{ps}},
		{`powershell "` + MARK + `"`, []guard.Shell{ps}},
		{`pwsh -File .\` + MARK + `.ps1`, nil},
		{`bash -c '` + MARK + `'`, []guard.Shell{posix}},
		{`wsl ` + MARK, []guard.Shell{posix}},
		{`wsl -d Ubuntu -u root -- ` + MARK, []guard.Shell{posix}},
	} {
		if got := marked(pwsh(t, c.in)); !slices.Equal(got, c.want) {
			t.Errorf("%q: inner shells with MARK = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestPowerShellDataHereStrings：作为数据的 here-string 正文换成占位符，全文规则不会匹配到其中的写法；交给解释器的
// 正文保留在全文里（与 POSIX 的 heredoc 相同）。
func TestPowerShellDataHereStrings(t *testing.T) {
	if text := pwsh(t, "Set-Content notes.md @'\ngit push --force\n'@").Units[0].Text; strings.Contains(text, "git push") || !strings.Contains(text, command.HeredocPlaceholder) {
		t.Errorf("data here-string kept in the full text: %q", text)
	}
	if text := pwsh(t, "@'\ngit push --force\n'@ | iex").Units[0].Text; !strings.Contains(text, "git push") {
		t.Errorf("executed here-string removed from the full text: %q", text)
	}
}

// TestPOSIXRunsPowerShell：POSIX 命令里交给 pwsh、powershell 的脚本按 PowerShell 检查：-c、-Command、
// -EncodedCommand，以及把 heredoc 正文交给它们。
func TestPOSIXRunsPowerShell(t *testing.T) {
	ps := []guard.Shell{guard.ShellPowerShell}
	for _, in := range []string{
		`pwsh -c '` + MARK + `'`,
		`powershell.exe -NoProfile -Command "` + MARK + `"`,
		`pwsh -EncodedCommand ` + encoded(MARK),
		"pwsh <<'EOF'\n" + MARK + "\nEOF",
		"cat <<'EOF' | powershell -Command -\n" + MARK + "\nEOF",
	} {
		if got := marked(expand(t, in)); !slices.Equal(got, ps) {
			t.Errorf("%q: inner shells with MARK = %v, want %v", in, got, ps)
		}
	}
	if got := marked(expand(t, "bash <<'EOF'\n"+MARK+"\nEOF")); !slices.Equal(got, []guard.Shell{guard.ShellPOSIX}) {
		t.Errorf("bash heredoc: %v", got)
	}
}

// TestPowerShellDepthLimit：PowerShell 与 POSIX 互相嵌套同样受 MaxDepth 限制。
func TestPowerShellDepthLimit(t *testing.T) {
	cmd := MARK
	for i := 0; i < command.MaxDepth+1; i++ {
		cmd = `pwsh -c "$(` + cmd + `)"`
	}
	e := pwsh(t, cmd)
	if !e.Limited {
		t.Errorf("expansion of %q is not limited", cmd)
	}
}

// TestPowerShellBlocksKeepDepth：脚本块、括号与子表达式是同一脚本里的代码，嵌套很深时也不触发深度限制；
// 交给解释器的嵌套照常计数（见 TestPowerShellDepthLimit）。
func TestPowerShellBlocksKeepDepth(t *testing.T) {
	cmd := MARK
	for i := 0; i < command.MaxDepth+3; i++ {
		cmd = "if ($a) { " + cmd + " }"
	}
	e := pwsh(t, cmd)
	if e.Limited {
		t.Errorf("expansion of %q is limited", cmd)
	}
	found := false
	for _, u := range e.Units {
		for _, p := range u.Positions() {
			found = found || strings.HasPrefix(p, MARK)
		}
	}
	if !found {
		t.Errorf("%q: %s not in a command position", cmd, MARK)
	}
}

// TestEncodedUnits：-EncodedCommand 解码出的单元标为 Encoded，选项的各种写法（-enc、/enc、--enc、Unicode 破折号）
// 与 Start-Process 的参数列表、POSIX 里的调用都一样；-Command 里的 -Enc（cmdlet 的 -Encoding）不算。
func TestEncodedUnits(t *testing.T) {
	enc := "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAeAA=" // Remove-Item x
	encoded := func(cmd string, sh guard.Shell) bool {
		e, err := command.Expand(context.Background(), cmd, sh)
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range e.Units {
			if u.Encoded {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{"powershell -EncodedCommand " + enc, "pwsh -enc " + enc, "powershell /enc " + enc, "pwsh --enc " + enc,
		"pwsh –enc " + enc, "Start-Process pwsh -ArgumentList '-EncodedCommand', '" + enc + "'"} {
		if !encoded(cmd, guard.ShellPowerShell) {
			t.Errorf("not encoded: %s", cmd)
		}
	}
	if !encoded(`bash -c "pwsh -e `+enc+`"`, guard.ShellPOSIX) {
		t.Error("nested in POSIX: not encoded")
	}
	for _, cmd := range []string{`pwsh -c "Get-Content x.txt -Enc UTF8"`, "pwsh -File build.ps1", "Get-ChildItem"} {
		if encoded(cmd, guard.ShellPowerShell) {
			t.Errorf("encoded: %s", cmd)
		}
	}
}

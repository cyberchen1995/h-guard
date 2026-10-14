package command_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/command"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

// TestPowerShellUnicodeDashesAndQuotes：PowerShell 把 Unicode 破折号（– — ―）当作 -，把中文引号（‘ ’ ‚ ‛、“ ” „）
// 当作引号，可以与 ASCII 引号混用；展开前换成 ASCII 写法，后面的命令照常切出（评审 C2、C3）。
func TestPowerShellUnicodeDashesAndQuotes(t *testing.T) {
	for in, want := range map[string]string{
		"Remove-Item –Recurse —Force ―Path C:\\":            `Remove-Item -Recurse -Force -Path C:\`,
		"Write-Host ‘x'; Remove-Item -Recurse -Force C:\\":  `Remove-Item -Recurse -Force C:\`,
		"Write-Host “x\"; Remove-Item -Recurse -Force C:\\": `Remove-Item -Recurse -Force C:\`,
	} {
		if got := pwsh(t, in).Units[0].Positions(); !slices.Contains(got, want) {
			t.Errorf("Positions(%q) = %q, want one of them to be %q", in, got, want)
		}
	}
}

// runsMark 返回把 MARK 当作命令执行的单元（某个命令位置以 MARK 开头）的 shell。只出现在字符串里不算。
func runsMark(e command.Expansion) []guard.Shell {
	var out []guard.Shell
	for _, u := range e.Units {
		for _, pos := range u.Positions() {
			if strings.HasPrefix(pos, MARK) {
				out = append(out, u.Shell)
				break
			}
		}
	}
	return out
}

// TestPowerShellExecutesLiterals：以字面量执行代码的其他静态写法同样提取（评审 C1、C5、I1–I3、M4）：
// -EncodedCommand 的 Base64 带空白或奇数个字节（.NET 照常解码）；字符串或 here-string 经管道交给 bash、sh、wsl
// （按 POSIX），中间隔着 Out-String 这类透传命令也算；iex(…)、Invoke-Expression(…)；Start-Process 启动
// pwsh 时 -ArgumentList 里的命令；[scriptblock]::Create(…)、InvokeScript(…)；wsl ~ 之后的命令。
// 交给 python 等别的解释器的 here-string 不当数据剥离（全文规则看得到），但也不按 shell 命令检查。
func TestPowerShellExecutesLiterals(t *testing.T) {
	ps, posix := guard.ShellPowerShell, guard.ShellPOSIX
	enc := encoded(MARK)
	odd, _ := base64.StdEncoding.DecodeString(encoded(MARK + "; #"))
	for _, c := range []struct {
		in   string
		want []guard.Shell
	}{
		{`pwsh -enc "` + enc[:8] + ` ` + enc[8:] + `"`, []guard.Shell{ps}},
		{"pwsh -enc \"" + enc[:8] + "\n" + enc[8:] + "\"", []guard.Shell{ps}},
		{`pwsh -enc ` + base64.StdEncoding.EncodeToString(append(odd, 'A')), []guard.Shell{ps}},
		{"@'\n" + MARK + "\n'@ | bash", []guard.Shell{posix}},
		{`'` + MARK + `' | sh`, []guard.Shell{posix}},
		{"@'\n" + MARK + "\n'@ | wsl", []guard.Shell{posix}},
		{"@'\n" + MARK + "\n'@ | Out-String | iex", []guard.Shell{ps}},
		{`'` + MARK + `' | Out-String | Invoke-Expression`, []guard.Shell{ps}},
		{`iex("` + MARK + `")`, []guard.Shell{ps}},
		{`Invoke-Expression('` + MARK + `')`, []guard.Shell{ps}},
		{"iex(@'\n" + MARK + "\n'@)", []guard.Shell{ps}},
		{`Start-Process pwsh -ArgumentList '-c','` + MARK + `'`, []guard.Shell{ps}},
		{`Start-Process -FilePath powershell.exe -ArgumentList "-Command ` + MARK + `"`, []guard.Shell{ps}},
		{`[scriptblock]::Create('` + MARK + `').Invoke()`, []guard.Shell{ps}},
		{`. ([ScriptBlock]::Create("` + MARK + `"))`, []guard.Shell{ps}},
		{`$ExecutionContext.InvokeCommand.InvokeScript('` + MARK + `')`, []guard.Shell{ps}},
		{`wsl ~ ` + MARK, []guard.Shell{posix}},
		// 赋值紧贴命令时按实际的命令识别解释器（计划评审 M3B-01）
		{`$r=pwsh -c '` + MARK + `'`, []guard.Shell{ps}},
		{`$r = bash -c '` + MARK + `'`, []guard.Shell{posix}},
		{`$r=iex '` + MARK + `'`, []guard.Shell{ps}},
		// -ArgumentList 的数组项之间可以有空白（计划评审 M3B-02）
		{`Start-Process pwsh -ArgumentList '-EncodedCommand', '` + enc + `'`, []guard.Shell{ps}},
		{`Start-Process -FilePath pwsh -ArgumentList '-c' , '` + MARK + `'`, []guard.Shell{ps}},
		// 计划第二轮评审 R2-01–R2-03：赋值之后的 iex(…) 与点调用；数组跨行或写成 @(…)
		{`$r=iex('` + MARK + `')`, []guard.Shell{ps}},
		{`$r = Invoke-Expression("` + MARK + `")`, []guard.Shell{ps}},
		{`$r = . pwsh -c '` + MARK + `'`, []guard.Shell{ps}},
		{"Start-Process pwsh -ArgumentList '-EncodedCommand',\n  '" + enc + "'", []guard.Shell{ps}},
		{`Start-Process pwsh -ArgumentList @('-EncodedCommand', '` + enc + `')`, []guard.Shell{ps}},
		{"Start-Process -FilePath pwsh -ArgumentList @(\n  '-c',\n  '" + MARK + "'\n)", []guard.Shell{ps}},
	} {
		if got := runsMark(pwsh(t, c.in)); !slices.Equal(got, c.want) {
			t.Errorf("%q: units running MARK = %v, want %v", c.in, got, c.want)
		}
	}
	e := pwsh(t, "@'\n"+MARK+"\n'@ | python3")
	if !strings.Contains(e.Units[0].Text, MARK) || len(runsMark(e)) != 0 {
		t.Errorf("here-string piped to python: %+v", e.Units)
	}
}

// TestPOSIXHeredocToBashStaysPOSIX：heredoc 交给 bash、同一行别处出现 pwsh 一词（文件名、参数）时，正文仍按 POSIX
// 检查（评审 I5：曾经只按 PowerShell 检查，丢失 deny）；真的交给 pwsh 时按 PowerShell。
func TestPOSIXHeredocToBashStaysPOSIX(t *testing.T) {
	for in, want := range map[string]guard.Shell{
		"bash <<'EOF' | tee pwsh.log\n" + MARK + "\nEOF": guard.ShellPOSIX,
		"pwsh <<'EOF'\n" + MARK + "\nEOF":                guard.ShellPowerShell,
	} {
		if got := runsMark(expand(t, in)); !slices.Contains(got, want) {
			t.Errorf("%q: units running MARK = %v, want %s among them", in, got, want)
		}
	}
}

package paths

import (
	"runtime"
	"slices"
	"testing"
)

// TestStripWindowsPrefix：\\?\ 与 \\.\ 前缀下的盘符路径、\\?\UNC\ 换回普通写法，它们与去掉前缀后的路径是同一个
// 文件（spec §5.5 第 4 步）。指向卷 GUID、GLOBALROOT 或设备的前缀无法映射到盘符路径，标为不透明（按命中处理）。
// / 与 \ 两种分隔符都认。
func TestStripWindowsPrefix(t *testing.T) {
	for _, c := range []struct {
		in, want string
		opaque   bool
	}{
		{`C:\Users\me\.env`, `C:\Users\me\.env`, false},
		{`\\?\C:\Users\me\.env`, `C:\Users\me\.env`, false},
		{`\\.\C:\Users\me\.env`, `C:\Users\me\.env`, false},
		{`//?/C:/Users/me/.env`, `C:/Users/me/.env`, false},
		{`\\?\c:\x`, `c:\x`, false},
		{`\\?\UNC\server\share\.env`, `\\server\share\.env`, false},
		{`\\?\unc\server\share\x`, `\\server\share\x`, false},
		{`\\server\share\.env`, `\\server\share\.env`, false},
		{`\\?\Volume{0d8a7c2e-1111-2222-3333-444455556666}\Users\me\.env`, `\\?\Volume{0d8a7c2e-1111-2222-3333-444455556666}\Users\me\.env`, true},
		{`\\?\GLOBALROOT\Device\HarddiskVolume3\Users\me\.env`, `\\?\GLOBALROOT\Device\HarddiskVolume3\Users\me\.env`, true},
		{`\\.\PhysicalDrive0`, `\\.\PhysicalDrive0`, true},
		{`relative\path`, `relative\path`, false},
		// NT 对象管理器的写法 \??\ 与 \\?\ 相同（评审 M7）
		{`\??\C:\Users\me\.env`, `C:\Users\me\.env`, false},
		{`\??\UNC\server\share\x`, `\\server\share\x`, false},
		// 盘符相对路径（C:foo 相对于 C 盘的当前目录）解析不出是哪个文件：不透明
		{`C:..\.ssh\id_ed25519`, `C:..\.ssh\id_ed25519`, true},
		{`c:secret.txt`, `c:secret.txt`, true},
	} {
		got, opaque := stripWindowsPrefix(c.in)
		if got != c.want || opaque != c.opaque {
			t.Errorf("stripWindowsPrefix(%q) = %q, %v; want %q, %v", c.in, got, opaque, c.want, c.opaque)
		}
	}
}

// TestWindowsForms：Windows 打开文件时去掉每段末尾的点与空格，「文件名:流名」打开的是同一个文件的数据流，
// 所以 .env.、.env 与 .env::$DATA 都是 .env（spec §5.5）。这些写法另作候选，任一命中即命中；盘符的冒号不算流。
// 与原路径相同时不返回。
func TestWindowsForms(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`C:\p\.env`, nil},
		{`C:\p\.env.`, []string{`C:\p\.env`}},
		{`C:\p\.env. . `, []string{`C:\p\.env`}},
		{`C:\p\.env::$DATA`, []string{`C:\p\.env`}},
		{`C:\p\.env:secret:$DATA`, []string{`C:\p\.env`}},
		{`C:\p.\.claude \settings.json`, []string{`C:\p\.claude\settings.json`}},
		{`C:/p/.env.`, []string{`C:\p\.env`}},
		{`\\server\share\.env.`, []string{`\\server\share\.env`}},
		{`C:\p\..\q\.env.`, []string{`C:\p\..\q\.env`}},
		{`C:\`, nil},
	} {
		if got := windowsForms(c.in, nil); !slices.Equal(got, c.want) {
			t.Errorf("windowsForms(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWindowsFormsMatch：去掉末尾的点、空格与数据流之后，受保护的路径照样命中（大小写不敏感）；Windows 下
// 路径与模式里的 \ 都按分隔符比较（在任何平台上都能测）。
func TestWindowsFormsMatch(t *testing.T) {
	m, err := Compile([]string{"**/.env", "~/.claude/settings.json"}, Env{Home: `C:\Users\Me`, FoldCase: true, Lexical: true, Windows: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{`C:\proj\.env.`, `C:\proj\.ENV::$DATA`, `c:\users\me\.claude\settings.json `, `\\?\C:\Users\me\.claude\settings.json`} {
		r := Resolved{Clean: p}
		stripped, _ := stripWindowsPrefix(p)
		r.Aliases = append([]string{stripped}, windowsForms(stripped, nil)...)
		if !m.Match(r) {
			t.Errorf("%q does not match", p)
		}
	}
	if m.Match(Resolved{Clean: `C:\proj\.envrc`}) {
		t.Error(".envrc matches **/.env")
	}
}

// TestWindowsAdminShares：本机的管理共享（\\localhost\C$\…、\\127.0.0.1\c$\…、本机名）就是盘符路径，另作候选，
// 否则写 {config} 或主目录下的文件可以绕开 ~/…、{config}/** 的模式（评审 I7）。别的主机与普通共享不映射。
func TestWindowsAdminShares(t *testing.T) {
	hosts := []string{"localhost", "127.0.0.1", "devbox"}
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`\\localhost\C$\Users\me\.netrc`, []string{`C:\Users\me\.netrc`}},
		{`\\127.0.0.1\c$\x`, []string{`c:\x`}},
		{`\\DEVBOX\D$\proj\.env.`, []string{`\\DEVBOX\D$\proj\.env`, `D:\proj\.env`}},
		{`\\otherhost\C$\Users\me\.netrc`, nil},
		{`\\localhost\share\x`, nil},
	} {
		if got := windowsForms(c.in, hosts); !slices.Equal(got, c.want) {
			t.Errorf("windowsForms(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWindowsRootRelative：Windows 上 \Users\me\x 与 /Users/me/x 是当前卷根下的路径，不是相对于 cwd 的路径
// （计划评审 M3B-04：曾被拼成 C:\work\Users\me\x，漏掉 ~/.ssh 下的私钥）。卷取 cwd 的盘符或 UNC 共享；
// 取不到时 ok 为假（调用方按不透明处理）。\\ 开头的 UNC、带盘符的路径与普通相对路径不在此列。
func TestWindowsRootRelative(t *testing.T) {
	for _, c := range []struct {
		in, cwd, want string
		rooted, ok    bool
	}{
		{`\Users\me\.ssh\id_ed25519`, `C:\work`, `C:\Users\me\.ssh\id_ed25519`, true, true},
		{`/Users/me/.ssh/id_ed25519`, `d:\proj`, `d:/Users/me/.ssh/id_ed25519`, true, true},
		{`\x`, `\\srv\share\dir`, `\\srv\share\x`, true, true},
		{`\x`, `relative`, ``, true, false},
		{`\x`, ``, ``, true, false},
		{`\\srv\share\x`, `C:\work`, ``, false, false},
		{`C:\x`, `C:\work`, ``, false, false},
		{`x\y`, `C:\work`, ``, false, false},
	} {
		got, rooted, ok := rootRelative(c.in, c.cwd)
		if got != c.want || rooted != c.rooted || ok != c.ok {
			t.Errorf("rootRelative(%q, %q) = %q, %v, %v; want %q, %v, %v", c.in, c.cwd, got, rooted, ok, c.want, c.rooted, c.ok)
		}
	}
}

func TestWindowsDefault(t *testing.T) {
	if WindowsDefault != (runtime.GOOS == "windows") {
		t.Errorf("WindowsDefault = %v on %s", WindowsDefault, runtime.GOOS)
	}
}

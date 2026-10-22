package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

// TestLocalFormsInterruptWithoutTheJudge：模型关闭时，requires_judge 规则只有后果大、几乎不会误报的形态打断
// （match.exec.local）；同一规则的其他写法、引号里提到的同样文本与只读的写法照常放行。
func TestLocalFormsInterruptWithoutTheJudge(t *testing.T) {
	e := newEnv(t)
	for cmd, want := range map[string]string{
		// 保住工作成果
		"git reset --hard":                        "ask",
		"cd repo && git reset --hard origin/main": "ask",
		"git -C repo clean -fdx":                  "ask",
		"git checkout -- .":                       "ask",
		"git stash clear":                         "ask",
		"git push --force":                        "ask",
		"/usr/bin/git push -f origin main":        "ask",
		"git push origin +main":                   "ask",
		"git filter-repo --path secrets":          "ask",
		"sudo rm -rf ~/projects":                  "ask",
		"rm -r -f ../other":                       "ask",
		"rm -rf .git":                             "ask",
		"git reset --soft HEAD~1":                 "pass",
		"git push --force-with-lease":             "pass",
		"git clean -n":                            "pass",
		"git checkout ./src":                      "pass",
		"rm -rf build":                            "pass",
		"rm -rf ./.github":                        "pass",
		"git commit -m 'avoid git reset --hard'":  "pass",
		// 阻止擅自发布
		"npm publish":             "ask",
		"FOO=1 pnpm publish":      "ask",
		"cargo publish":           "ask",
		"twine upload dist/*":     "ask",
		"docker push img:1":       "ask",
		"gh release create v1.0":  "ask",
		"npm publish --dry-run":   "pass",
		"cargo publish --dry-run": "pass",
		"gh release view v1.0":    "pass",
		"echo npm publish":        "pass",
		"git push":                "pass", // 是不是用户要求的推送要模型判断
		// 选项的各种写法
		"npm --workspace pkg publish":                         "ask",
		"npm publish --dry-run=false":                         "ask",
		"rm --recursive ~/projects":                           "ask",
		`git -C "other repo" reset --hard`:                    "ask",
		"git push --dry-run --force":                          "pass",
		"git push -nf":                                        "pass",
		"git clean -nfdx":                                     "pass",
		"npm run publish-docs":                                "pass",
		`cat "$HOME/.ssh/config"`:                             "ask", // 主目录变量按配置的主目录判断
		"cargo publish -n":                                    "pass",
		"docker image push registry.example/app:1":            "ask",
		"docker --context prod push app:1":                    "ask",
		"docker run --rm app push":                            "pass",
		"npm help publish":                                    "pass",
		"npm exec echo publish":                               "pass",
		"npm -w pkg publish":                                  "ask",
		"pnpm -r publish":                                     "ask",
		"yarn npm publish":                                    "ask",
		"cargo +nightly publish -p core":                      "ask",
		"git reset HEAD --hard":                               "ask",
		"git push --mirror":                                   "ask",
		"git push --mirror --dry-run":                         "pass",
		"gh -R owner/repo release create v1":                  "ask",
		"python3 -m twine upload dist/*":                      "ask",
		"npm pub":                                             "ask",
		"npm pub --dry-run":                                   "pass",
		"cd ~/.ssh && cat config":                             "ask",
		"rm -rf repo/.git":                                    "ask",
		"git clean -fd -- . -n":                               "ask",
		"git clean -n -- build":                               "pass",
		"docker compose push":                                 "ask",
		"docker compose -f prod.yml push web":                 "ask",
		"docker compose push --dry-run":                       "pass",
		"docker compose up":                                   "pass",
		"git-filter-repo --path secrets --invert-paths":       "ask",
		"python3 git-filter-repo --path x":                    "ask",
		"git-filter-repo --analyze":                           "pass",
		"git checkout -f main":                                "ask",
		"git checkout --force main":                           "ask",
		"git checkout main":                                   "pass",
		"gh release edit v1 --draft=false":                    "ask",
		"gh release edit v1 --notes x":                        "pass",
		"xargs npm publish </dev/null":                        "ask",
		"git --git-dir .git reset --hard":                     "ask",
		"git --work-tree /tmp/x push --force":                 "ask",
		"npm --dry-run publish":                               "pass",
		"npm --dry-run=false publish":                         "ask",
		"gh release -R owner/repo create v1":                  "ask",
		"gh release new v1":                                   "ask",
		"yarn workspaces foreach -A --no-private npm publish": "ask",
	} {
		out, errs, _ := e.run(nil, "check", cmd)
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("%q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
	for cmd, want := range map[string]string{
		"Remove-Item -Recurse ~/.cache":                "ask",
		"Remove-Item -Recurse -Force .git":             "ask",
		`Remove-Item -Recurse .\build`:                 "pass",
		"Remove-Item -Recurse ~/.cache -WhatIf":        "pass",
		"Remove-Item -Recurse -Path:~/.cache":          "ask",
		"Remove-Item -Recurse ~/.cache -WhatIf:$false": "ask",
		"Remove-Item -Recurse $env:HOME/projects":      "ask",
		"Publish-Module -Name Example -WhatIf":         "pass",
		"Publish-Module -Name Example":                 "ask",
		"git reset --hard":                             "ask",
		"npm publish":                                  "ask",
	} {
		out, errs, _ := e.run(nil, "check", cmd, "--shell", "powershell")
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("powershell %q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
}

// scenarioAsk 让 Claude Code 的 PreToolUse 运行 cmd，要求请求确认，说明里写明操作、后果与更稳妥的做法。
func scenarioAsk(t *testing.T, e *env, in []byte, op string, want ...string) {
	t.Helper()
	out, _, _ := e.run(in, "hook", "claudecode", "--event", "PreToolUse")
	d, reason := decisionOf(t, out)
	if d != "ask" {
		t.Errorf("%s: decision %s, want ask (%s)", op, d, reason)
		return
	}
	for _, w := range append([]string{"Operation: `" + op + "`", "Impact: ", "Safer way: "}, want...) {
		if !strings.Contains(reason, w) {
			t.Errorf("%s: reason lacks %q: %s", op, w, reason)
		}
	}
}

func scenarioPass(t *testing.T, e *env, in []byte, what string) {
	t.Helper()
	out, _, _ := e.run(in, "hook", "claudecode", "--event", "PreToolUse")
	if d, reason := decisionOf(t, out); d != "pass" {
		t.Errorf("%s: decision %s, want pass (%s)", what, d, reason)
	}
}

// TestScenarioKeepWork：保住工作成果。模型关闭时，丢弃整个工作区的改动、不带 lease 的强制推送、删除工作区之外或
// .git 都请求确认，说明写明会丢什么、先怎样保存；Codex 上被拦下后，用户批准一次，同一操作重试一次放行。
// 日常的写法（软 reset、带 lease 的推送、删 build）照常运行。
func TestScenarioKeepWork(t *testing.T) {
	e := newEnv(t)
	scenarioAsk(t, e, bash("git reset --hard origin/main"), "git reset --hard origin/main", "Uncommitted changes", "git stash push --all")
	scenarioAsk(t, e, bash("git clean -fdx"), "git clean -fdx", "untracked files")
	scenarioAsk(t, e, bash("git push --force origin main"), "git push --force origin main", "git branch backup-")
	scenarioAsk(t, e, bash("rm -rf ~/projects/old"), "rm -rf ~/projects/old", "no trash to restore from")
	scenarioAsk(t, e, bash("rm -rf .git"), "rm -rf .git")
	for _, cmd := range []string{"git reset --soft HEAD~1", "git push --force-with-lease", "rm -rf build", "git stash"} {
		scenarioPass(t, e, bash(cmd), cmd)
	}
	// Codex 不能请求确认：拦下并给出批准编号，批准后同一操作只放行一次
	ev := codexPre("Bash", map[string]any{"command": "git reset --hard origin/main"})
	out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse")
	d, reason := codexDecision(t, out)
	m := grantID.FindStringSubmatch(reason)
	if d != "deny" || m == nil || !strings.Contains(reason, "Uncommitted changes") {
		t.Fatalf("codex: %s %s", d, reason)
	}
	e.tty = true
	if out, _, code := e.run([]byte("y\n"), "allow", m[1]); code != 0 {
		t.Fatalf("approve: exit %d\n%s", code, out)
	}
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out != "" {
		t.Errorf("approved retry: %s", out)
	}
	if out, _, _ := e.run(ev, "hook", "codex", "--event", "PreToolUse"); out == "" {
		t.Error("the approval was used twice")
	}
}

// TestScenarioNoUnauthorizedPublish：阻止擅自发布。模型关闭时，发布包、镜像或 release 请求确认，说明写明
// 别人会看到、很难撤回，先核对版本；试运行与只读的查看照常运行。普通的 git push 要模型判断是不是用户要求的，
// 模型关闭时不打断（status 写明）。
func TestScenarioNoUnauthorizedPublish(t *testing.T) {
	e := newEnv(t)
	for _, cmd := range []string{"npm publish", "cargo publish", "twine upload dist/*", "docker push ghcr.io/o/app:1", "gh release create v2.0 --notes x"} {
		scenarioAsk(t, e, bash(cmd), cmd, "hard to take back", "the package version")
	}
	for _, cmd := range []string{"npm publish --dry-run", "cargo publish --dry-run", "gh release view v2.0", "npm pack", "git push"} {
		scenarioPass(t, e, bash(cmd), cmd)
	}
	if out, _, _ := e.run(nil, "status"); !strings.Contains(out, "publish (ask, only its high-impact forms while the judge is off)") {
		t.Errorf("status:\n%s", out)
	}
}

// TestScenarioCredentials：减少凭据泄露。读通常存放秘密的文件，不论用文件工具还是 shell 里常见的读法，
// 运行前都请求确认；示例文件与公钥照常读取；提示词里的凭据被拦下。
func TestScenarioCredentials(t *testing.T) {
	e := newEnv(t)
	scenarioAsk(t, e, bash("cat .env"), "cat .env", "enter the agent's context", "environment variable")
	scenarioAsk(t, e, bash("grep -i token ~/.aws/credentials"), "grep -i token ~/.aws/credentials")
	scenarioAsk(t, e, bash("base64 < ~/.ssh/id_ed25519"), "base64 < ~/.ssh/id_ed25519")
	out, _, _ := e.run(pre("Read", map[string]any{"file_path": "/w/.env"}, ""), "hook", "claudecode", "--event", "PreToolUse")
	if d, reason := decisionOf(t, out); d != "ask" || !strings.Contains(reason, ".env") {
		t.Errorf("Read .env: %s %s", d, reason)
	}
	for _, cmd := range []string{"cat .env.example", "cat ~/.ssh/id_ed25519.pub", "cat README.md", "echo .env"} {
		scenarioPass(t, e, bash(cmd), cmd)
	}
	out, _, _ = e.run(promptReq("deploy with aws_access_key_id = AKIAIOSFODNN7EXAMPL0", "composer"), "hook", "claudecode", "--event", "prompt.submit")
	if r, err := extproto.ParseReply([]byte(out)); err != nil || r.Action != extproto.ActionDeny {
		t.Errorf("prompt with a key: %q, %v", out, err)
	}
}

// TestShellGlobReads：通配符参数按工作目录里的文件展开，cat .env* 读到 .env 时同样请求确认；
// * 不匹配开头的点，与 shell 一致。
func TestShellGlobReads(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	for _, f := range []string{".env", ".env.example", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".ssh", "id_rsa"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for cmd, want := range map[string]string{
		"cat .env*":                             "ask",
		"head -n1 .e?v":                         "ask",
		"cat *":                                 "pass",
		"cat READ*":                             "pass",
		"cat .env.example*":                     "pass",
		"cat '[vault/.env'":                     "ask", // 不是合法的通配符：按字面检查
		"shopt -s dotglob; cat *":               "ask", // * 匹配 .env
		"shopt -s globstar; cat **/.env":        "ask", // ** 匹配零层或多层目录：读到 .env
		"shopt -s globstar; cat **/*.md":        "pass",
		"cat **/*.md":                           "pass",
		"cat */*":                               "pass",
		"cat .{env,example}":                    "ask",
		"cat .en{u..v}":                         "ask",  // 花括号序列
		"cat '.env*'":                           "pass", // 引号里的通配符按字面：读的是名为 .env* 的文件
		`cat .env\*`:                            "pass",
		"cat '.{env,example}'":                  "pass",
		`cat ".env"*`:                           "ask",
		"echo xargs -a .env":                    "pass", // 不在命令位置上的 xargs 不读文件
		"sudo xargs -a .env echo":               "ask",
		`home=/tmp; cat "$home/.netrc"`:         "pass", // POSIX 的 $home 不是 $HOME
		`cat "$HOME/.netrc"`:                    "ask",
		"git diff --no-index -- README.md .env": "ask",
		// 递归读取目录
		"grep -r TOKEN .":         "ask",
		"grep -rn TOKEN":          "ask",
		"grep -r TOKEN README.md": "pass",
		"grep -r TOKEN --exclude='.env*' --exclude-dir=.ssh .": "pass",
		"grep -r --include=*.md TOKEN .":                       "pass",
		"rg TOKEN":                                             "pass", // rg 默认跳过以点开头的文件与目录
		"rg --hidden TOKEN":                                    "ask",
		"rg -uu TOKEN .":                                       "ask",
		"git log | rg TOKEN":                                   "pass",
		"grep TOKEN .":                                         "pass", // 不递归：grep 不读目录
	} {
		out, errs, _ := e.run(nil, "check", cmd, "--cwd", dir)
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("%q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
	// PowerShell：引号里的通配符同样生效，没有花括号展开，-LiteralPath 按字面
	for cmd, want := range map[string]string{
		"Get-Content '.env*'":                           "ask",
		"Get-Content -LiteralPath '.env*'":              "pass",
		"Get-Content -LiteralPath '.{env,example}'":     "pass",
		"Get-Content @('.env')":                         "ask",
		`cmd /c "type .env"`:                            "ask",
		`cmd /c type %USERPROFILE%/.docker/config.json`: "ask",
		`cmd /c type %HOMEDRIVE%%HOMEPATH%/.netrc`:      "ask",
		"Get-Content README.md":                         "pass",
	} {
		out, errs, _ := e.run(nil, "check", cmd, "--shell", "powershell", "--cwd", dir)
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("%q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
}

// TestShellGlobUnreadable：通配符要读的目录读不了时，不当作没有匹配，请求确认（失败即确认）。
// 这里用符号链接环路（root 也读不了）；sudo sh -c 'cat /root/.ssh/id_rsa*' 读不了 /root 时是同样的情形。
func TestShellGlobUnreadable(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	if err := os.Symlink("loop", filepath.Join(dir, "loop")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	for cmd, want := range map[string]string{
		"sudo sh -c 'cat loop/id_rsa*'": "ask",
		"cat missing/id_rsa*":           "pass", // 不存在的目录里没有文件
	} {
		out, errs, _ := e.run(nil, "check", cmd, "--cwd", dir)
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("%q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
}

// TestShellGlobTooMany：通配符匹配的文件超过上限时没有逐个检查，请求确认（失败即确认）。
func TestShellGlobTooMany(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	for i := 0; i <= 1024; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%04d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for cmd, want := range map[string]string{
		"cat f*":    "ask",
		"cat f000*": "pass",
		"cat {.,x}{e,a}{n,b}{v,c}{,x}{,x}{,x}{,x}{,x}{,x}{,x}": "ask", // 花括号展开出 2048 个词，超过上限
		"cat f{0000..2000}":   "ask", // 花括号序列超过上限
		"cat f{0000..0005}":   "pass",
		"grep -r TOKEN .":     "ask", // 递归读取的文件超过上限
		"grep -r TOKEN f0001": "pass",
	} {
		out, errs, _ := e.run(nil, "check", cmd, "--cwd", dir)
		if !strings.Contains(out, "decision: "+want) {
			t.Errorf("%q: want %s\n%s%s", cmd, want, out, errs)
		}
	}
}

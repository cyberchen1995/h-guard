package codex

import (
	"errors"
	"reflect"
	"testing"

	"github.com/cyberchen1995/h-guard/pkg/guard"
)

func file(kind guard.ActionKind, path, to string) guard.Action {
	return guard.Action{Kind: kind, File: &guard.FileAction{Path: path, To: to}}
}

// TestPatchActions：apply_patch 的每个文件操作是一个动作：Add File、Update File 是写入，
// Delete File 是删除，Update File 加 Move to 是重命名（源与目标都检查）。
func TestPatchActions(t *testing.T) {
	for name, tc := range map[string]struct {
		patch string
		want  []guard.Action
	}{
		"add (recorded)": {"*** Begin Patch\n*** Add File: /tmp/hg-m0/codex/proj/a.txt\n+alpha\n*** End Patch",
			[]guard.Action{file(guard.ActionFileWrite, "/tmp/hg-m0/codex/proj/a.txt", "")}},
		"move (recorded)": {"*** Begin Patch\n*** Update File: /tmp/hg-m0/codex/proj/a.txt\n*** Move to: /tmp/hg-m0/codex/proj/b.txt\n@@\n alpha\n*** End Patch",
			[]guard.Action{file(guard.ActionFileRename, "/tmp/hg-m0/codex/proj/a.txt", "/tmp/hg-m0/codex/proj/b.txt")}},
		"delete (recorded)": {"*** Begin Patch\n*** Delete File: /tmp/hg-m0/codex/proj/b.txt\n*** End Patch",
			[]guard.Action{file(guard.ActionFileDelete, "/tmp/hg-m0/codex/proj/b.txt", "")}},
		"several files, relative paths, hunks with context": {
			"*** Begin Patch\n*** Update File: src/app.py\n@@ def main():\n-    print(1)\n+    print(2)\n@@\n x\n*** End of File\n" +
				"*** Add File: docs/new.md\n+# new\n+\n*** Delete File: old.txt\n*** Update File: .env\n@@\n-A=1\n+A=2\n*** End Patch\n",
			[]guard.Action{file(guard.ActionFileWrite, "src/app.py", ""), file(guard.ActionFileWrite, "docs/new.md", ""),
				file(guard.ActionFileDelete, "old.txt", ""), file(guard.ActionFileWrite, ".env", "")}},
		"CRLF and surrounding blank lines": {"\r\n*** Begin Patch\r\n*** Add File: a.txt\r\n+x\r\n*** End Patch\r\n\r\n",
			[]guard.Action{file(guard.ActionFileWrite, "a.txt", "")}},
		"paths with spaces": {"*** Begin Patch\n*** Add File: my dir/a b.txt\n+x\n*** End Patch",
			[]guard.Action{file(guard.ActionFileWrite, "my dir/a b.txt", "")}},
		"heredoc around the patch": {"apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\nEOF\n",
			[]guard.Action{file(guard.ActionFileDelete, "a.txt", "")}},
	} {
		got, err := patchActions(tc.patch)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, %v; want %+v", name, got, err, tc.want)
		}
	}
}

// TestPatchUnparsed：读不懂的 patch 不能当作「没有动作」放行，返回 errUnparsed（调用方请求确认）。
func TestPatchUnparsed(t *testing.T) {
	for name, patch := range map[string]string{
		"empty":               "",
		"no begin":            "*** Add File: a.txt\n+x\n*** End Patch",
		"no end":              "*** Begin Patch\n*** Add File: a.txt\n+x\n",
		"no operations":       "*** Begin Patch\n*** End Patch",
		"unknown header":      "*** Begin Patch\n*** Copy File: a.txt\n*** End Patch",
		"empty path":          "*** Begin Patch\n*** Delete File: \n*** End Patch",
		"empty move target":   "*** Begin Patch\n*** Update File: a.txt\n*** Move to:\n@@\n x\n*** End Patch",
		"stray line":          "*** Begin Patch\nhello\n*** Add File: a.txt\n+x\n*** End Patch",
		"bad add body":        "*** Begin Patch\n*** Add File: a.txt\nx\n*** End Patch",
		"bad hunk line":       "*** Begin Patch\n*** Update File: a.txt\n@@\n?x\n*** End Patch",
		"move without update": "*** Begin Patch\n*** Move to: b.txt\n*** End Patch",
		"text after end":      "*** Begin Patch\n*** Delete File: a.txt\n*** End Patch\n*** Delete File: b.txt\n",
	} {
		if got, err := patchActions(patch); !errors.Is(err, errUnparsed) {
			t.Errorf("%s: %+v, %v; want errUnparsed", name, got, err)
		}
	}
}

// FuzzPatchActions：任何输入都不 panic；解析成功时每个动作都有非空路径，重命名有非空目标。
func FuzzPatchActions(f *testing.F) {
	f.Add("*** Begin Patch\n*** Update File: a\n*** Move to: b\n@@\n x\n*** End Patch")
	f.Add("*** Begin Patch\n*** Add File: a\n+x\n*** Delete File: b\n*** End Patch\nEOF")
	f.Fuzz(func(t *testing.T, patch string) {
		acts, err := patchActions(patch)
		if err != nil {
			return
		}
		if len(acts) == 0 {
			t.Fatalf("%q: no actions and no error", patch)
		}
		for _, a := range acts {
			if err := a.Validate(); err != nil || a.File.Path == "" || (a.Kind == guard.ActionFileRename && a.File.To == "") {
				t.Fatalf("%q: bad action %+v (%v)", patch, a, err)
			}
		}
	})
}

// TestEmbeddedPatches：经 shell 调用的 apply_patch（Codex 会把 apply_patch 放进 PATH，任何 shell 写法都能打补丁）。
// 补丁正文对 shell 是数据，命令规则看不到其中的路径，所以文件动作是唯一的防线。命令提到 apply_patch 时，只接受
// 能静态读懂的写法：一次调用，补丁来自 heredoc 或单引号参数，可选的 cd <字面路径> && 前缀（相对路径按它解析），
// 可选的 bash -lc 包装；其余写法（补丁来自文件、管道、变量，会被展开的路径，多条命令）一律返回 errUnparsed。
// 没有提到 apply_patch 的补丁（如写进文件）读得出就照样加上文件动作，只会更严。
func TestEmbeddedPatches(t *testing.T) {
	del := "*** Begin Patch\n*** Delete File: /home/u/.codex/hooks.json\n*** End Patch"
	want := []guard.Action{file(guard.ActionFileDelete, "/home/u/.codex/hooks.json", "")}
	for name, cmd := range map[string]string{
		"heredoc":                  "apply_patch <<'EOF'\n" + del + "\nEOF",
		"heredoc, <<-":             "apply_patch <<-\"EOF\"\n" + del + "\n\tEOF\n",
		"unquoted literal heredoc": "apply_patch <<EOF\n" + del + "\nEOF",
		"after cd":                 "cd /w && apply_patch <<'EOF'\n" + del + "\nEOF",
		"bash -lc":                 "bash -lc \"apply_patch <<'EOF'\n" + del + "\nEOF\"",
		"bash -lc, single quotes":  "bash -lc 'apply_patch <<'\\''EOF'\\''\n" + del + "\nEOF'",
		"single-quoted arg":        "apply_patch '" + del + "'",
		"quoted command":           "\"apply_patch\" <<'EOF'\n" + del + "\nEOF",
		"applypatch":               "applypatch <<'EOF'\n" + del + "\nEOF",
		"written to a file":        "cat > fix.patch <<'EOF'\n" + del + "\nEOF",
	} {
		got, err := embeddedPatches(cmd)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// cd 的目录是字面路径时，相对路径按它解析（引号与转义按 shell 的规则去掉）
	rel := "*** Begin Patch\n*** Delete File: config.yaml\n*** End Patch"
	for name, cmd := range map[string]string{
		"cd":         "cd /home/u/.config/h-guard && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"quoted cd":  "'cd' '/home/u/.config/h-guard' && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"escaped cd": "\\cd /home/u/.config/h-guard/ && apply_patch <<'EOF'\n" + rel + "\nEOF",
	} {
		got, err := embeddedPatches(cmd)
		if err != nil || len(got) != 1 || got[0].File.Path != "/home/u/.config/h-guard/config.yaml" {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	if got, err := embeddedPatches("ls -la && git status"); err != nil || got != nil {
		t.Errorf("no patch: %+v, %v", got, err)
	}
	if got, err := embeddedPatches("echo 'run cd later' && git status"); err != nil || got != nil {
		t.Errorf("cd only as an argument: %+v, %v", got, err)
	}
	for name, cmd := range map[string]string{
		"from a file":       "apply_patch < fix.patch",
		"from a variable":   "printf %s \"$P\" | apply_patch",
		"obfuscated name":   "a'p'ply_patch < fix.patch",
		"escaped name":      "app\\ly_patch < fix.patch",
		"unreadable patch":  "apply_patch <<'EOF'\n*** Begin Patch\n*** Copy File: a\n*** End Patch\nEOF",
		"no end":            "apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: a\nEOF",
		"two invocations":   "apply_patch <<'A'\n*** Begin Patch\n*** Add File: /w/a\n+x\n*** End Patch\nA\napply_patch <<'B'\n" + del + "\nB",
		"subshell":          "(apply_patch <<'EOF'\n" + del + "\nEOF\n)",
		"pushd":             "pushd ~/.codex; apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: hooks.json\n*** End Patch\nEOF",
		"cd to a variable":  "cd \"$DIR\" && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"cd with ;":         "cd /w; apply_patch <<'EOF'\n" + rel + "\nEOF",
		"text after":        "apply_patch <<'EOF'\n" + del + "\nEOF\nrm -rf x",
		"double-quoted arg": "apply_patch \"" + del + "\"",
		// 别处的一份字面补丁不能抵消另一个读不懂来源的调用
		"unrelated literal patch": "cat <<'EOF'\n*** Begin Patch\n*** Add File: harmless.txt\n+x\n*** End Patch\nEOF\napply_patch < fix.patch",
		// 不带引号的 heredoc 会展开变量与命令替换，路径不是字面的
		"expanded heredoc path":   "TARGET=/home/u/.claude/settings.json; apply_patch <<EOF\n*** Begin Patch\n*** Delete File: ${TARGET}\n*** End Patch\nEOF",
		"expanded heredoc only":   "apply_patch <<EOF\n*** Begin Patch\n*** Delete File: $(echo x)\n*** End Patch\nEOF",
		"bash -lc with expansion": "bash -lc \"apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: $HOME/x\n*** End Patch\nEOF\"",
		// 内容行展开出来的值可以含换行与新的操作头
		"expanded content line": "apply_patch <<EOF\n*** Begin Patch\n*** Add File: harmless.txt\n+${PAYLOAD}\n*** End Patch\nEOF",
		"substituted content":   "apply_patch <<EOF\n*** Begin Patch\n*** Add File: harmless.txt\n+$(cat payload)\n*** End Patch\nEOF",
		// cd - 去 OLDPWD；选项；不以 / . .. 开头的相对目录受 CDPATH 影响
		"cd -":          "cd - && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"cd option":     "cd -P /w && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"cd via CDPATH": "cd project && apply_patch <<'EOF'\n" + rel + "\nEOF",
		// 反斜杠续行拆开的工具名
		"split name, no cd": "apply_\\\npatch < fix.patch",
		// ANSI-C 引用拼出的工具名是静态的，同样按调用读（读不懂就请求确认），不能当作数据
		"ANSI-C name":           "cd /w && a$'pply_patch' <<'EOF'\n" + rel + "\nEOF",
		"ANSI-C escaped name":   "$'\\x61pply_patch' < fix.patch",
		"ANSI-C after a quote":  "echo '$' && $'\\141pply_patch' < fix.patch",
		"dynamic name, a patch": "X=apply; Y=_patch; cd /w && $X$Y <<'EOF'\n" + rel + "\nEOF",
		// ~user、~+、~- 由运行时决定
		"cd ~user": "cd ~u/x && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"cd ~+":    "cd ~+ && apply_patch <<'EOF'\n" + rel + "\nEOF",
		"cd ~-":    "cd ~- && apply_patch <<'EOF'\n" + rel + "\nEOF",
		// ANSI-C 片段里的零字节截断该片段，之后拼接的部分照样是工具名
		"ANSI-C NUL octal":     "cd /w && a$'pply_\\0discard'patch <<'EOF'\n" + rel + "\nEOF",
		"ANSI-C NUL hex":       "cd /w && a$'pply_\\x00discard'patch <<'EOF'\n" + rel + "\nEOF",
		"ANSI-C NUL unicode":   "cd /w && a$'pply_\\u0000x'patch <<'EOF'\n" + rel + "\nEOF",
		"ANSI-C NUL control":   "cd /w && a$'pply_\\c@x'patch <<'EOF'\n" + rel + "\nEOF",
		"ANSI-C NUL, no patch": "a$'pply_\\000\\'x'patch < fix.patch",
		// 续行之后是用户名，同 ~user
		"cd ~ continued user": "cd ~\\\nu/x && apply_patch <<'EOF'\n" + rel + "\nEOF",
		// 不带 $、反引号拼出工具名（经 sed、xargs），补丁用 printf 写成一行：写进命令的字面补丁读不出时
		// 不能当作数据丢掉
		"unreadable data patch":  "printf '*** Begin Patch\\n*** Delete File: /h/x\\n*** End Patch\\n' > /tmp/p; echo apply_patcX | sed s/X/h/ | xargs -I{} sh -c '{} < /tmp/p'",
		"data patch without end": "cat > fix.patch <<'EOF'\n*** Begin Patch\n*** Delete File: /h/x\nEOF",
	} {
		if got, err := embeddedPatches(cmd); !errors.Is(err, errUnparsed) {
			t.Errorf("%s: %+v, %v; want errUnparsed", name, got, err)
		}
	}
	// 带引号的 ~ 是 cwd 下名为 ~ 的目录，不是 Home；不带引号的 ~ 与 ./、../ 开头的目录照常解析
	for cmd, want := range map[string]string{
		"cd '~' && apply_patch <<'EOF'\n" + rel + "\nEOF": "./~/config.yaml",
		// tilde 前缀（到第一个不带引号的 / 为止）里有任何引用就不展开，包括空引号
		"cd ~'' && apply_patch <<'EOF'\n" + rel + "\nEOF":     "./~/config.yaml",
		"cd ~\"/\" && apply_patch <<'EOF'\n" + rel + "\nEOF":  "./~/config.yaml",
		"cd ''~ && apply_patch <<'EOF'\n" + rel + "\nEOF":     "./~/config.yaml",
		"cd \\~ && apply_patch <<'EOF'\n" + rel + "\nEOF":     "./~/config.yaml",
		"cd ~ && apply_patch <<'EOF'\n" + rel + "\nEOF":       "~/config.yaml",
		"cd ~/'a b' && apply_patch <<'EOF'\n" + rel + "\nEOF": "~/a b/config.yaml",
		// 反斜杠续行在识别词之前就去掉，不是引用；单引号里的反斜杠换行是字面字符
		"cd ~\\\n/g && apply_patch <<'EOF'\n" + rel + "\nEOF":           "~/g/config.yaml",
		"cd \\\n~/g && apply_patch <<'EOF'\n" + rel + "\nEOF":           "~/g/config.yaml",
		"cd ~'\\\n'/g && apply_patch <<'EOF'\n" + rel + "\nEOF":         "./~\\\n/g/config.yaml",
		"cd ~/.config/h-guard && apply_patch <<'EOF'\n" + rel + "\nEOF": "~/.config/h-guard/config.yaml",
		"cd ./sub && apply_patch <<'EOF'\n" + rel + "\nEOF":             "./sub/config.yaml",
	} {
		if got, err := embeddedPatches(cmd); err != nil || len(got) != 1 || got[0].File.Path != want {
			t.Errorf("%q: %+v, %v; want %s", cmd, got, err, want)
		}
	}
	// 续行拆开的工具名照常按调用读（目录照常解析）
	if got, err := embeddedPatches("cd /h/.config/h-guard && apply_\\\npatch <<'EOF'\n" + rel + "\nEOF"); err != nil || len(got) != 1 || got[0].File.Path != "/h/.config/h-guard/config.yaml" {
		t.Errorf("split name after cd: %+v, %v", got, err)
	}
	if got, err := embeddedPatches("apply_\\\npatch <<'EOF'\n" + del + "\nEOF"); err != nil || len(got) != 1 {
		t.Errorf("split name: %+v, %v", got, err)
	}
	// 对照：展开之后的字面补丁（不带引号的 heredoc 里没有 $、反引号、反斜杠）照常读
	if got, err := embeddedPatches("apply_patch <<EOF\n*** Begin Patch\n*** Add File: a.txt\n+plain text\n*** End Patch\nEOF"); err != nil || len(got) != 1 {
		t.Errorf("unquoted literal heredoc: %+v, %v", got, err)
	}
	// 对照：只写入补丁数据（正文在带引号的 heredoc 里，其中的 $ 是字面字符）照旧按数据读
	if got, err := embeddedPatches("cat > fix.patch <<'EOF'\n*** Begin Patch\n*** Delete File: /w/$x\n*** End Patch\nEOF"); err != nil || len(got) != 1 {
		t.Errorf("data with a literal $: %+v, %v", got, err)
	}
	// 对照：带引号的 heredoc 与单引号参数里的 $ 是字面字符
	lit := "*** Begin Patch\n*** Delete File: /w/$x.txt\n*** End Patch"
	for name, cmd := range map[string]string{"quoted heredoc": "apply_patch <<'EOF'\n" + lit + "\nEOF", "single quotes": "apply_patch '" + lit + "'"} {
		if got, err := embeddedPatches(cmd); err != nil || len(got) != 1 || got[0].File.Path != "/w/$x.txt" {
			t.Errorf("%s: %+v, %v", name, got, err)
		}
	}
	// 相对路径但没有切换目录：照常按 cwd 解析
	if got, err := embeddedPatches("apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: hooks.json\n*** End Patch\nEOF"); err != nil || len(got) != 1 {
		t.Errorf("relative path without cd: %+v, %v", got, err)
	}
}

// FuzzEmbeddedPatches：任何命令都不 panic；读得出时每个动作都有非空路径。
func FuzzEmbeddedPatches(f *testing.F) {
	f.Add("cd '/w' && apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: a\n*** End Patch\nEOF")
	f.Add("bash -lc \"apply_patch '*** Begin Patch\n*** Add File: b\n+x\n*** End Patch'\"")
	f.Fuzz(func(t *testing.T, cmd string) {
		acts, err := embeddedPatches(cmd)
		if err != nil {
			return
		}
		for _, a := range acts {
			if a.File == nil || a.File.Path == "" {
				t.Fatalf("%q: bad action %+v", cmd, a)
			}
		}
	})
}

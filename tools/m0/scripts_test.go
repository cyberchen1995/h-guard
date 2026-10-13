package m0

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scenarioRe 匹配脚本里的场景调用：行首（可带环境变量前缀）的 scenario NAME。
var scenarioRe = regexp.MustCompile(`(?m)^(?:[A-Z_]+=\S+ )*scenario ([a-z0-9-]+) `)

// TestScriptsRunEveryJudgedScenario 核对录制脚本与 m0verdict 的场景名一致：判定表里的每个场景都由脚本运行，
// 脚本运行的每个场景都有判定。场景名不一致时，录制花了额度却只能得到「场景没有运行」。
func TestScriptsRunEveryJudgedScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("builds m0verdict")
	}
	bin := filepath.Join(t.TempDir(), "m0verdict")
	build := exec.Command("go", "build", "-o", bin, "../m0verdict")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build m0verdict: %v\n%s", err, out)
	}
	for harness, script := range map[string]string{"claudecode": "claude-scripted.sh", "codex": "codex-scripted.sh"} {
		t.Run(harness, func(t *testing.T) {
			src, err := os.ReadFile(script)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, m := range scenarioRe.FindAllStringSubmatch(string(src), -1) {
				names = append(names, m[1])
			}
			facts := "scenario\texit_code\tresult_bytes\treason_shown\thook_replies\thook_saw_secret\tin_result\tin_transcript\treplaced_in_transcript\ttarget_tool_seen\ttarget_calls\tleak_elsewhere\n"
			for _, n := range names {
				facts += n + "\t0\t1\tno\t0\t-\t-\t-\t-\t-\t-\t-\n"
			}
			path := filepath.Join(t.TempDir(), "facts.tsv")
			if err := os.WriteFile(path, []byte(facts), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(bin, "-harness", harness, "-facts", path).Output()
			if err != nil {
				t.Fatal(err)
			}
			table := string(out)
			for _, line := range strings.Split(table, "\n") {
				if strings.Contains(line, "场景没有运行") {
					t.Errorf("%s does not run %s", script, strings.Fields(line)[1])
				}
			}
			for _, n := range names {
				if !strings.Contains(table, "| "+n+" |") {
					t.Errorf("%s runs %s, which m0verdict does not judge", script, n)
				}
			}
		})
	}
}

// TestHarnessRunsDoNotReadStdin：codex exec 在 stdin 不是终端时会等待读入，脚本在管道里运行就会一直挂起。
// 每条 harness 调用都要显式从 /dev/null 读 stdin。
func TestHarnessRunsDoNotReadStdin(t *testing.T) {
	stmt := regexp.MustCompile(`(?ms)^\s*(?:\(cd [^\n]*&& )?(?:codex exec|claude -p)\b.*?\n[^\n]*\|\| rc=\$\?`)
	for _, script := range []string{"claude-scripted.sh", "codex-scripted.sh", "../m1/claude-pretooluse.sh"} {
		src, err := os.ReadFile(script)
		if err != nil {
			t.Fatal(err)
		}
		runs := stmt.FindAllString(string(src), -1)
		if len(runs) == 0 {
			t.Fatalf("%s: no harness run found", script)
		}
		for _, run := range runs {
			if !strings.Contains(run, "< /dev/null") {
				t.Errorf("%s: harness run does not read stdin from /dev/null:\n%s", script, run)
			}
		}
	}
}

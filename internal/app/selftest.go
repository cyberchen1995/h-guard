package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/seen"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

// entryTimeout 是自测运行一个入口的时限。
const entryTimeout = 30 * time.Second

// selftestBudget 是整个自测的时限：hooks.json 里重复了许多入口时（install 已报告为问题）不能一个个跑上几个小时。
const selftestBudget = 3 * time.Minute

// runEntry 运行 harness 的一个入口：不经 shell，继承本进程的环境再加上 env，stdin 是 harness 会发的 JSON。
func runEntry(argv, env []string, stdin []byte) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), entryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	// 入口派生的子进程继承了 stdout 又不退出时，超时杀掉直接子进程之后最多再等 2 秒，不能一直等 EOF
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = bytes.NewReader(stdin)
	// 输出有上限：坏掉的入口不停地写 stdout 也不能把自测的内存耗尽（hook 的回复只有几百字节）
	stdout, stderr := &cappedBuffer{max: maxEntryOutput}, &cappedBuffer{max: maxEntryOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	// 入口在自己的进程组里运行：超时或退出之后，它派生的子进程一并终止，自测不遗留进程
	killGroup(cmd)
	err := cmd.Run()
	reapGroup(cmd)
	if err == nil && stdout.over {
		err = fmt.Errorf("the entry wrote more than %d bytes", maxEntryOutput)
	}
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), err
}

// maxEntryOutput 是自测保留的入口输出上限（stdout 与 stderr 各自）。
const maxEntryOutput = 1 << 20

// cappedBuffer 只保留前 max 字节，之后的写入丢弃（不报错，进程照常结束）并记下超限。
type cappedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return c.Buffer.Write(p)
}

// selftestCommand 是自测的动作：模拟 agent 要运行的灾难性命令。它只作为 JSON 交给 hook，从不执行；
// 万一坏掉的入口真把它交给了 shell，开头的 false && 也让删除不会运行（灾难性规则照样拦下它）。
const selftestCommand = "false && rm -rf /"

// selftestPrompt 是自测的提示词：带一个编造的 API key（凭据检测认得出的形状）。
var selftestPrompt = "selftest: export OPENAI_API_KEY=sk-" + "hguardSelftestMadeUp0000"

// strictJSON 按 v 的字段严格解码：Codex 的回复格式不允许多余的字段（有就记为 hook 失败），也不能有多余的内容。
func strictJSON(b []byte, v any) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return false
	}
	_, err := d.Token()
	return errors.Is(err, io.EOF)
}

// selftestCase 是一项自测：按 harness 的格式发给入口的输入，与读回复的方法。
type selftestCase struct {
	name, event string
	input       func(cwd string) []byte
	// check 报告回复是否表示拦下；detail 是读到的结论（失败时给用户看）
	check func(out []byte) (ok bool, detail string)
}

func selftestCases(harness string) []selftestCase {
	action := selftestCase{
		name:  "action check (simulated `" + selftestCommand + "`, never run)",
		event: "PreToolUse",
		input: func(cwd string) []byte {
			b, _ := json.Marshal(map[string]any{
				"session_id": seen.SelftestSession, "cwd": cwd, "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "tool_input": map[string]string{"command": selftestCommand},
				"tool_use_id": "h-guard-selftest-1",
			})
			return b
		},
		check: func(out []byte) (bool, string) {
			var r struct {
				HookSpecificOutput struct {
					HookEventName            string `json:"hookEventName"`
					PermissionDecision       string `json:"permissionDecision"`
					PermissionDecisionReason string `json:"permissionDecisionReason"`
				} `json:"hookSpecificOutput"`
			}
			if json.Unmarshal(out, &r) != nil || r.HookSpecificOutput.PermissionDecision == "" {
				return false, "no decision in the reply (the command would run)"
			}
			// harness 不认缺少 hookEventName 的回复（照常执行工具）：回复必须完整
			if r.HookSpecificOutput.HookEventName != "PreToolUse" {
				return false, "the reply has no hookEventName PreToolUse, so the harness would ignore it (the command would run)"
			}
			if harness == "codex" && !strictJSON(out, &r) {
				return false, "the reply has fields Codex does not accept, so Codex would treat the hook as failed (the command would run)"
			}
			d := r.HookSpecificOutput.PermissionDecision
			// Codex 不认没有原因的 deny（记为 hook 失败、照常执行）
			if harness == "codex" && d == "deny" && strings.TrimSpace(r.HookSpecificOutput.PermissionDecisionReason) == "" {
				return false, "the deny has no permissionDecisionReason, so Codex would treat the hook as failed (the command would run)"
			}
			return d == "deny", d
		},
	}
	if harness == "codex" {
		prompt := selftestCase{
			name:  "prompt check (made-up API key)",
			event: "UserPromptSubmit",
			input: func(cwd string) []byte {
				b, _ := json.Marshal(map[string]any{
					"session_id": seen.SelftestSession, "cwd": cwd, "hook_event_name": "UserPromptSubmit", "prompt": selftestPrompt,
				})
				return b
			},
			check: func(out []byte) (bool, string) {
				var r struct {
					Decision string `json:"decision"`
					Reason   string `json:"reason"`
				}
				if json.Unmarshal(out, &r) != nil || r.Decision == "" {
					return false, "no decision in the reply (the prompt would be sent)"
				}
				if !strictJSON(out, &r) {
					return false, "the reply has fields Codex does not accept, so Codex would treat the hook as failed (the prompt would be sent)"
				}
				// Codex 不认没有原因的 block（记为 hook 失败、照常发送）
				if r.Decision == "block" && strings.TrimSpace(r.Reason) == "" {
					return false, "the block has no reason, so Codex would treat the hook as failed (the prompt would be sent)"
				}
				return r.Decision == "block", r.Decision
			},
		}
		return []selftestCase{action, prompt}
	}
	prompt := selftestCase{
		name:  "prompt check (made-up API key)",
		event: "prompt.submit",
		input: func(cwd string) []byte {
			data, _ := json.Marshal(map[string]any{"text": selftestPrompt})
			b, _ := json.Marshal(extproto.Request{Protocol: extproto.Protocol, Harness: "claudecode", Hook: "prompt.submit",
				Session: extproto.Session{ID: seen.SelftestSession, Cwd: cwd}, Data: data})
			return b
		},
		check: func(out []byte) (bool, string) {
			r, err := extproto.ParseReply(out)
			if err != nil {
				return false, "unrecognized reply (the prompt would be sent)"
			}
			return r.Action == extproto.ActionDeny, string(r.Action)
		},
	}
	return []selftestCase{action, prompt}
}

// runSelftest 是安装后的端到端自测：按 harness 写下的入口（插件脚本、hooks.json 里的命令）运行 h-guard，
// 送入一条模拟的灾难性命令与一条带编造凭据的提示词，核对它们被拦下。不执行任何命令、不调用判断后端
// （两项都由本地规则拦下）、不改 harness 的配置；结果记在缓存目录，status 显示最近一次。
// Codex 是否信任了这些 hook 只有 Codex 知道，自测无法核实，只能由「hook 真正运行」的记录间接说明。
func runSelftest(args []string, o Options) int {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	fs.SetOutput(o.Stderr)
	pos, err := parseInterleaved(fs, args)
	if err != nil || len(pos) > 1 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	harnesses := []string{"claudecode", "codex"}
	if len(pos) == 1 {
		if pos[0] != "claudecode" && pos[0] != "codex" {
			fmt.Fprintf(o.Stderr, "h-guard: cannot test %q (known: claudecode, codex)\n", pos[0])
			return 2
		}
		harnesses = pos[:1]
	}
	if o.Home == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the home directory is unavailable")
		return 1
	}
	if o.ConfigDir == "" {
		// 没有配置目录时插件目录会解析成相对路径：不能运行当前目录里碰巧放着的入口
		fmt.Fprintln(o.Stderr, "h-guard: the configuration directory is unavailable")
		return 1
	}
	if o.CacheDir == "" {
		// 被测入口把自己的版本记在缓存目录：没有它就分不出跑的是不是这个 h-guard，结果也记不下来
		fmt.Fprintln(o.Stderr, "h-guard: the cache directory is unavailable")
		return 1
	}
	t := install.Target{Home: o.Home, ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, GOOS: o.GOOS, Getenv: o.Getenv, Run: o.RunHarness, Now: o.Now}
	cwd, _ := os.Getwd()
	tested, failed := 0, 0
	deadline := time.Now().Add(selftestBudget)
	for _, h := range harnesses {
		entries, err := install.Entries(t, h)
		if errors.Is(err, install.ErrNotInstalled) {
			// 入口文件没了、harness 却还登记着 h-guard（install 认为装过）：这是坏掉的安装，记为失败，
			// 不能让之前一次通过的结果留在 status 里
			if lines := install.Inspect(t, h); len(lines) > 0 && !strings.HasPrefix(lines[0], "not installed") {
				fmt.Fprintf(o.Stdout, "%s: FAIL: h-guard is registered but its entries are missing (h-guard install %s --write)\n", h, h)
				failed++
				if werr := seen.WriteSelftest(seen.Dir(o.CacheDir), h, seen.Selftest{At: o.Now().UTC(), Version: buildID(), Config: configFingerprint(o),
					Cases: []seen.Case{{Name: "entries", Detail: "missing"}}}); werr != nil {
					fmt.Fprintln(o.Stderr, "h-guard: cannot record the result:", werr)
				}
				continue
			}
			if len(pos) == 1 {
				fmt.Fprintf(o.Stdout, "%s: not installed (h-guard install %s --write)\n", h, h)
				failed++
			} else {
				fmt.Fprintf(o.Stdout, "%s: not installed, skipped\n", h)
			}
			continue
		}
		if err != nil {
			fmt.Fprintf(o.Stdout, "%s: FAIL: %v\n", h, err)
			failed++
			// 记下这次失败：不能让之前一次通过的结果留在 status 里
			if werr := seen.WriteSelftest(seen.Dir(o.CacheDir), h, seen.Selftest{At: o.Now().UTC(), Version: buildID(), Config: configFingerprint(o),
				Cases: []seen.Case{{Name: "entries", Detail: secrets.Redact(err.Error())}}}); werr != nil {
				fmt.Fprintln(o.Stderr, "h-guard: cannot record the result:", werr)
			}
			continue
		}
		tested++
		fmt.Fprintf(o.Stdout, "%s:\n", h)
		st := seen.Selftest{At: o.Now().UTC(), Version: buildID(), Passed: true, Config: configFingerprint(o)}
		testedVersion := buildID()
		// 入口能跑不等于 harness 会运行它（插件没登记、h-guard 不在记下的路径……）：install 报告的问题都算失败
		for _, line := range install.Inspect(t, h) {
			if p, ok := strings.CutPrefix(line, "problem: "); ok {
				// 配置原文（matcher、记下的路径）可能带着凭据形状的文本或终端控制字符：遮蔽、转义之后再显示与记录
				p = action.Visible(secrets.Redact(p))
				fmt.Fprintf(o.Stdout, "  FAIL configuration: %s\n", p)
				st.Passed = false
				st.Cases = append(st.Cases, seen.Case{Name: "configuration", Detail: p})
			}
		}
		// Claude Code 的插件配置有问题时不运行入口：插件没登记或被改过时，入口里的程序与命令可能不是 h-guard 写下的
		// （hguard-bin 与 hguard.json 一起改掉也能通过文件比对），自测不该替它运行。Codex 的入口是 hooks.json 里
		// Codex 自己会运行的 h-guard 命令，照常逐个检查，好报出每个事件缺了什么
		var cases []selftestCase
		if st.Passed || h != "claudecode" {
			cases = selftestCases(h)
		} else {
			fmt.Fprintln(o.Stdout, "  FAIL entries not run: fix the configuration problems above first")
		}
		for _, c := range cases {
			res := seen.Case{Name: c.name}
			if len(entries[c.event]) == 0 {
				res.Detail = "no h-guard entry for " + c.event + " that runs for every tool (h-guard install " + h + " --write)"
			}
			// harness 对一个事件运行其中每一个入口：每一个都要拦下
			var replies []string
			for i, e := range entries[c.event] {
				if time.Now().After(deadline) {
					res.Passed, res.Detail = false, fmt.Sprintf("not every entry ran: the self-test stops after %s (%d entries for %s)", selftestBudget, len(entries[c.event]), c.event)
					break
				}
				// 只运行指向这个 h-guard 的入口：hooks.json 或插件里写的程序可能被换成了别的（只看名字与参数认不出来），
				// 自测不替它运行；指向旧版本时请用户用这个 h-guard 重新安装
				if !sameProgram(o, e.Program) {
					res.Passed, res.Detail = false, "not run: the entry runs "+action.Visible(e.Program)+", not this h-guard; reinstall with this h-guard"
					break
				}
				// 被测的 h-guard 记下自己的版本（自测记录，不算 harness 运行）：入口指向的可能不是当前这个 h-guard
				_ = seen.Clear(seen.Dir(o.CacheDir), seen.SelftestRuns(h))
				out, err := o.RunEntry(e.Argv, append(slices.Clone(e.Env), selftestEnv+"=1"), c.input(cwd))
				if v := seen.ReadRuns(seen.Dir(o.CacheDir), seen.SelftestRuns(h))[c.event].Version; v != buildID() {
					if v == "" {
						v = "unknown"
					}
					testedVersion = v
				}
				if err != nil {
					// 入口的 stderr 原样显示可以清屏、伪造结果行：转义控制字符；它会记进缓存里的自测结果，先遮蔽凭据
					res.Passed, res.Detail = false, "the entry did not run: "+action.Visible(secrets.Redact(err.Error()))
					break
				}
				ok, got := c.check(out)
				replies = append(replies, action.Visible(secrets.Redact(got))) // 回复来自入口，原样显示与记录前转义控制字符、遮蔽凭据
				res.Passed = ok && (i == 0 || res.Passed)
				res.Detail = "reply: " + strings.Join(replies, ", ")
			}
			mark := "ok  "
			if !res.Passed {
				mark, st.Passed = "FAIL", false
			}
			fmt.Fprintf(o.Stdout, "  %s %s: %s\n", mark, res.Name, res.Detail)
			st.Cases = append(st.Cases, res)
		}
		if testedVersion != buildID() {
			// 验证的不是这个 h-guard：自测不算通过，记下被测的版本，status 据此说明
			st.Version, st.Passed = testedVersion, false
			// 版本来自被测入口写的记录：原样比较，显示前转义控制字符
			fmt.Fprintf(o.Stdout, "  FAIL the installed entries run h-guard %s, not this h-guard (%s); reinstall with this h-guard\n", action.Visible(testedVersion), buildID())
		}
		if !st.Passed {
			failed++
		}
		if err := seen.WriteSelftest(seen.Dir(o.CacheDir), h, st); err != nil {
			fmt.Fprintln(o.Stderr, "h-guard: cannot record the result:", err)
		}
		for _, line := range runningLines(t, o, h) {
			fmt.Fprintln(o.Stdout, "  "+line)
		}
	}
	switch {
	case tested == 0 && failed == 0:
		fmt.Fprintln(o.Stdout, "nothing to test: install h-guard first (h-guard install claudecode --write, h-guard install codex --write)")
		return 1
	case failed > 0:
		fmt.Fprintln(o.Stdout, "self-test failed: h-guard does not protect as installed; see above, then h-guard status")
		return 1
	}
	fmt.Fprintln(o.Stdout, "self-test passed: the installed entries run h-guard and its local rules stop what they should")
	return 0
}

// runningLines 说明 harness 自己有没有运行过入口（「hook 真正运行」），这是自测替代不了的一层。
func runningLines(t install.Target, o Options, h string) []string {
	name := map[string]string{"claudecode": "Claude Code", "codex": "Codex"}[h]
	got, missing, last, _ := hookRuns(t, o, h)
	switch {
	case len(got) > 0 && len(missing) == 0:
		return []string{fmt.Sprintf("%s ran the hook: yes, last %s ago (%s)", name, ago(o.Now(), last.At), strings.Join(got, ", "))}
	case len(got) > 0:
		// 只运行过一部分入口：没运行过的那一层没有保护（Claude Code 的提示词检查走 mod，组织可能禁止）
		return []string{fmt.Sprintf("%s ran the hook: partly; seen %s, not yet %s", name, strings.Join(got, ", "), strings.Join(missing, ", "))}
	case h == "codex":
		return []string{
			"Codex ran the hook: not since it was installed",
			"Codex trust: unverified; h-guard cannot read Codex's trust state. Open Codex, run /hooks and trust the h-guard hooks; h-guard status shows when Codex starts running them",
		}
	}
	return []string{fmt.Sprintf("%s ran the hook: not since it was installed; restart %s and let it run any tool", name, name)}
}

// ago 把时间差写成粗略的「多久以前」。
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// configFingerprint 是配置目录里 config.yaml 与 rules/ 下全部文件的内容摘要（文件名与内容）。status 拿它与自测时
// 记下的比较：配置或规则改过之后，之前的自测结果不再代表现在的保护。读不到的文件按不存在处理。
func configFingerprint(o Options) string {
	if o.ConfigDir == "" {
		return ""
	}
	h := sha256.New()
	add := func(name string) {
		b, err := os.ReadFile(filepath.Join(o.ConfigDir, name))
		if err != nil {
			return
		}
		fmt.Fprintf(h, "%s\n%d\n", name, len(b))
		h.Write(b)
	}
	add("config.yaml")
	var names []string
	_ = filepath.WalkDir(filepath.Join(o.ConfigDir, "rules"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if rel, err := filepath.Rel(o.ConfigDir, p); err == nil {
				names = append(names, filepath.ToSlash(rel))
			}
		}
		return nil
	})
	slices.Sort(names)
	for _, n := range names {
		add(filepath.FromSlash(n))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// sameProgram 报告 prog 是不是这个 h-guard（install 写进入口的程序）：按文件身份比较，符号链接与不同写法的同一路径都算。
func sameProgram(o Options, prog string) bool {
	if o.Executable == nil || prog == "" {
		return false
	}
	exe, err := o.Executable()
	if err != nil {
		return false
	}
	a, err1 := os.Stat(prog)
	b, err2 := os.Stat(exe)
	return err1 == nil && err2 == nil && os.SameFile(a, b)
}

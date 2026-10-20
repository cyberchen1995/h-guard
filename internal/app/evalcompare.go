package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/check/action"
	"github.com/cyberchen1995/h-guard/internal/consent"
	"github.com/cyberchen1995/h-guard/internal/eval"
	hglog "github.com/cyberchen1995/h-guard/internal/log"
	"github.com/cyberchen1995/h-guard/pkg/guard"
	"github.com/cyberchen1995/h-guard/pkg/harness/extproto"
)

// hookOutput 是 Claude Code PreToolUse hook 的输出；放行时 stdout 为空。
type hookOutput struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// compareOptions 是 eval --compare 的选项：任务目录与留出集为空时用内置语料，jsonPath 为空时不写 JSON。
type compareOptions struct{ tasksDir, holdoutPath, jsonPath string }

// 替身与 hook 的时间设置；测试调小以缩短 judge_timeout 一行的耗时。
var (
	compareStubTimeoutMS = 300                    // judge_timeout 一行的 backends.stub.timeout_ms
	compareStubSleep     = 600 * time.Millisecond // 超时模式下替身作答前的睡眠，须长于上面的超时
	compareHookTimeout   = 5                      // hook --timeout 秒
)

// compareJudgeTimeoutMS 是 judge 与 judge_error 两行的 backends.stub.timeout_ms：替身立即作答，
// 超时留得宽，机器繁忙时也不会误判成超时。
const compareJudgeTimeoutMS = 5000

// 替身的 API key：只为满足后端「必须有 key」的要求，替身不校验它。
const (
	compareStubKeyEnv = "HG_EVAL_STUB_KEY"
	compareStubKey    = "eval-stub-not-a-secret"
)

// 留出集共用的沙箱工程文件，覆盖留出步骤引用的常见路径。
var compareHoldoutFiles = []string{".env", ".env.example", "src/main.go", "go.mod", "id_rsa", "id_rsa.pub"}

// 沙箱 home 下预置的文件，让 ~ 开头的路径指向存在的占位文件。
var compareHomeFiles = []string{".ssh/config", ".aws/credentials", ".netrc"}

// runEvalCompare 把会话任务与留出集按五种配置逐一重放：每步都经过真实的 hook 入口（Main），
// 决策与命中规则取自隔离沙箱里的决策日志。不读用户配置、不连外部后端：judge 是进程内的替身。
func runEvalCompare(o Options, co compareOptions) int {
	tasks, err := eval.Tasks()
	if co.tasksDir != "" {
		tasks, err = eval.LoadTasksDir(co.tasksDir)
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	holdout, err := eval.Holdout()
	if co.holdoutPath != "" {
		holdout, err = eval.LoadHoldout(co.holdoutPath)
	}
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	// 决策日志按 call_id（即步骤 id）回填结果，id 重复会让两步读到同一条日志
	if id, dup := duplicateStepID(tasks, holdout); dup {
		fmt.Fprintf(o.Stderr, "h-guard: step id %q is used more than once across the tasks and the held-out steps\n", shown(id))
		return 1
	}
	ctx := context.Background()
	var runs []eval.ConfigRun
	for _, cfg := range eval.Configs {
		r := &compareRunner{o: o}
		run, err := r.Run(ctx, cfg, tasks, holdout)
		if err != nil {
			fmt.Fprintf(o.Stderr, "h-guard: %s: %s\n", cfg, shown(err.Error()))
			return 1
		}
		n, k := 0, 0
		count := func(rs []eval.StepResult) {
			for _, res := range rs {
				n++
				if res.Decision == guard.DecisionAsk || res.Decision == guard.DecisionDeny {
					k++
				}
			}
		}
		for _, tr := range run.Tasks {
			count(tr.Results)
		}
		count(run.Holdout)
		fmt.Fprintf(o.Stderr, "[%s] %d steps, %d interrupts\n", cfg, n, k)
		runs = append(runs, run)
	}
	c := eval.Summarize(runs, compareCommit(), o.Now())
	eval.WriteComparison(o.Stdout, c)
	if co.jsonPath != "" {
		data, err := c.JSON()
		if err == nil {
			err = os.WriteFile(co.jsonPath, append(data, '\n'), 0o600)
		}
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
			return 1
		}
	}
	// 重放出错的步骤不计入任何计数，报告照常输出；退出码为 1 并在 stderr 写明，免得只看退出码的人误以为全部重放成功
	failed := 0
	for _, s := range c.Configs {
		failed += len(s.ReplayErrors)
	}
	if failed > 0 {
		fmt.Fprintf(o.Stderr, "h-guard: %d steps could not be replayed and are left out of the counts (see the replay errors sections of the report)\n", failed)
		return 1
	}
	return 0
}

// duplicateStepID 返回全部任务与留出集里第一个重复出现的步骤 id。
func duplicateStepID(tasks []eval.Task, holdout []eval.Step) (string, bool) {
	seen := map[string]bool{}
	steps := slices.Clone(holdout)
	for _, t := range tasks {
		steps = append(steps, t.Steps...)
	}
	for _, s := range steps {
		if seen[s.ID] {
			return s.ID, true
		}
		seen[s.ID] = true
	}
	return "", false
}

// compareCommit 返回报告里的版本：构建信息里的 vcs.revision 前 12 位，工作区有改动时加 -dirty；没有时用 Version。
func compareCommit() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Version
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return Version
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return rev
}

// compareRunner 在一个临时根目录下重放一个配置。
type compareRunner struct {
	o    Options
	root string // 临时根目录，Run 结束时整个删除
}

// compareEnv 是一个配置的沙箱目录与环境变量。
type compareEnv struct {
	configDir, cacheDir, home string
	getenv                    func(string) string
}

// Run 重放一个配置下的全部任务与留出集。ConfigNone 不运行 hook，每步都放行。
func (r *compareRunner) Run(ctx context.Context, cfg eval.Config, tasks []eval.Task, holdout []eval.Step) (eval.ConfigRun, error) {
	run := eval.ConfigRun{Config: cfg}
	if cfg == eval.ConfigNone {
		pass := func(steps []eval.Step) []eval.StepResult {
			out := make([]eval.StepResult, len(steps))
			for i, s := range steps {
				out[i] = eval.StepResult{Step: s, Decision: guard.DecisionPass}
			}
			return out
		}
		for _, t := range tasks {
			run.Tasks = append(run.Tasks, eval.TaskRun{Task: t, Results: pass(t.Steps)})
		}
		run.Holdout = pass(holdout)
		return run, nil
	}

	root, err := os.MkdirTemp("", "h-guard-compare-*")
	if err != nil {
		return run, err
	}
	r.root = root
	defer func() { _ = os.RemoveAll(root) }() // 先注册：在下面 stub.Close 之后执行
	env := compareEnv{
		configDir: filepath.Join(root, "config"),
		cacheDir:  filepath.Join(root, "cache"),
		home:      filepath.Join(root, "home"),
	}
	for _, d := range []string{env.configDir, env.cacheDir, env.home, filepath.Join(root, "proj")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return run, err
		}
	}
	if err := placeFiles(env.home, compareHomeFiles); err != nil {
		return run, err
	}
	getenv := r.o.Getenv
	env.getenv = func(k string) string {
		if k == compareStubKeyEnv {
			return compareStubKey
		}
		return getenv(k)
	}

	cfgYAML := "version: 1\nlog: {decisions: true}\n"
	var stub *eval.Stub
	if mode, ok := map[eval.Config]eval.StubMode{
		eval.ConfigJudge: eval.StubAnswer, eval.ConfigJudgeTimeout: eval.StubTimeout, eval.ConfigJudgeError: eval.StubError,
	}[cfg]; ok {
		all := slices.Clone(holdout)
		for _, t := range tasks {
			all = append(all, t.Steps...)
		}
		stub = eval.NewStub(all, mode, compareStubSleep)
		defer stub.Close() // 出错返回时关闭；正常结束时下面已先关闭，再关一次无妨
		// 只有超时一行用短超时；retries: 0：超时一行每次调用只等一次超时
		timeoutMS := compareJudgeTimeoutMS
		if cfg == eval.ConfigJudgeTimeout {
			timeoutMS = compareStubTimeoutMS
		}
		cfgYAML += "judge: {enabled: true, backend: stub}\n" +
			"backends: {stub: {type: typesafe, model: stub, base_url: '" + stub.URL() + "', api_key_env: " + compareStubKeyEnv +
			", timeout_ms: " + strconv.Itoa(timeoutMS) + ", retries: 0}}\n"
		id := consent.Identity{Backend: "stub", Type: "typesafe", Target: stub.URL()}
		if err := (consent.Store{Dir: env.configDir}).Grant(id, []consent.Scope{consent.ScopeAction}, r.o.Now()); err != nil {
			return run, err
		}
	}
	if err := os.WriteFile(filepath.Join(env.configDir, "config.yaml"), []byte(cfgYAML), 0o600); err != nil {
		return run, err
	}
	// 后端从进程环境读 key，不经 Options.Getenv：由 hook 加载沙箱配置目录里的 .env 写进进程环境
	// （已设置的变量不覆盖；替身不校验 key，值是什么都可以）
	dotenv := compareStubKeyEnv + "=" + compareStubKey + "\n"
	if err := os.WriteFile(filepath.Join(env.configDir, ".env"), []byte(dotenv), 0o600); err != nil {
		return run, err
	}

	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		cwd, err := r.project(t.ID, t.Project.Files)
		if err != nil {
			return run, fmt.Errorf("task %s: %w", t.ID, err)
		}
		results, err := r.runGroup(cfg, env, "cmp-"+string(cfg)+"-"+t.ID, false, cwd, t.Steps)
		if err != nil {
			return run, err
		}
		run.Tasks = append(run.Tasks, eval.TaskRun{Task: t, Results: results})
	}
	if err := ctx.Err(); err != nil {
		return run, err
	}
	cwd, err := r.project("holdout", compareHoldoutFiles)
	if err != nil {
		return run, err
	}
	if run.Holdout, err = r.runGroup(cfg, env, "cmp-"+string(cfg)+"-holdout", true, cwd, holdout); err != nil {
		return run, err
	}
	if stub != nil {
		// 先关闭再读用量：Close 等还在睡眠的超时回复写完，最后几次调用的输出字节才算得进去
		stub.Close()
		run.Usage = stub.Usage()
	}
	return run, nil
}

// project 在 proj/<name>/ 下建好占位文件，返回它的绝对路径。
func (r *compareRunner) project(name string, files []string) (string, error) {
	if !filepath.IsLocal(name) || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("id %q cannot name a directory", shown(name))
	}
	dir := filepath.Join(r.root, "proj", name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	return dir, placeFiles(dir, files)
}

// placeFiles 在 dir 下创建占位文件（含父目录）；.env 类文件写一行虚构的键值，以 / 结尾的只建目录。
// 路径必须留在 dir 之内。
func placeFiles(dir string, files []string) error {
	for _, f := range files {
		rel := filepath.FromSlash(strings.TrimSuffix(f, "/"))
		if !filepath.IsLocal(rel) {
			return fmt.Errorf("project file %q is outside the project", shown(f))
		}
		p := filepath.Join(dir, rel)
		if strings.HasSuffix(f, "/") {
			if err := os.MkdirAll(p, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		body := "placeholder\n"
		if strings.HasPrefix(filepath.Base(p), ".env") {
			body = "EXAMPLE_KEY=not-a-real-value\n"
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// runGroup 重放一组步骤（一个任务或留出集），再读一次决策日志补全结果。
// perStep 为真时（留出集）每步一个会话 <session>-<step.ID>：留出样本互不相干，一个样本的用户指令
// 不能留在指令缓存里影响后面的样本；任务的步骤共用一个会话，指令随会话累积。
// 日志读不了是沙箱的问题，整个配置报错；单步的问题记在 StepResult.Err。
func (r *compareRunner) runGroup(cfg eval.Config, env compareEnv, session string, perStep bool, cwd string, steps []eval.Step) ([]eval.StepResult, error) {
	var results []eval.StepResult
	if perStep {
		for _, s := range steps {
			results = append(results, r.runSteps(cfg, env, session+"-"+s.ID, cwd, []eval.Step{s})...)
		}
	} else {
		results = r.runSteps(cfg, env, session, cwd, steps)
	}
	logs, err := readDecisions(env.cacheDir)
	if err != nil {
		return nil, err
	}
	for i := range results {
		res := &results[i]
		if res.Err != "" {
			continue
		}
		d, ok := logs[res.Step.ID]
		switch {
		case !ok:
			res.Err = "no decision log entry"
		case d.Decision != res.Decision:
			res.Err = fmt.Sprintf("output %s but log %s", res.Decision, d.Decision)
		default:
			for _, f := range d.Findings {
				res.Findings = append(res.Findings, f.Rule)
			}
			res.Fallbacks = d.Fallbacks
			res.DisabledHits = signalList(d.Signals, action.Name, "judge_disabled_hits")
			res.Latency = time.Duration(d.LatencyMS.Total) * time.Millisecond
		}
	}
	return results, nil
}

// signalList 取决策日志里某个 Check 的一项字符串数组信号：日志的 signals 按 Check 名字分开，
// 形如 {"action": {"judge_disabled_hits": [...]}}；JSON 解出的数组转回 []string，缺项时为 nil。
func signalList(signals map[string]any, check, key string) []string {
	per, _ := signals[check].(map[string]any)
	list, _ := per[key].([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// runSteps 逐步调用 hook：先把这一步的用户指令以 prompt.submit 送进会话的指令缓存，再发 PreToolUse。
// 指令在同一会话里累积，后面的步骤也看得到。Err 只写固定的短语与决策：命令与路径可能带凭据，报告不遮蔽它。
func (r *compareRunner) runSteps(cfg eval.Config, env compareEnv, session string, cwd string, steps []eval.Step) []eval.StepResult {
	out := make([]eval.StepResult, 0, len(steps))
	for _, s := range steps {
		res := eval.StepResult{Step: s}
		for _, req := range s.UserRequests {
			stdout, code := r.hook(env, []string{"hook", "claudecode", "--event", "prompt.submit"}, requestJSON(map[string]any{
				"protocol": extproto.Protocol, "harness": "claudecode", "harness_version": "2.1.296",
				"hook": "prompt.submit", "session": map[string]string{"id": session, "cwd": cwd},
				"data": map[string]any{"text": req, "origin": map[string]string{"kind": "composer"}},
			}))
			if code != 0 || promptRejected(stdout) {
				res.Err = "prompt rejected"
				break
			}
		}
		if res.Err != "" {
			out = append(out, res)
			continue
		}
		args := []string{"hook", "claudecode", "--event", "PreToolUse", "--timeout", strconv.Itoa(compareHookTimeout)}
		stdout, code := r.hook(env, args, requestJSON(map[string]any{
			"session_id": session, "transcript_path": "", "cwd": cwd, "hook_event_name": "PreToolUse",
			"permission_mode": "default", "tool_name": s.Tool, "tool_input": toolInput(s), "tool_use_id": s.ID,
		}))
		res.Decision, res.Err = hookDecision(stdout, code)
		out = append(out, res)
	}
	return out
}

// hook 以沙箱目录调用一次 Main，返回 stdout 与退出码；stderr 丢弃。
func (r *compareRunner) hook(env compareEnv, args []string, stdin []byte) (string, int) {
	var stdout, stderr bytes.Buffer
	o := r.o
	o.Stdin, o.Stdout, o.Stderr = bytes.NewReader(stdin), &stdout, &stderr
	o.ConfigDir, o.CacheDir, o.Home, o.Getenv = env.configDir, env.cacheDir, env.home, env.getenv
	code := Main(args, o)
	return stdout.String(), code
}

// toolInput 按工具组装 Claude Code 的 tool_input，键名与 claudecode adapter 读取的一致。
func toolInput(s eval.Step) map[string]any {
	switch s.Tool {
	case "Bash", "PowerShell":
		return map[string]any{"command": s.Command}
	case "Grep":
		return map[string]any{"path": s.Path, "pattern": "."}
	}
	return map[string]any{"file_path": s.Path}
}

// promptRejected 报告 prompt.submit 的回复是否拦下了指令：空输出是放行，读不懂的回复按拦下处理。
func promptRejected(stdout string) bool {
	if strings.TrimSpace(stdout) == "" {
		return false
	}
	r, err := extproto.ParseReply([]byte(stdout))
	return err != nil || r.Action != extproto.ActionPass
}

// hookDecision 把 PreToolUse 的输出转成决策：空输出是放行。
func hookDecision(stdout string, code int) (guard.Decision, string) {
	if code != 0 {
		return "", "hook exited " + strconv.Itoa(code)
	}
	if strings.TrimSpace(stdout) == "" {
		return guard.DecisionPass, ""
	}
	var h hookOutput
	if err := json.Unmarshal([]byte(stdout), &h); err != nil {
		return "", "hook output is not valid JSON"
	}
	switch d := guard.Decision(h.HookSpecificOutput.PermissionDecision); d {
	case guard.DecisionAsk, guard.DecisionDeny:
		return d, ""
	}
	return "", "hook output has no ask or deny decision"
}

// readDecisions 读取 cacheDir/logs 下全部 decisions-*.jsonl（重放可能跨过午夜，日志按天分文件），
// 按 call_id 取最后一条。
func readDecisions(cacheDir string) (map[string]hglog.Decision, error) {
	files, err := filepath.Glob(filepath.Join(cacheDir, "logs", "decisions-*.jsonl"))
	if err != nil {
		return nil, err
	}
	slices.Sort(files) // 文件名带日期，按名排序即按时间先后
	out := map[string]hglog.Decision{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, line := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var d hglog.Decision
			if err := json.Unmarshal(line, &d); err != nil {
				return nil, errors.New("decision log has a line that is not valid JSON")
			}
			if d.CallID != "" {
				out[d.CallID] = d
			}
		}
	}
	return out, nil
}

// requestJSON 编码 hook 的输入；输入只含字符串与嵌套的 map，编码不会失败。
func requestJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

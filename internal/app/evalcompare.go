package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/cyberchen1995/h-guard/internal/config"
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

// 留出步骤没写 files（nil）时沙箱里预置的默认文件，覆盖内置留出步骤引用的常见路径；
// 写了 files 的步骤只用自己声明的那些，显式写成空数组则沙箱为空。
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
	// 替身按命令与 judge 会收到的指令列表查标注，分不开、标注又不同的两步会让后一步的标注悄悄失效
	if err := eval.AmbiguousCases(stubCases(tasks, holdout, compareRequestWindow())); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", shown(err.Error()))
		return 1
	}
	// 后端从进程环境读替身的 key（不经 Options.Getenv）。调用方环境里已有这个变量时（哪怕是空值），
	// 沙箱里的 .env 也不会覆盖它，judge 调用会因没有 key 全部降级；所以重放期间直接设好，结束时还原
	restore := setProcessEnv(compareStubKeyEnv, compareStubKey)
	defer restore()
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

// setProcessEnv 把进程环境变量 k 设为 v，返回还原函数：原来有就恢复原值（含空值），原来没有就删掉。
func setProcessEnv(k, v string) func() {
	prev, had := os.LookupEnv(k)
	_ = os.Setenv(k, v)
	return func() {
		if had {
			_ = os.Setenv(k, prev)
		} else {
			_ = os.Unsetenv(k)
		}
	}
}

// allSteps 返回留出集与全部任务的步骤：先留出集，再按任务顺序。
func allSteps(tasks []eval.Task, holdout []eval.Step) []eval.Step {
	steps := slices.Clone(holdout)
	for _, t := range tasks {
		steps = append(steps, t.Steps...)
	}
	return steps
}

// compareRequestWindow 返回重放时 action 检查发给 judge 的指令条数：沙箱配置不设 policy，取内置默认的
// policy.request_window；hook 从指令缓存只读最近 requestScan 条，再大也只有这么多。
func compareRequestWindow() int {
	return min(config.Defaults().Policy.RequestWindow, requestScan)
}

// stubCases 按 hook 实际会看到的样子推算每步发给 judge 的指令，供替身建表：
// 任务共用一个会话，重放器在每步之前把这一步的 user_requests 依次送进指令缓存（重复的照样再送），
// 缓存随会话累积，action 检查取其中最近 window 条（userRequests，internal/check/action/check.go）；
// 留出步骤各自一个会话，只有自己的 user_requests，同样取最近 window 条。
// 与 hook 一致的细节：空白指令不写入缓存（cache.Prompts.Add），也不参与选取；重放器送的都是用户本人的指令
// （origin composer），不会被当成 automated 滤掉；缓存不去重，7 天过期与每会话 50 条上限在一次重放里碰不到。
// 被 prompt.submit 拦下的指令不写入缓存，但那一步记为重放错误，不需要预测。
func stubCases(tasks []eval.Task, holdout []eval.Step, window int) []eval.StubCase {
	appendSent := func(sent []string, reqs []string) []string {
		for _, r := range reqs {
			if strings.TrimSpace(r) != "" {
				sent = append(sent, r)
			}
		}
		return sent
	}
	last := func(sent []string) []string {
		if window <= 0 {
			return nil
		}
		return slices.Clone(sent[max(0, len(sent)-window):])
	}
	var cases []eval.StubCase
	for _, s := range holdout {
		cases = append(cases, eval.StubCase{Step: s, Requests: last(appendSent(nil, s.UserRequests))})
	}
	for _, t := range tasks {
		var sent []string
		for _, s := range t.Steps {
			sent = appendSent(sent, s.UserRequests)
			cases = append(cases, eval.StubCase{Step: s, Requests: last(sent)})
		}
	}
	return cases
}

// duplicateStepID 返回全部任务与留出集里第一个重复出现的步骤 id。
func duplicateStepID(tasks []eval.Task, holdout []eval.Step) (string, bool) {
	seen := map[string]bool{}
	for _, s := range allSteps(tasks, holdout) {
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
	// 任务沙箱在 proj/tasks/<id>，留出步骤各自在 proj/holdout/<序号>：任务 id 叫 holdout 也不会撞上
	for _, d := range []string{env.configDir, env.cacheDir, env.home, filepath.Join(root, "proj"),
		filepath.Join(root, "proj", "tasks"), filepath.Join(root, "proj", "holdout")} {
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
		stub = eval.NewStub(stubCases(tasks, holdout, compareRequestWindow()), mode, compareStubSleep)
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

	for _, t := range tasks {
		if err := ctx.Err(); err != nil {
			return run, err
		}
		cwd, err := r.project("tasks", t.ID, t.Project.Files)
		if err != nil {
			return run, fmt.Errorf("task %s: %w", t.ID, err)
		}
		results, err := r.runGroup(cfg, env, []stepGroup{{compareSession(cfg, "task", t.ID), cwd, t.Steps}})
		if err != nil {
			return run, err
		}
		run.Tasks = append(run.Tasks, eval.TaskRun{Task: t, Results: results})
	}
	if err := ctx.Err(); err != nil {
		return run, err
	}
	// 每个留出步骤一个沙箱目录，按序号命名（id 可能含不能做目录名的字符），文件取自步骤的 files
	groups := make([]stepGroup, 0, len(holdout))
	for i, s := range holdout {
		files := s.Files
		if files == nil {
			files = compareHoldoutFiles
		}
		cwd, err := r.project("holdout", strconv.Itoa(i+1), files)
		if err != nil {
			return run, fmt.Errorf("held-out step %s: %w", s.ID, err)
		}
		groups = append(groups, stepGroup{compareSession(cfg, "holdout", s.ID), cwd, []eval.Step{s}})
	}
	if run.Holdout, err = r.runGroup(cfg, env, groups); err != nil {
		return run, err
	}
	if stub != nil {
		// 先关闭再读用量：Close 等还在睡眠的超时回复写完，最后几次调用的输出字节才算得进去
		stub.Close()
		run.Usage = stub.Usage()
	}
	return run, nil
}

// project 在 proj/<parent>/<name>/ 下建好占位文件，返回它的绝对路径；parent 为空时就是 proj/<name>/。
// name 是任务 id 或固定的 holdout，必须是单独一级目录名。
func (r *compareRunner) project(parent, name string, files []string) (string, error) {
	if !filepath.IsLocal(name) || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("id %q cannot name a directory", shown(name))
	}
	dir := filepath.Join(r.root, "proj", parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	return dir, placeFiles(dir, files)
}

// placeFiles 在 dir 下创建占位文件（含父目录）；.env 类文件写一行虚构的键值，以 / 结尾的只建目录。
// 路径必须留在 dir 之内。
func placeFiles(dir string, files []string) error {
	for _, f := range files {
		if err := eval.ValidFixturePath(f); err != nil {
			return errors.New(shown(err.Error()))
		}
		rel := filepath.FromSlash(strings.TrimSuffix(f, "/"))
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

// stepGroup 是在同一个会话、同一个工作目录里依次重放的几步。
type stepGroup struct {
	session, cwd string
	steps        []eval.Step
}

// runGroup 依次重放 groups（一个任务是一组；留出集每步一组），再读一次决策日志补全结果。
// 任务的步骤共用会话 compareSession(cfg, "task", id)，指令随会话累积；留出步骤各用 compareSession(cfg, "holdout", id)
// 与自己的沙箱目录：留出样本互不相干，一个样本的用户指令不能留在指令缓存里影响后面的样本。
// 日志读不了是沙箱的问题，整个配置报错；单步的问题记在 StepResult.Err。
func (r *compareRunner) runGroup(cfg eval.Config, env compareEnv, groups []stepGroup) ([]eval.StepResult, error) {
	var results []eval.StepResult
	for _, g := range groups {
		results = append(results, r.runSteps(cfg, env, g.session, g.cwd, g.steps)...)
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

// compareSession 返回重放用的会话 ID：cmp-<配置>-<kind>-<sha256(id) 的前 16 位十六进制>。
// 指令缓存按会话 ID 分目录，目录名只留安全字符且至多 120 个（internal/cache Prompts.sessionDir），
// 直接用原始 id 时只差标点、或只在 120 字符之后才不同的两个 id 会落进同一个目录；
// 哈希之后会话 ID 全是安全字符、长度固定，不同的 id 各得一个会话。
func compareSession(cfg eval.Config, kind, id string) string {
	sum := sha256.Sum256([]byte(id))
	return "cmp-" + string(cfg) + "-" + kind + "-" + hex.EncodeToString(sum[:])[:16]
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

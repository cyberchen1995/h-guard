package exec_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
	"github.com/cyberchen1995/h-guard/pkg/judge/exec"
	"github.com/cyberchen1995/h-guard/pkg/judge/judgetest"
)

var (
	probQ  = judge.Question{ID: "publish", Kind: judge.KindProbability, Instructions: judge.Instructions{Question: "Would it publish?"}}
	scaleQ = judge.Question{ID: "blast_radius", Kind: judge.KindScale, Instructions: judge.Instructions{Question: "How much?"},
		Levels: []string{"a", "b", "c", "d"}}
)

// helperEnv 打开测试二进制的「判断程序」模式；它必须列在后端的 env 里才会传给程序，
// 这本身也验证了环境变量白名单。
const helperEnv = "HG_EXEC_HELPER"

// TestMain 让测试二进制兼作判断程序：HG_EXEC_HELPER 指定行为。
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helper(mode))
	}
	os.Exit(m.Run())
}

func helper(mode string) int {
	switch mode {
	case "exit3":
		return 3
	case "garbage":
		fmt.Print("not json")
		return 0
	case "big":
		fmt.Print(strings.Repeat("x", 1<<20+10))
		return 0
	case "orphan":
		return orphan()
	case "daemon", "daemon-holding":
		return daemon(mode == "daemon-holding")
	case "orphan-child":
		os.WriteFile(os.Getenv("HG_EXEC_PIDFILE"), []byte(fmt.Sprint(os.Getpid())), 0o600)
		time.Sleep(time.Minute)
		return 0
	}
	var req struct {
		Protocol  string           `json:"protocol"`
		State     map[string]any   `json:"state"`
		Questions []judge.Question `json:"questions"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil || req.Protocol != exec.Protocol {
		return 2
	}
	answers := map[string]any{"unasked": map[string]any{"p": 0.9}}
	for _, q := range req.Questions {
		switch {
		case mode == "nulls" && q.Kind == judge.KindScale:
			answers[q.ID] = map[string]any{"dist": []any{0.5, nil, 0.5, 0}}
		case mode == "nulls":
			answers[q.ID] = map[string]any{"p": nil}
		case q.Kind == judge.KindScale:
			answers[q.ID] = map[string]any{"dist": []float64{0, 0.25, 0.75, 0}}
		default:
			answers[q.ID] = map[string]any{"p": 0.25}
		}
	}
	model := "helper-model"
	if mode == "ids" { // 把收到的题目 ID 放进 model 字段带回
		ids := make([]string, len(req.Questions))
		for i, q := range req.Questions {
			ids[i] = q.ID
		}
		model = strings.Join(ids, ",")
	}
	if mode == "env" { // 把收到的环境变量名与工作目录放进 model 字段带回
		var keys []string
		for _, kv := range os.Environ() {
			keys = append(keys, strings.SplitN(kv, "=", 2)[0])
		}
		sort.Strings(keys)
		wd, _ := os.Getwd()
		model = strings.Join(keys, ",") + "|" + wd
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"answers": answers, "model": model,
		"usage": map[string]int{"input_tokens": 10, "output_tokens": 2}})
	return 0
}

// orphan 启动一个继承 stdout 的子进程，等它写下 pid 后一直挂着：模拟遗留子进程的判断程序。
func orphan() int {
	self, _ := os.Executable()
	child := osexec.Command(self)
	child.Env = append(os.Environ(), helperEnv+"=orphan-child")
	child.Stdout = os.Stdout
	if child.Start() != nil {
		return 1
	}
	for i := 0; i < 200; i++ {
		if data, _ := os.ReadFile(os.Getenv("HG_EXEC_PIDFILE")); len(data) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(time.Minute)
	return 0
}

// daemon 启动一个子进程（写下 pid 后一直挂着），然后正常输出答案并退出：模拟留下后台进程的判断程序。
// holding 为真时子进程继承 stdout，输出管道一直被占着。
func daemon(holding bool) int {
	self, _ := os.Executable()
	child := osexec.Command(self)
	child.Env = append(os.Environ(), helperEnv+"=orphan-child")
	if holding {
		child.Stdout = os.Stdout
	}
	if child.Start() != nil {
		return 1
	}
	for i := 0; i < 200; i++ {
		if data, _ := os.ReadFile(os.Getenv("HG_EXEC_PIDFILE")); len(data) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	fmt.Print(`{"answers": {}}`)
	return 0
}

// newBackend 返回以测试二进制为判断程序、行为为 mode 的后端。
func newBackend(t *testing.T, mode string, o exec.Options) *exec.Backend {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(helperEnv, mode)
	o.Command = self
	o.Env = append(o.Env, helperEnv)
	b, err := exec.New("local-judge", o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnswersFromTheProgram(t *testing.T) {
	b := newBackend(t, "answer", exec.Options{})
	resp, err := b.Ask(context.Background(), map[string]any{"call": "x"}, []judge.Question{probQ, scaleQ})
	if err != nil {
		t.Fatal(err)
	}
	if p := resp.Answers["publish"].P; p == nil || *p != 0.25 {
		t.Errorf("publish = %v", p)
	}
	if d := resp.Answers["blast_radius"].Dist; len(d) != 4 || d[2] != 0.75 {
		t.Errorf("blast_radius = %v", d)
	}
	if _, ok := resp.Answers["unasked"]; ok {
		t.Error("an answer to a question that was not asked was kept")
	}
	if resp.Model != "helper-model" || resp.Usage.InputTokens != 10 {
		t.Errorf("model %q usage %+v", resp.Model, resp.Usage)
	}
}

func TestNullAnswersStayMissing(t *testing.T) {
	b := newBackend(t, "nulls", exec.Options{})
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
	if err != nil || len(resp.Answers) != 0 {
		t.Errorf("answers %+v err %v", resp.Answers, err)
	}
}

func TestOnlyListedEnvAndConfiguredDir(t *testing.T) {
	t.Setenv("HG_EXEC_SECRET", "synthetic-secret")
	t.Setenv("HG_EXEC_LISTED", "1")
	b := newBackend(t, "env", exec.Options{Env: []string{"HG_EXEC_LISTED"}})
	dir := t.TempDir()
	b.SetDir(dir)
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
	if err != nil {
		t.Fatal(err)
	}
	keys, wd, _ := strings.Cut(resp.Model, "|")
	got := map[string]bool{}
	for _, k := range strings.Split(keys, ",") {
		got[k] = true
	}
	if got["HG_EXEC_SECRET"] || !got["HG_EXEC_LISTED"] || !got[helperEnv] || (os.Getenv("PATH") != "" && !got["PATH"]) {
		t.Errorf("env keys = %s", keys)
	}
	want, _ := filepath.EvalSymlinks(dir)
	if got, _ := filepath.EvalSymlinks(wd); got != want {
		t.Errorf("working dir = %q, want %q", got, want)
	}
}

// 没有任何可传的变量（PATH、HOME、LANG 与列出的变量都为空）时，程序不能继承父进程的全部环境：
// cmd.Env 为 nil 时 os/exec 会整体继承。HG_EXEC_HELPER 总是列在 env 里，测试二进制的判断程序模式
// 碰不到这种情况，所以这里改用 /bin/sh，把它收到的秘密变量打印到 model 字段带回。
func TestNoInheritanceWhenNoListedVariableIsSet(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("needs /bin/sh")
	}
	t.Setenv("HG_TEST_SECRET", "synthetic-not-a-key")
	t.Setenv("PATH", "")
	t.Setenv("HOME", "")
	t.Setenv("LANG", "")
	t.Setenv("HG_TEST_UNSET", "")
	b, err := exec.New("sh", exec.Options{Command: "/bin/sh", Env: []string{"HG_TEST_UNSET"},
		Args: []string{"-c", `printf '{"answers":{},"model":"%s"}' "$HG_TEST_SECRET"`}})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "" {
		t.Errorf("the program inherited the parent environment: it saw HG_TEST_SECRET=%q", resp.Model)
	}
}

func TestFailuresAreErrors(t *testing.T) {
	for mode, kind := range map[string]judge.ErrorKind{
		"exit3":   judge.Unavailable,
		"garbage": judge.BadResponse,
		"big":     judge.BadResponse,
	} {
		b := newBackend(t, mode, exec.Options{})
		resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ})
		if judge.KindOf(err) != kind || len(resp.Answers) != 0 {
			t.Errorf("%s: err = %v (want %v), answers %+v", mode, err, kind, resp.Answers)
		}
	}
	b, _ := exec.New("missing", exec.Options{Command: filepath.Join(t.TempDir(), "no-such-program")})
	if _, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.Unavailable {
		t.Errorf("missing program: %v", err)
	}
}

func TestConformance(t *testing.T) {
	for name, kinds := range map[string][]judge.Kind{
		"default":          nil,
		"probability only": {judge.KindProbability},
		"scale only":       {judge.KindScale},
	} {
		t.Run(name, func(t *testing.T) {
			judgetest.Run(t, func(t *testing.T) judge.Backend { return newBackend(t, "answer", exec.Options{Kinds: kinds}) },
				[]judge.Question{probQ, scaleQ})
		})
	}
}

// TestKindsLimitWhatTheProgramIsAsked：程序只收到 kinds 中题型的题；一道都不剩时不启动程序。
func TestKindsLimitWhatTheProgramIsAsked(t *testing.T) {
	b := newBackend(t, "ids", exec.Options{Kinds: []judge.Kind{judge.KindProbability}})
	if c := b.Caps(); !slices.Equal(c.Kinds, []judge.Kind{judge.KindProbability}) || !c.Supports(judge.KindProbability) || c.Supports(judge.KindScale) {
		t.Errorf("caps = %+v", c)
	}
	resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ, scaleQ})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Model != "publish" {
		t.Errorf("the program was asked %q, want only publish", resp.Model)
	}
	if _, ok := resp.Answers["blast_radius"]; ok || resp.Answers["publish"].P == nil {
		t.Errorf("answers = %+v", resp.Answers)
	}
	// exit3 模式一旦启动就是后端出错：没有出错说明程序没有启动
	b = newBackend(t, "exit3", exec.Options{Kinds: []judge.Kind{judge.KindScale}})
	if resp, err := b.Ask(context.Background(), map[string]any{}, []judge.Question{probQ}); err != nil || len(resp.Answers) != 0 {
		t.Errorf("nothing to ask: answers %+v, err %v", resp.Answers, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Ask(ctx, map[string]any{}, []judge.Question{probQ}); judge.KindOf(err) != judge.Timeout {
		t.Errorf("nothing to ask, canceled ctx: err = %v, want a timeout", err)
	}
	// Caps 返回副本：改动它不影响后端
	b.Caps().Kinds[0] = judge.KindProbability
	if c := b.Caps(); c.Kinds[0] != judge.KindScale {
		t.Errorf("Caps().Kinds aliases the backend: %+v", c)
	}
}

// judgeDir 是测试里 exec 后端命令所在的绝对目录：Windows 上以 /opt 开头的路径缺盘符，不算绝对路径。
func judgeDir() string {
	if runtime.GOOS == "windows" {
		return `C:\opt\judge`
	}
	return "/opt/judge"
}

func TestNewAndDescribe(t *testing.T) {
	dir := judgeDir()
	sep := string(filepath.Separator)
	for name, o := range map[string]exec.Options{
		"relative command": {Command: "judge"},
		"env with value":   {Command: dir, Env: []string{"KEY=v"}},
		"negative timeout": {Command: dir, TimeoutMS: -1},
		"bad probability":  {Command: dir, Probability: "guess"},
		"unknown kind":     {Command: dir, Kinds: []judge.Kind{judge.KindProbability, "HGCanaryKind987654"}},
		"empty kinds":      {Command: dir, Kinds: []judge.Kind{}},
		"duplicate kinds":  {Command: dir, Kinds: []judge.Kind{judge.KindScale, judge.KindProbability, judge.KindScale}},
	} {
		_, err := exec.New("b", o)
		if err == nil || strings.Contains(err.Error(), "HGCanaryKind987654") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	b, err := exec.New("local", exec.Options{Command: dir + sep + ".." + sep + "judge" + sep + "run", Args: []string{"--model", "a b"}, Model: "m1", Probability: "logprobs"})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Describe(); got != (judge.Info{Target: strconv.Quote(filepath.Clean(dir+sep+"run")) + ` "--model" "a b"`, Model: "m1", Probability: "logprobs"}) {
		t.Errorf("Describe() = %+v", got)
	}
	if c := b.Caps(); !c.Calibrated || !c.Batch || c.Mechanism != judge.MechanismProgram ||
		!slices.Equal(c.Kinds, []judge.Kind{judge.KindProbability, judge.KindScale}) {
		t.Errorf("caps = %+v", c)
	}
	if b2, _ := exec.New("v", exec.Options{Command: dir}); b2.Caps().Calibrated || b2.Describe().Probability != "verbalized" {
		t.Errorf("default probability: caps %+v, info %+v", b2.Caps(), b2.Describe())
	}
	if _, ok := judge.LookupType(exec.Type); !ok {
		t.Error("type not registered")
	}
}

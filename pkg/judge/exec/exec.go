// Package exec 是外部进程判断后端（spec §8.4，exec 协议 v1），后端类型名 exec。导入本包即注册该类型。
//
// 每次 Ask 启动一次配置的程序（绝对路径与参数，不经过 shell），stdin 写入
// {"protocol": "h-guard.judge/v1", "state": {...}, "questions": [...]}，stdout 读回
// {"answers": {<id>: {"p": 0.3} | {"dist": [...]}}, "model": "...", "usage": {...}}。
//   - 环境变量只传 PATH、HOME、LANG 与配置 env 中列出的变量；工作目录由入口设为 h-guard 配置目录（SetDir）。
//   - stdout 上限 1 MiB；stderr 丢弃。
//   - 截止时间到达时，以及程序退出之后，都终止整个进程组（Unix），不遗留子进程；Windows 只终止该进程
//     （Job Object 在 M3）。判断程序不能把长期运行的服务留在自己的进程组里。
//   - 非零退出、超时、无法解析、超出上限都是后端出错，不会产生放行。
//   - 配置项 kinds 声明程序能回答的题型（默认 probability 与 scale）；程序只会收到这些题型的题，
//     一道都不剩时不启动程序（Caps().Kinds，取答方式 Mechanism program）。
//
// 答案保留「没有给出」：{"p": null}、{} 与分布中的任一 null 都不当作 0（spec §8.1）。
package exec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/pkg/judge"
)

// Type 是注册的后端类型名；Protocol 是协议版本。
const (
	Type     = "exec"
	Protocol = "h-guard.judge/v1"
)

const (
	DefaultTimeout = 10 * time.Second
	maxOutput      = 1 << 20
)

// baseEnv 是总会传给程序的环境变量。
var baseEnv = []string{"PATH", "HOME", "LANG"}

// Options 是 exec 后端的配置项。
type Options struct {
	Command string   `yaml:"command" json:"command"` // 程序的绝对路径
	Args    []string `yaml:"args" json:"args"`
	Env     []string `yaml:"env" json:"env"` // 额外传给程序的环境变量名
	// Model、Probability 由程序的作者声明，只用于校准指纹（spec §8.3）。Probability 取 native、logprobs
	// 或 verbalized（默认）；前两种表示概率经过校准（Caps().Calibrated）。
	Model       string `yaml:"model" json:"model"`
	Probability string `yaml:"probability" json:"probability"`
	TimeoutMS   int    `yaml:"timeout_ms" json:"timeout_ms"`
	// Kinds 是程序能回答的题型，只能取 probability、scale；不写（nil）时两种都能回答。
	// 空列表与重复都是配置错误。
	Kinds []judge.Kind `yaml:"kinds" json:"kinds"`
}

// defaultKinds 是不写 kinds 时程序能回答的题型，也是 kinds 能取的全部值。
var defaultKinds = []judge.Kind{judge.KindProbability, judge.KindScale}

func init() {
	if err := judge.RegisterType(Type, func(name string, decode func(v any) error) (judge.Backend, error) {
		var o Options
		if err := decode(&o); err != nil {
			return nil, err
		}
		return New(name, o)
	}); err != nil {
		panic(err)
	}
}

// Backend 是 exec 后端。创建时不启动程序。
type Backend struct {
	name, command, model, probability string
	args, env                         []string
	kinds                             []judge.Kind
	timeout                           time.Duration
	dir                               string
}

// New 按配置创建后端；配置非法时返回错误。
func New(name string, o Options) (*Backend, error) {
	if !filepath.IsAbs(o.Command) {
		return nil, errors.New("exec: command must be an absolute path")
	}
	b := &Backend{name: name, command: filepath.Clean(o.Command), args: o.Args, env: o.Env, model: o.Model,
		probability: o.Probability, timeout: DefaultTimeout, dir: os.TempDir()}
	switch b.probability {
	case "":
		b.probability = "verbalized"
	case "native", "logprobs", "verbalized":
	default:
		return nil, errors.New("exec: probability must be native, logprobs or verbalized")
	}
	for _, e := range o.Env {
		if e == "" || strings.ContainsAny(e, "=\x00") {
			return nil, errors.New("exec: env lists variable names only")
		}
	}
	kinds, err := parseKinds(o.Kinds)
	if err != nil {
		return nil, err
	}
	b.kinds = kinds
	switch {
	case o.TimeoutMS < 0:
		return nil, errors.New("exec: timeout_ms must not be negative")
	case o.TimeoutMS > 0:
		b.timeout = time.Duration(o.TimeoutMS) * time.Millisecond
	}
	return b, nil
}

// parseKinds 校验配置的题型；说明不回显取值。nil 取默认值，返回的切片不与配置共用底层数组。
func parseKinds(ks []judge.Kind) ([]judge.Kind, error) {
	if ks == nil {
		return slices.Clone(defaultKinds), nil
	}
	if len(ks) == 0 {
		return nil, errors.New("exec: kinds must list at least one question kind")
	}
	for i, k := range ks {
		switch {
		case !slices.Contains(defaultKinds, k):
			return nil, errors.New("exec: kinds may only list probability and scale")
		case slices.Contains(ks[:i], k):
			return nil, errors.New("exec: kinds lists a question kind more than once")
		}
	}
	return slices.Clone(ks), nil
}

// SetDir 设置程序的工作目录（入口设为 h-guard 配置目录，spec §8.4）。
func (b *Backend) SetDir(dir string) { b.dir = dir }

func (b *Backend) Name() string { return b.name }

// Caps 声明的 Kinds 是副本：调用方改动它不影响后端。
func (b *Backend) Caps() judge.BackendCaps {
	return judge.BackendCaps{Calibrated: b.probability != "verbalized", Batch: true, Mechanism: judge.MechanismProgram,
		Kinds: slices.Clone(b.kinds)}
}

// Describe 实现 judge.Describer：同意绑定程序的绝对路径与参数（spec §8.5）。
func (b *Backend) Describe() judge.Info {
	parts := []string{strconv.Quote(b.command)}
	for _, a := range b.args {
		parts = append(parts, strconv.Quote(a))
	}
	return judge.Info{Target: strings.Join(parts, " "), Model: b.model, Probability: b.probability}
}

type request struct {
	Protocol  string           `json:"protocol"`
	State     map[string]any   `json:"state"`
	Questions []judge.Question `json:"questions"`
}

type wireAnswer struct {
	P    *float64   `json:"p"`
	Dist []*float64 `json:"dist"` // 指针保留 null
}

type response struct {
	Answers map[string]wireAnswer `json:"answers"`
	Model   string                `json:"model"`
	Usage   judge.Usage           `json:"usage"`
}

// Ask 启动一次程序问完 qs 中 kinds 内的题；其余题型不发给程序、保持未答（直接调用 Ask 时同样如此，
// 不只靠 judge.AskAll）。一道都不剩时不启动程序。
func (b *Backend) Ask(ctx context.Context, state map[string]any, qs []judge.Question) (judge.Response, error) {
	qs = slices.DeleteFunc(slices.Clone(qs), func(q judge.Question) bool { return !slices.Contains(b.kinds, q.Kind) })
	if len(qs) == 0 {
		if err := ctx.Err(); err != nil {
			return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: err}
		}
		return judge.Response{Answers: map[string]judge.Answer{}}, nil
	}
	in, err := json.Marshal(request{Protocol: Protocol, State: state, Questions: qs})
	if err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: err}
	}
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	out := &limitedBuffer{max: maxOutput, overflow: cancel}
	cmd := osexec.CommandContext(ctx, b.command, b.args...)
	cmd.Dir = b.dir
	cmd.Env = b.environ()
	cmd.Stdin = bytes.NewReader(in)
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	// 程序退出（或被终止）后，留下的子进程仍占着 stdout 时最多再等 1 秒；Windows 上没有进程组，靠它保证返回
	cmd.WaitDelay = time.Second
	killGroup(cmd)
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
		}
		return judge.Response{}, &judge.Error{Kind: judge.Unavailable, Err: errors.New("cannot start the program")}
	}
	werr := cmd.Wait()
	// 程序退出后仍可能留下子进程（后台任务，或占着输出管道直到 WaitDelay 到期）：返回前终止整个进程组
	// （评审 M2-08）。进程组里还有成员时组号不会被系统复用，所以不会误杀别的进程。
	reapGroup(cmd)
	switch {
	case out.exceeded:
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("output larger than 1 MiB")}
	case ctx.Err() != nil:
		return judge.Response{}, &judge.Error{Kind: judge.Timeout, Err: ctx.Err()}
	case errors.Is(werr, osexec.ErrWaitDelay):
		return judge.Response{}, &judge.Error{Kind: judge.Unavailable, Err: errors.New("the program exited but its output stayed open")}
	case werr != nil:
		code := -1
		var ee *osexec.ExitError
		if errors.As(werr, &ee) {
			code = ee.ExitCode()
		}
		return judge.Response{}, &judge.Error{Kind: judge.Unavailable, Err: fmt.Errorf("the program exited with code %d", code)}
	}
	data := out.buf.Bytes()
	var r response
	if err := json.Unmarshal(data, &r); err != nil {
		return judge.Response{}, &judge.Error{Kind: judge.BadResponse, Err: errors.New("output is not a valid JSON response")}
	}
	resp := judge.Response{Answers: map[string]judge.Answer{}, Model: r.Model, Usage: r.Usage}
	for _, q := range qs {
		w, ok := r.Answers[q.ID]
		if !ok {
			continue
		}
		a := judge.Answer{P: w.P}
		for _, p := range w.Dist {
			if p == nil { // 分布中任一项没有给出，整道题当作没有给出
				a.Dist = nil
				break
			}
			a.Dist = append(a.Dist, *p)
		}
		if a.P != nil || a.Dist != nil {
			resp.Answers[q.ID] = a
		}
	}
	return resp, nil
}

// environ 只传 PATH、HOME、LANG 与配置列出的变量。
func (b *Backend) environ() []string {
	// 不能返回 nil：cmd.Env 为 nil 时 os/exec 会整体继承父进程的环境，包括 API key。
	env := make([]string, 0, len(baseEnv)+len(b.env))
	for _, k := range append(append([]string(nil), baseEnv...), b.env...) {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// limitedBuffer 收集 stdout，超过 max 字节时记下并调用 overflow（终止程序）。
// 只由 os/exec 的复制协程写入；Wait 返回后读取。
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	exceeded bool
	overflow func()
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.max {
		w.exceeded = true
		w.overflow()
		return 0, errors.New("output larger than the limit")
	}
	return w.buf.Write(p)
}

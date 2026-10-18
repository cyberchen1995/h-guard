package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/cyberchen1995/h-guard/extensions"
	"github.com/cyberchen1995/h-guard/internal/store"
)

// 单文件扩展（opencode 插件、pi 与 omp 的扩展、dsh 插件）：内嵌的模板里 CONFIG 一行（pi 的模板另有 HARNESS 一行）
// 以 「// h-guard install」 结尾，install 把它们换成本次安装的取值，其余内容原样写出。
const extMarker = "// h-guard install"

var (
	extConfigLine  = regexp.MustCompile(`(?m)^const CONFIG = (.*) ` + regexp.QuoteMeta(extMarker) + `$`)
	extHarnessLine = regexp.MustCompile(`(?m)^const HARNESS = '([a-z]+)' ` + regexp.QuoteMeta(extMarker) + `$`)
)

// OpenCodeWritten、PiWritten、OMPWritten、DSHWritten 是各扩展按其源码编写的 harness 版本（还没有经过录制核实）。
const (
	OpenCodeWritten = "1.19.3"
	PiWritten       = "1.3.0"
	OMPWritten      = "18.11.3"
	DSHWritten      = "0.2.1-rc.2"
)

// extConfig 是写进扩展的 CONFIG：h-guard 的命令（不含 --event）与等待它的毫秒数。
type extConfig struct {
	Command   []string `json:"command"`
	TimeoutMS int      `json:"timeout_ms"`
}

// renderExt 按 t 的 h-guard 路径与超时写出 harness 的扩展。
func renderExt(tmpl []byte, harness string, t Target) ([]byte, error) {
	cfg, _ := json.Marshal(extConfig{
		Command:   []string{t.Bin, "hook", harness, "--timeout", strconv.Itoa(t.Timeout)},
		TimeoutMS: t.Timeout * 1000,
	})
	if len(extConfigLine.FindAllIndex(tmpl, -1)) != 1 {
		return nil, errors.New("embedded extension: unexpected CONFIG line")
	}
	out := extConfigLine.ReplaceAllLiteral(tmpl, []byte("const CONFIG = "+string(cfg)+" "+extMarker))
	if extHarnessLine.Match(tmpl) {
		out = extHarnessLine.ReplaceAllLiteral(out, []byte("const HARNESS = '"+harness+"' "+extMarker))
	}
	return out, nil
}

// isOurExt 报告文件是否是 h-guard 写出的扩展。
func isOurExt(b []byte) bool {
	return bytes.Contains(b, []byte("'h-guard.ext/v1'")) && extConfigLine.Match(b)
}

// installedExt 读出已写出的扩展里的 harness、h-guard 路径与超时（秒）；读不出时 ok 为假。
func installedExt(b []byte, harness string) (bin string, timeout int, ok bool) {
	m := extConfigLine.FindSubmatch(b)
	if m == nil {
		return "", 0, false
	}
	var cfg extConfig
	if json.Unmarshal(m[1], &cfg) != nil || len(cfg.Command) != 5 || cfg.Command[1] != "hook" || cfg.Command[2] != harness ||
		cfg.Command[3] != "--timeout" {
		return "", 0, false
	}
	n, err := strconv.Atoi(cfg.Command[4])
	if err != nil || n*1000 != cfg.TimeoutMS {
		return cfg.Command[0], 0, false
	}
	return cfg.Command[0], n, true
}

// extHarness 返回扩展文件里 HARNESS 一行的取值；没有这一行时为空。
func extHarness(b []byte) string {
	if m := extHarnessLine.FindSubmatch(b); m != nil {
		return string(m[1])
	}
	return ""
}

// extFileStep 计划一个归本项目所有的单文件扩展：安装时写出 data（内容相同时不改动），移除时删掉它；符号链接见下。文件已存在而
// 不是 h-guard 的扩展时不覆盖、不删除。执行时（持有读改写锁）先复核文件与计划时相同；覆盖或删除前把原文件备份到
// <cache_dir>/backups/<name>.<时间>.<随机串>/。
func extFileStep(t Target, path, name string, data []byte, remove bool) (Step, error) {
	// path 是符号链接时写它指向的文件，链接本身保留（与 Editor 相同，dotfiles 管理的配置）；移除时只删链接
	target := path
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return Step{}, fmt.Errorf("%s is a symbolic link whose target cannot be resolved; not changing it", path)
		}
		target = resolved
	}
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Step{}, err
	}
	if exists && !isOurExt(old) {
		if remove {
			return Step{}, fmt.Errorf("%s does not look like h-guard's extension; not removing it", path)
		}
		return Step{}, fmt.Errorf("%s exists and is not h-guard's extension; not overwriting it", path)
	}
	ed := t.editor()
	verify := func() error {
		now, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if (err == nil) != exists || !bytes.Equal(now, old) {
			return fmt.Errorf("%s changed since the install was planned: %w", path, store.ErrConflict)
		}
		return nil
	}
	backup := func() error {
		if exists {
			return backupDir(ed, name, map[string][]byte{filepath.Base(path): old})
		}
		return nil
	}
	if remove {
		return Step{Path: path, Summary: "remove h-guard's extension", changes: exists, lockDir: ed.LockDir, verify: verify,
			apply: func() error {
				if err := backup(); err != nil {
					return err
				}
				return os.Remove(path)
			}}, nil
	}
	return Step{Path: path, Summary: "write h-guard's extension", changes: !exists || !bytes.Equal(old, data), lockDir: ed.LockDir, verify: verify,
		apply: func() error {
			if err := backup(); err != nil {
				return err
			}
			return store.WriteAtomic(target, data, 0o600)
		}}, nil
}

// OpenCodeConfigDir 是 opencode 的全局配置目录：$XDG_CONFIG_HOME/opencode，默认 ~/.config/opencode（Windows 同样如此）。
func OpenCodeConfigDir(t Target) string {
	if d := t.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "opencode")
	}
	return filepath.Join(t.Home, ".config", "opencode")
}

// OpenCodePlugin 是写出的 opencode 插件：<opencode 配置目录>/plugins/h-guard.js，opencode 启动时自动加载。
func OpenCodePlugin(t Target) string {
	return filepath.Join(OpenCodeConfigDir(t), "plugins", "h-guard.js")
}

// OpenCode 计划 opencode 的安装或移除：写出或删掉插件文件。opencode 的配置文件不改动。
func OpenCode(t Target, remove bool) ([]Step, error) {
	data, err := renderExt(extensions.OpenCode, "opencode", t)
	if err != nil {
		return nil, err
	}
	s, err := extFileStep(t, OpenCodePlugin(t), "opencode-plugin", data, remove)
	if err != nil {
		return nil, err
	}
	if !remove {
		s.Summary = "write h-guard's opencode plugin"
	}
	return []Step{s}, nil
}

// PiAgentDir 是 pi 的 agent 目录：$PI_CODING_AGENT_DIR（见 ExpandPiDir），默认 ~/.pi/agent。
func PiAgentDir(t Target) string {
	if d := t.Getenv("PI_CODING_AGENT_DIR"); d != "" {
		return ExpandPiDir(t.Home, d)
	}
	return filepath.Join(t.Home, ".pi", "agent")
}

// ExpandPiDir 与 pi 一样展开 $PI_CODING_AGENT_DIR 开头的 ~（~、~/…，Windows 上另有 ~\…）；其余原样返回。
func ExpandPiDir(home, d string) string {
	switch {
	case d == "~":
		return home
	case strings.HasPrefix(d, "~/"), runtime.GOOS == "windows" && strings.HasPrefix(d, `~\`):
		return filepath.Join(home, d[2:])
	}
	return d
}

// OMPAgentDir 是 oh-my-pi 默认配置档的 agent 目录：$PI_CODING_AGENT_DIR，默认 ~/<$PI_CONFIG_DIR 或 .omp>/agent。
// 用 OMP_PROFILE 选择的其他配置档在 ~/.omp/profiles/<名字>/agent，不在这里。
func OMPAgentDir(t Target) string {
	if d := t.Getenv("PI_CODING_AGENT_DIR"); d != "" {
		return d
	}
	root := t.Getenv("PI_CONFIG_DIR")
	if root == "" {
		root = ".omp"
	}
	return filepath.Join(t.Home, root, "agent")
}

// PiExtension 与 OMPExtension 是写出的扩展：<agent 目录>/extensions/ 下的单个文件，启动时自动加载。
// 两个文件名不同：PI_CODING_AGENT_DIR 让两者共用一个目录时，install 能认出另一个并拒绝。
func PiExtension(t Target) string { return filepath.Join(PiAgentDir(t), "extensions", "h-guard.js") }
func OMPExtension(t Target) string {
	return filepath.Join(OMPAgentDir(t), "extensions", "h-guard-omp.js")
}

// Pi 计划 pi（harness 为 pi）或 oh-my-pi（omp）的安装或移除：写出或删掉扩展文件，设置文件不改动。
func Pi(t Target, harness string, remove bool) ([]Step, error) {
	path, other := PiExtension(t), OMPExtension(t)
	if harness == "omp" {
		path, other = other, path
	}
	if !remove && sameDir(filepath.Dir(path), filepath.Dir(other)) {
		// 同一个扩展目录会被 pi 与 omp 都加载：两个扩展会把同一次调用各报告一次，而且其中一个报错 harness
		if b, err := os.ReadFile(other); err == nil && isOurExt(b) {
			return nil, fmt.Errorf("%s already holds h-guard's %s extension, and pi and omp load the same extensions directory here (PI_CODING_AGENT_DIR); install h-guard for only one of them", filepath.Dir(path), extHarness(b))
		}
	}
	data, err := renderExt(extensions.Pi, harness, t)
	if err != nil {
		return nil, err
	}
	s, err := extFileStep(t, path, harness+"-extension", data, remove)
	if err != nil {
		return nil, err
	}
	if !remove {
		s.Summary = "write h-guard's " + harness + " extension"
	}
	return []Step{s}, nil
}

// sameDir 报告两个目录是否是同一个：都存在时按文件系统判断（符号链接、目录联接指向同一处也算）；还不存在时比较名字
// 与上一级目录（~/.omp/agent 链接到 ~/.pi/agent 时，两边还没建的 extensions 同样是一个目录）。
func sameDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	fa, erra := os.Stat(a)
	fb, errb := os.Stat(b)
	if erra == nil && errb == nil {
		return os.SameFile(fa, fb)
	}
	pa, pb := filepath.Dir(a), filepath.Dir(b)
	if filepath.Base(a) != filepath.Base(b) || pa == a || pb == b {
		return false
	}
	return sameDir(pa, pb)
}

// harnessVersionNote 检查 harness 的版本：低于扩展按其编写的版本时说明（不阻止）；找不到命令时说明。
// major 不为 0 时，主版本号不同的版本说明不受支持（opencode 2.x 的插件 API 不同）。
func harnessVersionNote(t Target, cmd, product, written string, major int) []string {
	v := harnessVersion(t, cmd)
	if v == "" {
		return []string{fmt.Sprintf("%s was not found; the extension takes effect when %s starts", cmd, product)}
	}
	v = strings.TrimPrefix(v, cmd+"/") // omp --version 打印 omp/<版本>
	if major > 0 {
		if m, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0]); err == nil && m != major {
			return []string{fmt.Sprintf("%s %s is not supported: h-guard's extension uses the %d.x plugin API and does not load there", product, v, major)}
		}
	}
	if versionLess(v, written) {
		return []string{fmt.Sprintf("%s %s is older than the version h-guard's extension was written for (%s)", product, v, written)}
	}
	return nil
}

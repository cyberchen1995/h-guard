package install

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
)

// Target 是 install 作用的环境。Run 运行 harness 的命令行（取版本、校验插件），nil 表示不可用。
type Target struct {
	Home      string // 用户主目录
	ConfigDir string // h-guard 的配置目录
	CacheDir  string // h-guard 的缓存目录：读改写锁与备份放在这里
	Bin       string // 写进入口的 h-guard 路径
	Timeout   int    // 秒：harness 的 hook 超时，同一值以 --timeout 传给 h-guard
	GOOS      string
	Getenv    func(string) string
	// LookupEnv 与 os.LookupEnv 一样区分设置为空与没有设置；nil 时按 Getenv，空值当作没有设置
	LookupEnv func(string) (string, bool)
	Run       func(name string, args ...string) ([]byte, error)
	// Query 运行 harness 的只读查询命令，只取标准输出（命令失败时也返回已有的输出），nil 表示不可用
	Query func(name string, args ...string) ([]byte, error)
	Now   func() time.Time
}

func (t Target) editor() Editor {
	return Editor{LockDir: filepath.Join(t.CacheDir, "install"), BackupDir: filepath.Join(t.CacheDir, "backups"), Now: t.Now}
}

// lookupEnv 查环境变量，设置为空的变量也算设置了（与 Python 的 os.environ 相同）；没有 LookupEnv 时按 Getenv，
// 空值当作没有设置。名字为空时总是没有设置。
func (t Target) lookupEnv(name string) (string, bool) {
	switch {
	case name == "":
		return "", false
	case t.LookupEnv != nil:
		return t.LookupEnv(name)
	case t.Getenv != nil:
		v := t.Getenv(name)
		return v, v != ""
	}
	return "", false
}

// listSep 是目标平台的路径列表分隔符。
func (t Target) listSep() string {
	if t.GOOS == "windows" {
		return ";"
	}
	return ":"
}

// Step 是 install 的一步：改动一个文件或目录。Preview 是改动后的内容（harness 的配置文件），供只打印不写入时展示。
type Step struct {
	Path    string
	Summary string
	Preview []byte
	// Manual 是 h-guard 不能替用户做、要用户自己完成的改动（如只读或 JSON5 的配置里要加入的设置）；这一步没有改动，
	// Apply 跳过它，install 总是打印它
	Manual  string
	changes bool
	lockDir string       // 执行时持有的读改写锁
	verify  func() error // 可选：执行前（持锁）复核计划时读到的状态，不论这一步有没有改动
	apply   func() error // 调用方已持有锁
}

// Changes 报告这一步是否会改动内容（重复安装、没有安装时移除都不改动）。
func (s Step) Changes() bool { return s.changes }

// Apply 在一把读改写锁下先复核全部步骤（包括没有改动的：别的步骤可能依赖它们，如登记插件依赖插件仍在），再依次执行有改动的步骤，遇到错误即停止。另一个 install 持有锁时返回 store.ErrLocked，什么都不改动。
// 没有任何改动时不加锁、不复核。
func Apply(steps []Step) error {
	var todo []Step
	for _, s := range steps {
		if s.changes {
			todo = append(todo, s)
		}
	}
	if len(todo) == 0 {
		return nil
	}
	unlock, err := store.Lock(todo[0].lockDir)
	if err != nil {
		return err
	}
	defer unlock()
	for _, s := range steps {
		if s.verify != nil {
			if err := s.verify(); err != nil {
				return err
			}
		}
	}
	for _, s := range todo {
		if err := s.apply(); err != nil {
			return err
		}
	}
	return nil
}

// ErrExists 表示要新建的文件已经存在且内容不同。
var ErrExists = errors.New("already exists with other content")

// NewFile 计划写一个新文件（如 migrate 生成的规则包）：文件不存在时新建（0o600），内容相同时不改动，已存在且内容
// 不同时返回 ErrExists（计划与执行时都检查，执行按读改写约定加锁、比对哈希）。
func NewFile(t Target, path string, data []byte, summary string) (Step, error) {
	change := func(old []byte, exists bool) ([]byte, error) {
		if exists && !bytes.Equal(old, data) {
			return nil, fmt.Errorf("%s %w", path, ErrExists)
		}
		return data, nil
	}
	old, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Step{}, err
	}
	if _, err := change(old, exists); err != nil {
		return Step{}, err
	}
	ed := t.editor()
	return Step{Path: path, Summary: summary, Preview: data, changes: !exists, lockDir: ed.LockDir,
		apply: func() error {
			_, err := ed.editLocked(path, change)
			return err
		}}, nil
}

// Package seen 记录 h-guard 的入口确实被 harness 运行过、以及最近一次自测的结果，供 status 区分
// 「配置已写入」「hook 真正运行」「拦截验证通过」三种状态。
//
// 记录放在缓存目录的 seen/ 下，每个 harness 一份：<harness>.runs/<事件>.json 是各事件最近一次运行的时间，
// <harness>.selftest.json 是最近一次自测。记录只是状态提示，写不进去或读不出来都不影响检查本身。
package seen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyberchen1995/h-guard/internal/store"
)

// SelftestSession 是自测发给 hook 的会话 id：带它的调用不算 harness 运行过 hook。
const SelftestSession = "h-guard-selftest"

// refresh 是同一事件两次写入之间的最短间隔：hook 每次调用都写会拖慢它，状态提示不需要秒级精度。
const refresh = time.Minute

// Run 是一个事件最近一次运行。
type Run struct {
	At      time.Time `json:"at"`
	Version string    `json:"version"`
}

// Runs 是一个 harness 各事件最近一次运行，键是 hook 的事件名（如 PreToolUse、prompt.submit）。
type Runs map[string]Run

// Latest 返回最近的一次运行与它的事件名；没有记录时 ok 为假。
func (r Runs) Latest() (event string, run Run, ok bool) {
	for ev, x := range r {
		if !ok || x.At.After(run.At) || (x.At.Equal(run.At) && ev < event) {
			event, run, ok = ev, x, true
		}
	}
	return event, run, ok
}

// Case 是自测的一项。
type Case struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Selftest 是一次自测的结果。
type Selftest struct {
	At      time.Time `json:"at"`
	Version string    `json:"version"`
	Passed  bool      `json:"passed"`
	Cases   []Case    `json:"cases"`
	// Config 是自测时配置与规则的指纹：之后改了配置（停用规则、关掉类别），结果就不再代表现在的保护
	Config string `json:"config,omitempty"`
}

// Dir 是缓存目录下的记录目录；cacheDir 为空时为空。
func Dir(cacheDir string) string {
	if cacheDir == "" {
		return ""
	}
	return filepath.Join(cacheDir, "seen")
}

// runsDir 是 harness 的运行记录目录，每个事件一个文件：并发运行的不同事件各写各的，不会互相覆盖。
func runsDir(dir, harness string) string      { return filepath.Join(dir, harness+".runs") }
func selftestPath(dir, harness string) string { return filepath.Join(dir, harness+".selftest.json") }

// ReadRuns 读 harness 的运行记录；没有时返回空。
func ReadRuns(dir, harness string) Runs {
	runs := Runs{}
	if dir == "" {
		return runs
	}
	entries, _ := os.ReadDir(runsDir(dir, harness))
	for _, e := range entries {
		event, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() {
			continue
		}
		var run Run
		if b, err := os.ReadFile(filepath.Join(runsDir(dir, harness), e.Name())); err == nil && json.Unmarshal(b, &run) == nil {
			runs[event] = run
		}
	}
	return runs
}

// SelftestRuns 是自测调用入口时的记录名：被测的 h-guard 记下自己的版本，不算 harness 运行了 hook。
func SelftestRuns(harness string) string { return "selftest-" + harness }

// Clear 删除 harness 的运行记录。
func Clear(dir, harness string) error {
	if dir == "" || harness == "" {
		return nil // 没有记录目录：不能拿相对路径去删
	}
	return os.RemoveAll(runsDir(dir, harness))
}

// Record 记下 harness 的 event 在 now 运行过。距上次记录不到一分钟、版本也相同时不写。
func Record(dir, harness, event, version string, now time.Time) error {
	if dir == "" || harness == "" || event == "" || strings.ContainsAny(event+harness, `/\`) {
		return nil
	}
	path := filepath.Join(runsDir(dir, harness), event+".json")
	var last Run
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &last) == nil &&
		last.Version == version && now.Sub(last.At) < refresh && !now.Before(last.At) {
		return nil
	}
	b, err := json.Marshal(Run{At: now.UTC(), Version: version})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(runsDir(dir, harness), 0o700); err != nil {
		return err
	}
	return store.WriteAtomic(path, b, 0o600)
}

// WriteSelftest 记下 harness 最近一次自测的结果。
func WriteSelftest(dir, harness string, st Selftest) error {
	if dir == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return store.WriteAtomic(selftestPath(dir, harness), b, 0o600)
}

// ReadSelftest 读 harness 最近一次自测的结果；没有时 ok 为假。
func ReadSelftest(dir, harness string) (Selftest, bool) {
	var st Selftest
	if dir == "" {
		return st, false
	}
	b, err := os.ReadFile(selftestPath(dir, harness))
	if err != nil || json.Unmarshal(b, &st) != nil || st.At.IsZero() {
		return Selftest{}, false
	}
	return st, true
}

// Command fiximport 把 hookrec 的一个场景的原始记录整理为 testdata/fixtures 下的一组样本，并替换本机路径
// （spec §7.5）。harness、版本、平台与批次取自记录目录中的 manifest，不取导入时 CLI 报告的版本（评审 H07）。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/fixtures"
)

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	raw := flag.String("raw", "", "一个场景的 hookrec 记录目录，含 "+fixtures.ManifestFile+"（必填）")
	dest := flag.String("dest", "testdata/fixtures", "样本根目录")
	var workdirs, extra multiFlag
	flag.Var(&workdirs, "workdir", "录制用的临时目录，替换为 "+fixtures.WorkdirPlaceholder+"；可重复，链接路径与物理路径都要给")
	flag.Var(&extra, "replace", "额外替换，格式 OLD=NEW，可重复")
	flag.Parse()
	if *raw == "" {
		fail(errors.New("-raw is required"))
	}

	m, err := fixtures.ReadManifest(*raw)
	if err != nil {
		fail(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fail(err)
	}
	variants, err := workdirVariants(workdirs)
	if err != nil {
		fail(err)
	}
	rules := fixtures.LocalPathRules(home, variants)
	for _, kv := range extra {
		oldValue, newValue, ok := strings.Cut(kv, "=")
		if !ok || oldValue == "" {
			fail(fmt.Errorf("bad -replace %q, want OLD=NEW", kv))
		}
		rules = append(rules, fixtures.Replacement{Old: oldValue, New: newValue})
	}
	written, err := fixtures.Import(*raw, *dest, m.Meta(), rules)
	if err != nil {
		fail(err)
	}
	for _, p := range written {
		fmt.Println(p)
	}
}

// workdirVariants 返回每个录制目录的绝对路径，以及解析符号链接后的写法（两者不同时），去重。
func workdirVariants(wds []string) ([]string, error) {
	var out []string
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, wd := range wds {
		if wd == "" {
			continue
		}
		abs, err := filepath.Abs(wd)
		if err != nil {
			return nil, err
		}
		add(abs)
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			add(real)
		}
	}
	return out, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fiximport:", err)
	os.Exit(1)
}

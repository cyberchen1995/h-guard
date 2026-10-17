package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cyberchen1995/h-guard/internal/install"
	"github.com/cyberchen1995/h-guard/internal/migrate"
	"github.com/cyberchen1995/h-guard/pkg/detect/secrets"
)

// runMigrate 把 Python 版的 questions.json 转成配置与规则包：默认只打印将要写入的内容；--write 时
// 写入 config.yaml（已有内容保留、改动前备份）与规则目录。规则文件已存在且内容不同时不覆盖，什么都不写。
// agent 在 hook 下运行它会被护栏自我保护拦下请求确认。
func runMigrate(args []string, o Options) int {
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	flags.SetOutput(o.Stderr)
	write := flags.Bool("write", false, "write the result (default: only print it)")
	skipInvalid := flags.Bool("skip-invalid", false, "write the rest when some rules cannot be migrated")
	pos, err := parseInterleaved(flags, args)
	if err != nil || len(pos) != 1 {
		fmt.Fprint(o.Stderr, usage)
		return 2
	}
	if o.ConfigDir == "" || o.CacheDir == "" {
		fmt.Fprintln(o.Stderr, "h-guard: the config or cache directory is unavailable")
		return 1
	}
	data, err := readLimited(pos[0], 4<<20)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	r, err := migrate.Convert(data)
	if err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	if v := o.Getenv("H_GUARD_LOG"); v != "" && v != "0" && !strings.EqualFold(v, "off") && !strings.EqualFold(v, "false") {
		r.Notes = append(r.Notes, "H_GUARD_LOG is set: the decision log is now a switch in the config (log: {decisions: true}) and is written under the cache directory; not migrated")
	}
	t := install.Target{ConfigDir: o.ConfigDir, CacheDir: o.CacheDir, Now: o.Now}
	var steps []install.Step
	if len(r.Config) > 0 {
		step, err := install.ConfigValues(t, "migrated settings", r.Config)
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		steps = append(steps, step)
	}
	dir := filepath.Join(o.ConfigDir, "rules")
	names := slices.Sorted(maps.Keys(r.Rules))
	for _, name := range names {
		step, err := install.NewFile(t, filepath.Join(dir, name), r.Rules[name], "migrated rule")
		if errors.Is(err, install.ErrExists) {
			fmt.Fprintf(o.Stderr, "h-guard: %s already exists; move it away or merge by hand, nothing was written\n", filepath.Join(dir, name))
			return 1
		}
		if err != nil {
			fmt.Fprintln(o.Stderr, "h-guard:", err)
			return 1
		}
		steps = append(steps, step)
	}
	for _, n := range r.Notes {
		fmt.Fprintln(o.Stdout, "note:", n)
	}
	if len(r.Skipped) > 0 && !*skipInvalid {
		// 迁移不了的可能是用户自己的 deny 规则：静默丢掉就少了保护
		fmt.Fprintf(o.Stderr, "h-guard: %s could not be migrated (see the notes); nothing was written. Fix them in the questions.json, or run again with --skip-invalid to migrate the rest\n", strings.Join(r.Skipped, ", "))
		return 1
	}
	if len(steps) == 0 && len(names) == 0 {
		fmt.Fprintln(o.Stdout, "nothing to migrate: the file matches the defaults of the Python version, which the built-in rules cover")
		return 0
	}
	verb := "would write"
	if *write {
		verb = "writing"
	}
	for _, s := range steps {
		if s.Changes() {
			fmt.Fprintf(o.Stdout, "%s %s:\n%s", verb, s.Path, s.Preview)
		}
	}
	// 写入之前按 hook 的要求校验合并后的配置与规则目录：不写出 hook 读不了的配置
	if err := checkMigrated(o, steps, dir, r.Rules); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard: the migrated result would not load:", secrets.MaskForLog(err.Error()))
		fmt.Fprintln(o.Stderr, "h-guard: nothing was written; fix the questions.json or the existing config first")
		return 1
	}
	if !*write {
		fmt.Fprintln(o.Stdout, "nothing was written; run again with --write to apply")
		return 0
	}
	if err := install.Apply(steps); err != nil {
		fmt.Fprintln(o.Stderr, "h-guard:", err)
		return 1
	}
	fmt.Fprintln(o.Stdout, "done; check the result with h-guard config validate, then reinstall the harness entries with h-guard install")
	return 0
}

// readLimited 读取至多 limit 字节的文件，超过时报错。
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

// checkMigrated 在临时目录里放好迁移后的 config.yaml 与规则目录（已有的规则加上生成的规则），按 hook 的方式加载。
func checkMigrated(o Options, steps []install.Step, dir string, generated map[string][]byte) error {
	tmp, err := os.MkdirTemp("", "h-guard-migrate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	cfg := filepath.Join(o.ConfigDir, "config.yaml")
	data, err := os.ReadFile(cfg)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, s := range steps {
		if s.Path == cfg && s.Changes() {
			data = s.Preview
		}
	}
	if len(data) > 0 {
		if err := os.WriteFile(filepath.Join(tmp, "config.yaml"), data, 0o600); err != nil {
			return err
		}
	}
	rulesDir := filepath.Join(tmp, "rules")
	if err := os.MkdirAll(rulesDir, 0o700); err != nil {
		return err
	}
	if err := copyRules(dir, rulesDir); err != nil {
		return err
	}
	for name, b := range generated {
		if err := os.WriteFile(filepath.Join(rulesDir, name), b, 0o600); err != nil {
			return err
		}
	}
	// 与 hook 相同地加载（含题型校验与配置里按 id 的规则开关）
	_, err = loadConfig(Options{ConfigDir: tmp, Getenv: o.Getenv}, "", true)
	return err
}

// copyRules 把已有的规则目录（含子目录）复制到 dst；目录不存在时什么都不做。
func copyRules(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return filepath.SkipAll
			}
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
}

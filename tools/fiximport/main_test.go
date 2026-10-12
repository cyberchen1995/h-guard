package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestWorkdirVariantsKeepsEveryWrittenForm(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	got, err := workdirVariants([]string{link, real})
	if err != nil {
		t.Fatal(err)
	}
	// 记录里可能出现链接路径（HG_M0_WORK）与物理路径（harness 报告的 cwd），两种都要替换
	for _, want := range []string{link, resolved} {
		if !slices.Contains(got, want) {
			t.Errorf("workdirVariants = %v, missing %s", got, want)
		}
	}
}

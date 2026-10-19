package install

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain：测试不读本机 Hermes 的托管范围（/etc/hermes），只读测试自己用 HERMES_MANAGED_DIR 给出的目录。
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "hg-install-")
	if err == nil {
		HermesManagedDefault = filepath.Join(dir, "no-managed-scope")
	}
	code := m.Run()
	if err == nil {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

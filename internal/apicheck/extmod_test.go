package apicheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestExternalModule(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a separate module")
	}
	cmd := exec.Command("go", "test", "./...")
	cmd.Dir = filepath.Join("..", "..", "testdata", "extmod")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go test in testdata/extmod failed: %v\n%s", err, out)
	}
}

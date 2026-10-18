//go:build unix

package app

import (
	"os/exec"
	"syscall"
)

// killGroup 让入口在自己的进程组里运行，超时时终止整个进程组。
func killGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// reapGroup 在入口退出后终止它的进程组里剩下的进程。
func reapGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

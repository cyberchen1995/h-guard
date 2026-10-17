//go:build unix

package exec

import (
	osexec "os/exec"
	"syscall"
)

// killGroup 让程序在自己的进程组里运行，截止时间到达时终止整个进程组，不遗留子进程。
func killGroup(cmd *osexec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// reapGroup 在程序退出后终止它的进程组里剩下的进程；组里已经没有进程时什么都不做。
func reapGroup(cmd *osexec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

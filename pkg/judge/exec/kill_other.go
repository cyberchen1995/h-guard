//go:build !unix

package exec

import osexec "os/exec"

// killGroup 在非 Unix 平台上只终止该进程（CommandContext 的默认行为），Windows 上还没有用 Job Object 管理子进程。
func killGroup(*osexec.Cmd) {}

// reapGroup 在非 Unix 平台上什么都不做（没有进程组，Windows 上还没有用 Job Object）。
func reapGroup(*osexec.Cmd) {}

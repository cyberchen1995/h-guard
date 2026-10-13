//go:build !unix

package exec

import osexec "os/exec"

// killGroup 在非 Unix 平台上只终止该进程（CommandContext 的默认行为）；Windows 的 Job Object 在 M3。
func killGroup(*osexec.Cmd) {}

// reapGroup 在非 Unix 平台上什么都不做（没有进程组；Windows 的 Job Object 在 M3）。
func reapGroup(*osexec.Cmd) {}

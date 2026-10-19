//go:build !unix

package app

import "os/exec"

// killGroup 在非 Unix 平台上只终止入口本身（CommandContext 的默认行为）。
func killGroup(*exec.Cmd) {}

// reapGroup 在非 Unix 平台上什么都不做。
func reapGroup(*exec.Cmd) {}

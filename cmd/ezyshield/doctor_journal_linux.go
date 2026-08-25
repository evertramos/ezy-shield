//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// applyProbeCredential makes cmd run with the probe identity's credentials
// (uid, gid, supplementary groups) — the same identity resolution systemd
// performs for the unit at process start. syscall.Credential is
// Linux-specific, hence this file's build tag (same split as
// doctor_ownership_linux.go).
func applyProbeCredential(cmd *exec.Cmd, id journalProbeID) {
	if !id.drop {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: id.uid, Gid: id.gid, Groups: id.groups},
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package daemon

// SO_PEERCRED capture for control-socket audit attribution (issue #212).
// Access CONTROL stays with the kernel via socket file permissions; the
// peer credential is used only to RECORD who issued a mutating verb in the
// append-only audit journal.

import (
	"net"
	"syscall"
)

// peerCredOf returns the unix peer credentials of conn when it is a unix
// socket connection on Linux. ok is false for non-unix conns (tests use
// net.Pipe) or when the syscall fails — callers must degrade to "unknown",
// never refuse service on a missing credential (the kernel already enforced
// access at connect time).
func peerCredOf(conn net.Conn) (uid, gid uint32, ok bool) {
	uc, isUnix := conn.(*net.UnixConn)
	if !isUnix {
		return 0, 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil || cred == nil {
		return 0, 0, false
	}
	return cred.Uid, cred.Gid, true
}

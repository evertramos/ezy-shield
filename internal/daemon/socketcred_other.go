// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package daemon

import "net"

// peerCredOf is the non-Linux stub: SO_PEERCRED is Linux-specific, so audit
// attribution degrades to "unknown" (access control itself is unaffected —
// the kernel enforces socket file permissions on every platform).
func peerCredOf(net.Conn) (uid, gid uint32, ok bool) {
	return 0, 0, false
}

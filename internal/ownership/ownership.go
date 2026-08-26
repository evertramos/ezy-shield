// SPDX-License-Identifier: AGPL-3.0-only

// Package ownership centralizes the EzyShield daemon's unix group and the
// socket group-ownership logic shared by the daemon and the privileged
// enforcer. Keeping this security-sensitive behavior in one place stops the two
// implementations from drifting apart (issue #6).
package ownership

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// Group is the unix group the EzyShield daemon runs as. Control sockets are
// group-owned by this group with mode 0660 so any admin in it can drive
// ezyshield without sudo, matching the fail2ban/sshguard pattern.
const Group = "ezyshield"

// ViewGroup is the read-only tier (issue #212): membership grants access to
// the ezyshield-ro.sock socket, which serves only read verbs (status, list,
// watch, report, …). It must NEVER be granted write authority — the split
// exists precisely so monitoring users cannot unban an attacker or disarm
// the daemon.
const ViewGroup = "ezyshield-view"

// ChownToGroup sets path's group to group, leaving the owner unchanged (uid
// -1). Leaving the owner alone is deliberate: the call then never needs
// CAP_CHOWN — which the enforcer's CapabilityBoundingSet deliberately withholds
// — while still letting group members use the socket. It works whether the
// caller runs as root (sudo) or as the unprivileged ezyshield user under
// systemd. Returns an error the caller is expected to log.
func ChownToGroup(path, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w", group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return fmt.Errorf("parse gid %q: %w", g.Gid, err)
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("chown %s to group %q: %w", path, group, err)
	}
	return nil
}

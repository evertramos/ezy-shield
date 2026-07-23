package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"os/user"
	"strconv"

	"github.com/evertramos/ezy-shield/internal/ownership"
)

// errDaemonGroupMissing means the unix group "ezyshield" is not present on the
// host yet — typically because 'ezyshield init' has not finished the user/
// group bootstrap step. Callers can use errors.Is to gate group-dependent
// operations (e.g., chown) without aborting.
var errDaemonGroupMissing = errors.New("ezyshield group not found")

// lookupDaemonGID returns the GID of the daemon group, or errDaemonGroupMissing
// when the group does not exist on this host.
func lookupDaemonGID() (int, error) {
	g, err := user.LookupGroup(ownership.Group)
	if err != nil {
		var unknown user.UnknownGroupError
		if errors.As(err, &unknown) {
			return 0, errDaemonGroupMissing
		}
		return 0, fmt.Errorf("lookup group %s: %w", ownership.Group, err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("invalid gid %q for group %s: %w", g.Gid, ownership.Group, err)
	}
	return gid, nil
}

// gidToUint32 narrows a GID from os/user (an int, via strconv.Atoi) to the
// uint32 the kernel's Stat_t uses. POSIX guarantees GIDs fit in uint32, but
// the source string comes from the group database / NSS backend, so an
// out-of-range value is rejected instead of silently wrapping into a wrong
// ownership comparison (CodeQL go/incorrect-integer-conversion, issue #260).
// The int64 comparison keeps the guard correct on 32-bit builds too.
func gidToUint32(gid int) (uint32, bool) {
	if gid < 0 || int64(gid) > int64(math.MaxUint32) {
		return 0, false
	}
	return uint32(gid), true
}

// applyDaemonOwnership chmods path to mode and chowns it to root:ezyshield.
// When the ezyshield group is missing the chown is skipped and the function
// returns nil — init's group-bootstrap step is expected to run first in
// production, but tests using --config-dir on a clean host don't have it and
// must still succeed (the chmod alone is enough for the test path).
func applyDaemonOwnership(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	gid, err := lookupDaemonGID()
	if err != nil {
		if errors.Is(err, errDaemonGroupMissing) {
			return nil
		}
		return err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

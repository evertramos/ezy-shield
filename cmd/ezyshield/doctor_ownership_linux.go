//go:build linux

package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"syscall"

	"github.com/evertramos/ezy-shield/internal/ownership"
)

// checkConfigOwnership verifies that path is owned by root:ezyshield, the
// ownership 'ezyshield init' sets after issue #91. Reading uid/gid from
// FileInfo.Sys() requires the Linux-only syscall.Stat_t type, hence this
// file's build tag.
func checkConfigOwnership(path, label string) CheckResult {
	name := label + ": ownership"

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "file absent -- run 'ezyshield init' first"}
	}
	if err != nil {
		return CheckResult{Name: name, Status: statusFail, Hint: err.Error()}
	}

	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "ownership info unavailable on this kernel"}
	}

	wantGID, err := lookupDaemonGID()
	if err != nil {
		if errors.Is(err, errDaemonGroupMissing) {
			return CheckResult{Name: name, Status: statusFail,
				Hint: fmt.Sprintf("group %q does not exist -- run 'ezyshield init' as root to create it",
					ownership.Group),
			}
		}
		return CheckResult{Name: name, Status: statusFail, Hint: err.Error()}
	}

	const wantUID uint32 = 0
	gotUID := st.Uid
	gotGID := st.Gid
	// wantGID comes from /etc/group via os/user — it's a small positive int,
	// so the narrowing conversion to uint32 is safe.
	wantGIDu32 := uint32(wantGID) //nolint:gosec // group ids fit in uint32

	if gotUID != wantUID || gotGID != wantGIDu32 {
		return CheckResult{Name: name, Status: statusFail,
			Hint: fmt.Sprintf("ownership %d:%d, want %d:%d (root:%s) -- run: chown root:%s %s",
				gotUID, gotGID, wantUID, wantGIDu32, ownership.Group, ownership.Group, path),
		}
	}
	return CheckResult{Name: name, Status: statusPass}
}

// checkEnvOwnership returns "" when path is owned by root:ezyshield (issue #13
// §8), or a hint string describing the remediation otherwise. Unlike
// checkConfigOwnership above, this returns a hint (not a CheckResult) because
// its caller (checkEnvFile) rolls the result into its own CheckResult so all
// .env failures share the same Name.
func checkEnvOwnership(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return err.Error()
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Best-effort: on kernels where we can't check, don't block.
		return ""
	}
	wantGID, err := lookupDaemonGID()
	if err != nil {
		if errors.Is(err, errDaemonGroupMissing) {
			return fmt.Sprintf("group %q does not exist -- run 'ezyshield init' as root", ownership.Group)
		}
		return err.Error()
	}
	// POSIX guarantees GIDs fit in uint32, but CodeQL flags the narrowing so
	// we do an explicit bounds check — costs one branch, silences a legit
	// static-analysis warning, and would catch a truly bizarre libc that
	// hands back a negative or absurdly large id before we misinterpret it.
	if wantGID < 0 || wantGID > math.MaxUint32 {
		return fmt.Sprintf("gid %d for group %q out of uint32 range -- refusing to compare", wantGID, ownership.Group)
	}
	wantGIDu32 := uint32(wantGID)
	if st.Uid != 0 || st.Gid != wantGIDu32 {
		return fmt.Sprintf("ownership %d:%d, want 0:%d (root:%s) -- run: chown root:%s %s",
			st.Uid, st.Gid, wantGIDu32, ownership.Group, ownership.Group, path)
	}
	return ""
}

package main

// doctor_cdn.go — health of the shared-CDN-range ban guard's data
// (issue #178). The embedded provider table backs the decision engine's
// anti-lockout check that keeps shared CDN edge IPs from ever being banned;
// if it fails to load, that invariant silently disappears — this check makes
// the state loud instead.

import (
	"fmt"

	"github.com/evertramos/ezy-shield/internal/cdndetect"
)

// checkCDNRanges verifies the embedded shared-CDN-range table loads and
// carries ranges. doctor runs the same binary as the daemon, so this reflects
// exactly the data the running daemon's guard sees.
func checkCDNRanges() CheckResult {
	ranges, err := cdndetect.SharedRanges()
	if err != nil {
		return CheckResult{
			Name:   "cdn range data",
			Status: statusFail,
			Hint: fmt.Sprintf("shared-CDN-range ban guard is NOT verifying bans (%v) — "+
				"bans are marked [cdn-ranges-unverified] in the audit log; reinstall or update "+
				"the %s binary (the range table ships embedded)", err, progName),
		}
	}
	return CheckResult{
		Name:   "cdn range data",
		Status: statusPass,
		Hint:   fmt.Sprintf("%d shared edge ranges loaded", len(ranges)),
	}
}

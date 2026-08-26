// SPDX-License-Identifier: AGPL-3.0-only

package main

// Systemd unit hardening checks (issue #213). The check logic lives in
// internal/unitcheck — implemented once, consumed here (on-demand doctor)
// and by the daemon's periodic hardening self-check (issue #563). This
// file only adapts unitcheck.Result to doctor's CheckResult.

import (
	"context"

	"github.com/evertramos/ezy-shield/internal/unitcheck"
)

const enforcerUnitName = unitcheck.EnforcerUnitName

// toCheckResult maps a unitcheck outcome onto doctor's status vocabulary.
func toCheckResult(r unitcheck.Result) CheckResult {
	status := statusNA
	switch r.Status {
	case unitcheck.StatusPass:
		status = statusPass
	case unitcheck.StatusFail:
		status = statusFail
	case unitcheck.StatusWarn:
		status = statusWarn
	}
	return CheckResult{Name: r.Name, Status: status, Hint: r.Hint}
}

// checkUnitHardening verifies the effective unit configuration on systemd
// hosts: AF_NETLINK reachable for the enforcer, RuntimeDirectory present for
// both services. Non-systemd hosts get a single N/A.
func checkUnitHardening(ctx context.Context) []CheckResult {
	results := unitcheck.UnitHardening(ctx)
	out := make([]CheckResult, 0, len(results))
	for _, r := range results {
		out = append(out, toCheckResult(r))
	}
	return out
}

// checkEnforcerNetlinkProbe performs the functional half of issue #213: ask
// the running helper to execute a read-only nft operation inside its own
// sandbox ("netcheck" verb).
func checkEnforcerNetlinkProbe(path string) CheckResult {
	return toCheckResult(unitcheck.NetlinkProbe(context.Background(), path))
}

// SPDX-License-Identifier: AGPL-3.0-only

package main

// Anti-lockout mode check (ADR-0013, issue #560): report which immunity
// mode policy.yaml selects and, when the authenticated-peer mode is on,
// whether logind actually answers — a broken loginctl silently falls back
// to ESTABLISHED-only immunity, and the operator should know.

import (
	"context"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
)

// probeLoginctl is injectable for tests.
var probeLoginctl = func(ctx context.Context) error {
	if _, err := exec.LookPath("loginctl"); err != nil {
		return err
	}
	// G204: fixed binary, fixed args.
	return exec.CommandContext(ctx, "loginctl", "list-sessions", "--no-legend").Run()
}

// checkAntiLockoutMode reports the effective ADR-0013 mode.
func checkAntiLockoutMode(configDir string) CheckResult {
	const name = "anti-lockout: peer immunity mode"
	pol, err := config.LoadPolicy(filepath.Join(configDir, "policy.yaml"))
	if err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "policy.yaml not loadable -- the policy checks report that separately"}
	}
	if !pol.RequireAuthenticatedPeer() {
		return CheckResult{Name: name, Status: statusPass,
			Hint: "ESTABLISHED-only (default). ADR-0013 authenticated-peer mode available via policy anti_lockout.require_authenticated: true"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := probeLoginctl(ctx); err != nil {
		return CheckResult{Name: name, Status: statusWarn,
			Hint: "authenticated-peer mode is ON but loginctl is not answering (" + sanitizeErrorMessage(err.Error()) +
				") -- the daemon FAILS OPEN to ESTABLISHED-only immunity, so the #559 protection is not active on this host"}
	}
	return CheckResult{Name: name, Status: statusPass,
		Hint: "authenticated-peer mode ON (ADR-0013), logind answering"}
}

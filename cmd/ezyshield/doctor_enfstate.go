package main

// doctor_enfstate.go — doctor check for the honest enforcement state
// (issue #174). Queries the running daemon's status verb and warns/fails
// when the daemon is detecting but not actually enforcing, so `doctor`
// can never imply protection that isn't real.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// checkEnforcementState asks the daemon for its enforcement state and maps
// it to a doctor result. When the daemon is not running the check is N/A
// (other checks already report a stopped daemon); a DEGRADED enforcer while
// detection runs is a FAIL — that is the "claims protection it doesn't
// have" case this issue exists to surface.
func checkEnforcementState(socketPath string) CheckResult {
	const name = "enforcement: state"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := daemon.Call(ctx, socketPath, daemon.SocketRequest{Verb: "status"})
	if err != nil || resp == nil || len(resp.Data) == 0 {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "daemon not reachable — start it with 'ezyshield run' (or systemctl start ezyshield)"}
	}
	var sd daemon.StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "could not parse daemon status: " + err.Error()}
	}

	switch sd.EnforcementState {
	case string(daemon.EnfActive):
		return CheckResult{Name: name, Status: statusPass, Hint: "ACTIVE — bans are enforced"}
	case string(daemon.EnfDryRun):
		return CheckResult{Name: name, Status: statusWarn,
			Hint: "DRY-RUN — detection is running but NOTHING is enforced; 'ezyshield arm' when ready"}
	case string(daemon.EnfDegraded):
		detail := sd.EnforcementDetail
		if detail == "" {
			detail = "the enforcer's recent Ban/Sync failed"
		}
		return CheckResult{Name: name, Status: statusFail,
			Hint: fmt.Sprintf("DEGRADED — armed but the enforcer is FAILING (%s); bans are NOT being applied. "+
				"Check the enforcer: systemctl status ezyshield-enforcer, and the daemon logs", detail)}
	case string(daemon.EnfDisabled):
		return CheckResult{Name: name, Status: statusWarn,
			Hint: "DISABLED — no enforcer configured; detection only, nothing is blocked. " +
				"Configure the enforce section in config.yaml to enforce bans"}
	default:
		return CheckResult{Name: name, Status: statusNA,
			Hint: "daemon reported no enforcement state (older daemon build?)"}
	}
}

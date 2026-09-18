// SPDX-License-Identifier: AGPL-3.0-only

package main

// doctor_collstate.go — doctor check for the running daemon's observation
// state (issue #580), the collector-side mirror of checkEnforcementState
// (doctor_enfstate.go, issue #174).
//
// Every other doctor check inspects the host and infers what the daemon can
// probably do. This one asks the daemon what it is actually doing: a
// collector that has been failing for hours is reported by the process that
// owns the failure, with the collector named and its last error quoted.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// checkCollectorsState asks the daemon for collectors_state and maps it to a
// doctor result. N/A when the daemon is not running (other checks report a
// stopped daemon); DEGRADED is a FAIL — the daemon is up and reporting that
// at least one source is not being read.
func checkCollectorsState(socketPath string) CheckResult {
	const name = "collectors: observation state"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := daemon.Call(ctx, socketPath, daemon.SocketRequest{Verb: "status"})
	if err != nil || resp == nil || len(resp.Data) == 0 {
		return CheckResult{Name: name, Status: statusNA,
			Hint: "daemon not reachable — start it with '" + progName + " run' (or systemctl start ezyshield)"}
	}
	var sd daemon.StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "could not parse daemon status: " + err.Error()}
	}

	switch sd.CollectorsState {
	case string(daemon.CollOK):
		return CheckResult{Name: name, Status: statusPass, Hint: "OK — every configured collector is reading"}
	case string(daemon.CollDegraded):
		detail := sd.CollectorsDetail
		if detail == "" {
			detail = "the daemon named no collector"
		}
		return CheckResult{Name: name, Status: statusFail,
			Hint: fmt.Sprintf("DEGRADED — a configured collector is NOT reading its source (%s); "+
				"nothing from that source is detected, however healthy enforcement looks. "+
				"Check the source's permissions for the service user (see the 'docker: socket access' and "+
				"'journald: readable' checks) and the daemon logs", detail)}
	case string(daemon.CollNone):
		return CheckResult{Name: name, Status: statusWarn,
			Hint: "NONE — no collectors configured; nothing is observed. " +
				"Add a collectors entry to config.yaml"}
	default:
		return CheckResult{Name: name, Status: statusNA,
			Hint: "daemon reported no collectors state (older daemon build?)"}
	}
}

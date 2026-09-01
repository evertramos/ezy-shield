// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// "disable_all" socket verb — the one-command panic button (issue #176):
// disarm the daemon (no new bans) AND remove every active block everywhere.
// Behind the same root:ezyshield 0660 socket as every other mutating verb —
// there is deliberately NO config flag for this; only a socket-capable
// operator can trigger it, and every part of it is audited.
//
// Semantics: bans_active is cleared (history/strikes preserved — see
// store.UnbanAll), then the enforcers reconcile against the now-empty
// desired state: the nftables Sync removes every element via the helper,
// and edge enforcers (Cloudflare) empty their lists through their normal
// reconcile path. `ezyshield arm` (or `enable`) later re-arms WITHOUT
// re-applying anything — the rows are gone, so there is nothing to re-add.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// DisableAllData is the Data payload for a successful "disable_all" response.
type DisableAllData struct {
	// Disarmed is always true on success (the daemon is now in dry-run).
	Disarmed bool `json:"disarmed"`
	// BansRemoved is the number of active bans cleared from the store.
	BansRemoved int `json:"bans_removed"`
	// EnforcersSynced reports whether the empty state reached the
	// enforcers. False = the store is clear and the daemon disarmed, but
	// kernel/edge blocks may LINGER until the next reconcile succeeds —
	// the response Error carries the sync failure alongside this payload.
	EnforcersSynced bool `json:"enforcers_synced"`
}

// handleDisableAll executes the panic sequence: disarm → clear bans →
// reconcile empty state. Each step is audited; a partial failure reports
// honestly instead of pretending everything is unblocked.
func (d *Daemon) handleDisableAll(ctx context.Context) SocketResponse {
	// 1. Disarm first — no new bans while we clear. Same persist-first
	//    path as the disarm verb (policy.yaml updated, audited, published).
	if err := d.setArmedState(ctx, false, "disarm", "operator ran '"+progInvocation+" disable --all'"); err != nil {
		return SocketResponse{Error: fmt.Sprintf("disarm: %v", err)}
	}
	if err := d.store.DeleteState(ctx, stateKeyArmWindow); err != nil {
		slog.ErrorContext(ctx, "daemon: clearing arm window on disable_all", "err", err)
	}

	// 2. Clear every active ban (history preserved; one summary audit row).
	//    Taken under enforceMu (issue #575) so the clear cannot land between
	//    a reconcile's desired-state snapshot and its kernel write — that
	//    reconcile would re-add every ban we just cleared. The mutex is
	//    released before step 3: syncEnforcer takes it itself.
	d.enforceMu.Lock()
	removed, err := d.store.UnbanAll(ctx, "panic button: operator ran disable --all")
	d.enforceMu.Unlock()
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("clear active bans: %v", err)}
	}

	// 3. Reconcile: the empty desired state empties local + edge alike.
	data := DisableAllData{Disarmed: true, BansRemoved: removed, EnforcersSynced: true}
	if d.enforcer != nil {
		if err := d.syncEnforcer(ctx); err != nil {
			slog.ErrorContext(ctx, "daemon: disable_all enforcer sync failed", "err", err)
			data.EnforcersSynced = false
			raw, _ := json.Marshal(data)
			return SocketResponse{
				Error: fmt.Sprintf("daemon disarmed and %d bans cleared, but the enforcer sync failed: %v — existing kernel/edge blocks may linger until a reconcile succeeds", removed, err),
				Data:  raw,
			}
		}
	}

	slog.WarnContext(ctx, "daemon: panic button executed — disarmed, all blocks removed",
		"bans_removed", removed)
	raw, _ := json.Marshal(data)
	return SocketResponse{OK: true, Data: raw}
}

// progInvocation is the program name used inside audit reasons. Kept as a
// var so the CLI-side rename guard (progname_guard_test) stays authoritative
// in cmd/; the daemon only echoes it in human-readable audit text.
const progInvocation = "ezyshield"

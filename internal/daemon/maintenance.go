package daemon

// Retention maintenance (issue #184): the daily job that prunes aged rows
// per the retention: config section, audits what it deleted, and reclaims
// file space when fragmentation warrants it. Also backs the "prune" socket
// verb (`ezyshield maintenance prune [--dry-run]`).
//
// Everything here is a no-op unless the operator configured retention:
// d.retention stays nil otherwise and both the loop and the verb refuse.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"
)

// maintenanceVacuumThreshold is the freelist/page_count ratio above which
// the post-prune space reclamation runs a full VACUUM.
const maintenanceVacuumThreshold = 0.25

// maintenanceTickVal returns the injected test interval or the daily default.
func (d *Daemon) maintenanceTickVal() time.Duration {
	if d.maintenanceTick > 0 {
		return d.maintenanceTick
	}
	return 24 * time.Hour
}

// runMaintenance runs the prune once per tick. The first run is delayed by
// one full tick plus a jitter (up to 30 min, skipped in tests) so a fleet
// provisioned from the same image doesn't VACUUM in lockstep, and boot is
// never burdened with a prune.
func (d *Daemon) runMaintenance(ctx context.Context) {
	if d.retention == nil {
		return
	}
	jitter := time.Duration(0)
	if d.maintenanceTick == 0 {
		jitter = rand.N(30 * time.Minute) //nolint:gosec // schedule spreading, not security
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(d.maintenanceTickVal() + jitter):
	}
	for {
		d.runPruneOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.maintenanceTickVal()):
		}
	}
}

// runPruneOnce executes one full maintenance pass: batched prune per table,
// an audit_log summary row per table that lost rows, then threshold-gated
// space reclamation. Errors are logged, never fatal — the next tick retries.
func (d *Daemon) runPruneOnce(ctx context.Context) {
	if d.retention == nil {
		return
	}
	stats, auditSkipped, err := d.store.PruneRetention(ctx, *d.retention, time.Now())
	if err != nil {
		slog.ErrorContext(ctx, "daemon: retention prune failed", "err", err)
		// stats still holds what completed before the error; fall through
		// so partial work is audited.
	}
	for _, st := range stats {
		if st.Count == 0 {
			continue
		}
		reason := fmt.Sprintf("retention prune: table=%s deleted=%d window=%s", st.Table, st.Count, st.Window)
		slog.InfoContext(ctx, "daemon: "+reason)
		if aerr := d.store.AuditSystem(ctx, "retention_prune", reason); aerr != nil {
			slog.ErrorContext(ctx, "daemon: audit retention_prune", "err", aerr)
		}
	}
	if auditSkipped {
		slog.WarnContext(ctx, "daemon: audit_log retention configured but not pruned — no export archives the journal; set retention.audit_export_not_required: true to acknowledge deletion without export")
	}
	if err != nil {
		return
	}
	start := time.Now()
	ran, freePages, verr := d.store.ReclaimSpace(ctx, maintenanceVacuumThreshold)
	switch {
	case verr != nil:
		slog.ErrorContext(ctx, "daemon: space reclamation failed", "err", verr)
	case ran:
		slog.InfoContext(ctx, "daemon: reclaimed database space",
			"free_pages", freePages, "took", time.Since(start).Round(time.Millisecond))
	}
}

// PruneTableData is one table's row in a "prune" verb response.
type PruneTableData struct {
	Table string `json:"table"`
	// Window is the human-readable retention window applied (e.g. "17520h0m0s"
	// renders via time.Duration.String; the CLI reformats it).
	Window string `json:"window"`
	// Count is rows deleted (real run) or rows that would be deleted (dry run).
	Count int64 `json:"count"`
}

// PruneData is the Data payload for a successful "prune" response.
type PruneData struct {
	DryRun bool             `json:"dry_run"`
	Tables []PruneTableData `json:"tables"`
	// AuditSkipped is true when audit_log has a window configured but
	// pruning it was refused for lack of audit_export_not_required: true.
	AuditSkipped bool `json:"audit_skipped,omitempty"`
	// VacuumRan reports whether space reclamation ran (real runs only).
	VacuumRan bool `json:"vacuum_ran,omitempty"`
}

// handlePrune serves the "prune" socket verb. Dry-run is read-only; a real
// run prunes, audits and reclaims space exactly like the daily job. The
// CLI enforces its own --yes confirmation; the daemon side only requires
// that retention is configured at all.
func (d *Daemon) handlePrune(ctx context.Context, req SocketRequest) SocketResponse {
	if d.retention == nil {
		return SocketResponse{Error: "retention is not configured; add a retention: section to config.yaml (see docs reference/retention)"}
	}
	data := PruneData{DryRun: req.DryRun}
	if req.DryRun {
		stats, err := d.store.CountPruneCandidates(ctx, *d.retention, time.Now())
		if err != nil {
			return SocketResponse{Error: fmt.Sprintf("count prune candidates: %v", err)}
		}
		data.AuditSkipped = d.retention.Audit > 0 && !d.retention.AuditPruneAcknowledged
		for _, st := range stats {
			data.Tables = append(data.Tables, PruneTableData{Table: st.Table, Window: st.Window.String(), Count: st.Count})
		}
		raw, _ := json.Marshal(data)
		return SocketResponse{OK: true, Data: raw}
	}
	stats, auditSkipped, err := d.store.PruneRetention(ctx, *d.retention, time.Now())
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("prune: %v", err)}
	}
	data.AuditSkipped = auditSkipped
	for _, st := range stats {
		if st.Count > 0 {
			reason := fmt.Sprintf("retention prune: table=%s deleted=%d window=%s", st.Table, st.Count, st.Window)
			if aerr := d.store.AuditSystem(ctx, "retention_prune", reason); aerr != nil {
				slog.ErrorContext(ctx, "daemon: audit retention_prune", "err", aerr)
			}
		}
		data.Tables = append(data.Tables, PruneTableData{Table: st.Table, Window: st.Window.String(), Count: st.Count})
	}
	ran, _, verr := d.store.ReclaimSpace(ctx, maintenanceVacuumThreshold)
	if verr != nil {
		slog.ErrorContext(ctx, "daemon: space reclamation failed", "err", verr)
	}
	data.VacuumRan = ran
	raw, _ := json.Marshal(data)
	return SocketResponse{OK: true, Data: raw}
}

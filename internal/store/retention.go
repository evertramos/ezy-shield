package store

// Retention pruning (issue #184): window-bounded, batched deletion of aged
// rows from the unbounded tables — strikes (+ fully-aged offenders),
// audit_log, ai_usage. bans_active and allowlist are NEVER touched here, by
// construction: no query in this file names them except as guards protecting
// rows from deletion.
//
// audit_log is append-only everywhere else in the package; this file holds
// its single sanctioned delete path. It only ever removes rows older than
// the configured window, refuses to run at all unless the operator has
// explicitly acknowledged that no export archives the journal
// (RetentionPolicy.AuditPruneAcknowledged), and the caller (daemon) audits
// every prune run — so deletion itself leaves a trace in the journal it
// pruned.
//
// Deletes run in batches of retentionBatchSize through id-subquery form
// (`DELETE ... WHERE id IN (SELECT ... LIMIT n)`), each batch its own
// autocommit transaction, with a context check between batches — a large
// backlog never holds the write lock long enough to starve the hot path.

import (
	"context"
	"fmt"
	"time"
)

// RetentionPolicy is the parsed retention configuration handed to the prune
// methods. A zero window disables pruning for that table.
type RetentionPolicy struct {
	Strikes time.Duration
	Audit   time.Duration
	AIUsage time.Duration
	// AuditPruneAcknowledged mirrors retention.audit_export_not_required:
	// audit_log rows are deleted only when this is true. False = the audit
	// table is reported as skipped even if Audit > 0.
	AuditPruneAcknowledged bool
}

// PruneStat reports, per table, how many rows a prune run deleted (or, for
// CountPruneCandidates, would delete).
type PruneStat struct {
	Table string
	// Window is the retention window the count was evaluated against.
	Window time.Duration
	Count  int64
}

// retentionBatchSize bounds each DELETE batch. Overridable in tests to
// exercise multi-batch runs with small fixtures.
var retentionBatchSize = 500

// strikePruneWhere selects strike rows old enough to prune while protecting
// escalation coherence: the most recent strike of an IP with an active ban
// is never deleted, whatever its age — unban/expiry flows and operator
// reports resolve the ban's context through it.
const strikePruneWhere = `
	s.recorded_at < ?
	AND NOT (
		EXISTS (SELECT 1 FROM bans_active b WHERE b.ip = s.ip)
		AND s.id = (SELECT MAX(s2.id) FROM strikes s2 WHERE s2.ip = s.ip)
	)`

// offenderPruneWhere selects offender rows whose entire strike history has
// aged out and that have no active ban. Deleting the row resets escalation
// for that IP — acceptable only because every strike is already gone (the
// documented strikes-window trade-off).
const offenderPruneWhere = `
	NOT EXISTS (SELECT 1 FROM strikes s WHERE s.ip = o.ip)
	AND NOT EXISTS (SELECT 1 FROM bans_active b WHERE b.ip = o.ip)`

// cutoffRFC3339 renders now-window in the store's canonical timestamp form.
func cutoffRFC3339(now time.Time, window time.Duration) string {
	return now.Add(-window).UTC().Format(time.RFC3339)
}

// CountPruneCandidates returns, per table, how many rows PruneRetention
// would delete right now. Read-only — this backs the --dry-run path.
// Tables with a zero window are omitted. The audit table is counted even
// without AuditPruneAcknowledged (the dry-run answer to "what WOULD happen
// if I acknowledged" is exactly what the operator is deciding on).
func (s *DB) CountPruneCandidates(ctx context.Context, pol RetentionPolicy, now time.Time) ([]PruneStat, error) {
	var out []PruneStat
	count := func(table string, window time.Duration, query string, args ...any) error {
		if window == 0 {
			return nil
		}
		var n int64
		if err := s.db.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
			return fmt.Errorf("store: count prune candidates %s: %w", table, err)
		}
		out = append(out, PruneStat{Table: table, Window: window, Count: n})
		return nil
	}
	if err := count("strikes", pol.Strikes,
		`SELECT COUNT(*) FROM strikes s WHERE `+strikePruneWhere,
		cutoffRFC3339(now, pol.Strikes)); err != nil {
		return nil, err
	}
	// Offenders eligible once the strike prune above has run: history
	// entirely inside the prune window and no active ban.
	if err := count("offenders", pol.Strikes, `
		SELECT COUNT(*) FROM offenders o
		WHERE NOT EXISTS (
			SELECT 1 FROM strikes s WHERE s.ip = o.ip AND NOT (`+strikePruneWhere+`)
		)
		AND NOT EXISTS (SELECT 1 FROM bans_active b WHERE b.ip = o.ip)`,
		cutoffRFC3339(now, pol.Strikes)); err != nil {
		return nil, err
	}
	if err := count("audit_log", pol.Audit,
		`SELECT COUNT(*) FROM audit_log WHERE recorded_at < ?`,
		cutoffRFC3339(now, pol.Audit)); err != nil {
		return nil, err
	}
	if err := count("ai_usage", pol.AIUsage,
		`SELECT COUNT(*) FROM ai_usage WHERE called_at < ?`,
		cutoffRFC3339(now, pol.AIUsage)); err != nil {
		return nil, err
	}
	return out, nil
}

// deleteBatched runs the id-subquery delete until no rows remain, honoring
// ctx between batches, and returns the total rows deleted.
func (s *DB) deleteBatched(ctx context.Context, table, query string, args ...any) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		res, err := s.db.ExecContext(ctx, query, append(args, retentionBatchSize)...)
		if err != nil {
			return total, fmt.Errorf("store: prune %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("store: prune %s rows affected: %w", table, err)
		}
		total += n
		if n < int64(retentionBatchSize) {
			return total, nil
		}
	}
}

// PruneRetention deletes aged rows per pol and returns per-table deletion
// counts plus whether the audit table was skipped for lack of the explicit
// acknowledgement. bans_active and allowlist are never touched. The caller
// is responsible for auditing the run (daemon: op "retention_prune").
func (s *DB) PruneRetention(ctx context.Context, pol RetentionPolicy, now time.Time) (stats []PruneStat, auditSkipped bool, err error) {
	if pol.Strikes > 0 {
		cutoff := cutoffRFC3339(now, pol.Strikes)
		n, err := s.deleteBatched(ctx, "strikes", `
			DELETE FROM strikes WHERE id IN (
				SELECT s.id FROM strikes s WHERE `+strikePruneWhere+` LIMIT ?
			)`, cutoff)
		if err != nil {
			return stats, false, err
		}
		stats = append(stats, PruneStat{Table: "strikes", Window: pol.Strikes, Count: n})
		n, err = s.deleteBatched(ctx, "offenders", `
			DELETE FROM offenders WHERE ip IN (
				SELECT o.ip FROM offenders o WHERE `+offenderPruneWhere+` LIMIT ?
			)`)
		if err != nil {
			return stats, false, err
		}
		stats = append(stats, PruneStat{Table: "offenders", Window: pol.Strikes, Count: n})
	}
	if pol.Audit > 0 {
		if !pol.AuditPruneAcknowledged {
			auditSkipped = true
		} else {
			n, err := s.deleteBatched(ctx, "audit_log", `
				DELETE FROM audit_log WHERE id IN (
					SELECT id FROM audit_log WHERE recorded_at < ? LIMIT ?
				)`, cutoffRFC3339(now, pol.Audit))
			if err != nil {
				return stats, false, err
			}
			stats = append(stats, PruneStat{Table: "audit_log", Window: pol.Audit, Count: n})
		}
	}
	if pol.AIUsage > 0 {
		n, err := s.deleteBatched(ctx, "ai_usage", `
			DELETE FROM ai_usage WHERE id IN (
				SELECT id FROM ai_usage WHERE called_at < ? LIMIT ?
			)`, cutoffRFC3339(now, pol.AIUsage))
		if err != nil {
			return stats, auditSkipped, err
		}
		stats = append(stats, PruneStat{Table: "ai_usage", Window: pol.AIUsage, Count: n})
	}
	return stats, auditSkipped, nil
}

// ReclaimSpace measures fragmentation (freelist pages vs total pages) and
// runs VACUUM when the free ratio exceeds threshold (e.g. 0.25). Returns
// whether a VACUUM ran and how many free pages the measurement saw. VACUUM
// rewrites the whole file — the threshold keeps it rare; the maintenance
// job runs this after pruning, off the hot path.
func (s *DB) ReclaimSpace(ctx context.Context, threshold float64) (ran bool, freePages int64, err error) {
	var pageCount int64
	if err := s.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err != nil {
		return false, 0, fmt.Errorf("store: page_count: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&freePages); err != nil {
		return false, 0, fmt.Errorf("store: freelist_count: %w", err)
	}
	if pageCount == 0 || float64(freePages)/float64(pageCount) < threshold {
		return false, freePages, nil
	}
	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return false, freePages, fmt.Errorf("store: VACUUM: %w", err)
	}
	return true, freePages, nil
}

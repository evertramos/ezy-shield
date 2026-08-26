package store

// Internal-package tests for retention pruning (issue #184): they reach the
// unexported db handle to backdate rows (RecordStrike stamps wall-clock
// time) and to override retentionBatchSize for multi-batch runs.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func openRetentionDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// strikeAt records a strike for ip and backdates it (and the offender's
// last_seen) to at.
func strikeAt(t *testing.T, db *DB, ip string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := db.RecordStrike(ctx, sdk.Action{
		IP: netip.MustParseAddr(ip), Op: "ban", TTL: time.Hour, Strike: 1, Reason: "test",
	}); err != nil {
		t.Fatalf("RecordStrike %s: %v", ip, err)
	}
	ts := at.UTC().Format(time.RFC3339)
	if _, err := db.db.ExecContext(ctx, `
		UPDATE strikes SET recorded_at = ?
		WHERE id = (SELECT MAX(id) FROM strikes WHERE ip = ?)`, ts, ip); err != nil {
		t.Fatalf("backdate strike %s: %v", ip, err)
	}
}

func expireBan(t *testing.T, db *DB, ip string) {
	t.Helper()
	if _, err := db.db.ExecContext(context.Background(),
		`DELETE FROM bans_active WHERE ip = ?`, ip); err != nil {
		t.Fatalf("expire ban %s: %v", ip, err)
	}
}

func countRows(t *testing.T, db *DB, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count (%s): %v", query, err)
	}
	return n
}

func TestPruneRetention_ExactSurvivorsAndGuards(t *testing.T) {
	t.Parallel()
	db := openRetentionDB(t)
	ctx := context.Background()
	now := time.Now()
	window := 30 * 24 * time.Hour
	old := now.Add(-40 * 24 * time.Hour)
	fresh := now.Add(-1 * 24 * time.Hour)

	// aged: two old strikes, ban expired → strikes AND offender row prunable.
	strikeAt(t, db, "192.0.2.1", old)
	strikeAt(t, db, "192.0.2.1", old)
	expireBan(t, db, "192.0.2.1")
	// banned: one OLD strike but an ACTIVE ban → its newest strike survives.
	strikeAt(t, db, "192.0.2.2", old)
	// mixed: old strike prunable, fresh strike survives → offender kept.
	strikeAt(t, db, "192.0.2.3", old)
	strikeAt(t, db, "192.0.2.3", fresh)
	expireBan(t, db, "192.0.2.3")

	pol := RetentionPolicy{Strikes: window}
	stats, auditSkipped, err := db.PruneRetention(ctx, pol, now)
	if err != nil {
		t.Fatalf("PruneRetention: %v", err)
	}
	if auditSkipped {
		t.Fatal("auditSkipped must be false when no audit window is configured")
	}
	got := map[string]int64{}
	for _, st := range stats {
		got[st.Table] = st.Count
	}
	// Deleted: aged's 2 + banned's 0 + mixed's 1 old = 3 strikes; 1 offender.
	if got["strikes"] != 3 || got["offenders"] != 1 {
		t.Fatalf("deleted = %v, want strikes=3 offenders=1", got)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM strikes WHERE ip = '192.0.2.1'`); n != 0 {
		t.Fatalf("aged offender still has %d strikes", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM strikes WHERE ip = '192.0.2.2'`); n != 1 {
		t.Fatalf("banned IP's newest strike must survive, have %d", n)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM offenders WHERE ip = '192.0.2.1'`); n != 0 {
		t.Fatal("fully-aged offender row must be dropped")
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM offenders WHERE ip IN ('192.0.2.2','192.0.2.3')`); n != 2 {
		t.Fatalf("offenders with surviving strikes/ban must be kept, have %d", n)
	}
	// bans_active untouched.
	if n := countRows(t, db, `SELECT COUNT(*) FROM bans_active`); n != 1 {
		t.Fatalf("bans_active rows = %d, want 1 (never pruned)", n)
	}
}

func TestPruneRetention_EscalationCoherence(t *testing.T) {
	t.Parallel()
	db := openRetentionDB(t)
	ctx := context.Background()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.9")

	// Repeat offender: 2 old (in-window-prunable) strikes + 1 fresh, no ban.
	strikeAt(t, db, ip.String(), now.Add(-200*24*time.Hour))
	strikeAt(t, db, ip.String(), now.Add(-190*24*time.Hour))
	strikeAt(t, db, ip.String(), now.Add(-time.Hour))
	expireBan(t, db, ip.String())

	before, err := db.GetStrikeCount(ctx, ip)
	if err != nil {
		t.Fatalf("GetStrikeCount before: %v", err)
	}
	if _, _, err := db.PruneRetention(ctx, RetentionPolicy{Strikes: 180 * 24 * time.Hour}, now); err != nil {
		t.Fatalf("PruneRetention: %v", err)
	}
	after, err := db.GetStrikeCount(ctx, ip)
	if err != nil {
		t.Fatalf("GetStrikeCount after: %v", err)
	}
	// Escalation reads offenders.total_strikes, which pruning old strike
	// ROWS must not decrement — the repeat offender still escalates.
	if before != 3 || after != before {
		t.Fatalf("total_strikes before=%d after=%d, want both 3", before, after)
	}
}

func TestPruneRetention_AuditGateAndWindow(t *testing.T) {
	t.Parallel()
	db := openRetentionDB(t)
	ctx := context.Background()
	now := time.Now()

	// Two audit rows: one old, one fresh.
	if err := db.AuditSystem(ctx, "test_old", "old row"); err != nil {
		t.Fatalf("AuditSystem: %v", err)
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE audit_log SET recorded_at = ?`,
		now.Add(-400*24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("backdate audit: %v", err)
	}
	if err := db.AuditSystem(ctx, "test_fresh", "fresh row"); err != nil {
		t.Fatalf("AuditSystem: %v", err)
	}

	// Without the explicit acknowledgement: nothing deleted, skipped=true.
	pol := RetentionPolicy{Audit: 365 * 24 * time.Hour}
	stats, skipped, err := db.PruneRetention(ctx, pol, now)
	if err != nil {
		t.Fatalf("PruneRetention: %v", err)
	}
	if !skipped || len(stats) != 0 {
		t.Fatalf("unacknowledged audit prune: skipped=%v stats=%v, want skipped and empty", skipped, stats)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM audit_log`); n != 2 {
		t.Fatalf("audit rows = %d, want 2 (gate must protect them)", n)
	}

	// Acknowledged: only the aged row goes.
	pol.AuditPruneAcknowledged = true
	stats, skipped, err = db.PruneRetention(ctx, pol, now)
	if err != nil {
		t.Fatalf("PruneRetention ack: %v", err)
	}
	if skipped || len(stats) != 1 || stats[0].Table != "audit_log" || stats[0].Count != 1 {
		t.Fatalf("acknowledged audit prune stats = %v skipped=%v, want audit_log=1", stats, skipped)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM audit_log WHERE op = 'test_fresh'`); n != 1 {
		t.Fatal("fresh audit row must survive")
	}
}

func TestPruneRetention_BatchingAndCounts(t *testing.T) {
	// Not parallel: overrides the package-level batch size.
	orig := retentionBatchSize
	retentionBatchSize = 3
	defer func() { retentionBatchSize = orig }()

	db := openRetentionDB(t)
	ctx := context.Background()
	now := time.Now()

	for range 10 {
		if err := db.RecordUsage(ctx, "anthropic",
			sdk.Usage{InputTokens: 10, OutputTokens: 5, CostUSD: 0.001}, ""); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
	}
	if _, err := db.db.ExecContext(ctx, `UPDATE ai_usage SET called_at = ?`,
		now.Add(-100*24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("backdate ai_usage: %v", err)
	}

	pol := RetentionPolicy{AIUsage: 90 * 24 * time.Hour}
	cand, err := db.CountPruneCandidates(ctx, pol, now)
	if err != nil {
		t.Fatalf("CountPruneCandidates: %v", err)
	}
	if len(cand) != 1 || cand[0].Table != "ai_usage" || cand[0].Count != 10 {
		t.Fatalf("candidates = %v, want ai_usage=10", cand)
	}
	stats, _, err := db.PruneRetention(ctx, pol, now)
	if err != nil {
		t.Fatalf("PruneRetention: %v", err)
	}
	if len(stats) != 1 || stats[0].Count != 10 {
		t.Fatalf("deleted = %v, want ai_usage=10 across batches of 3", stats)
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM ai_usage`); n != 0 {
		t.Fatalf("ai_usage rows left = %d, want 0", n)
	}
}

func TestReclaimSpace_ThresholdGate(t *testing.T) {
	t.Parallel()
	db := openRetentionDB(t)
	ctx := context.Background()

	// Threshold above 100% free can never trigger.
	ran, _, err := db.ReclaimSpace(ctx, 1.5)
	if err != nil {
		t.Fatalf("ReclaimSpace: %v", err)
	}
	if ran {
		t.Fatal("VACUUM must not run below threshold")
	}
	// Threshold 0 always triggers (freelist/page >= 0) — asserts the VACUUM
	// statement itself executes cleanly on this build.
	if _, _, err := db.ReclaimSpace(ctx, 0); err != nil {
		t.Fatalf("ReclaimSpace(0): %v", err)
	}
}

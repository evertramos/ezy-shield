package daemon

// Tests for the retention maintenance layer (issue #184): the "prune" socket
// verb (dry-run vs real, refusal without config) and the audit trail a real
// run leaves.

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // raw handle for backdating fixture rows

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newRetentionDaemon builds a daemon on a FILE-backed store (so tests can
// open a second raw connection to backdate fixture rows) plus that raw handle.
func newRetentionDaemon(t *testing.T, retention *config.RetentionCfg) (*Daemon, *store.DB, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "retention.db")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	d, err := New(Config{
		Cfg: &config.Config{Retention: retention},
		Policy: &config.Policy{
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db, raw
}

// seedOldStrike records a strike and backdates it via the raw handle — the
// daemon store interface has no backdating.
func seedOldStrike(t *testing.T, db *store.DB, raw *sql.DB, ip string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	if err := db.RecordStrike(ctx, sdk.Action{
		IP: netip.MustParseAddr(ip), Op: "ban", TTL: time.Minute, Strike: 1, Reason: "seed",
	}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	// Let the ban lapse so nothing shields the strike, then age the strike.
	if _, err := db.ExpireBans(ctx, time.Now().Add(48*time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	if _, err := raw.ExecContext(ctx, `UPDATE strikes SET recorded_at = ? WHERE ip = ?`,
		time.Now().Add(-age).UTC().Format(time.RFC3339), ip); err != nil {
		t.Fatalf("backdate: %v", err)
	}
}

func TestHandlePrune_RefusedWithoutRetentionConfig(t *testing.T) {
	d, _, _ := newRetentionDaemon(t, nil)
	resp := d.handlePrune(context.Background(), SocketRequest{Verb: "prune"})
	if resp.OK || !strings.Contains(resp.Error, "retention is not configured") {
		t.Fatalf("resp = %+v, want refusal naming the missing config", resp)
	}
}

func TestHandlePrune_DryRunCountsWithoutDeleting(t *testing.T) {
	d, db, raw := newRetentionDaemon(t, &config.RetentionCfg{Strikes: "180d"})
	seedOldStrike(t, db, raw, "192.0.2.30", 200*24*time.Hour)

	resp := d.handlePrune(context.Background(), SocketRequest{Verb: "prune", DryRun: true})
	if !resp.OK {
		t.Fatalf("dry-run failed: %s", resp.Error)
	}
	var data PruneData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !data.DryRun {
		t.Fatal("response must be marked dry_run")
	}
	counts := map[string]int64{}
	for _, tb := range data.Tables {
		counts[tb.Table] = tb.Count
	}
	if counts["strikes"] != 1 || counts["offenders"] != 1 {
		t.Fatalf("dry-run counts = %v, want strikes=1 offenders=1", counts)
	}
	// Nothing deleted, nothing audited.
	rows, err := db.StrikesForIP(context.Background(), netip.MustParseAddr("192.0.2.30"), 10)
	if err != nil {
		t.Fatalf("StrikesForIP: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("dry-run deleted rows: %d strikes left, want 1", len(rows))
	}
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.Op == "retention_prune" {
			t.Fatal("dry-run must not write retention_prune audit rows")
		}
	}
}

func TestHandlePrune_RealRunDeletesAndAudits(t *testing.T) {
	d, db, raw := newRetentionDaemon(t, &config.RetentionCfg{Strikes: "180d"})
	seedOldStrike(t, db, raw, "192.0.2.31", 200*24*time.Hour)

	resp := d.handlePrune(context.Background(), SocketRequest{Verb: "prune"})
	if !resp.OK {
		t.Fatalf("prune failed: %s", resp.Error)
	}
	rows, err := db.StrikesForIP(context.Background(), netip.MustParseAddr("192.0.2.31"), 10)
	if err != nil {
		t.Fatalf("StrikesForIP: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("strikes left = %d, want 0", len(rows))
	}
	var audited int
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	for _, e := range entries {
		if e.Op == "retention_prune" && strings.Contains(e.Reason, "deleted=1") {
			audited++
		}
	}
	if audited != 2 { // one summary per table: strikes + offenders
		t.Fatalf("retention_prune audit rows = %d, want 2 (strikes, offenders)", audited)
	}
}

func TestHandlePrune_AuditSkippedSurfaced(t *testing.T) {
	d, _, _ := newRetentionDaemon(t, &config.RetentionCfg{Audit: "365d"})
	resp := d.handlePrune(context.Background(), SocketRequest{Verb: "prune", DryRun: true})
	if !resp.OK {
		t.Fatalf("dry-run failed: %s", resp.Error)
	}
	var data PruneData
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !data.AuditSkipped {
		t.Fatal("audit window configured without acknowledgement must surface audit_skipped")
	}
}

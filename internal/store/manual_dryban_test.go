// SPDX-License-Identifier: AGPL-3.0-only

package store

// Regression test for issue #358 item 2: a manual ban issued while disarmed
// used to be audit-log-only — invisible in `ezyshield list` and the status
// SimulatedBans count, unlike pipeline dry_bans (ADR-0009 §5 "dry-run
// mirrors armed"). RecordManualBan now records it as a dry_run row.

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestRecordManualBan_DryRunRowIsVisible(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ip := netip.MustParseAddr("192.0.2.77")
	if err := db.RecordManualBan(ctx, ip, time.Hour, "manual while disarmed", true); err != nil {
		t.Fatalf("RecordManualBan: %v", err)
	}

	// The row must surface through ActiveBans as a dry_ban, exactly like a
	// pipeline simulated ban.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("manual dry-run ban not visible in ActiveBans (audit-only regression): %d rows", len(bans))
	}
	if bans[0].Op != "dry_ban" {
		t.Errorf("Op = %q, want dry_ban", bans[0].Op)
	}

	// The audit trail must name the op truthfully too.
	var op string
	if err := db.db.QueryRowContext(ctx,
		`SELECT op FROM audit_log WHERE ip = ? ORDER BY id DESC LIMIT 1`, ip.String()).Scan(&op); err != nil {
		t.Fatalf("audit query: %v", err)
	}
	if op != "dry_ban" {
		t.Errorf("audit op = %q, want dry_ban", op)
	}

	// An armed manual ban stays a real ban.
	ip2 := netip.MustParseAddr("192.0.2.78")
	if err := db.RecordManualBan(ctx, ip2, time.Hour, "manual while armed", false); err != nil {
		t.Fatalf("RecordManualBan armed: %v", err)
	}
	bans, err = db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	real := 0
	for _, b := range bans {
		if b.Op == "ban" {
			real++
		}
	}
	if real != 1 {
		t.Errorf("expected exactly 1 real ban among %d rows", len(bans))
	}
}

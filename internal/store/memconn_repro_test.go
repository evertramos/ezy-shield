// SPDX-License-Identifier: AGPL-3.0-only

package store

// Regression test for issue #474: database/sql discards a connection whose
// in-flight query was interrupted by context cancellation, and with a plain
// ":memory:" DSN the replacement connection arrived at a brand-new EMPTY
// database — schema and data silently vanished mid-run. It surfaced as
// test-suite flakiness ("no such table: strikes" in the daemon end-to-end
// tests under -count=2), because a canceled daemon shutdown reliably
// interrupts in-flight store queries. The fix pins a named shared-cache
// memory database with a dedicated keep-alive connection.

import (
	"context"
	"testing"
	"time"
)

func TestOpen_MemoryDBSurvivesInterruptedQuery(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	timed, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	// Interrupt a query mid-flight: the pool discards its connection, and
	// pre-fix the replacement saw an empty database.
	var n int
	_ = db.db.QueryRowContext(timed,
		"WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt) SELECT count(*) FROM cnt").Scan(&n)

	var after int
	if err := db.db.QueryRowContext(ctx, "SELECT count(*) FROM strikes").Scan(&after); err != nil {
		t.Fatalf("schema lost after interrupted query (issue #474): %v", err)
	}
}

// TestOpen_MemoryDBsAreIsolated guards the shared-cache naming: two
// Open(":memory:") stores must never see each other's data.
func TestOpen_MemoryDBsAreIsolated(t *testing.T) {
	ctx := context.Background()
	a, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer func() { _ = a.Close() }()
	b, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer func() { _ = b.Close() }()

	if _, err := a.db.ExecContext(ctx,
		"INSERT INTO daemon_state(key, value, updated_at) VALUES ('isolation-probe', 'a', strftime('%s','now'))"); err != nil {
		t.Fatalf("insert into a: %v", err)
	}
	var n int
	if err := b.db.QueryRowContext(ctx,
		"SELECT count(*) FROM daemon_state WHERE key = 'isolation-probe'").Scan(&n); err != nil {
		t.Fatalf("query b: %v", err)
	}
	if n != 0 {
		t.Fatalf("store b sees store a's data — shared-cache names are colliding")
	}
}

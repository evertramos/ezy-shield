// SPDX-License-Identifier: AGPL-3.0-only

package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
)

// Migration-integrity tests (issue #329). The old TestMigrations asserted
// nothing; these verify (a) schema_migrations actually records every
// embedded migration, and (b) the upgrade path — the thing production
// hosts run on every release — works on a POPULATED older-version
// database, since 004/005 ALTER tables that hold live ban rows.

// migrationFiles returns the *.sql migrations from the package directory,
// sorted, keyed by version. Reading the real files (rather than
// hardcoding a count) keeps these tests honest when migration 007 lands.
func migrationFiles(t *testing.T) map[int]string {
	t.Helper()
	entries, err := os.ReadDir("migrations")
	if err != nil {
		t.Fatalf("reading migrations dir: %v", err)
	}
	files := make(map[int]string)
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			t.Fatalf("unversioned migration file %q: %v", e.Name(), err)
		}
		files[v] = filepath.Join("migrations", e.Name())
	}
	if len(files) == 0 {
		t.Fatal("no migration files found")
	}
	return files
}

// appliedVersions queries schema_migrations directly.
func appliedVersions(t *testing.T, path string) []int {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	defer raw.Close() //nolint:errcheck
	rows, err := raw.QueryContext(context.Background(), "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var got []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return got
}

// TestMigrations_RecordsEveryVersion: after Open, schema_migrations holds
// exactly the embedded versions — the assertion the old test claimed to
// make but never did.
func TestMigrations_RecordsEveryVersion(t *testing.T) {
	files := migrationFiles(t)
	want := make([]int, 0, len(files))
	for v := range files {
		want = append(want, v)
	}
	sort.Ints(want)

	path := filepath.Join(t.TempDir(), "fresh.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = db.Close()

	got := appliedVersions(t, path)
	if len(got) != len(want) {
		t.Fatalf("applied versions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("applied versions = %v, want %v", got, want)
		}
	}

	// Idempotency, now with teeth: a second Open must not change the table.
	db2, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	_ = db2.Close()
	if again := appliedVersions(t, path); len(again) != len(want) {
		t.Fatalf("second Open changed schema_migrations: %v", again)
	}
}

// TestMigrations_UpgradeFromV3WithLiveData builds a version-3 database the
// way a pre-004 production host would look — populated offenders and
// bans_active rows (including a permanent ban: expires_at NULL) — then
// runs store.Open and asserts migrations 004+ apply cleanly on the
// populated tables and both the old rows and the new columns behave.
func TestMigrations_UpgradeFromV3WithLiveData(t *testing.T) {
	ctx := context.Background()
	files := migrationFiles(t)
	path := filepath.Join(t.TempDir(), "v3.db")

	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	// Apply migrations 1..3 exactly as migrate() would.
	if _, err := raw.ExecContext(ctx, `CREATE TABLE schema_migrations (
		version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for v := 1; v <= 3; v++ {
		body, err := os.ReadFile(files[v]) //nolint:gosec // repo-local migration file
		if err != nil {
			t.Fatalf("read migration %d: %v", v, err)
		}
		if _, err := raw.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply migration %d: %v", v, err)
		}
		if _, err := raw.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
			v, time.Now().UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("record migration %d: %v", v, err)
		}
	}
	// Live data in the v3 shape (RFC 5737 addresses).
	now := time.Now().UTC().Format(time.RFC3339)
	later := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	stmts := []string{
		fmt.Sprintf(`INSERT INTO offenders(ip, first_seen, last_seen, total_strikes)
			VALUES('203.0.113.10','%s','%s',2)`, now, now),
		fmt.Sprintf(`INSERT INTO offenders(ip, first_seen, last_seen, total_strikes)
			VALUES('203.0.113.11','%s','%s',5)`, now, now),
		fmt.Sprintf(`INSERT INTO bans_active(ip, banned_at, expires_at, strike_num, reason)
			VALUES('203.0.113.10','%s','%s',2,'timed ban')`, now, later),
		fmt.Sprintf(`INSERT INTO bans_active(ip, banned_at, expires_at, strike_num, reason)
			VALUES('203.0.113.11','%s',NULL,5,'permanent ban')`, now),
	}
	for _, s := range stmts {
		if _, err := raw.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed v3 data: %v", err)
		}
	}
	_ = raw.Close()

	// The upgrade under test: Open applies 004..N on the populated tables.
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatalf("Open (upgrade path): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	got := appliedVersions(t, path)
	if len(got) != len(files) {
		t.Fatalf("applied versions after upgrade = %v, want all %d", got, len(files))
	}

	// Old rows survived and are visible through the current-store API.
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 2 {
		t.Fatalf("bans after upgrade = %d, want the 2 seeded rows: %+v", len(bans), bans)
	}

	// The 004/005 columns exist with their defaults on the migrated rows.
	raw2, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("raw reopen: %v", err)
	}
	defer raw2.Close() //nolint:errcheck
	var supTotal, dryRun int
	if err := raw2.QueryRowContext(ctx,
		"SELECT suppressed_total, dry_run FROM bans_active WHERE ip = '203.0.113.11'").
		Scan(&supTotal, &dryRun); err != nil {
		t.Fatalf("migrated columns missing on pre-existing row: %v", err)
	}
	if supTotal != 0 || dryRun != 0 {
		t.Errorf("defaults on migrated row = suppressed_total:%d dry_run:%d, want 0/0", supTotal, dryRun)
	}
	var hadIneff int
	if err := raw2.QueryRowContext(ctx,
		"SELECT had_ineffective FROM offenders WHERE ip = '203.0.113.11'").Scan(&hadIneff); err != nil {
		t.Fatalf("offenders.had_ineffective missing on pre-existing row: %v", err)
	}
}

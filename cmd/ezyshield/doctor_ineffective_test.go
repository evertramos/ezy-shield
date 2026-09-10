// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the ban_ineffective doctor check (issue #146): N/A on a missing
// DB, PASS on a clean one, WARN on historical-only offenders, FAIL naming
// the offenders — with the reported count never capped by the 10-row detail
// limit.

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
)

// newDoctorDB creates a fully migrated database and returns its path plus a
// writable handle for seeding rows.
func newDoctorDB(t *testing.T) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ezyshield.db")
	st, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store close: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return path, db
}

func seedIneffectiveBan(t *testing.T, db *sql.DB, ip string, strike, events int) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `INSERT INTO bans_active
		(ip, banned_at, expires_at, strike_num, reason, suppressed_after_grace, ineffective_fired)
		VALUES (?, '2026-07-22T00:00:00Z', NULL, ?, 'test', ?, 1)`, ip, strike, events)
	if err != nil {
		t.Fatalf("seed ban %s: %v", ip, err)
	}
}

func TestCheckBanIneffective_MissingDBIsNA(t *testing.T) {
	res := checkBanIneffective(filepath.Join(t.TempDir(), "nope.db"))
	if res.Status != statusNA {
		t.Fatalf("missing DB: status = %s, want N/A", res.Status)
	}
}

func TestCheckBanIneffective_CleanDBPasses(t *testing.T) {
	path, _ := newDoctorDB(t)
	if res := checkBanIneffective(path); res.Status != statusPass {
		t.Fatalf("clean DB: status = %s (%s), want PASS", res.Status, res.Hint)
	}
}

func TestCheckBanIneffective_HistoricalOnlyWarns(t *testing.T) {
	path, db := newDoctorDB(t)
	_, err := db.ExecContext(context.Background(), `INSERT INTO offenders (ip, first_seen, last_seen, total_strikes, had_ineffective)
		VALUES ('192.0.2.7', '2026-07-01T00:00:00Z', '2026-07-02T00:00:00Z', 3, 1)`)
	if err != nil {
		t.Fatal(err)
	}
	res := checkBanIneffective(path)
	if res.Status != statusWarn {
		t.Fatalf("historical only: status = %s (%s), want WARN", res.Status, res.Hint)
	}
}

func TestCheckBanIneffective_ActiveFailsNamingOffenders(t *testing.T) {
	path, db := newDoctorDB(t)
	seedIneffectiveBan(t, db, "203.0.113.9", 3, 42)
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("active ineffective: status = %s (%s), want FAIL", res.Status, res.Hint)
	}
	for _, want := range []string{"1 active ban(s)", "203.0.113.9", "strike 3", "42 post-grace"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
}

func TestCheckBanIneffective_CountNotCappedByDetailLimit(t *testing.T) {
	path, db := newDoctorDB(t)
	for i := 0; i < 14; i++ {
		seedIneffectiveBan(t, db, fmt.Sprintf("203.0.113.%d", i+1), 2, 5+i)
	}
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("status = %s, want FAIL", res.Status)
	}
	if !strings.Contains(res.Hint, "14 active ban(s)") {
		t.Errorf("hint must report the true total (14), not the 10-row detail cap:\n%s", res.Hint)
	}
	if !strings.Contains(res.Hint, "worst 10:") {
		t.Errorf("hint should label the truncated detail list:\n%s", res.Hint)
	}
}

// TestDoctorRODSN_AppliesBusyTimeoutAndStaysReadOnly pins the RUNTIME effect
// of the doctor's read-only DSN, mirroring internal/store/pragma_test.go
// (issue #406, same class as #321): the previous mattn-style _busy_timeout=2000
// parameter was silently ignored by modernc.org/sqlite, leaving busy_timeout=0
// so the check could fail with SQLITE_BUSY the instant the daemon held a write
// lock instead of waiting 2 s. mode=ro must survive the conversion.
func TestDoctorRODSN_AppliesBusyTimeoutAndStaysReadOnly(t *testing.T) {
	ctx := context.Background()
	path, _ := newDoctorDB(t)

	db, err := sql.Open("sqlite", doctorRODSN(path))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	var busyTimeout int
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busyTimeout != 2000 {
		t.Errorf("busy_timeout = %d, want 2000", busyTimeout)
	}

	// mode=ro is a safety invariant: the doctor must never mutate the
	// daemon's database, so any write on this connection must fail.
	if _, err := db.ExecContext(ctx, `CREATE TABLE doctor_ro_probe (x INTEGER)`); err == nil {
		t.Error("write succeeded on the doctor connection, want read-only failure")
	}
}

// seedFlaggedBanAt seeds a flagged ban whose last suppressed event is at
// last (RFC 3339) — the issue #587 "still leaking?" input.
func seedFlaggedBanAt(t *testing.T, db *sql.DB, ip string, last string) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `INSERT INTO bans_active
		(ip, banned_at, expires_at, strike_num, reason, suppressed_after_grace, ineffective_fired, last_suppressed_at)
		VALUES (?, '2026-07-22T00:00:00Z', NULL, 5, 'test', 26, 1, ?)`, ip, last)
	if err != nil {
		t.Fatalf("seed ban %s: %v", ip, err)
	}
}

// TestCheckBanIneffective_QuietFlaggedBanWarns (issue #587): a permanent ban
// that leaked once and has been silent for the re-arm window is a past
// incident — WARN naming it, never an eternal FAIL.
func TestCheckBanIneffective_QuietFlaggedBanWarns(t *testing.T) {
	path, db := newDoctorDB(t)
	quiet := time.Now().UTC().Add(-3 * 24 * time.Hour).Format(time.RFC3339Nano)
	seedFlaggedBanAt(t, db, "203.0.113.20", quiet)
	res := checkBanIneffective(path)
	if res.Status != statusWarn {
		t.Fatalf("quiet flagged ban: status = %s (%s), want WARN", res.Status, res.Hint)
	}
	for _, want := range []string{"203.0.113.20", "quiet", "no ban is leaking now"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
}

// TestCheckBanIneffective_RecentLeakFails: an event inside the window is a
// current leak → FAIL, with quiet ones reported separately and not counted.
func TestCheckBanIneffective_RecentLeakFails(t *testing.T) {
	path, db := newDoctorDB(t)
	recent := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	quiet := time.Now().UTC().Add(-3 * 24 * time.Hour).Format(time.RFC3339Nano)
	seedFlaggedBanAt(t, db, "203.0.113.21", recent)
	seedFlaggedBanAt(t, db, "203.0.113.22", quiet)
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("recent leak: status = %s (%s), want FAIL", res.Status, res.Hint)
	}
	for _, want := range []string{"1 active ban(s) leaking", "203.0.113.21", "plus 1 flagged ban(s) quiet"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
	if strings.Contains(res.Hint, "203.0.113.22 (strike") {
		t.Errorf("quiet ban must not be listed as current:\n%s", res.Hint)
	}
}

// TestCheckBanIneffective_UnknownTimestampFailsClosed: a row flagged before
// the column existed has no timestamp — unknown is treated as current.
func TestCheckBanIneffective_UnknownTimestampFailsClosed(t *testing.T) {
	path, db := newDoctorDB(t)
	seedIneffectiveBan(t, db, "203.0.113.23", 5, 26) // last_suppressed_at NULL
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("NULL timestamp: status = %s (%s), want FAIL (fail closed)", res.Status, res.Hint)
	}
}

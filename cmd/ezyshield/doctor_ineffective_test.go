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

// seedIneffectiveBan seeds a flagged ban that is leaking NOW: its last
// suppressed event is minutes old (the shape a live leak has since
// migration 010). A row without a timestamp is the pre-migration/unknown
// shape — see seedIneffectiveBanUnknown.
func seedIneffectiveBan(t *testing.T, db *sql.DB, ip string, strike, events int) {
	t.Helper()
	recent := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	_, err := db.ExecContext(context.Background(), `INSERT INTO bans_active
		(ip, banned_at, expires_at, strike_num, reason, suppressed_after_grace, ineffective_fired, last_suppressed_at)
		VALUES (?, '2026-07-22T00:00:00Z', NULL, ?, 'test', ?, 1, ?)`, ip, strike, events, recent)
	if err != nil {
		t.Fatalf("seed ban %s: %v", ip, err)
	}
}

// seedIneffectiveBanUnknown seeds a flagged ban with NO last_suppressed_at —
// a row flagged before the column existed (issue #600).
func seedIneffectiveBanUnknown(t *testing.T, db *sql.DB, ip string, strike, events int) {
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
	for _, want := range []string{"203.0.113.20", "quiet", "no ban is known to be leaking now"} {
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

// TestCheckBanIneffective_UnknownTimestampWarns (issue #600): a row flagged
// before last_suppressed_at existed says nothing about NOW — it is a past
// incident with an unknown time: WARN, labelled as unknown, never "within
// the last 24h".
func TestCheckBanIneffective_UnknownTimestampWarns(t *testing.T) {
	path, db := newDoctorDB(t)
	seedIneffectiveBanUnknown(t, db, "203.0.113.23", 5, 26)
	res := checkBanIneffective(path)
	if res.Status != statusWarn {
		t.Fatalf("NULL timestamp: status = %s (%s), want WARN", res.Status, res.Hint)
	}
	for _, want := range []string{"203.0.113.23", "last leak time unknown", "flagged before this version"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
	if strings.Contains(res.Hint, "leaking within the last") {
		t.Errorf("unknown timestamp must not be reported as a current leak:\n%s", res.Hint)
	}
}

// TestCheckBanIneffective_RecentPlusUnknown: a real current leak still
// FAILs, counting only itself; the unknown row is mentioned apart.
func TestCheckBanIneffective_RecentPlusUnknown(t *testing.T) {
	path, db := newDoctorDB(t)
	recent := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
	seedFlaggedBanAt(t, db, "203.0.113.24", recent)
	seedIneffectiveBanUnknown(t, db, "203.0.113.25", 5, 26)
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("recent + unknown: status = %s (%s), want FAIL", res.Status, res.Hint)
	}
	for _, want := range []string{"1 active ban(s) leaking", "203.0.113.24", "plus 1 flagged ban(s)", "unknown last leak time"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
	if strings.Contains(res.Hint, "203.0.113.25 (strike") {
		t.Errorf("unknown row must not be listed as current:\n%s", res.Hint)
	}
}

// TestCheckBanIneffective_InGraceOnlyWarnsNotFail (issue #656): a recently
// flagged ban whose traffic was ALL inside the grace window
// (suppressed_after_grace = 0) is HTTP connection reuse, not a leak — the
// ban is effective. It must be WARN, never a red FAIL. Reproduces the
// dogfood 34.140.132.132 case (phase=in_grace, 0 post-grace events).
func TestCheckBanIneffective_InGraceOnlyWarnsNotFail(t *testing.T) {
	path, db := newDoctorDB(t)
	seedIneffectiveBan(t, db, "203.0.113.40", 2, 0) // recent, 0 post-grace
	res := checkBanIneffective(path)
	if res.Status != statusWarn {
		t.Fatalf("in-grace-only flagged ban: status = %s (%s), want WARN", res.Status, res.Hint)
	}
	for _, want := range []string{"203.0.113.40", "only DURING the grace window", "not a leak", "effective"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
	if strings.Contains(res.Hint, "leaking after the grace") {
		t.Errorf("in-grace-only must not be reported as a post-grace leak:\n%s", res.Hint)
	}
}

// TestCheckBanIneffective_RealLeakPlusInGrace (issue #656): a genuine
// post-grace leak still FAILs, counting only itself; a concurrent
// in-grace-only firing is mentioned apart, not counted into the FAIL.
func TestCheckBanIneffective_RealLeakPlusInGrace(t *testing.T) {
	path, db := newDoctorDB(t)
	seedIneffectiveBan(t, db, "203.0.113.41", 3, 42) // real post-grace leak
	seedIneffectiveBan(t, db, "203.0.113.42", 2, 0)  // in-grace reuse only
	res := checkBanIneffective(path)
	if res.Status != statusFail {
		t.Fatalf("real leak present: status = %s (%s), want FAIL", res.Status, res.Hint)
	}
	for _, want := range []string{"1 active ban(s) leaking after the grace", "203.0.113.41", "in-grace connection reuse only"} {
		if !strings.Contains(res.Hint, want) {
			t.Errorf("hint missing %q:\n%s", want, res.Hint)
		}
	}
	if strings.Contains(res.Hint, "203.0.113.42 (strike") {
		t.Errorf("in-grace-only ban must not be listed as a current leak:\n%s", res.Hint)
	}
}

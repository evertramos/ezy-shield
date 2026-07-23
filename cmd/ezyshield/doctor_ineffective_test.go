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

// SPDX-License-Identifier: AGPL-3.0-only

package main

// doctor_ineffective.go — doctor check for the ban_ineffective diagnostic
// (ADR-0009 §4, issue #146): surfaces active bans whose traffic kept
// flowing (bans_active.ineffective_fired = 1) and the count of offenders
// that ever had one, with the systemic remedies. Read-only: the database
// is opened in ro mode and no migration runs — a missing/inaccessible DB
// or a pre-004 schema degrades to N/A, never an error.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
	_ "modernc.org/sqlite" // register "sqlite" driver (read-only use here)
)

// ineffectiveRemedy is the hint shared by both failure shapes: the signal
// is systemic, the fix is the enforcement path — never per-IP sentencing.
const ineffectiveRemedy = "traffic flows despite active bans — fix the enforcement path: " +
	"edge enforcement (Cloudflare/Bunny), real-IP parsing behind a CDN/proxy, or enforcer health; " +
	"a firing logged with phase=in_grace points instead to HTTP connection reuse or a late enforcer. " +
	"Per-IP action will not help (ADR-0009)"

// doctorRODSN builds the DSN for the doctor's read-only diagnostics
// connection. mode=ro: doctor must never mutate or migrate the daemon's
// database. _pragma=busy_timeout(2000): wait up to 2 s instead of failing
// with SQLITE_BUSY while the daemon holds a write lock — the mattn-style
// _busy_timeout=2000 previously used here was silently ignored by
// modernc.org/sqlite (issue #406, same class as #321).
// TestDoctorRODSN_AppliesBusyTimeoutAndStaysReadOnly pins both effects.
func doctorRODSN(dbPath string) string {
	return "file:" + dbPath + "?mode=ro&_pragma=busy_timeout(2000)" //nolint:gosec // path is the admin-controlled --db flag
}

// checkBanIneffective inspects the store for fired ban_ineffective
// diagnostics. dbPath is the SQLite database location (the daemon's --db).
func checkBanIneffective(dbPath string) CheckResult {
	const name = "bans: ban_ineffective diagnostics"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	db, err := sql.Open("sqlite", doctorRODSN(dbPath))
	if err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "cannot open database: " + err.Error()}
	}
	defer db.Close() //nolint:errcheck // read-only close

	if err := db.PingContext(ctx); err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: fmt.Sprintf("database not readable at %s (daemon not initialized yet?): %v", dbPath, err)}
	}

	// Every flagged ban, split by whether it is STILL leaking (issue #587):
	// a suppressed event within store.IneffectiveRearmAfter means the leak is
	// current — FAIL; older means it leaked once and went quiet — WARN, so
	// the check can return to a non-failing state without an operator
	// touching a permanent ban. A NULL timestamp (row flagged before the
	// column existed) says nothing about NOW: it is reported as unknown in
	// the past bucket (issue #600) — filing it as current kept the exact
	// eternal FAIL #587 set out to remove, and a diagnostic FAIL enforces
	// nothing, so there is no safety to buy by failing closed here. The
	// store re-arms such a row on its next suppressed event, which is when
	// it earns a real timestamp.
	rows, err := db.QueryContext(ctx, `
		SELECT ip, strike_num, suppressed_after_grace, last_suppressed_at
		FROM bans_active WHERE ineffective_fired = 1
		ORDER BY suppressed_after_grace DESC`)
	if err != nil {
		// Pre-migration-010 schema or missing table: nothing to diagnose.
		return CheckResult{Name: name, Status: statusNA, Hint: "schema has no diagnostics yet: " + err.Error()}
	}
	defer rows.Close() //nolint:errcheck // read-only close

	now := time.Now().UTC()
	// currentLeak: a recent firing with post-grace events — enforcement is
	// genuinely failing (FAIL). currentGrace: a recent firing whose traffic
	// was ALL inside the grace window (suppressed_after_grace == 0) — HTTP
	// keep-alive/HTTP-2 connection reuse on an already-established connection,
	// not a leak; the ban is effective, so it is a WARN, not a red FAIL
	// (issue #656; the #586 phased diagnostic intends in-grace to be tolerated).
	var currentLeak, currentGrace, past ineffectiveHits
	for rows.Next() {
		var h ineffectiveHit
		var last sql.NullString
		if err := rows.Scan(&h.ip, &h.strike, &h.evts, &last); err != nil {
			return CheckResult{Name: name, Status: statusNA, Hint: "scan: " + err.Error()}
		}
		if !last.Valid {
			h.unknown = true
			past = append(past, h)
			continue
		}
		if ts, perr := time.Parse(time.RFC3339Nano, last.String); perr == nil {
			if q := now.Sub(ts); q >= store.IneffectiveRearmAfter {
				h.quietFor = q
				past = append(past, h)
				continue
			}
		}
		if h.evts > 0 {
			currentLeak = append(currentLeak, h)
		} else {
			currentGrace = append(currentGrace, h)
		}
	}
	if err := rows.Err(); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: err.Error()}
	}

	var everHad int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM offenders WHERE had_ineffective = 1`).Scan(&everHad); err != nil {
		everHad = 0 // best-effort context; the active-ban signal stands alone
	}

	// A real post-grace leak is the only FAIL.
	if len(currentLeak) > 0 {
		hint := fmt.Sprintf("%d active ban(s) leaking after the grace window within the last %s: %s — %s",
			len(currentLeak), store.IneffectiveRearmAfter, describeHits(currentLeak.labels(false), 10), ineffectiveRemedy)
		var aside []string
		if len(currentGrace) > 0 {
			aside = append(aside, fmt.Sprintf("%d flagged for in-grace connection reuse only (0 post-grace events)", len(currentGrace)))
		}
		if len(past) > 0 {
			aside = append(aside, fmt.Sprintf("%d flagged ban(s) quiet for %s or more or with an unknown last leak time", len(past), store.IneffectiveRearmAfter))
		}
		if len(aside) > 0 {
			hint += " (plus " + strings.Join(aside, ", ") + ", not counted)"
		}
		return CheckResult{Name: name, Status: statusFail, Hint: hint}
	}

	// No post-grace leak. Recent in-grace-only firings are connection reuse,
	// not an enforcement failure: WARN, never FAIL (issue #656).
	if len(currentGrace) > 0 {
		hint := fmt.Sprintf("%d recently flagged ban(s) saw traffic only DURING the grace window (0 post-grace events): %s — HTTP keep-alive/HTTP-2 connection reuse on an already-established connection, not a leak; the ban is effective. No action needed",
			len(currentGrace), describeHits(currentGrace.labels(false), 10))
		if len(past) > 0 {
			hint += fmt.Sprintf(". Plus %d flagged in the past (quiet %s or more, or unknown)", len(past), store.IneffectiveRearmAfter)
		}
		return CheckResult{Name: name, Status: statusWarn, Hint: hint}
	}

	if len(past) > 0 {
		return CheckResult{Name: name, Status: statusWarn,
			Hint: fmt.Sprintf("no ban is known to be leaking now; %d flagged ban(s) leaked in the past (quiet for %s or more, or with an unknown last leak time): %s — a new leak on any of them fires ban_ineffective again",
				len(past), store.IneffectiveRearmAfter, describeHits(past.labels(true), 10))}
	}
	if everHad > 0 {
		return CheckResult{Name: name, Status: statusWarn,
			Hint: fmt.Sprintf("no ACTIVE ineffective ban, but %d offender(s) had one historically — %s", everHad, ineffectiveRemedy)}
	}
	return CheckResult{Name: name, Status: statusPass}
}

// describeHits joins up to limit labels; the caller's count is never
// capped — "10 flagged" when 200 are would silently understate the incident.
func describeHits(labels []string, limit int) string {
	if len(labels) <= limit {
		return strings.Join(labels, "; ")
	}
	return fmt.Sprintf("worst %d: %s", limit, strings.Join(labels[:limit], "; "))
}

// ineffectiveHit is one flagged ban; quietFor is zero for a current leak
// and the silence length for a past one; unknown marks a row flagged before
// last_suppressed_at existed (issue #600) — past bucket, no silence length.
type ineffectiveHit struct {
	ip           string
	strike, evts int
	quietFor     time.Duration
	unknown      bool
}

type ineffectiveHits []ineffectiveHit

// labels renders the hits for the hint: post-grace event counts for current
// leaks, silence length for past ones.
func (hs ineffectiveHits) labels(quiet bool) []string {
	out := make([]string, 0, len(hs))
	for _, h := range hs {
		switch {
		case quiet && h.unknown:
			out = append(out, fmt.Sprintf("%s (strike %d, last leak time unknown — flagged before this version)", h.ip, h.strike))
		case quiet:
			out = append(out, fmt.Sprintf("%s (strike %d, quiet %s)", h.ip, h.strike, h.quietFor.Round(time.Hour)))
		default:
			out = append(out, fmt.Sprintf("%s (strike %d, %d post-grace events)", h.ip, h.strike, h.evts))
		}
	}
	return out
}

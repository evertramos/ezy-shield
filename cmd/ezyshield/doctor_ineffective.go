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

	_ "modernc.org/sqlite" // register "sqlite" driver (read-only use here)
)

// ineffectiveRemedy is the hint shared by both failure shapes: the signal
// is systemic, the fix is the enforcement path — never per-IP sentencing.
const ineffectiveRemedy = "traffic flows despite active bans — fix the enforcement path: " +
	"edge enforcement (Cloudflare/Bunny), real-IP parsing behind a CDN/proxy, or enforcer health. " +
	"Per-IP action will not help (ADR-0009)"

// checkBanIneffective inspects the store for fired ban_ineffective
// diagnostics. dbPath is the SQLite database location (the daemon's --db).
func checkBanIneffective(dbPath string) CheckResult {
	const name = "bans: ban_ineffective diagnostics"

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// mode=ro: doctor must never mutate or migrate the daemon's database.
	dsn := "file:" + dbPath + "?mode=ro&_busy_timeout=2000" //nolint:gosec // path is the admin-controlled --db flag
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: "cannot open database: " + err.Error()}
	}
	defer db.Close() //nolint:errcheck // read-only close

	if err := db.PingContext(ctx); err != nil {
		return CheckResult{Name: name, Status: statusNA,
			Hint: fmt.Sprintf("database not readable at %s (daemon not initialized yet?): %v", dbPath, err)}
	}

	rows, err := db.QueryContext(ctx, `
		SELECT ip, strike_num, suppressed_after_grace
		FROM bans_active WHERE ineffective_fired = 1
		ORDER BY suppressed_after_grace DESC LIMIT 10`)
	if err != nil {
		// Pre-migration-004 schema or missing table: nothing to diagnose.
		return CheckResult{Name: name, Status: statusNA, Hint: "schema has no diagnostics yet: " + err.Error()}
	}
	defer rows.Close() //nolint:errcheck // read-only close

	type hit struct {
		ip           string
		strike, evts int
	}
	var hits []hit
	for rows.Next() {
		var h hit
		if err := rows.Scan(&h.ip, &h.strike, &h.evts); err != nil {
			return CheckResult{Name: name, Status: statusNA, Hint: "scan: " + err.Error()}
		}
		hits = append(hits, h)
	}
	if err := rows.Err(); err != nil {
		return CheckResult{Name: name, Status: statusNA, Hint: err.Error()}
	}

	var everHad int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM offenders WHERE had_ineffective = 1`).Scan(&everHad); err != nil {
		everHad = 0 // best-effort context; the active-ban signal stands alone
	}

	if len(hits) == 0 {
		if everHad > 0 {
			return CheckResult{Name: name, Status: statusWarn,
				Hint: fmt.Sprintf("no ACTIVE ineffective ban, but %d offender(s) had one historically — %s", everHad, ineffectiveRemedy)}
		}
		return CheckResult{Name: name, Status: statusPass}
	}

	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		parts = append(parts, fmt.Sprintf("%s (strike %d, %d post-grace events)", h.ip, h.strike, h.evts))
	}
	return CheckResult{
		Name:   name,
		Status: statusFail,
		Hint: fmt.Sprintf("%d active ban(s) flagged ineffective: %s — %s",
			len(hits), strings.Join(parts, "; "), ineffectiveRemedy),
	}
}

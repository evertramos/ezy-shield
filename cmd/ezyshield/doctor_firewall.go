// SPDX-License-Identifier: AGPL-3.0-only

package main

// ── Firewall coexistence checks (issue #177) ────────────────────────────────
//
// Many target hosts already run ufw or firewalld. EzyShield manages its own
// nftables table (`inet ezyshield`, hooked at raw priority), so coexistence
// usually works — but it has sharp edges: a manager that flushes or replaces
// the whole ruleset on reload can silently delete our table, leaving bans
// recorded as active while nothing is enforced. These checks detect active
// managers, explain the interaction honestly, and FAIL loudly on the real
// conflict signature (our table gone while active bans exist).
//
// Everything is read-only: unit state comes from `systemctl show`, table
// presence from `nft list tables`, ban counts from a read-only SQLite open.
// The ufw/firewalld CLIs are never executed — some of their subcommands
// mutate state, so they are off-limits by contract.

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// fwCoexistState is everything the pure evaluator needs; the collectors
// below fill it from the live system, tests fill it directly.
type fwCoexistState struct {
	ufwActive       bool
	firewalldActive bool
	// nftTables is the parsed `nft list tables` output ("inet ezyshield",
	// "ip filter", ...). nil with tablesUnknown=true means the listing was
	// unavailable (no privilege / no nft) — table checks then skip.
	nftTables     []string
	tablesUnknown bool
	// activeBans counts real (non-simulated) rows in bans_active;
	// -1 = unknown (database unreadable).
	activeBans int
}

const fwCoexistDocs = "docs: guides/firewall-coexistence"

// unitActiveState returns systemd's ActiveState for unit ("active",
// "inactive", ...), or ok=false on non-systemd hosts. Injectable for tests.
var unitActiveState = func(ctx context.Context, unit string) (state string, ok bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "", false
	}
	// G204: fixed binary, fixed property, unit names are compile-time
	// constants at the call sites.
	out, err := exec.CommandContext(ctx, "systemctl", "show", unit, //nolint:gosec
		"--property=ActiveState", "--no-pager").Output()
	if err != nil {
		return "", true // systemd present, unit unqueryable — treat as not active
	}
	_, v, _ := strings.Cut(strings.TrimSpace(string(out)), "=")
	return v, true
}

// listNftTables returns the table names from `nft list tables` (read-only).
// Injectable for tests.
var listNftTables = func(ctx context.Context) ([]string, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("nft not installed: %w", err)
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "tables").Output()
	if err != nil {
		return nil, fmt.Errorf("nft list tables: %w (root privileges required)", err)
	}
	var tables []string
	for _, line := range strings.Split(string(out), "\n") {
		// Lines look like "table inet ezyshield".
		if rest, found := strings.CutPrefix(strings.TrimSpace(line), "table "); found {
			tables = append(tables, rest)
		}
	}
	return tables, nil
}

// countActiveBans counts real (non-dry-run) active bans via a read-only
// database open; -1 when the database is unreadable. Injectable for tests.
var countActiveBans = func(ctx context.Context, dbPath string) int {
	db, err := sql.Open("sqlite", doctorRODSN(dbPath))
	if err != nil {
		return -1
	}
	defer db.Close() //nolint:errcheck // read-only close
	var n int
	// dry_run was added in migration 005; fall back to the plain count on
	// older schemas where every row is a real ban.
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bans_active WHERE dry_run = 0`).Scan(&n)
	if err != nil {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM bans_active`).Scan(&n); err != nil {
			return -1
		}
	}
	return n
}

// collectFirewallState gathers the live inputs for the evaluator.
func collectFirewallState(ctx context.Context, dbPath string) fwCoexistState {
	st := fwCoexistState{activeBans: -1}
	if s, ok := unitActiveState(ctx, "ufw.service"); ok && s == "active" {
		st.ufwActive = true
	}
	if s, ok := unitActiveState(ctx, "firewalld.service"); ok && s == "active" {
		st.firewalldActive = true
	}
	tables, err := listNftTables(ctx)
	if err != nil {
		st.tablesUnknown = true
	} else {
		st.nftTables = tables
	}
	st.activeBans = countActiveBans(ctx, dbPath)
	return st
}

// hasEzyshieldTable reports whether any listed table belongs to EzyShield.
// The default is "inet ezyshield"; custom names (issue #268) still keep the
// "ezyshield" token by convention, so match on the name word.
func hasEzyshieldTable(tables []string) bool {
	for _, tbl := range tables {
		for _, f := range strings.Fields(tbl) {
			if strings.Contains(f, "ezyshield") {
				return true
			}
		}
	}
	return false
}

// evaluateFirewallCoexistence is the pure decision core (table-driven tests
// drive it directly).
func evaluateFirewallCoexistence(st fwCoexistState) []CheckResult {
	const coexistName = "firewall: coexistence"
	const tableName = "firewall: ezyshield nftables table"

	var managers []string
	if st.ufwActive {
		managers = append(managers, "ufw")
	}
	if st.firewalldActive {
		managers = append(managers, "firewalld")
	}

	var out []CheckResult
	switch {
	case len(managers) == 0:
		out = append(out, CheckResult{Name: coexistName, Status: statusNA,
			Hint: "no other firewall manager (ufw/firewalld) is active"})
	default:
		out = append(out, CheckResult{Name: coexistName, Status: statusPass,
			Hint: strings.Join(managers, " + ") + " active alongside EzyShield -- coexistence works: EzyShield keeps its own nftables table hooked at raw priority, and " +
				"ufw/firewalld reloads normally leave foreign tables alone. Watch out for: full ruleset flushes (nftables.service restart, iptables -F scripts, " +
				"some firewalld backends on reload) which DELETE our table until the enforcer restarts, and for managing the same IPs in both tools (confusing, not harmful). " +
				fwCoexistDocs})
	}

	switch {
	case st.tablesUnknown:
		out = append(out, CheckResult{Name: tableName, Status: statusNA,
			Hint: "cannot list nftables tables (needs root and the nft binary) -- re-run doctor with sudo for the conflict check"})
	case hasEzyshieldTable(st.nftTables):
		out = append(out, CheckResult{Name: tableName, Status: statusPass})
	case st.activeBans > 0:
		// The real conflict: bans recorded as active, table gone —
		// enforcement is silently absent (the worst failure mode).
		hint := fmt.Sprintf("%d active ban(s) recorded but the ezyshield nftables table is GONE -- nothing is being enforced. "+
			"A firewall manager or script likely flushed the ruleset", st.activeBans)
		if len(managers) > 0 {
			hint += " (" + strings.Join(managers, "/") + " is active on this host)"
		}
		hint += ". Fix: systemctl restart ezyshield-enforcer ezyshield  -- the enforcer recreates the table and the daemon re-syncs every ban from its store. " + fwCoexistDocs
		out = append(out, CheckResult{Name: tableName, Status: statusFail, Hint: hint})
	default:
		out = append(out, CheckResult{Name: tableName, Status: statusWarn,
			Hint: "ezyshield nftables table not present (no active bans recorded, so nothing is lost) -- it is created when ezyshield-enforcer starts; " +
				"if the enforcer IS running, something flushed the ruleset: restart it (systemctl restart ezyshield-enforcer). " + fwCoexistDocs})
	}
	return out
}

// checkFirewallCoexistence is the doctor entry point (issue #177).
func checkFirewallCoexistence(ctx context.Context, dbPath string) []CheckResult {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return evaluateFirewallCoexistence(collectFirewallState(cctx, dbPath))
}

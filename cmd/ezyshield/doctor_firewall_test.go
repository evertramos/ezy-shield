package main

// Table-driven tests for the firewall coexistence checks (issue #177),
// driving the pure evaluator with fixture states — no ufw/firewalld/nft
// needed on the test host, and nothing outside doctor changes.

import (
	"context"
	"strings"
	"testing"
)

func fwResultsByName(rs []CheckResult) map[string]CheckResult {
	m := map[string]CheckResult{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func TestFirewallCoexistence_TableDriven(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		st          fwCoexistState
		wantCoexist string // status of "firewall: coexistence"
		wantTable   string // status of "firewall: ezyshield nftables table"
		wantInHint  string // substring required in the table check's hint ("" = none)
	}{
		{
			name:        "no managers, table present",
			st:          fwCoexistState{nftTables: []string{"inet ezyshield"}, activeBans: 0},
			wantCoexist: statusNA,
			wantTable:   statusPass,
		},
		{
			name: "ufw active, table present — benign coexistence",
			st: fwCoexistState{ufwActive: true,
				nftTables: []string{"ip filter", "inet ezyshield"}, activeBans: 3},
			wantCoexist: statusPass,
			wantTable:   statusPass,
		},
		{
			name: "firewalld active, table GONE with active bans — the real conflict",
			st: fwCoexistState{firewalldActive: true,
				nftTables: []string{"inet firewalld"}, activeBans: 5},
			wantCoexist: statusPass,
			wantTable:   statusFail,
			wantInHint:  "nothing is being enforced",
		},
		{
			name:        "table gone, no bans — warn, nothing lost yet",
			st:          fwCoexistState{ufwActive: true, nftTables: []string{"ip filter"}, activeBans: 0},
			wantCoexist: statusPass,
			wantTable:   statusWarn,
			wantInHint:  "no active bans recorded",
		},
		{
			name:        "tables unknown (no privilege) — conflict check skips",
			st:          fwCoexistState{firewalldActive: true, tablesUnknown: true, activeBans: 5},
			wantCoexist: statusPass,
			wantTable:   statusNA,
			wantInHint:  "sudo",
		},
		{
			name: "custom table name still recognized",
			st: fwCoexistState{ufwActive: true,
				nftTables: []string{"inet ezyshield_custom"}, activeBans: 1},
			wantCoexist: statusPass,
			wantTable:   statusPass,
		},
		{
			name:        "both managers named in the conflict hint",
			st:          fwCoexistState{ufwActive: true, firewalldActive: true, nftTables: []string{}, activeBans: 2},
			wantCoexist: statusPass,
			wantTable:   statusFail,
			wantInHint:  "ufw/firewalld",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := fwResultsByName(evaluateFirewallCoexistence(tc.st))
			co := got["firewall: coexistence"]
			if co.Status != tc.wantCoexist {
				t.Fatalf("coexistence = %+v, want %s", co, tc.wantCoexist)
			}
			tb := got["firewall: ezyshield nftables table"]
			if tb.Status != tc.wantTable {
				t.Fatalf("table check = %+v, want %s", tb, tc.wantTable)
			}
			if tc.wantInHint != "" && !strings.Contains(tb.Hint, tc.wantInHint) {
				t.Fatalf("table hint %q lacks %q", tb.Hint, tc.wantInHint)
			}
		})
	}
}

func TestFirewallCoexistence_BenignHintExplainsInteraction(t *testing.T) {
	t.Parallel()
	got := fwResultsByName(evaluateFirewallCoexistence(fwCoexistState{
		ufwActive: true, nftTables: []string{"inet ezyshield"}, activeBans: 0,
	}))
	hint := got["firewall: coexistence"].Hint
	for _, want := range []string{"ufw", "raw priority", "Watch out for", "firewall-coexistence"} {
		if !strings.Contains(hint, want) {
			t.Fatalf("coexistence hint %q lacks %q", hint, want)
		}
	}
}

func TestCollectFirewallState_UsesInjectedProbes(t *testing.T) {
	origUnit, origTables, origBans := unitActiveState, listNftTables, countActiveBans
	t.Cleanup(func() {
		unitActiveState, listNftTables, countActiveBans = origUnit, origTables, origBans
	})
	unitActiveState = func(_ context.Context, unit string) (string, bool) {
		if unit == "ufw.service" {
			return "active", true
		}
		return "inactive", true
	}
	listNftTables = func(_ context.Context) ([]string, error) {
		return []string{"inet ezyshield"}, nil
	}
	countActiveBans = func(_ context.Context, _ string) int { return 7 }

	st := collectFirewallState(context.Background(), "unused.db")
	if !st.ufwActive || st.firewalldActive || st.tablesUnknown || st.activeBans != 7 {
		t.Fatalf("collected state = %+v", st)
	}
	if !hasEzyshieldTable(st.nftTables) {
		t.Fatalf("table not recognized in %v", st.nftTables)
	}
}

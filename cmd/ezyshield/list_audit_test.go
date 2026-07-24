package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// runListCmd executes the list command with args against sockPath and returns
// stdout plus the command error. Mirrors runReportCmd in report_test.go.
func runListCmd(t *testing.T, jsonMode bool, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	cmd := newListCmd()
	root := &cobra.Command{Use: "ezyshield"}
	root.PersistentFlags().BoolVar(&jsonOutput, "json", false, "")
	root.AddCommand(cmd)
	jsonOutput = jsonMode
	defer func() { jsonOutput = false }()
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs(append([]string{"list"}, args...))
	err := root.Execute()
	return stdout.String(), err
}

// auditFixture returns audit rows exercising every TTL/strike branch plus a
// reason carrying an ANSI escape, so the table test proves sanitization.
func auditFixture() []daemon.EventEntry {
	return []daemon.EventEntry{
		{ID: 4, RecordedAt: "2026-07-08T16:39:58Z", Op: "ban", IP: "203.0.113.238", TTLSeconds: 0, Strike: 0, Reason: "manual ban via CLI"},
		{ID: 3, RecordedAt: "2026-07-08T16:39:39Z", Op: "ban", IP: "203.0.113.238", TTLSeconds: 300, Strike: 1, Reason: "score=70 \x1b[31mcategory=scanner\x1b[0m source=rules"},
		{ID: 2, RecordedAt: "2026-07-08T16:19:42Z", Op: "expired", IP: "203.0.113.12", TTLSeconds: 0, Strike: 1, Reason: "TTL reached"},
	}
}

func TestListAudit_Table(t *testing.T) {
	sock, reqs := mockReportServer(t, dataResp(t, auditFixture()))

	out, err := runListCmd(t, false, "--audit", "--ip", "203.0.113.238", "--limit", "50", "--socket", sock)
	if err != nil {
		t.Fatalf("list --audit: %v\n%s", err, out)
	}

	// Header and every rendered branch.
	for _, want := range []string{
		"TIME", "IP", "ACTION", "STRIKE", "TTL", "REASON",
		"2026-07-08 16:39:39", // RFC3339 → display format
		"perm",                // ban, TTL 0
		"5m0s",                // ban, 300s
		"expired",             // op passthrough
		"category=scanner",    // sanitized reason text preserved
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	// The ESC byte from the hostile reason must be stripped.
	if strings.ContainsRune(out, 0x1b) {
		t.Errorf("ESC leaked into terminal output:\n%q", out)
	}

	// Wire shape: exactly one events request carrying the filter + limit.
	if len(*reqs) != 1 {
		t.Fatalf("want 1 request, got %d", len(*reqs))
	}
	got := (*reqs)[0]
	if got.Verb != "events" || got.IP != "203.0.113.238" || got.Limit != 50 {
		t.Errorf("wire req = %+v; want verb=events ip=203.0.113.238 limit=50", got)
	}
}

func TestListAudit_JSON(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, auditFixture()))

	out, err := runListCmd(t, true, "--audit", "--socket", sock)
	if err != nil {
		t.Fatalf("list --audit --json: %v\n%s", err, out)
	}
	var entries []daemon.EventEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("output is not a JSON array of events: %v\n%s", err, out)
	}
	if len(entries) != 3 {
		t.Errorf("got %d entries, want 3", len(entries))
	}
}

func TestListAudit_Empty(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, []daemon.EventEntry{}))

	out, err := runListCmd(t, false, "--audit", "--ip", "203.0.113.9", "--socket", sock)
	if err != nil {
		t.Fatalf("list --audit (empty): %v", err)
	}
	if !strings.Contains(out, "no recorded actions for 203.0.113.9") {
		t.Errorf("empty result should name the filtered IP; got:\n%s", out)
	}
}

// TestListAudit_FlagGuards covers the two misuse guards: --ip/--limit are
// rejected without --audit, and --audit rejects the ban-grouping flags.
func TestListAudit_FlagGuards(t *testing.T) {
	sock, _ := mockReportServer(t, dataResp(t, []daemon.EventEntry{}))

	if _, err := runListCmd(t, false, "--ip", "203.0.113.1", "--socket", sock); err == nil {
		t.Error("--ip without --audit should error")
	}
	if _, err := runListCmd(t, false, "--audit", "--allow", "--socket", sock); err == nil {
		t.Error("--audit with --allow should error")
	}
}

func TestAuditTTL(t *testing.T) {
	cases := []struct {
		op   string
		secs int64
		want string
	}{
		{"ban", 300, "5m0s"},
		{"ban", 0, "perm"},
		{"expired", 0, "-"},
		{"unban", 0, "-"},
		{"allow", 0, "-"},
	}
	for _, c := range cases {
		if got := auditTTL(c.op, c.secs); got != c.want {
			t.Errorf("auditTTL(%q,%d) = %q, want %q", c.op, c.secs, got, c.want)
		}
	}
}

func TestAuditStrikeAndTime(t *testing.T) {
	if got := auditStrike(0); got != "-" {
		t.Errorf("auditStrike(0) = %q, want -", got)
	}
	if got := auditStrike(3); got != "3" {
		t.Errorf("auditStrike(3) = %q, want 3", got)
	}
	if got := formatAuditTime("2026-07-08T16:39:39Z"); got != "2026-07-08 16:39:39" {
		t.Errorf("formatAuditTime = %q, want 2026-07-08 16:39:39", got)
	}
	// Unparseable input is returned sanitized, not dropped.
	if got := formatAuditTime("garbage"); got != "garbage" {
		t.Errorf("formatAuditTime(garbage) = %q, want garbage", got)
	}
}

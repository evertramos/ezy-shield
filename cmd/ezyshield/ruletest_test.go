// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for `ezyshield rule test` (issue #224): dry evaluation against a
// seeded store, standalone file vs named rule, allowlisted-hit warning,
// invalid rules, --json, and the no-side-effects guarantee.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
)

// ruleTestConfig pins the rule layers to the embedded base plus an empty
// overlay dir, so tests never read the host's real /etc/ezyshield.
func ruleTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return writeFile(t, dir, "config.yaml", "rules_dir: "+filepath.Join(dir, "rules.d")+"\n")
}

const ruleTestFixture = `
rules:
  - name: test_daily
    kinds: [ssh_fail]
    window: 24h
    threshold: 5
    score: 75
    category: bruteforce
`

// seedEvents writes n events for ip/kind, one per hour counting back from
// the current hour.
func seedEvents(t *testing.T, dbPath, ip, kind string, n int) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close() //nolint:errcheck
	addr := netip.MustParseAddr(ip)
	for i := 0; i < n; i++ {
		bucket := store.HourBucket(time.Now().Add(-time.Duration(i) * time.Hour))
		if err := db.IncrEventCount(ctx, addr, kind, bucket); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
}

func runRuleTestCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	jsonOutput = false
	t.Cleanup(func() { jsonOutput = false })
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"rule", "test"}, args...))
	err := root.Execute()
	return out.String() + errb.String(), err
}

func TestRuleTest_StandaloneFileFiresAndHasNoSideEffects(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "203.0.113.7", "ssh_fail", 5)
	ruleFile := writeFile(t, dir, "rule.yaml", ruleTestFixture)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, ruleFile, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err != nil {
		t.Fatalf("rule test: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Would have fired : 1 time(s)") {
		t.Errorf("expected 1 detection, got:\n%s", out)
	}
	if !strings.Contains(out, "Unique IPs       : 1") {
		t.Errorf("expected 1 unique IP, got:\n%s", out)
	}
	if !strings.Contains(out, "203.0.113.7") {
		t.Errorf("expected the IP in the sample, got:\n%s", out)
	}
	if !strings.Contains(out, "Allowlisted hits : 0") {
		t.Errorf("expected no allowlisted hits, got:\n%s", out)
	}

	// No side effects: nothing may have been written to the audit journal
	// or the strike tables.
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close() //nolint:errcheck
	audit, err := db.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(audit) != 0 {
		t.Errorf("rule test wrote %d audit entries; must be side-effect free", len(audit))
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("bans: %v", err)
	}
	if len(bans) != 0 {
		t.Errorf("rule test created %d bans; must be side-effect free", len(bans))
	}
}

func TestRuleTest_BelowThresholdDoesNotFire(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "203.0.113.8", "ssh_fail", 3)
	ruleFile := writeFile(t, dir, "rule.yaml", ruleTestFixture)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, ruleFile, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err != nil {
		t.Fatalf("rule test: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Would have fired : 0 time(s)") {
		t.Errorf("expected 0 detections, got:\n%s", out)
	}
}

func TestRuleTest_AllowlistedHitIsFlagged(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "203.0.113.9", "ssh_fail", 6)
	ruleFile := writeFile(t, dir, "rule.yaml", ruleTestFixture)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy+"admin_cidrs:\n  - 203.0.113.0/24\n")

	out, err := runRuleTestCLI(t, ruleFile, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err != nil {
		t.Fatalf("rule test: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Allowlisted hits : 1") {
		t.Errorf("expected 1 allowlisted hit, got:\n%s", out)
	}
	if !strings.Contains(out, "[ALLOWLISTED: policy]") {
		t.Errorf("expected the ALLOWLISTED marker, got:\n%s", out)
	}
}

func TestRuleTest_NamedBuiltinRule(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "198.51.100.4", "ssh_fail", 5)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, "ssh_bruteforce_daily", "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err != nil {
		t.Fatalf("rule test: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Rule test: ssh_bruteforce_daily") {
		t.Errorf("expected the named rule header, got:\n%s", out)
	}
	if !strings.Contains(out, "Would have fired : 1 time(s)") {
		t.Errorf("expected 1 detection, got:\n%s", out)
	}
}

func TestRuleTest_UnknownNameListsRules(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "198.51.100.5", "ssh_fail", 1)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, "no_such_rule", "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err == nil {
		t.Fatalf("expected an error for an unknown rule name, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "ssh_bruteforce_daily") {
		t.Errorf("error should list available rules, got: %v", err)
	}
}

func TestRuleTest_InvalidRuleFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "198.51.100.6", "ssh_fail", 1)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)
	bad := writeFile(t, dir, "bad.yaml", `
rules:
  - name: no_category
    kinds: [ssh_fail]
    window: 24h
    threshold: 5
    score: 75
`)

	out, err := runRuleTestCLI(t, bad, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err == nil {
		t.Fatalf("expected a validation error, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "category") {
		t.Errorf("error should name the failing validation, got: %v", err)
	}
}

func TestRuleTest_JSONEnvelope(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "203.0.113.10", "ssh_fail", 7)
	ruleFile := writeFile(t, dir, "rule.yaml", ruleTestFixture)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, ruleFile, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath, "--json")
	if err != nil {
		t.Fatalf("rule test --json: %v\n%s", err, out)
	}
	var doc struct {
		Results []ruleTestResult `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(doc.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(doc.Results))
	}
	r := doc.Results[0]
	if r.Rule.Name != "test_daily" || r.Detections != 1 || r.UniqueIPs != 1 {
		t.Errorf("unexpected result: %+v", r)
	}
	perDayTotal := 0
	for _, n := range r.PerDay {
		perDayTotal += n
	}
	if perDayTotal != r.Detections {
		t.Errorf("per_day sums to %d, want %d", perDayTotal, r.Detections)
	}
	if r.Limitation == "" {
		t.Errorf("limitation line must always be present")
	}
}

func TestRuleTest_FieldLevelIsUpperBound(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	seedEvents(t, dbPath, "203.0.113.11", "http_404", 12)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)
	ruleFile := writeFile(t, dir, "rule.yaml", `
rules:
  - name: field_rule
    kinds: [http_404]
    field: path
    contains: wp-login
    window: 60s
    threshold: 10
    score: 60
    category: scanner
`)

	out, err := runRuleTestCLI(t, ruleFile, "--db", dbPath,
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err != nil {
		t.Fatalf("rule test: %v\n%s", err, out)
	}
	if !strings.Contains(out, "UPPER BOUND") {
		t.Errorf("field-level rules must be loudly marked as an upper bound, got:\n%s", out)
	}
}

func TestRuleTest_MissingDatabaseErrors(t *testing.T) {
	dir := t.TempDir()
	ruleFile := writeFile(t, dir, "rule.yaml", ruleTestFixture)
	polPath := writeFile(t, dir, "policy.yaml", validPolicy)

	out, err := runRuleTestCLI(t, ruleFile, "--db", filepath.Join(dir, "absent.db"),
		"--config", ruleTestConfig(t), "--policy", polPath)
	if err == nil {
		t.Fatalf("expected an error for a missing database, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "no database") {
		t.Errorf("error should say the database is missing, got: %v", err)
	}
}

func TestSimulateRule_RisingEdgeDeduplicates(t *testing.T) {
	t.Parallel()
	base := store.HourBucket(time.Now())
	hour := int64(3600)
	// Two consecutive saturated hours are ONE incident…
	rows := []store.HourCount{
		{IP: "203.0.113.20", BucketStart: base - hour, Count: 5},
		{IP: "203.0.113.20", BucketStart: base, Count: 5},
	}
	sims := simulateRule(rows, 24*time.Hour, 5)
	if len(sims) != 1 || len(sims[0].detections) != 1 {
		t.Fatalf("consecutive saturated hours: detections = %+v, want exactly 1", sims)
	}

	// …while a drop below the threshold (window slid past the first burst)
	// makes the next crossing a NEW detection.
	rows = []store.HourCount{
		{IP: "203.0.113.20", BucketStart: base - 50*hour, Count: 5},
		{IP: "203.0.113.20", BucketStart: base, Count: 5},
	}
	sims = simulateRule(rows, 24*time.Hour, 5)
	if len(sims) != 1 || len(sims[0].detections) != 2 {
		t.Fatalf("separated bursts: detections = %+v, want exactly 2", sims)
	}
}

func TestParseSinceDuration(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]time.Duration{
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"90m": 90 * time.Minute,
	} {
		got, err := parseSinceDuration(in)
		if err != nil || got != want {
			t.Errorf("parseSinceDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-24h", "0", "xd", "abc"} {
		if _, err := parseSinceDuration(in); err == nil {
			t.Errorf("parseSinceDuration(%q) should fail", in)
		}
	}
}

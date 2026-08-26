// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for `ezyshield report --since` (issue #229): golden markdown from a
// fixed digest, seeded-store aggregation, hostile-field rendering, the
// --narrative path with a mock provider, and its degradation on failure.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// goldenDigest is a fully deterministic digestData fixture.
func goldenDigest() *digestData {
	d := &digestData{
		SchemaVersion: digestSchemaVersion,
		Since:         "2026-08-25T00:00:00Z",
		WindowSeconds: 86400,
		GeneratedAt:   "2026-08-26T00:00:00Z",
	}
	d.Totals.Events = 42
	d.Totals.EventIPs = 3
	d.Totals.Strikes = 5
	d.Totals.StrikeIPs = 2
	d.Totals.Bans = 1
	d.Totals.DryBans = 2
	d.Totals.Unbans = 1
	d.EventsByKind = []digestKV{{Name: "ssh_fail", Count: 42}}
	d.Categories = []digestKV{{Name: "bruteforce", Count: 5, UniqueIPs: 2}}
	d.Rules = []digestKV{{Name: "ssh_bruteforce_daily", Count: 5, UniqueIPs: 2}}
	d.TopOffenders = []digestOffender{
		{IP: "203.0.113.7", Strikes: 3, MaxStrike: 3, TotalStrikes: 4, New: false},
		{IP: "198.51.100.9", Strikes: 2, MaxStrike: 1, TotalStrikes: 2, New: true},
	}
	d.NewOffenders = 1
	d.RepeatOffenders = 1
	d.ActiveBans = 2
	d.PermanentBans = 1
	d.DryRunBans = 1
	d.Patterns = []string{"escalation: 203.0.113.7 reached strike 3 (total strikes on record: 4)"}
	return d
}

const goldenDigestMarkdown = `# EzyShield digest — last 24h0m0s

_Window since 2026-08-25T00:00:00Z · generated 2026-08-26T00:00:00Z_

## Totals

| Metric | Count |
|---|---|
| Events (persisted counters) | 42 |
| IPs with events | 3 |
| Strikes | 5 |
| IPs struck | 2 |
| Bans | 1 |
| Dry-run bans | 2 |
| Unbans/expiries | 1 |
| Notify-only | 0 |

## Events by kind

| Kind | Events |
|---|---|
| ssh_fail | 42 |

## Strikes by category

| Category | Verdicts | Unique IPs |
|---|---|---|
| bruteforce | 5 | 2 |

## Strikes by rule

| Rule | Verdicts | Unique IPs |
|---|---|---|
| ssh_bruteforce_daily | 5 | 2 |

## Top offenders

| IP | Strikes (window) | Max strike | Total strikes | New |
|---|---|---|---|---|
| 203.0.113.7 | 3 | 3 | 4 | repeat |
| 198.51.100.9 | 2 | 1 | 2 | new |

New offenders: 1 · repeat offenders: 1

## Enforcement

- Active bans: 2 (1 permanent, 1 dry-run)

## Notable patterns

- escalation: 203.0.113.7 reached strike 3 (total strikes on record: 4)

_Event totals come from the persisted hourly counters, which only track kinds referenced by long-window rules._
`

// TestDigestMarkdown_Golden pins the documented section structure exactly:
// any change to the digest layout must consciously update this golden.
func TestDigestMarkdown_Golden(t *testing.T) {
	t.Parallel()
	got := renderDigestMarkdown(goldenDigest())
	if got != goldenDigestMarkdown {
		t.Errorf("digest markdown drifted from golden.\n--- got ---\n%s\n--- want ---\n%s", got, goldenDigestMarkdown)
	}
}

// seedDigestStore records two offenders with rule verdicts plus persisted
// event counters. Returns the db path.
func seedDigestStore(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "digest.db")
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close() //nolint:errcheck

	strike := func(ip string, num int, op string) {
		t.Helper()
		err := db.RecordStrike(ctx, sdk.Action{
			IP:     netip.MustParseAddr(ip),
			Op:     op,
			TTL:    5 * time.Minute,
			Strike: num,
			Reason: "rule/ssh_bruteforce: threshold met",
			Verdicts: []sdk.Verdict{{
				Category: "bruteforce",
				Reason:   "rule/ssh_bruteforce: 10 events in 1m0s (threshold 5)",
				Source:   "rules",
				Score:    80,
			}},
		})
		if err != nil {
			t.Fatalf("seed strike: %v", err)
		}
	}
	strike("203.0.113.21", 1, "dry_ban")
	strike("203.0.113.21", 2, "dry_ban")
	strike("198.51.100.22", 1, "dry_ban")

	for i := 0; i < 4; i++ {
		bucket := store.HourBucket(time.Now().Add(-time.Duration(i) * time.Hour))
		if err := db.IncrEventCount(ctx, netip.MustParseAddr("203.0.113.21"), "ssh_fail", bucket); err != nil {
			t.Fatalf("seed events: %v", err)
		}
	}
	return dbPath
}

func TestBuildDigest_SeededStore(t *testing.T) {
	dbPath := seedDigestStore(t)
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close() //nolint:errcheck

	d, err := buildDigest(ctx, db, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatalf("buildDigest: %v", err)
	}
	if d.Totals.Strikes != 3 || d.Totals.StrikeIPs != 2 {
		t.Errorf("strikes = %d on %d IPs, want 3 on 2", d.Totals.Strikes, d.Totals.StrikeIPs)
	}
	if d.Totals.DryBans != 3 || d.Totals.Bans != 0 {
		t.Errorf("dry_bans = %d, bans = %d, want 3/0", d.Totals.DryBans, d.Totals.Bans)
	}
	if len(d.Categories) != 1 || d.Categories[0].Name != "bruteforce" || d.Categories[0].Count != 3 || d.Categories[0].UniqueIPs != 2 {
		t.Errorf("categories = %+v", d.Categories)
	}
	if len(d.Rules) != 1 || d.Rules[0].Name != "ssh_bruteforce" || d.Rules[0].UniqueIPs != 2 {
		t.Errorf("rules = %+v", d.Rules)
	}
	if d.Totals.Events != 4 || d.Totals.EventIPs != 1 {
		t.Errorf("events = %d from %d IPs, want 4 from 1", d.Totals.Events, d.Totals.EventIPs)
	}
	if len(d.TopOffenders) != 2 || d.TopOffenders[0].IP != "203.0.113.21" || d.TopOffenders[0].Strikes != 2 {
		t.Errorf("top offenders = %+v", d.TopOffenders)
	}
	// Both offenders were first seen inside the window.
	if d.NewOffenders != 2 || d.RepeatOffenders != 0 {
		t.Errorf("new/repeat = %d/%d, want 2/0", d.NewOffenders, d.RepeatOffenders)
	}
	// Dry-run pattern must surface (bans were simulated only).
	joined := strings.Join(d.Patterns, "\n")
	if !strings.Contains(joined, "dry-run mode") {
		t.Errorf("expected the dry-run pattern, got %+v", d.Patterns)
	}
	if d.ActiveBans != 2 || d.DryRunBans != 2 {
		t.Errorf("active bans = %d (dry %d), want 2 (dry 2)", d.ActiveBans, d.DryRunBans)
	}
}

// TestDigestMarkdown_HostileFields: categories/rules copied from hostile
// log-derived verdicts must not break table structure or carry escape
// sequences into the document.
func TestDigestMarkdown_HostileFields(t *testing.T) {
	t.Parallel()
	d := goldenDigest()
	d.Categories = []digestKV{{Name: "bad|cat\x1b[31mred\nnewline", Count: 1, UniqueIPs: 1}}
	d.Rules = []digestKV{{Name: "rule|with|pipes", Count: 1, UniqueIPs: 1}}
	out := renderDigestMarkdown(d)

	if strings.Contains(out, "\x1b") {
		t.Errorf("escape sequence leaked into markdown")
	}
	if strings.Contains(out, "bad|cat") {
		t.Errorf("unescaped pipe leaked into a table cell")
	}
	if !strings.Contains(out, `bad\|cat`) || !strings.Contains(out, `rule\|with\|pipes`) {
		t.Errorf("pipes must be escaped in cells, got:\n%s", out)
	}
}

func runReportDigestCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	jsonOutput = false
	t.Cleanup(func() { jsonOutput = false })
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"report"}, args...))
	err := root.Execute()
	return out.String() + errb.String(), err
}

func TestReportDigest_JSONEnvelope(t *testing.T) {
	dbPath := seedDigestStore(t)
	out, err := runReportDigestCLI(t, "--since", "24h", "--db", dbPath, "--json")
	if err != nil {
		t.Fatalf("report --since --json: %v\n%s", err, out)
	}
	var d digestData
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if d.SchemaVersion != digestSchemaVersion || d.Totals.Strikes != 3 {
		t.Errorf("unexpected digest: %+v", d)
	}
	if d.Narrative != "" {
		t.Errorf("narrative must be absent without --narrative")
	}
}

func TestReportDigest_MarkdownMode(t *testing.T) {
	dbPath := seedDigestStore(t)
	out, err := runReportDigestCLI(t, "--since", "24h", "--db", dbPath, "-o", "md")
	if err != nil {
		t.Fatalf("report --since -o md: %v\n%s", err, out)
	}
	for _, section := range []string{"# EzyShield digest", "## Totals", "## Strikes by rule", "## Enforcement"} {
		if !strings.Contains(out, section) {
			t.Errorf("markdown missing section %q:\n%s", section, out)
		}
	}
}

func TestReportDigest_FlagValidation(t *testing.T) {
	dbPath := seedDigestStore(t)
	if out, err := runReportDigestCLI(t, "203.0.113.21", "--since", "24h", "--db", dbPath); err == nil {
		t.Errorf("--since with an IP argument must error, got:\n%s", out)
	}
	if out, err := runReportDigestCLI(t, "--narrative", "--db", dbPath); err == nil {
		t.Errorf("--narrative without --since must error, got:\n%s", out)
	}
}

func TestReportDigest_NarrativeMockProvider(t *testing.T) {
	dbPath := seedDigestStore(t)
	var prompt string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if len(req.Messages) > 0 {
			prompt = req.Messages[0].Content
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message":           map[string]string{"content": "Mostly SSH brute force from two addresses; daemon is in dry-run."},
			"prompt_eval_count": 10,
			"eval_count":        5,
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml",
		"ai:\n  provider: ollama\n  model: test\n  endpoint: "+srv.URL+"\n")

	out, err := runReportDigestCLI(t, "--since", "24h", "--db", dbPath,
		"--narrative", "--config", cfgPath)
	if err != nil {
		t.Fatalf("report --since --narrative: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Mostly SSH brute force") {
		t.Errorf("narrative missing from output:\n%s", out)
	}
	// The model input is the aggregated digest, never raw log lines.
	if !strings.Contains(prompt, `"schema_version"`) {
		t.Errorf("narrative prompt must embed the digest JSON:\n%s", prompt)
	}

	// Usage accounting must have been recorded for the provider.
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close() //nolint:errcheck
	usage, err := db.TodayUsage(ctx, "ollama")
	if err != nil {
		t.Fatalf("usage: %v", err)
	}
	if usage.InputTokens != 10 || usage.OutputTokens != 5 {
		t.Errorf("usage not recorded: %+v", usage)
	}
}

func TestReportDigest_NarrativeFailureDegrades(t *testing.T) {
	dbPath := seedDigestStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml",
		"ai:\n  provider: ollama\n  model: test\n  endpoint: "+srv.URL+"\n")

	out, err := runReportDigestCLI(t, "--since", "24h", "--db", dbPath,
		"--narrative", "--config", cfgPath)
	if err != nil {
		t.Fatalf("digest must degrade, not fail: %v\n%s", err, out)
	}
	if !strings.Contains(out, "AI narrative unavailable") {
		t.Errorf("expected the degradation note, got:\n%s", out)
	}
	if !strings.Contains(out, "Strikes: 3") {
		t.Errorf("plain digest must still render, got:\n%s", out)
	}
}

func TestReportDigest_NarrativeBudgetGate(t *testing.T) {
	dbPath := seedDigestStore(t)
	ctx := context.Background()
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := db.RecordUsage(ctx, "ollama", sdk.Usage{InputTokens: 900, OutputTokens: 200}, ""); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
	_ = db.Close()

	dir := t.TempDir()
	cfgPath := writeFile(t, dir, "config.yaml",
		"ai:\n  provider: ollama\n  model: test\n  endpoint: http://127.0.0.1:1\n  token_budget_daily: 1000\n")

	out, err := runReportDigestCLI(t, "--since", "24h", "--db", dbPath,
		"--narrative", "--config", cfgPath)
	if err != nil {
		t.Fatalf("budget gate must degrade, not fail: %v\n%s", err, out)
	}
	if !strings.Contains(out, "daily token budget exhausted") {
		t.Errorf("expected the budget note, got:\n%s", out)
	}
}

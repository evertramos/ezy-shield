package rules_test

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

var (
	ip1 = netip.MustParseAddr("1.2.3.4")
	t0  = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	w60 = 60 * time.Second
)

// mustEngine creates an Engine from the embedded defaults and fails the test
// on error.
func mustEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	return e
}

// makeAgg builds a minimal sdk.Aggregate with the given kind counts and sample.
func makeAgg(ip netip.Addr, window time.Duration, sample []sdk.Event) sdk.Aggregate {
	kinds := make(map[string]int)
	for _, ev := range sample {
		kinds[ev.Kind]++
	}
	return sdk.Aggregate{
		IP:     ip,
		Window: window,
		Count:  len(sample),
		Kinds:  kinds,
		Sample: sample,
	}
}

func sshEvent(kind string) sdk.Event {
	return sdk.Event{
		Time:     t0,
		SourceIP: ip1,
		Kind:     kind,
		Fields:   map[string]string{"username": "root", "port": "22"},
	}
}

func httpEvent(status, path string) sdk.Event {
	return sdk.Event{
		Time:     t0,
		SourceIP: ip1,
		Kind:     "http_request",
		Fields:   map[string]string{"status": status, "method": "GET", "path": path},
	}
}

// ---- ssh_bruteforce ----

func TestEvaluate_SSHBruteforce_Triggers(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 6)
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "bruteforce")
	if found == nil {
		t.Fatalf("expected bruteforce verdict, got %v", verdicts)
	}
	if found.Score != 85 {
		t.Errorf("Score = %d, want 85", found.Score)
	}
	if found.Source != "rules" {
		t.Errorf("Source = %q, want rules", found.Source)
	}
	if found.IP != ip1 {
		t.Errorf("IP = %v, want %v", found.IP, ip1)
	}
}

func TestEvaluate_SSHBruteforce_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 4) // threshold is 5; 4 must not trigger
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "bruteforce"); v != nil {
		t.Errorf("expected no bruteforce verdict below threshold, got %v", v)
	}
}

func TestEvaluate_SSHBruteforce_AtThreshold(t *testing.T) {
	e := mustEngine(t)
	// Exactly 5 — must trigger (≥ 5).
	sample := make([]sdk.Event, 5)
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if findVerdict(verdicts, "bruteforce") == nil {
		t.Error("expected bruteforce verdict at threshold (count == threshold)")
	}
}

func TestEvaluate_SSHBruteforce_InvalidUserCounts(t *testing.T) {
	e := mustEngine(t)
	// Mix of ssh_invalid_user events; both kinds count toward the rule.
	sample := []sdk.Event{
		sshEvent("ssh_invalid_user"),
		sshEvent("ssh_invalid_user"),
		sshEvent("ssh_fail"),
		sshEvent("ssh_invalid_user"),
		sshEvent("ssh_fail"),
		sshEvent("ssh_invalid_user"),
	}
	agg := makeAgg(ip1, w60, sample)

	if findVerdict(e.Evaluate(context.Background(), agg), "bruteforce") == nil {
		t.Error("expected bruteforce from mixed ssh_fail + ssh_invalid_user")
	}
}

func TestEvaluate_SSHAccept_DoesNotTrigger(t *testing.T) {
	e := mustEngine(t)
	// Only successful logins — must not trigger ssh_bruteforce.
	sample := make([]sdk.Event, 10)
	for i := range sample {
		sample[i] = sshEvent("ssh_accept")
	}
	agg := makeAgg(ip1, w60, sample)

	if v := findVerdict(e.Evaluate(context.Background(), agg), "bruteforce"); v != nil {
		t.Errorf("ssh_accept events must not trigger bruteforce, got %v", v)
	}
}

// ---- http_scanner ----

func TestEvaluate_HTTPScanner_Triggers(t *testing.T) {
	e := mustEngine(t)
	// 21 × 404 — above threshold of 20.
	sample := make([]sdk.Event, 21)
	for i := range sample {
		sample[i] = httpEvent("404", "/notfound")
	}
	agg := makeAgg(ip1, w60, sample)

	if findVerdict(e.Evaluate(context.Background(), agg), "scanner") == nil {
		t.Fatal("expected scanner verdict for 21 404s")
	}
}

func TestEvaluate_HTTPScanner_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 19) // 19 < 20
	for i := range sample {
		sample[i] = httpEvent("404", "/notfound")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	// Must not trigger scanner from 404 threshold (wp_probe threshold is 3 so
	// wp-login test would fire; ensure we check 404-only paths here).
	count404 := 0
	for _, v := range verdicts {
		if v.Category == "scanner" && strings.Contains(v.Reason, "http_scanner") {
			count404++
		}
	}
	if count404 != 0 {
		t.Errorf("expected no http_scanner below threshold, got %d matches", count404)
	}
}

func TestEvaluate_HTTPScanner_OnlyCountsStatusField(t *testing.T) {
	e := mustEngine(t)
	// 200 OK requests — must not trigger http_scanner even if count > 20.
	sample := make([]sdk.Event, 30)
	for i := range sample {
		sample[i] = httpEvent("200", "/index.html")
	}
	agg := makeAgg(ip1, w60, sample)

	// http_scanner checks status==404 specifically; 200s should not count.
	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "http_scanner") {
			t.Errorf("http 200s triggered http_scanner verdict: %v", v)
		}
	}
}

// ---- http_wp_probe ----

func TestEvaluate_WPProbe_Triggers(t *testing.T) {
	e := mustEngine(t)
	sample := []sdk.Event{
		httpEvent("200", "/wp-login.php"),
		httpEvent("200", "/wp-login.php"),
		httpEvent("200", "/wp-login.php"),
	}
	agg := makeAgg(ip1, w60, sample)

	if findVerdict(e.Evaluate(context.Background(), agg), "scanner") == nil {
		t.Fatal("expected scanner verdict for wp-login probes")
	}
}

func TestEvaluate_WPProbe_SubstringMatch(t *testing.T) {
	e := mustEngine(t)
	// Paths containing wp-login as a substring.
	sample := []sdk.Event{
		httpEvent("200", "/blog/wp-login.php?redirect_to=%2F"),
		httpEvent("200", "/wp-login.php"),
		httpEvent("200", "/subdir/wp-login.php"),
	}
	agg := makeAgg(ip1, w60, sample)

	if findVerdict(e.Evaluate(context.Background(), agg), "scanner") == nil {
		t.Fatal("expected scanner verdict for wp-login substring paths")
	}
}

func TestEvaluate_WPProbe_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	sample := []sdk.Event{
		httpEvent("200", "/wp-login.php"),
		httpEvent("200", "/wp-login.php"),
	}
	agg := makeAgg(ip1, w60, sample)

	// Two wp-login hits — below threshold of 3.
	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "http_wp_probe") {
			t.Errorf("expected no http_wp_probe below threshold, got %v", v)
		}
	}
}

func TestEvaluate_WPProbe_NormalPathDoesNotMatch(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 10)
	for i := range sample {
		sample[i] = httpEvent("200", "/index.html")
	}
	agg := makeAgg(ip1, w60, sample)

	for _, v := range e.Evaluate(context.Background(), agg) {
		if strings.Contains(v.Reason, "http_wp_probe") {
			t.Errorf("/index.html triggered http_wp_probe: %v", v)
		}
	}
}

// ---- window mismatch ----

func TestEvaluate_WindowMismatchSkipsRule(t *testing.T) {
	e := mustEngine(t)
	// All built-in rules use a 60s window; using 10m here means no rule should fire.
	sample := make([]sdk.Event, 100)
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, 10*time.Minute, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if len(verdicts) != 0 {
		t.Errorf("expected no verdicts on window mismatch, got %v", verdicts)
	}
}

// ---- Engine.Windows ----

func TestEngine_Windows(t *testing.T) {
	e := mustEngine(t)
	ws := e.Windows()
	if len(ws) == 0 {
		t.Fatal("Windows() returned empty slice")
	}
	found60 := false
	for _, w := range ws {
		if w == 60*time.Second {
			found60 = true
		}
	}
	if !found60 {
		t.Errorf("expected 60s window in Windows(), got %v", ws)
	}
}

// ---- override file ----

func TestNew_OverrideFile(t *testing.T) {
	content := `
rules:
  - name: test_rule
    kinds: [ssh_fail]
    window: 30s
    threshold: 2
    score: 50
    category: bruteforce
`
	tmp := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := rules.New(tmp, "")
	if err != nil {
		t.Fatalf("New(override): %v", err)
	}

	ws := e.Windows()
	if len(ws) != 1 || ws[0] != 30*time.Second {
		t.Errorf("override windows = %v, want [30s]", ws)
	}

	sample := []sdk.Event{sshEvent("ssh_fail"), sshEvent("ssh_fail")}
	agg := makeAgg(ip1, 30*time.Second, sample)
	if findVerdict(e.Evaluate(context.Background(), agg), "bruteforce") == nil {
		t.Error("override rule not applied")
	}
}

func TestNew_InvalidYAML(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(tmp, []byte("not: valid: yaml: [[["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.New(tmp, ""); err == nil {
		t.Error("expected error on invalid YAML")
	}
}

func TestNew_ValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "missing name",
			content: `rules:
  - kinds: [ssh_fail]
    window: 60s
    threshold: 5
    score: 80
    category: bruteforce`,
		},
		{
			name: "empty kinds",
			content: `rules:
  - name: test
    kinds: []
    window: 60s
    threshold: 5
    score: 80
    category: bruteforce`,
		},
		{
			name: "zero threshold",
			content: `rules:
  - name: test
    kinds: [ssh_fail]
    window: 60s
    threshold: 0
    score: 80
    category: bruteforce`,
		},
		{
			name: "score out of range",
			content: `rules:
  - name: test
    kinds: [ssh_fail]
    window: 60s
    threshold: 5
    score: 101
    category: bruteforce`,
		},
		{
			name: "value and contains both set",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    value: "/foo"
    contains: "bar"
    window: 60s
    threshold: 3
    score: 70
    category: scanner`,
		},
		{
			name: "missing category",
			content: `rules:
  - name: test
    kinds: [ssh_fail]
    window: 60s
    threshold: 5
    score: 80`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(tmp, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.New(tmp, ""); err == nil {
				t.Errorf("expected validation error for %q", tc.name)
			}
		})
	}
}

// ---- sustained rules (low & slow detection) ----

func TestEvaluate_WPProbeSustained_Triggers(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 10 wp-login hits in 1h window triggers http_wp_probe_sustained
	sample := make([]sdk.Event, 10)
	for i := range sample {
		sample[i] = httpEvent("200", "/wp-login.php?action=login")
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "bruteforce")
	if found == nil {
		t.Fatalf("expected sustained bruteforce verdict, got %v", verdicts)
	}
	if found.Score != 75 {
		t.Errorf("Score = %d, want 75", found.Score)
	}
}

func TestEvaluate_WPProbeSustained_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 9 hits (below threshold of 10) must not trigger
	sample := make([]sdk.Event, 9)
	for i := range sample {
		sample[i] = httpEvent("200", "/wp-login.php")
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "bruteforce"); v != nil && v.Score == 75 {
		t.Errorf("expected no sustained bruteforce verdict below threshold, got %v", v)
	}
}

func TestEvaluate_WPProbeSustained_LegitimateUserDoesNotTrigger(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 3 wp-login hits in 1h (normal admin login behavior)
	sample := make([]sdk.Event, 3)
	for i := range sample {
		sample[i] = httpEvent("200", "/wp-login.php?action=login")
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "bruteforce"); v != nil && v.Score == 75 {
		t.Errorf("expected no sustained bruteforce for legitimate user, got %v", v)
	}
}

func TestEvaluate_XMLRPCSustained_Triggers(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 8 xmlrpc hits in 1h window triggers http_xmlrpc_sustained
	sample := make([]sdk.Event, 8)
	for i := range sample {
		sample[i] = httpEvent("200", "/xmlrpc.php")
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "bruteforce")
	if found == nil {
		t.Fatalf("expected sustained xmlrpc bruteforce verdict, got %v", verdicts)
	}
	if found.Score != 75 {
		t.Errorf("Score = %d, want 75", found.Score)
	}
}

func TestEvaluate_ScannerSustained_Triggers(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 60 distinct 404s in 1h window triggers http_scanner_sustained
	sample := make([]sdk.Event, 60)
	for i := range sample {
		sample[i] = httpEvent("404", fmt.Sprintf("/path/%d", i))
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "scanner")
	if found == nil {
		t.Fatalf("expected sustained scanner verdict, got %v", verdicts)
	}
	if found.Score != 70 {
		t.Errorf("Score = %d, want 70", found.Score)
	}
}

func TestEvaluate_SSHBruteforceSustained_Triggers(t *testing.T) {
	e := mustEngine(t)
	w3600 := 3600 * time.Second
	// 15 ssh_fail events in 1h window triggers ssh_bruteforce_sustained
	sample := make([]sdk.Event, 15)
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, w3600, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "bruteforce")
	if found == nil {
		t.Fatalf("expected sustained ssh bruteforce verdict, got %v", verdicts)
	}
	if found.Score != 80 {
		t.Errorf("Score = %d, want 80", found.Score)
	}
}

// ---- contains_any ----

func TestEvaluate_ContainsAny_Triggers(t *testing.T) {
	content := `
rules:
  - name: test_contains_any
    kinds: [http_request]
    field: path
    contains_any: [phpunit, shell.php, .git]
    window: 60s
    threshold: 2
    score: 90
    category: exploit_probe
`
	tmp := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := rules.New(tmp, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Two matches: one with phpunit, one with .git
	sample := []sdk.Event{
		httpEvent("200", "/admin/phpunit"),
		httpEvent("200", "/repo/.git/config"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "exploit_probe"); v == nil {
		t.Fatal("expected exploit_probe verdict from contains_any")
	}
}

func TestEvaluate_ContainsAny_NoMatch(t *testing.T) {
	content := `
rules:
  - name: test_contains_any
    kinds: [http_request]
    field: path
    contains_any: [phpunit, shell.php, .git]
    window: 60s
    threshold: 2
    score: 90
    category: exploit_probe
`
	tmp := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := rules.New(tmp, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// No matches: legitimate paths
	sample := []sdk.Event{
		httpEvent("200", "/index.html"),
		httpEvent("200", "/api/users"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "exploit_probe"); v != nil {
		t.Errorf("expected no exploit_probe, got %v", v)
	}
}

func TestEvaluate_ContainsAny_PartialMatch(t *testing.T) {
	content := `
rules:
  - name: test_contains_any
    kinds: [http_request]
    field: path
    contains_any: [phpunit, shell.php, .git]
    window: 60s
    threshold: 2
    score: 90
    category: exploit_probe
`
	tmp := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := rules.New(tmp, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Only one match, threshold is 2 — must not fire
	sample := []sdk.Event{
		httpEvent("200", "/admin/phpunit"),
		httpEvent("200", "/index.html"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "exploit_probe"); v != nil {
		t.Errorf("expected no verdict below threshold, got %v", v)
	}
}

func TestNew_ContainsAndContainsAny_MutualExclusion(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "value and contains_any both set",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    value: "/foo"
    contains_any: ["bar", "baz"]
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
		{
			name: "contains and contains_any both set",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    contains: "bar"
    contains_any: ["foo", "baz"]
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
		{
			name: "value, contains, and contains_any all set",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    value: "/foo"
    contains: "bar"
    contains_any: ["baz", "qux"]
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(tmp, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.New(tmp, ""); err == nil {
				t.Errorf("expected validation error for %q", tc.name)
			}
		})
	}
}

// ---- http_rce_probe ----

func TestEvaluate_RCEProbe_Triggers(t *testing.T) {
	e := mustEngine(t)
	// Single RCE probe path must trigger (threshold=1, score=95)
	sample := []sdk.Event{
		httpEvent("404", "/.git/config"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "exploit_probe")
	if found == nil {
		t.Fatalf("expected exploit_probe verdict, got %v", verdicts)
	}
	if found.Score != 95 {
		t.Errorf("Score = %d, want 95", found.Score)
	}
}

func TestEvaluate_RCEProbe_MultipleExploitPaths(t *testing.T) {
	e := mustEngine(t)
	// Multiple different RCE paths
	sample := []sdk.Event{
		httpEvent("500", "/admin.php"),
		httpEvent("200", "/phpunit"),
		httpEvent("404", "/.aws/credentials"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "exploit_probe")
	if found == nil {
		t.Fatalf("expected exploit_probe verdict for multiple probes, got %v", verdicts)
	}
}

func TestEvaluate_RCEProbe_NoFalsePositives(t *testing.T) {
	e := mustEngine(t)
	// Legitimate paths must not trigger
	sample := []sdk.Event{
		httpEvent("200", "/index.html"),
		httpEvent("200", "/api/users"),
		httpEvent("200", "/config/app.json"),
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	if v := findVerdict(verdicts, "exploit_probe"); v != nil {
		t.Errorf("expected no exploit_probe for legitimate paths, got %v", v)
	}
}

// ---- http_scanner_400 ----

func TestEvaluate_HTTPScanner400_Triggers(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 10)
	for i := range sample {
		sample[i] = httpEvent("400", "/path")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "scanner")
	if found == nil {
		t.Fatalf("expected scanner verdict for 10 400s, got %v", verdicts)
	}
	if found.Score != 60 {
		t.Errorf("Score = %d, want 60", found.Score)
	}
}

func TestEvaluate_HTTPScanner400_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 9) // 9 < 10
	for i := range sample {
		sample[i] = httpEvent("400", "/path")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "scanner")
	if found != nil && found.Score == 60 {
		t.Errorf("expected no 400 scanner below threshold, got %v", found)
	}
}

// ---- http_scanner_503 ----

func TestEvaluate_HTTPScanner503_Triggers(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 15)
	for i := range sample {
		sample[i] = httpEvent("503", "/path")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "scanner")
	if found == nil {
		t.Fatalf("expected scanner verdict for 15 503s, got %v", verdicts)
	}
	if found.Score != 65 {
		t.Errorf("Score = %d, want 65", found.Score)
	}
}

func TestEvaluate_HTTPScanner503_BelowThreshold(t *testing.T) {
	e := mustEngine(t)
	sample := make([]sdk.Event, 14) // 14 < 15
	for i := range sample {
		sample[i] = httpEvent("503", "/path")
	}
	agg := makeAgg(ip1, w60, sample)

	verdicts := e.Evaluate(context.Background(), agg)
	found := findVerdict(verdicts, "scanner")
	if found != nil && found.Score == 65 {
		t.Errorf("expected no 503 scanner below threshold, got %v", found)
	}
}

// ---- http_env_probe expanded ----

func TestEvaluate_EnvProbe_ExpandedVariants(t *testing.T) {
	e := mustEngine(t)
	// Test all env variants trigger
	cases := []string{".env", ".env.local", ".env.production", ".env.staging"}
	for _, path := range cases {
		sample := []sdk.Event{
			httpEvent("200", "/"+path),
		}
		agg := makeAgg(ip1, w60, sample)

		verdicts := e.Evaluate(context.Background(), agg)
		if v := findVerdict(verdicts, "scanner"); v == nil || v.Score != 90 {
			t.Errorf("expected env_probe for %q, got %v", path, v)
		}
	}
}

// ---- context cancellation ----

func TestEvaluate_ContextCancelled(t *testing.T) {
	e := mustEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	sample := make([]sdk.Event, 10)
	for i := range sample {
		sample[i] = sshEvent("ssh_fail")
	}
	agg := makeAgg(ip1, w60, sample)
	// Must not panic; may return 0 or some verdicts.
	_ = e.Evaluate(ctx, agg)
}

// ---- helpers ----

// findVerdict returns the first verdict with the given category, or nil.
func findVerdict(verdicts []sdk.Verdict, category string) *sdk.Verdict {
	for i := range verdicts {
		if verdicts[i].Category == category {
			return &verdicts[i]
		}
	}
	return nil
}

// TestNew_FieldMatcherCrossCheck reproduces issue #316: either half of the
// field/matcher pair alone must fail validation at load time. A matcher with
// no field was silently ignored (the rule counted EVERY event of its kinds —
// over-matching legitimate users), and a field with no matcher could never
// increment (a protective custom rule was dead). Both previously loaded
// without any warning.
func TestNew_FieldMatcherCrossCheck(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "value without field over-matches",
			content: `rules:
  - name: test
    kinds: [http_request]
    value: "404"
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
		{
			name: "contains without field over-matches",
			content: `rules:
  - name: test
    kinds: [http_request]
    contains: "/wp-"
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
		{
			name: "contains_any without field over-matches",
			content: `rules:
  - name: test
    kinds: [http_request]
    contains_any: ["/wp-", "/.git"]
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
		{
			name: "field without matcher never fires",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: status
    window: 60s
    threshold: 1
    score: 70
    category: scanner`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(tmp, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.New(tmp, ""); err == nil {
				t.Errorf("expected validation error for %q", tc.name)
			}
		})
	}
}

// ---- issue #417: http_wp_probe / _sustained same-origin re-auth carve-out ----
//
// These tests use RFC 3849 / RFC 5737 documentation addresses and placeholder
// hostnames only (Hard Rule 8). They encode the exact traffic shapes from the
// 2026-08-06 kylian audit: a legitimate admin bouncing through the WordPress
// re-auth / 2FA / password-change flow must produce ZERO strikes, while every
// documented bot pattern must still strike.

// wpEvent builds an http_request event carrying referer and host so the
// same-origin exclusion (issue #417) can be exercised.
func wpEvent(status, path, referer, host string) sdk.Event {
	return sdk.Event{
		Time:     t0,
		SourceIP: ip1,
		Kind:     "http_request",
		Fields: map[string]string{
			"status":  status,
			"method":  "GET",
			"path":    path,
			"referer": referer,
			"host":    host,
		},
	}
}

func hasWPProbe(verdicts []sdk.Verdict) bool {
	for _, v := range verdicts {
		if strings.Contains(v.Reason, "rule/http_wp_probe:") {
			return true
		}
	}
	return false
}

func hasWPProbeSustained(verdicts []sdk.Verdict) bool {
	for _, v := range verdicts {
		if strings.Contains(v.Reason, "rule/http_wp_probe_sustained:") {
			return true
		}
	}
	return false
}

// TestEvaluate_WPProbe_ReauthFlow_NoStrike is the primary repro from issue #417.
// The admin's session expired; the browser walks reauth=1 → re-auth POST →
// iThemes 2FA on-board → password change — every wp-login hit carries a
// same-origin Referer pointing back at the login/admin pages. It must NOT fire.
func TestEvaluate_WPProbe_ReauthFlow_NoStrike(t *testing.T) {
	e := mustEngine(t)
	const host = "site.example"
	loginRef := "https://" + host + "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1"
	adminRef := "https://" + host + "/wp-admin/"
	sample := []sdk.Event{
		wpEvent("200", "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1", adminRef, host),
		wpEvent("200", "/wp-login.php", loginRef, host),
		wpEvent("200", "/wp-login.php", loginRef, host),
		wpEvent("200", "/wp-login.php", loginRef, host),
		wpEvent("200", "/wp-login.php?action=lostpassword", loginRef, host),
		wpEvent("200", "/wp-login.php?action=itsec-2fa-on-board", loginRef, host),
		wpEvent("302", "/wp-login.php?action=itsec-update-password", loginRef, host),
	}
	agg := makeAgg(ip1, w60, sample)

	if hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("re-auth/2FA flow (same-origin referer) must NOT trigger http_wp_probe")
	}
}

// TestEvaluate_WPProbe_ColdScanner_Strikes: an anonymous scanner blasting
// wp-login with no Referer (the classic brute) must still be caught.
func TestEvaluate_WPProbe_ColdScanner_Strikes(t *testing.T) {
	e := mustEngine(t)
	const host = "site.example"
	sample := []sdk.Event{
		wpEvent("200", "/wp-login.php", "", host),
		wpEvent("200", "/wp-login.php", "", host),
		wpEvent("200", "/wp-login.php", "", host),
	}
	agg := makeAgg(ip1, w60, sample)

	if !hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("cold scanner (no referer) must still trigger http_wp_probe")
	}
}

// TestEvaluate_WPProbe_CrossVhostReferer_Strikes: the multi-vhost bot from the
// audit hits site A's wp-login carrying a Referer for a DIFFERENT site (or the
// site root). The same-origin gate keeps every such hit counted.
func TestEvaluate_WPProbe_CrossVhostReferer_Strikes(t *testing.T) {
	e := mustEngine(t)
	sample := []sdk.Event{
		// cross-vhost referer whose path even contains wp-login — still counted
		// because the referer host != the request vhost.
		wpEvent("301", "/wp-login.php", "http://other.example/wp-login.php", "site.example"),
		// same-host referer but pointing at the site root (path has no wp-login/
		// wp-admin) — not an auth-flow origin, so counted.
		wpEvent("200", "/wp-login.php", "http://site.example/", "site.example"),
		wpEvent("200", "/wp-login.php", "http://another.example/", "site.example"),
	}
	agg := makeAgg(ip1, w60, sample)

	if !hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("cross-vhost / root-referer bot must still trigger http_wp_probe")
	}
}

// TestEvaluate_WPProbe_PathSuffixEvasion_Strikes: the /wp-login.php/<payload>
// suffix-evasion technique from the audit still counts (path contains wp-login;
// no same-origin auth-flow referer).
func TestEvaluate_WPProbe_PathSuffixEvasion_Strikes(t *testing.T) {
	e := mustEngine(t)
	const host = "site.example"
	sample := []sdk.Event{
		wpEvent("200", "/wp-login.php/xmlrpc.php", "", host),
		wpEvent("200", "/wp-login.php/wp-json/jwt-auth/v1/token", "", host),
		wpEvent("200", "/wp-login.php/wp-login.php", "", host),
	}
	agg := makeAgg(ip1, w60, sample)

	if !hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("path-suffix evasion must still trigger http_wp_probe")
	}
}

// TestEvaluate_WPProbe_ForgedSameOriginNeedsHostMatch documents the residual
// forgery surface and its bound: a scanner that forges a same-origin auth-flow
// Referer (host AND path both matching the target) evades THIS one rule — but
// only when it wins the host match. A forged Referer for the wrong host does
// not evade. (Defense-in-depth: 404/400/503/xmlrpc/env/rce rules still count.)
func TestEvaluate_WPProbe_ForgedSameOriginNeedsHostMatch(t *testing.T) {
	e := mustEngine(t)
	// Forged referer host does not match the vhost → still counted.
	sample := make([]sdk.Event, 3)
	for i := range sample {
		sample[i] = wpEvent("200", "/wp-login.php",
			"https://wrong.example/wp-login.php", "site.example")
	}
	agg := makeAgg(ip1, w60, sample)
	if !hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("forged referer for the wrong host must NOT evade http_wp_probe")
	}
}

// TestEvaluate_WPProbe_UnknownHostFallback: on log formats that carry no vhost
// (nginx "combined"), the host field is empty and same-origin cannot be
// decided; the auth-flow Referer alone then carves the hit out. Verifies the
// documented fallback so combined-format WP installs also get the FP fix.
func TestEvaluate_WPProbe_UnknownHostFallback(t *testing.T) {
	e := mustEngine(t)
	ref := "https://site.example/wp-login.php?reauth=1"
	sample := []sdk.Event{
		wpEvent("200", "/wp-login.php", ref, ""), // host empty
		wpEvent("200", "/wp-login.php", ref, ""),
		wpEvent("200", "/wp-login.php", ref, ""),
		wpEvent("200", "/wp-login.php", ref, ""),
	}
	agg := makeAgg(ip1, w60, sample)
	if hasWPProbe(e.Evaluate(context.Background(), agg)) {
		t.Fatal("auth-flow referer must carve out even when host is unknown")
	}
}

// TestEvaluate_WPProbeSustained_ReauthFlow_NoStrike: the same carve-out covers
// the low-&-slow tier — an admin re-authenticating a dozen times over an hour
// must not accumulate toward the sustained threshold.
func TestEvaluate_WPProbeSustained_ReauthFlow_NoStrike(t *testing.T) {
	e := mustEngine(t)
	const host = "site.example"
	ref := "https://" + host + "/wp-login.php?reauth=1"
	sample := make([]sdk.Event, 12) // sustained threshold is 10
	for i := range sample {
		sample[i] = wpEvent("200", "/wp-login.php", ref, host)
	}
	agg := makeAgg(ip1, 3600*time.Second, sample)
	if hasWPProbeSustained(e.Evaluate(context.Background(), agg)) {
		t.Fatal("sustained re-auth flow (same-origin) must NOT trigger http_wp_probe_sustained")
	}
}

// TestEvaluate_WPProbeSustained_ColdScanner_Strikes: low-&-slow anonymous brute
// (no referer) must still cross the sustained threshold.
func TestEvaluate_WPProbeSustained_ColdScanner_Strikes(t *testing.T) {
	e := mustEngine(t)
	const host = "site.example"
	sample := make([]sdk.Event, 12)
	for i := range sample {
		sample[i] = wpEvent("200", "/wp-login.php", "", host)
	}
	agg := makeAgg(ip1, 3600*time.Second, sample)
	if !hasWPProbeSustained(e.Evaluate(context.Background(), agg)) {
		t.Fatal("sustained cold scanner must still trigger http_wp_probe_sustained")
	}
}

// TestValidateExclude rejects half-specified exclusion blocks at load time
// (fail-closed), mirroring the field/matcher pair check of issue #316.
func TestValidateExclude(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{
			name: "exclude without field",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    contains: wp-login
    exclude:
      contains_any: [wp-admin]
    window: 60s
    threshold: 3
    score: 80
    category: scanner`,
		},
		{
			name: "exclude without contains_any",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    contains: wp-login
    exclude:
      field: referer
    window: 60s
    threshold: 3
    score: 80
    category: scanner`,
		},
		{
			name: "exclude with empty substring",
			content: `rules:
  - name: test
    kinds: [http_request]
    field: path
    contains: wp-login
    exclude:
      field: referer
      contains_any: [""]
    window: 60s
    threshold: 3
    score: 80
    category: scanner`,
		},
		{
			name: "exclude on kind-only rule",
			content: `rules:
  - name: test
    kinds: [ssh_fail]
    exclude:
      field: referer
      contains_any: [wp-admin]
    window: 60s
    threshold: 3
    score: 80
    category: bruteforce`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(t.TempDir(), "rules.yaml")
			if err := os.WriteFile(tmp, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := rules.New(tmp, ""); err == nil {
				t.Errorf("expected validation error for %q", tc.name)
			}
		})
	}
}

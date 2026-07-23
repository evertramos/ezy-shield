package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// scriptedPrompter drives runCDNStep with a canned sequence of answers.
// asks/askBools are consumed in order; asking more than the script provides
// falls back to the default (matching the real closure behaviour when the
// input scanner is exhausted).
type scriptedPrompter struct {
	strings []string
	bools   []bool
	// asksSeen / boolsSeen are the prompt texts observed, in order, so
	// tests can assert wording.
	asksSeen  []string
	boolsSeen []string
}

func (s *scriptedPrompter) ask(q, def string) string {
	s.asksSeen = append(s.asksSeen, q)
	if len(s.strings) == 0 {
		return def
	}
	v := s.strings[0]
	s.strings = s.strings[1:]
	if v == "" {
		return def
	}
	return v
}

func (s *scriptedPrompter) askBool(q string, def bool) bool {
	s.boolsSeen = append(s.boolsSeen, q)
	if len(s.bools) == 0 {
		return def
	}
	v := s.bools[0]
	s.bools = s.bools[1:]
	return v
}

// httpFake is a cfClient implementation that returns canned responses.
//
// Since dryValidateCFToken now runs a two-phase probe (identity + scope),
// most tests need to serve more than one response per run. The fake
// supports two modes:
//
//   - Legacy single-response: set `status` + `bodyJSON`. Every Do() call
//     returns the same tuple. Kept so tests that don't care which endpoint
//     was hit (e.g. TransientError, where err is set) stay minimal.
//   - URL-routed: set `byPath` keyed on req.URL.Path. The fake looks up
//     the response by path; unknown paths return 404 so tests fail loudly
//     if the production code drifts to a new endpoint they didn't stub.
type httpFake struct {
	status   int
	bodyJSON string
	err      error
	byPath   map[string]httpFakeResp
	// byMethodPath routes on "METHOD /path" and wins over byPath — needed
	// when the same path must answer differently per verb (the issue #234
	// preflight GETs and POSTs /rules/lists).
	byMethodPath map[string]httpFakeResp
	// byPathQuery routes on "/path?rawquery" and wins over everything —
	// needed when the same path must answer differently per query (the
	// issue #121 paginated /zones enumeration).
	byPathQuery map[string]httpFakeResp
	// requests captures every Do() call for assertions on URL / headers.
	requests []*http.Request
}

// httpFakeResp is one canned response in the byPath map.
type httpFakeResp struct {
	status   int
	bodyJSON string
}

func (h *httpFake) Do(req *http.Request) (*http.Response, error) {
	h.requests = append(h.requests, req)
	if h.err != nil {
		return nil, h.err
	}
	if h.byPathQuery != nil {
		if r, ok := h.byPathQuery[req.URL.Path+"?"+req.URL.RawQuery]; ok {
			return &http.Response{
				StatusCode: r.status,
				Body:       io.NopCloser(bytes.NewBufferString(r.bodyJSON)),
				Header:     make(http.Header),
			}, nil
		}
	}
	if h.byMethodPath != nil {
		if r, ok := h.byMethodPath[req.Method+" "+req.URL.Path]; ok {
			return &http.Response{
				StatusCode: r.status,
				Body:       io.NopCloser(bytes.NewBufferString(r.bodyJSON)),
				Header:     make(http.Header),
			}, nil
		}
	}
	if h.byPath != nil {
		r, ok := h.byPath[req.URL.Path]
		if !ok {
			// Loud 404 with a body pointing at the unstubbed path so
			// the test failure names the endpoint the caller forgot.
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body: io.NopCloser(bytes.NewBufferString(
					`{"success":false,"errors":[{"code":7003,"message":"httpFake: no stub for ` + req.URL.Path + `"}]}`)),
				Header: make(http.Header),
			}, nil
		}
		return &http.Response{
			StatusCode: r.status,
			Body:       io.NopCloser(bytes.NewBufferString(r.bodyJSON)),
			Header:     make(http.Header),
		}, nil
	}
	return &http.Response{
		StatusCode: h.status,
		Body:       io.NopCloser(bytes.NewBufferString(h.bodyJSON)),
		Header:     make(http.Header),
	}, nil
}

// dockerFake supplies canned `docker ps` + `docker inspect` output for the
// CDN-detection step.
type dockerFake struct {
	ps      string
	psErr   error
	inspect map[string]string
}

func (d *dockerFake) Ps(_ context.Context, _ string) (string, error) {
	return d.ps, d.psErr
}
func (d *dockerFake) Inspect(_ context.Context, container, _ string) (string, error) {
	return d.inspect[container], nil
}

// resolverFake feeds cdndetect canned DNS answers.
type resolverFake struct {
	answers map[string][]netip.Addr
	errs    map[string]error
}

func (r *resolverFake) LookupNetIP(_ context.Context, _ /*network*/, host string) ([]netip.Addr, error) {
	if err, ok := r.errs[host]; ok {
		return nil, err
	}
	return r.answers[host], nil
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return a
}

// captureStep runs runCDNStep in a background writer and returns the printed
// output.
func captureStep(t *testing.T, fn func(w *wPrinter)) string {
	t.Helper()
	var buf bytes.Buffer
	p := &wPrinter{w: &buf}
	fn(p)
	return buf.String()
}

// ── Happy path: lists mode ────────────────────────────────────────────────────

func TestRunCDNStep_HappyPath_Lists(t *testing.T) {
	t.Parallel()

	// One nginx-proxy container with two vhosts, both CF-fronted.
	docker := &dockerFake{
		ps: strings.Join([]string{
			"nginx-proxy\tnginxproxy/nginx-proxy",
			"app\tcompany/app",
		}, "\n"),
		inspect: map[string]string{
			"nginx-proxy": "PATH=/usr/bin\n",
			"app":         "VIRTUAL_HOST=derrierelesfagots.be,shop.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"derrierelesfagots.be": {mustAddr(t, "104.21.13.183")},
			"shop.example.com":     {mustAddr(t, "172.67.132.246")},
		},
	}
	// Account-token happy path: identity probe hits the account verify
	// endpoint (200), then the scope probe hits rules/lists (200).
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rules/lists":   {status: 200, bodyJSON: `{"success":true,"result":[]}`},
		},
	}

	prompt := &scriptedPrompter{
		strings: []string{
			"lists",                            // mode
			"block",                            // action
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // account_id (32 hex)
			"ezyshield_blocked",                // list name
		},
		bools: []bool{
			true, // Configure the CF enforcer now?
		},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "cf-test-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if !step.cfEnabled {
		t.Fatalf("cfEnabled false; out=%q", out)
	}
	if len(step.cfAccounts) == 0 {
		t.Fatal("cfCfg nil despite cfEnabled")
	}
	if step.cfAccounts[0].cfg.Mode != "lists" {
		t.Errorf("mode=%q, want lists", step.cfAccounts[0].cfg.Mode)
	}
	if step.cfAccounts[0].cfg.AccountID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("account_id=%q", step.cfAccounts[0].cfg.AccountID)
	}
	if step.cfAccounts[0].cfg.ListName != "ezyshield_blocked" {
		t.Errorf("list_name=%q", step.cfAccounts[0].cfg.ListName)
	}
	if string(step.cfAccounts[0].cfg.APIToken) != "env:CLOUDFLARE_API_TOKEN" {
		t.Errorf("api_token=%q, want env:CLOUDFLARE_API_TOKEN", string(step.cfAccounts[0].cfg.APIToken))
	}
	if step.cfAccounts[0].tokenEnvVar != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("cfTokenEnvVar=%q", step.cfAccounts[0].tokenEnvVar)
	}
	if step.cfAccounts[0].wafRuleExpression != "(ip.src in $ezyshield_blocked)" {
		t.Errorf("waf rule = %q", step.cfAccounts[0].wafRuleExpression)
	}
	// The token itself must NEVER appear on stdout.
	if strings.Contains(out, "cf-test-token") {
		t.Errorf("wizard leaks the token on stdout: %q", out)
	}
	// The output must include the manual-step instruction for lists mode.
	if !strings.Contains(out, "Custom Rules") {
		t.Errorf("lists mode should print WAF rule instructions; out=%q", out)
	}
	// And it must include the exact rule expression.
	if !strings.Contains(out, "(ip.src in $ezyshield_blocked)") {
		t.Errorf("stdout missing WAF rule expression; out=%q", out)
	}
	// Two-phase probe: (1) account tokens/verify, (2) rules/lists?per_page=1.
	// No user/tokens/verify request should happen — the account verify
	// returned 200 on the first shot, so the fallback is skipped.
	if len(httpc.requests) != 4 {
		t.Fatalf("http calls=%d, want 4 (identity + scope + list find + list create); paths=%v",
			len(httpc.requests), reqPaths(httpc.requests))
	}
	if got := httpc.requests[0].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify" {
		t.Errorf("phase-1 URL path = %q", got)
	}
	if got := httpc.requests[1].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rules/lists" {
		t.Errorf("phase-2 URL path = %q", got)
	}
	if got := httpc.requests[1].URL.RawQuery; got != "per_page=1" {
		t.Errorf("phase-2 query = %q, want per_page=1", got)
	}
	// Issue #234 capability preflight: (3) find (GET per_page=100), then —
	// canned result is empty — (4) create (POST).
	if got := httpc.requests[2].Method; got != http.MethodGet {
		t.Errorf("preflight find method = %s, want GET", got)
	}
	if got := httpc.requests[2].URL.RawQuery; got != "per_page=100" {
		t.Errorf("preflight find query = %q, want per_page=100", got)
	}
	if got := httpc.requests[3].Method; got != http.MethodPost {
		t.Errorf("preflight create method = %s, want POST", got)
	}
	if !strings.Contains(out, `Created Custom IP List "ezyshield_blocked"`) {
		t.Errorf("stdout missing list-created line; out=%q", out)
	}
	if got := httpc.requests[0].Header.Get("Authorization"); got != "Bearer cf-test-token" {
		t.Errorf("auth header wrong: %q", got)
	}
	// The abort banner (#93) must NOT fire on the happy path — it exists
	// only to make silent bails visible.
	if strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner fired on happy path: %q", out)
	}
}

// reqPaths returns the URL paths from a captured request list — used in
// test failure messages so the reader sees which endpoints were hit.
func reqPaths(rs []*http.Request) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.URL.Path
	}
	return out
}

// ── Happy path: rulesets mode ────────────────────────────────────────────────

func TestRunCDNStep_HappyPath_Rulesets(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	// Rulesets mode never collects an account ID, so the identity probe
	// (Phase 1) is SKIPPED: /accounts//tokens/verify would be a broken
	// URL and /user/tokens/verify rejects account-owned (cfat_) tokens —
	// running it here would misreport valid tokens as expired. The scope
	// probe against the first zone's rulesets endpoint is the single
	// source of truth: 200 proves the token is both alive and scoped.
	// Only that route exists in the fake; any verify request would 404
	// and fail the exact-request-count assertion below.
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/zones/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/rulesets": {status: 200, bodyJSON: `{"success":true,"result":[]}`},
		},
	}

	prompt := &scriptedPrompter{
		strings: []string{
			"rulesets",  // mode
			"challenge", // action
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,cccccccccccccccccccccccccccccccc", // zone_ids
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "cf-tok-rs", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if !step.cfEnabled {
		t.Fatalf("cfEnabled false; out=%q", out)
	}
	if step.cfAccounts[0].cfg.Mode != "rulesets" {
		t.Errorf("mode=%q, want rulesets", step.cfAccounts[0].cfg.Mode)
	}
	if step.cfAccounts[0].cfg.Action != "challenge" {
		t.Errorf("action=%q", step.cfAccounts[0].cfg.Action)
	}
	if len(step.cfAccounts[0].cfg.ZoneIDs) != 2 {
		t.Fatalf("zone_ids len=%d, want 2", len(step.cfAccounts[0].cfg.ZoneIDs))
	}
	// Rulesets mode should NOT print WAF rule instructions.
	if strings.Contains(out, "Custom Rules") {
		t.Errorf("rulesets mode leaked lists-mode instructions: %q", out)
	}
	// Rulesets mode = scope probe ONLY: exactly one request, against
	// zones/{first_zone}/rulesets?per_page=1. No identity probe may run
	// (no account ID exists to verify against, and /user/tokens/verify
	// would falsely reject cfat_ account tokens).
	if len(httpc.requests) != 3 {
		t.Fatalf("http calls=%d, want 3 (scope probe + per-zone rule-count preflight); paths=%v",
			len(httpc.requests), reqPaths(httpc.requests))
	}
	for _, r := range httpc.requests {
		if strings.Contains(r.URL.Path, "/tokens/verify") {
			t.Errorf("identity probe ran in rulesets mode (no account ID available): %s", r.URL.Path)
		}
	}
	if got := httpc.requests[0].URL.Path; got != "/zones/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/rulesets" {
		t.Errorf("scope-probe URL path = %q (want /zones/{first_zone}/rulesets)", got)
	}
	if got := httpc.requests[0].URL.RawQuery; got != "per_page=1" {
		t.Errorf("scope-probe query = %q, want per_page=1", got)
	}
}

// ── Rulesets mode failure — scope probe rejects, message covers both causes ─

// TestRunCDNStep_Rulesets_TokenRejected covers the cfat_/rulesets edge
// case: with no account ID, the wizard cannot run an identity probe, so a
// 403 on the zone rulesets read is ambiguous — dead token OR missing
// Zone:Firewall Services:Edit. The message must name both possibilities
// (not just "lacks scope") and the abort banner must fire.
func TestRunCDNStep_Rulesets_TokenRejected(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/zones/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/rulesets": {
				status:   403,
				bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"insufficient permissions"}]}`,
			},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"rulesets", "block",
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "cfat_rejected-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite 403 on scope probe")
	}
	if len(step.cfAccounts) > 0 {
		t.Errorf("accounts were populated on failure: %+v", step.cfAccounts)
	}
	// No identity probe: rulesets mode has no account ID, and the user
	// verify endpoint rejects cfat_ tokens (the very bug this guards).
	for _, r := range httpc.requests {
		if strings.Contains(r.URL.Path, "/tokens/verify") {
			t.Errorf("identity probe ran in rulesets mode: %s", r.URL.Path)
		}
	}
	// Without an identity check the 403 is ambiguous — the message must
	// admit it could be a dead token, not blame only the scope.
	if !strings.Contains(out, "invalid, expired, or lacks scope") {
		t.Errorf("rulesets rejection message must cover dead-token AND scope: %q", out)
	}
	if !strings.Contains(out, "Zone:Firewall Services:Edit") {
		t.Errorf("wizard didn't tell the operator which scope to enable: %q", out)
	}
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing on rulesets token rejection: %q", out)
	}
	if strings.Contains(out, "cfat_rejected-token") {
		t.Error("token leaked on failure path")
	}
}

// ── Invalid / expired token — both verify endpoints reject ─────────────────

// TestRunCDNStep_InvalidToken_BothVerifyFail is the exact scenario the
// old dryValidateCFToken conflated with "wrong scope": every call to the
// CF API returns 401. Under the two-phase design, the identity probe
// hits BOTH /accounts/{id}/tokens/verify and /user/tokens/verify, and
// only when both reject does the wizard report the token as
// invalid/expired. The message must NOT falsely blame the scope — that's
// what the historical 403 on GET /accounts/{id} did.
func TestRunCDNStep_InvalidToken_BothVerifyFail(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	// Both verify endpoints reject. The scope probe is never reached.
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify": {
				status:   401,
				bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"Invalid API token"}]}`,
			},
			"/user/tokens/verify": {
				status:   401,
				bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"Invalid API token"}]}`,
			},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"ezyshield_blocked",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "expired-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite invalid token")
	}
	if len(step.cfAccounts) > 0 {
		t.Errorf("accounts were populated on failure: %+v", step.cfAccounts)
	}
	// Both verify endpoints must have been probed, in order.
	if len(httpc.requests) < 2 {
		t.Fatalf("expected >= 2 requests (account+user verify); got %d, paths=%v",
			len(httpc.requests), reqPaths(httpc.requests))
	}
	if got := httpc.requests[0].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify" {
		t.Errorf("first probe should be account verify, got %q", got)
	}
	if got := httpc.requests[1].URL.Path; got != "/user/tokens/verify" {
		t.Errorf("second probe should be user verify, got %q", got)
	}
	// The scope probe must NOT have been reached — Phase 2 is gated on
	// Phase 1 success.
	for _, r := range httpc.requests {
		if strings.HasSuffix(r.URL.Path, "/rules/lists") || strings.HasSuffix(r.URL.Path, "/rulesets") {
			t.Errorf("scope probe reached despite failed identity probe: %s", r.URL.Path)
		}
	}
	// The message must name the failure honestly — the historical
	// "token lacks scope" was a bug for this input.
	if !strings.Contains(out, "invalid, expired") {
		t.Errorf("invalid-token message missing 'invalid, expired': %q", out)
	}
	if strings.Contains(out, "token lacks scope") {
		t.Errorf("wizard blamed scope on an identity failure — regression on the original bug: %q", out)
	}
	// The loud-skip warning should still fire.
	if !strings.Contains(out, "CDN detected but no edge enforcer configured") {
		t.Errorf("loud-skip warning missing after CF setup failure: %q", out)
	}
	// Issue #93: the abort banner must ALSO fire.
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing after CF setup failure: %q", out)
	}
	// The token itself must NEVER appear.
	if strings.Contains(out, "expired-token") {
		t.Error("token leaked on failure path")
	}
}

// ── Wrong scope — identity OK, but Account Filter Lists is missing ─────────

// TestRunCDNStep_WrongScope_ListsForbidden is the case the original
// dryValidateCFToken pretended to test but couldn't distinguish from an
// invalid token. The identity probe succeeds (token is real and belongs
// to the account), then the rules/lists probe returns 403 because the
// operator forgot to add "Account Filter Lists:Edit" to the token.
// The scope-hint text must name that exact scope so the operator can fix
// it without hunting through CF docs.
func TestRunCDNStep_WrongScope_ListsForbidden(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify": {
				status: 200, bodyJSON: `{"success":true}`,
			},
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rules/lists": {
				status:   403,
				bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"insufficient permissions"}]}`,
			},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"ezyshield_blocked",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "narrow-scope-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite 403 wrong-scope")
	}
	if !strings.Contains(out, "token lacks scope") {
		t.Errorf("scope-mismatch message missing 'token lacks scope': %q", out)
	}
	if !strings.Contains(out, "403") {
		t.Errorf("scope-mismatch message missing HTTP 403: %q", out)
	}
	if !strings.Contains(out, "Account:Account Filter Lists:Edit") {
		t.Errorf("wizard didn't tell the operator which scope to enable: %q", out)
	}
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing on wrong-scope failure: %q", out)
	}
	if strings.Contains(out, "narrow-scope-token") {
		t.Error("token leaked on failure path")
	}
}

// ── User-owned token happy path (personal token) ───────────────────────────

// TestRunCDNStep_HappyPath_UserToken_Lists covers the class of tokens
// that live under a Cloudflare USER (personal API tokens), rather than
// under an account. The account verify endpoint rejects these ("token
// isn't a member of this account's token pool"), but the user verify
// endpoint accepts them, and if the user has been granted Account Filter
// Lists:Edit on the target account the scope probe succeeds. The bug
// this test guards against: the old validation used a single account
// endpoint that would 403 personal tokens even when they were perfectly
// configured.
func TestRunCDNStep_HappyPath_UserToken_Lists(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			// Account verify rejects — this token doesn't live in the
			// account's token pool.
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify": {
				status:   401,
				bodyJSON: `{"success":false,"errors":[{"code":1001,"message":"invalid API token for account"}]}`,
			},
			// User verify accepts — it's a personal token.
			"/user/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			// Scope probe succeeds — the operator granted Account
			// Filter Lists:Edit to the personal token.
			"/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rules/lists": {
				status: 200, bodyJSON: `{"success":true,"result":[]}`,
			},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"ezyshield_blocked",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    docker,
			Resolver:     resolver,
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "personal-cf-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if !step.cfEnabled {
		t.Fatalf("cfEnabled false on user-token happy path; out=%q", out)
	}
	if len(httpc.requests) != 5 {
		t.Fatalf("http calls=%d, want 5 (account verify + user verify + scope + list find + list create); paths=%v",
			len(httpc.requests), reqPaths(httpc.requests))
	}
	if got := httpc.requests[0].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/tokens/verify" {
		t.Errorf("phase-1a URL = %q", got)
	}
	if got := httpc.requests[1].URL.Path; got != "/user/tokens/verify" {
		t.Errorf("phase-1b URL = %q", got)
	}
	if got := httpc.requests[2].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/rules/lists" {
		t.Errorf("phase-2 URL = %q", got)
	}
	if strings.Contains(out, "personal-cf-token") {
		t.Error("token leaked on happy path")
	}
	if strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner fired on user-token happy path: %q", out)
	}
}

// ── Transient error (5xx) ────────────────────────────────────────────────────

func TestRunCDNStep_TransientError(t *testing.T) {
	t.Parallel()
	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	httpc := &httpFake{err: errors.New("dial tcp: i/o timeout")}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"ezyshield_blocked",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:   docker,
			Resolver:    resolver,
			HTTPClient:  httpc,
			TokenReader: func(string) (string, error) { return "ok-token", nil },
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite transient API error")
	}
	if !strings.Contains(out, "unreachable") {
		t.Errorf("transient-error message missing 'unreachable': %q", out)
	}
	// Issue #93: the abort banner must fire so the operator doesn't lose
	// the transient-error message under later wizard output.
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing after transient CF API error: %q", out)
	}
}

// ── Silent-bail scenarios (issue #93) ────────────────────────────────────────

// TestRunCDNStep_Issue93_InvalidAccountIDShowsBanner covers the specific
// path that produced the original bug report: the operator was prompted for
// the CF token and pasted it, but then hit ENTER (or a typo) at the
// account_id prompt. The single "must be 32 lowercase hex" line scrolled
// past under the later AI + systemd output, and config.yaml silently lacked
// enforce.cloudflare. The banner must fire so this can't happen again.
func TestRunCDNStep_Issue93_InvalidAccountIDShowsBanner(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists", // mode
			"block", // action
			"",      // account_id — operator hits ENTER
		},
		bools: []bool{true}, // "Configure the CF enforcer now?" → yes
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:   docker,
			Resolver:    resolver,
			TokenReader: func(string) (string, error) { return "opt-in-token", nil },
			// No HTTPClient — dry-validate should never be reached.
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite invalid account_id")
	}
	if !strings.Contains(out, "account_id must be 32 lowercase hex") {
		t.Errorf("per-line reason missing: %q", out)
	}
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing on invalid account_id: %q", out)
	}
	// The token itself must NEVER appear on stdout.
	if strings.Contains(out, "opt-in-token") {
		t.Error("token leaked on abort path")
	}
}

// TestRunCDNStep_Issue93_InvalidListNameShowsBanner covers the sibling
// silent-bail path: valid account_id but a list_name that fails the
// [A-Za-z0-9_]+ Cloudflare constraint.
func TestRunCDNStep_Issue93_InvalidListNameShowsBanner(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=one.example.com\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"one.example.com": {mustAddr(t, "104.21.13.183")},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists",
			"block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"has-dashes-not-allowed",
		},
		bools: []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:   docker,
			Resolver:    resolver,
			TokenReader: func(string) (string, error) { return "opt-in-token", nil },
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite invalid list_name")
	}
	if !strings.Contains(out, "list_name must match") {
		t.Errorf("per-line reason missing: %q", out)
	}
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing on invalid list_name: %q", out)
	}
}

// TestRunCDNStep_Issue93_GenericPathBailShowsBanner covers the path where
// no CDN was auto-detected (DNS didn't resolve to a known CF range, CF
// Tunnel, etc.) but the operator said "yes, this server IS behind a CDN"
// on the generic follow-up prompt and then bailed inside the subflow.
// printLoudSkipWarning is a no-op in this branch because there are no
// matched domains to warn about — so the new abort banner is the ONLY
// signal the operator has that config.yaml won't get the CF section.
func TestRunCDNStep_Issue93_GenericPathBailShowsBanner(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=behind-tunnel.example.com\n",
		},
	}
	// Resolves to a non-CF IP so no auto-detect matches.
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"behind-tunnel.example.com": {mustAddr(t, "203.0.113.4")},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{
			"lists",
			"block",
			"", // account_id → empty → subflow bails
		},
		bools: []bool{
			true, // "Does this server sit behind a CDN?" → yes (generic path)
		},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:   docker,
			Resolver:    resolver,
			TokenReader: func(string) (string, error) { return "opt-in-token", nil },
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite subflow bail")
	}
	// The domain-level loud-skip warning specifically MUST NOT fire here
	// (nothing to warn about), so the abort banner is our only defense.
	if strings.Contains(out, "CDN detected but no edge enforcer configured") {
		t.Errorf("domain-level loud-skip warning fired on no-detection path: %q", out)
	}
	if !strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner missing on generic-path silent bail: %q", out)
	}
}

// ── Loud-skip when user says no ──────────────────────────────────────────────

func TestRunCDNStep_LoudSkipWhenCDNDetected(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{
		ps: "app\tcompany/app",
		inspect: map[string]string{
			"app": "VIRTUAL_HOST=derrierelesfagots.be\n",
		},
	}
	resolver := &resolverFake{
		answers: map[string][]netip.Addr{
			"derrierelesfagots.be": {mustAddr(t, "104.21.13.183")},
		},
	}
	prompt := &scriptedPrompter{
		bools: []bool{false /* skip the CF setup */},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI: docker,
			Resolver:  resolver,
			// No HTTPClient/TokenReader — should never be called.
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite user skipping")
	}
	if !strings.Contains(out, "CDN detected but no edge enforcer configured") {
		t.Errorf("loud-skip warning missing: %q", out)
	}
	if !strings.Contains(out, "derrierelesfagots.be") {
		t.Errorf("loud-skip warning missing the detected domain: %q", out)
	}
	if !strings.Contains(out, "104.21.13.183") {
		t.Errorf("loud-skip warning missing the detected CDN IP: %q", out)
	}
	if !strings.Contains(out, "Cloudflare") {
		t.Errorf("loud-skip warning missing the provider name: %q", out)
	}
	// Issue #93: the abort banner exists to catch bail-outs mid-subflow,
	// NOT the "operator declined the CF setup" case. When the operator
	// explicitly said no, runCloudflareSubflow is never entered, so the
	// banner must stay silent.
	if strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner fired when operator declined CF setup: %q", out)
	}
}

// ── No vhosts + generic 'no CDN' answer ──────────────────────────────────────

func TestRunCDNStep_NoVHosts_NoLoudWarn(t *testing.T) {
	t.Parallel()

	docker := &dockerFake{ps: ""} // no containers → no vhosts
	prompt := &scriptedPrompter{bools: []bool{false}}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI: docker,
		})
	})
	if step.cfEnabled {
		t.Fatal("cfEnabled=true with no vhosts and no user opt-in")
	}
	// Because nothing matched, the loud warning must NOT fire.
	if strings.Contains(out, "CDN detected but no edge enforcer configured") {
		t.Errorf("loud warning fired without detection: %q", out)
	}
	// But the generic question MUST have been asked.
	if len(prompt.boolsSeen) == 0 || !strings.Contains(prompt.boolsSeen[0], "CDN") {
		t.Errorf("generic CDN question not asked: seen=%v", prompt.boolsSeen)
	}
}

// ── --yes mode short-circuits everything ─────────────────────────────────────

func TestRunCDNStep_YesModeSkipsWholeStep(t *testing.T) {
	t.Parallel()
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, &scriptedPrompter{}, step, cdnDeps{Yes: true})
	})
	if step.cfEnabled {
		t.Error("cfEnabled=true in --yes mode")
	}
	if !strings.Contains(out, "skipped (--yes mode)") {
		t.Errorf("--yes mode should announce the skip: %q", out)
	}
}

// ── Token env var naming — single vs multi-account ───────────────────────────

func TestCFEnvVarForName(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"", "CLOUDFLARE_API_TOKEN"},
		{"main", "CLOUDFLARE_API_TOKEN_MAIN"},
		{"client-a", "CLOUDFLARE_API_TOKEN_CLIENT_A"},
	}
	for _, tc := range cases {
		got := cfEnvVarForName(tc.in)
		if got != tc.want {
			t.Errorf("cfEnvVarForName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── emitCloudflareYAML produces valid, LoadConfig-parseable output ────────────

func TestEmitCloudflareYAML_LoadsBack(t *testing.T) {
	t.Parallel()
	step := &cdnStep{
		cfEnabled: true,
		cfAccounts: mustCFAccounts(t,
			"lists", "block",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ezyshield_blocked",
			nil),
	}
	body := renderTestConfig(t, step)

	if !strings.Contains(body, "cloudflare:") {
		t.Errorf("emitted yaml missing 'cloudflare:' header: %q", body)
	}
	if !strings.Contains(body, "api_token: env:CLOUDFLARE_API_TOKEN") {
		t.Errorf("api_token wrong: %q", body)
	}
	if !strings.Contains(body, "mode: lists") {
		t.Errorf("mode wrong: %q", body)
	}
	if !strings.Contains(body, "list_name: ezyshield_blocked") {
		t.Errorf("list_name wrong: %q", body)
	}
	// Round-trip via config.LoadConfigReader — this is the same check
	// writeGeneratedConfig runs before committing to disk.
	loadTestConfig(t, body)
}

// TestEmitCloudflareYAML_Rulesets asserts zone_ids are emitted as a sequence.
func TestEmitCloudflareYAML_Rulesets(t *testing.T) {
	t.Parallel()
	step := &cdnStep{
		cfEnabled: true,
		cfAccounts: mustCFAccounts(t,
			"rulesets", "block",
			"", "",
			[]string{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}),
	}
	body := renderTestConfig(t, step)

	if !strings.Contains(body, "zone_ids:") {
		t.Errorf("emitted yaml missing zone_ids: %q", body)
	}
	if !strings.Contains(body, "- bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Errorf("zone_id not emitted as list item: %q", body)
	}
	loadTestConfig(t, body)
}

// ── writeCloudflareEnvFile merges with an existing AI key ────────────────────

func TestWriteCloudflareEnvFile_PreservesAIKey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	envPath := filepath.Join(dir, envFileName)

	// Simulate the AI step running first.
	if err := writeEnvFileContent(envPath, "ANTHROPIC_API_KEY", "sk-ant-preexisting"); err != nil {
		t.Fatalf("prep: %v", err)
	}

	wrote, kept, err := writeCloudflareEnvFile(dir, "CLOUDFLARE_API_TOKEN", "cf-secret-xyz")
	if err != nil {
		t.Fatalf("writeCloudflareEnvFile: %v", err)
	}
	if !wrote || kept {
		t.Errorf("wrote=%v kept=%v, want wrote=true kept=false", wrote, kept)
	}

	data, err := os.ReadFile(envPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	if !strings.Contains(body, "ANTHROPIC_API_KEY=sk-ant-preexisting") {
		t.Errorf("AI key was clobbered by CF write: %q", body)
	}
	if !strings.Contains(body, "CLOUDFLARE_API_TOKEN=cf-secret-xyz") {
		t.Errorf("CF token not written: %q", body)
	}
	// Idempotency: re-writing the same value keeps it.
	wrote, kept, err = writeCloudflareEnvFile(dir, "CLOUDFLARE_API_TOKEN", "cf-secret-xyz")
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if wrote || !kept {
		t.Errorf("idempotent re-run wrote=%v kept=%v, want wrote=false kept=true", wrote, kept)
	}
	// File mode must be 0600.
	info, err := os.Stat(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file perms = %04o, want 0600", info.Mode().Perm())
	}
}

// ── Config emitter test helpers ──────────────────────────────────────────────

// mustCFAccounts wraps mustCFConfig into the one-account cfAccounts slice
// most emission tests need.
func mustCFAccounts(t *testing.T, mode, action, accountID, listName string, zoneIDs []string) []cfAccountSetup {
	t.Helper()
	return []cfAccountSetup{{ //nolint:gosec // G101: env-var NAME, not a credential value
		cfg:         *mustCFConfig(t, mode, action, accountID, listName, zoneIDs),
		tokenEnvVar: "CLOUDFLARE_API_TOKEN",
	}}
}

// mustCFConfig builds a *config.CloudflareCfg for the tests. APIToken is
// always the fixed env:CLOUDFLARE_API_TOKEN reference (matching what the
// wizard writes in the single-account happy path).
func mustCFConfig(t *testing.T, mode, action, accountID, listName string, zoneIDs []string) *config.CloudflareCfg {
	t.Helper()
	return &config.CloudflareCfg{ //nolint:gosec // G101: APIToken below is a SecretRef sentinel pointing at env var, not a secret value
		APIToken:  "env:CLOUDFLARE_API_TOKEN",
		Mode:      mode,
		Action:    action,
		AccountID: accountID,
		ListName:  listName,
		ZoneIDs:   zoneIDs,
	}
}

// renderTestConfig runs writeGeneratedConfig with a state wired to emit
// only the enforce.cloudflare block, then returns the file body for
// assertions.
func renderTestConfig(t *testing.T, step *cdnStep) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// The state needs only the fields writeGeneratedConfig actually
	// reads. nftPath is empty so only cloudflare is emitted.
	state := &wizardState{cdn: step}
	if err := writeGeneratedConfig(cfgPath, state); err != nil {
		t.Fatalf("writeGeneratedConfig: %v", err)
	}
	b, err := os.ReadFile(cfgPath) //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// loadTestConfig runs the yaml through the same strict loader
// writeGeneratedConfig uses. Failing here means the emitter has drifted
// from the schema.
func loadTestConfig(t *testing.T, body string) {
	t.Helper()
	if _, err := config.LoadConfigReader(strings.NewReader(body), "test"); err != nil {
		t.Fatalf("emitted config failed re-load: %v\nbody=%s", err, body)
	}
}

// ── Multi-account support (issue #217) ───────────────────────────────────────

// multiAccountHTTPFake stubs both a lists-mode account (verify + scope +
// preflight create-or-adopt) and a rulesets-mode account (zone rulesets).
func multiAccountHTTPFake(accountID, zoneID string) *httpFake {
	return &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + accountID + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/" + accountID + "/rules/lists":   {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"/zones/" + zoneID + "/rulesets":            {status: 200, bodyJSON: `{"success":true,"result":[]}`},
		},
	}
}

// seqTokenReader returns a TokenReader that hands out one token per call so
// multi-account tests can prove each account keeps its own secret.
func seqTokenReader(t *testing.T, tokens ...string) func(string) (string, error) {
	t.Helper()
	i := 0
	return func(string) (string, error) {
		if i >= len(tokens) {
			t.Fatalf("token reader called %d times, only %d tokens scripted", i+1, len(tokens))
		}
		tok := tokens[i]
		i++
		return tok, nil
	}
}

// TestRunCDNStep_MultiAccount drives the issue #217 happy path: a lists-mode
// account followed by a rulesets-mode account for a second Cloudflare account
// (e.g. another client). The first account gets named when the second is
// added; each account keeps its own token env var.
func TestRunCDNStep_MultiAccount(t *testing.T) {
	t.Parallel()
	const acctID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const zoneID = "dddddddddddddddddddddddddddddddd"

	prompt := &scriptedPrompter{
		strings: []string{
			// account 1 (no name prompt on the first account)
			"lists", "block", acctID, "ezyshield_blocked",
			"", // zone coverage: ENTER = manual setup (issue #121)
			// "add another?" = yes → name for the first account
			"main",
			// account 2: name, mode, action, zone_ids
			"client_b", "rulesets", "challenge", zoneID,
		},
		bools: []bool{
			true, // Does this server sit behind a CDN?
			true, // Add another Cloudflare account?
			// exhausted → default false: stop after the second account
		},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    &dockerFake{},
			HTTPClient:   multiAccountHTTPFake(acctID, zoneID),
			TokenReader:  seqTokenReader(t, "cf-tok-main-secret", "cf-tok-clientb-secret"),
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if !step.cfEnabled {
		t.Fatalf("cfEnabled false; out=%q", out)
	}
	if len(step.cfAccounts) != 2 {
		t.Fatalf("accounts = %d, want 2; out=%q", len(step.cfAccounts), out)
	}
	first, second := step.cfAccounts[0], step.cfAccounts[1]
	if first.cfg.Name != "main" || first.cfg.Mode != "lists" {
		t.Errorf("first account = %+v, want name=main mode=lists", first.cfg)
	}
	if first.tokenEnvVar != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("first env var = %q (naming the first account later must not change its env var)", first.tokenEnvVar)
	}
	if second.cfg.Name != "client_b" || second.cfg.Mode != "rulesets" || second.cfg.Action != "challenge" {
		t.Errorf("second account = %+v", second.cfg)
	}
	if second.tokenEnvVar != "CLOUDFLARE_API_TOKEN_CLIENT_B" {
		t.Errorf("second env var = %q, want CLOUDFLARE_API_TOKEN_CLIENT_B", second.tokenEnvVar)
	}
	if string(second.cfg.APIToken) != "env:CLOUDFLARE_API_TOKEN_CLIENT_B" {
		t.Errorf("second api_token ref = %q", string(second.cfg.APIToken))
	}
	if first.token != "cf-tok-main-secret" || second.token != "cf-tok-clientb-secret" {
		t.Errorf("tokens crossed accounts: %q / %q", first.token, second.token)
	}
	// Secret discipline: neither token on stdout, and String() redacts both.
	for _, tok := range []string{"cf-tok-main-secret", "cf-tok-clientb-secret"} {
		if strings.Contains(out, tok) {
			t.Errorf("wizard leaked token %q on stdout", tok)
		}
		if strings.Contains(step.String(), tok) {
			t.Errorf("cdnStep.String() leaked token %q: %s", tok, step.String())
		}
	}
	// The generated YAML must be a two-entry sequence the strict loader accepts.
	body := renderTestConfig(t, step)
	if !strings.Contains(body, "- name: main") || !strings.Contains(body, "- name: client_b") {
		t.Errorf("yaml missing sequence entries:\n%s", body)
	}
	cfg, err := config.LoadConfigReader(strings.NewReader(body), "test")
	if err != nil {
		t.Fatalf("emitted config failed re-load: %v\nbody=%s", err, body)
	}
	if n := len(cfg.Enforce.Cloudflare); n != 2 {
		t.Fatalf("loaded accounts = %d, want 2", n)
	}
}

// TestRunCDNStep_MultiAccount_SecondFails: an invalid second account must not
// take down the first — the wizard keeps what was already validated and says
// so, and the abort banner must NOT fire (something WAS configured).
func TestRunCDNStep_MultiAccount_SecondFails(t *testing.T) {
	t.Parallel()
	const acctID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block", acctID, "ezyshield_blocked",
			"",         // zone coverage: ENTER = manual setup
			"main",     // name for the first account
			"client_b", // second account name
			"rulesets", "block",
			"not-a-zone-id", // invalid → second account fails
		},
		bools: []bool{true, true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    &dockerFake{},
			HTTPClient:   multiAccountHTTPFake(acctID, "unused"),
			TokenReader:  seqTokenReader(t, "cf-tok-1", "cf-tok-2"),
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if !step.cfEnabled {
		t.Fatalf("cfEnabled false — first account must survive; out=%q", out)
	}
	if len(step.cfAccounts) != 1 {
		t.Fatalf("accounts = %d, want 1 (second failed); out=%q", len(step.cfAccounts), out)
	}
	if step.cfAccounts[0].cfg.Name != "main" {
		t.Errorf("surviving account = %+v", step.cfAccounts[0].cfg)
	}
	if !strings.Contains(out, "This account was NOT added") {
		t.Errorf("missing loud partial-failure line; out=%q", out)
	}
	if strings.Contains(out, "Cloudflare enforcer setup did NOT complete") {
		t.Errorf("abort banner fired although the first account succeeded: %q", out)
	}
}

// TestRunCDNStep_MultiAccount_DuplicateNameRejected: the second account may
// not reuse a session name.
func TestRunCDNStep_MultiAccount_DuplicateNameRejected(t *testing.T) {
	t.Parallel()
	const acctID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	prompt := &scriptedPrompter{
		strings: []string{
			"lists", "block", acctID, "ezyshield_blocked",
			"",     // zone coverage: ENTER = manual setup
			"main", // name for the first account
			"main", // duplicate name for the second → rejected
		},
		bools: []bool{true, true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    &dockerFake{},
			HTTPClient:   multiAccountHTTPFake(acctID, "unused"),
			TokenReader:  seqTokenReader(t, "cf-tok-1", "cf-tok-2"),
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if len(step.cfAccounts) != 1 {
		t.Fatalf("accounts = %d, want 1; out=%q", len(step.cfAccounts), out)
	}
	if !strings.Contains(out, `already used in this run`) {
		t.Errorf("missing duplicate-name rejection; out=%q", out)
	}
}

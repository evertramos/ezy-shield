// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the zone-coverage prompt + WAF rule rollout (issue #121).

import (
	"context"
	"strings"
	"testing"
)

const (
	zcAcct  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	zcZone1 = "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1"
	zcZone2 = "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2"
	zcZone3 = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3"
)

// zcBaseStubs returns the token-validation + list-preflight stubs every
// lists-mode run needs.
func zcBaseStubs() map[string]httpFakeResp {
	return map[string]httpFakeResp{
		"/accounts/" + zcAcct + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
		"/accounts/" + zcAcct + "/rules/lists":   {status: 200, bodyJSON: `{"success":true,"result":[]}`},
	}
}

// zcRunLists drives a lists-mode CDN step with the given coverage answer.
func zcRunLists(t *testing.T, httpc *httpFake, coverageAnswer string) (*cdnStep, string) {
	t.Helper()
	prompt := &scriptedPrompter{
		strings: []string{"lists", "block", zcAcct, "ezyshield_blocked", coverageAnswer},
		bools:   []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    &dockerFake{},
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "cf-zc-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})
	return step, out
}

// TestRunCDNStep_Lists_ZoneCoverageAll: answering 'all' enumerates the
// paginated /zones endpoint, persists the snapshot into zone_ids, and rolls
// the WAF rule out per zone — creating where absent, adopting where an
// ezyshield rule already exists. Zone names from the API are sanitized.
func TestRunCDNStep_Lists_ZoneCoverageAll(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byPath: zcBaseStubs(),
		byPathQuery: map[string]httpFakeResp{
			// Two pages prove pagination is followed. Page 2 carries a
			// hostile zone name with an embedded ESC (JSON  escape).
			"/zones?account.id=" + zcAcct + "&per_page=50&page=1": {status: 200, bodyJSON: `{"success":true,"result":[{"id":"` + zcZone1 + `","name":"one.example.com"}],"result_info":{"page":1,"total_pages":2}}`},
			"/zones?account.id=" + zcAcct + "&per_page=50&page=2": {status: 200, bodyJSON: `{"success":true,"result":[{"id":"` + zcZone2 + `","name":"two.example\u001b[31m.com"}],"result_info":{"page":2,"total_pages":2}}`},
		},
		byMethodPath: map[string]httpFakeResp{
			// zone1: no ruleset yet → wizard creates ruleset+rule.
			"GET /zones/" + zcZone1 + "/rulesets":  {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"POST /zones/" + zcZone1 + "/rulesets": {status: 200, bodyJSON: `{"success":true,"result":{"id":"rs1","rules":[{"id":"r1"}]}}`},
			// zone2: ruleset exists and already carries the ezyshield rule.
			"GET /zones/" + zcZone2 + "/rulesets":     {status: 200, bodyJSON: `{"success":true,"result":[{"id":"rs2","phase":"http_request_firewall_custom"}]}`},
			"GET /zones/" + zcZone2 + "/rulesets/rs2": {status: 200, bodyJSON: `{"success":true,"result":{"rules":[{"id":"r9","description":"ezyshield-list-block"}]}}`},
		},
	}

	step, out := zcRunLists(t, httpc, "all")

	if !step.cfEnabled || len(step.cfAccounts) != 1 {
		t.Fatalf("accounts=%d cfEnabled=%v; out=%q", len(step.cfAccounts), step.cfEnabled, out)
	}
	cfg := step.cfAccounts[0].cfg
	if len(cfg.ZoneIDs) != 2 || cfg.ZoneIDs[0] != zcZone1 || cfg.ZoneIDs[1] != zcZone2 {
		t.Errorf("zone_ids = %v, want the enumerated snapshot", cfg.ZoneIDs)
	}
	if !strings.Contains(out, zcZone1+" (one.example.com) — configured") {
		t.Errorf("missing 'configured' report line; out=%q", out)
	}
	if !strings.Contains(out, "— already present") {
		t.Errorf("missing 'already present' report line; out=%q", out)
	}
	// Hostile zone name: the ESC byte must not survive into the terminal.
	if strings.Contains(out, "\x1b") {
		t.Errorf("unsanitized control char in output: %q", out)
	}
	// With zones configured automatically, the generic manual block is gone.
	if strings.Contains(out, "one-time manual step") {
		t.Errorf("manual instructions printed although zones were configured; out=%q", out)
	}
	if strings.Contains(out, "cf-zc-token") {
		t.Errorf("token leaked on stdout: %q", out)
	}
	// The generated YAML persists zone_ids and round-trips the strict loader.
	body := renderTestConfig(t, step)
	if !strings.Contains(body, "- "+zcZone1) || !strings.Contains(body, "- "+zcZone2) {
		t.Errorf("zone_ids not emitted:\n%s", body)
	}
	loadTestConfig(t, body)
}

// TestRunCDNStep_Lists_ZoneCoverageExplicit: explicit IDs are used verbatim
// (no enumeration call), a failing zone is loud, gets scoped manual
// instructions, and still persists — the enforcer retries it at sync.
func TestRunCDNStep_Lists_ZoneCoverageExplicit(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byPath: zcBaseStubs(),
		byMethodPath: map[string]httpFakeResp{
			"GET /zones/" + zcZone1 + "/rulesets":  {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"POST /zones/" + zcZone1 + "/rulesets": {status: 200, bodyJSON: `{"success":true,"result":{"id":"rs1","rules":[{"id":"r1"}]}}`},
			"GET /zones/" + zcZone3 + "/rulesets":  {status: 403, bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`},
		},
	}

	step, out := zcRunLists(t, httpc, zcZone1+","+zcZone3)

	if !step.cfEnabled || len(step.cfAccounts) != 1 {
		t.Fatalf("accounts=%d; out=%q", len(step.cfAccounts), out)
	}
	cfg := step.cfAccounts[0].cfg
	if len(cfg.ZoneIDs) != 2 {
		t.Fatalf("zone_ids = %v, want both explicit zones persisted", cfg.ZoneIDs)
	}
	for _, r := range httpc.requests {
		if r.URL.Path == "/zones" {
			t.Errorf("explicit IDs must not trigger enumeration, but /zones was called")
		}
	}
	if !strings.Contains(out, zcZone1+" — configured") {
		t.Errorf("missing configured line; out=%q", out)
	}
	if !strings.Contains(out, "FAILED") || !strings.Contains(out, "HTTP 403: Authentication error") {
		t.Errorf("missing per-zone failure line; out=%q", out)
	}
	if !strings.Contains(out, "could not be configured automatically") ||
		!strings.Contains(out, "• zone "+zcZone3) {
		t.Errorf("missing scoped manual instructions for the failed zone; out=%q", out)
	}
}

// TestRunCDNStep_Lists_ZoneEnumerationFails: when the token cannot list
// zones (missing Zone Read scope), the wizard degrades to today's manual
// path — the account still succeeds, zone_ids stays empty, and the message
// names the missing scope.
func TestRunCDNStep_Lists_ZoneEnumerationFails(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byPath: zcBaseStubs(),
		byPathQuery: map[string]httpFakeResp{
			"/zones?account.id=" + zcAcct + "&per_page=50&page=1": {status: 403, bodyJSON: `{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}]}`},
		},
	}

	step, out := zcRunLists(t, httpc, "all")

	if !step.cfEnabled || len(step.cfAccounts) != 1 {
		t.Fatalf("account must still succeed on enumeration failure; out=%q", out)
	}
	if len(step.cfAccounts[0].cfg.ZoneIDs) != 0 {
		t.Errorf("zone_ids must stay empty on degrade: %v", step.cfAccounts[0].cfg.ZoneIDs)
	}
	if !strings.Contains(out, "could not enumerate zones") ||
		!strings.Contains(out, "Zone:Zone:Read") {
		t.Errorf("missing degrade message naming the scope; out=%q", out)
	}
	// Manual instructions come back on the degrade path.
	if !strings.Contains(out, "one-time manual step") {
		t.Errorf("manual instructions absent on degrade path; out=%q", out)
	}
	// Abort banner must NOT fire — the account was configured.
	if strings.Contains(out, "setup did NOT complete") {
		t.Errorf("abort banner fired on degrade path; out=%q", out)
	}
}

// TestRunCDNStep_Lists_ZoneCoverageInvalidID: a malformed explicit zone ID
// fails this account (same policy as the rulesets zone prompt).
// TestRunCDNStep_Lists_ZoneCoverageInvalidID (issue #489 semantics): a
// malformed zone answer no longer discards the freshly-validated account —
// the prompt re-prompts (the exhausted script answers ENTER) and the setup
// completes on the manual-zones path.
func TestRunCDNStep_Lists_ZoneCoverageInvalidID(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{byPath: zcBaseStubs()}

	step, out := zcRunLists(t, httpc, "not-a-zone")

	if !strings.Contains(out, `zone_id "not-a-zone" is not 32 hex chars`) {
		t.Errorf("missing validation message; out=%q", out)
	}
	if !step.cfEnabled || len(step.cfAccounts) != 1 {
		t.Fatalf("account must SURVIVE a malformed zone answer (manual fallback, issue #489); out=%q", out)
	}
	if len(step.cfAccounts[0].cfg.ZoneIDs) != 0 {
		t.Errorf("manual fallback must not persist zone_ids, got %v", step.cfAccounts[0].cfg.ZoneIDs)
	}
}

// TestPromptCFZoneCoverage pins the issue #489 input normalization: the
// prompt's own text displays 'all' quoted, so quoted answers must work.
func TestPromptCFZoneCoverage(t *testing.T) {
	t.Parallel()
	zone := zcZone1

	tests := []struct {
		name    string
		answers []string
		wantAll bool
		wantIDs []string
	}{
		{"bare all", []string{"all"}, true, nil},
		{"quoted all — the exact field input", []string{"'all'"}, true, nil},
		{"double-quoted uppercase", []string{`"ALL"`}, true, nil},
		{"quoted zone id", []string{"'" + zone + "'"}, false, []string{zone}},
		{"invalid then valid re-prompt", []string{"not-a-zone", "all"}, true, nil},
		{"three invalid answers fall back to manual", []string{"x", "y", "z"}, false, nil},
		{"enter keeps manual", []string{""}, false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pr := &scriptedPrompter{strings: tt.answers}
			var cov cfZoneCoverage
			_ = captureStep(t, func(p *wPrinter) {
				cov = promptCFZoneCoverage(p, pr)
			})
			if cov.all != tt.wantAll {
				t.Errorf("all = %v, want %v", cov.all, tt.wantAll)
			}
			if len(cov.ids) != len(tt.wantIDs) {
				t.Fatalf("ids = %v, want %v", cov.ids, tt.wantIDs)
			}
			for i := range tt.wantIDs {
				if cov.ids[i] != tt.wantIDs[i] {
					t.Errorf("ids = %v, want %v", cov.ids, tt.wantIDs)
				}
			}
		})
	}
}

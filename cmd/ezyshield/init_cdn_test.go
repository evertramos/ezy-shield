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

// httpFake is a cfClient implementation that returns a canned response.
type httpFake struct {
	status   int
	bodyJSON string
	err      error
	// requests captures every Do() call for assertions on URL / headers.
	requests []*http.Request
}

func (h *httpFake) Do(req *http.Request) (*http.Response, error) {
	h.requests = append(h.requests, req)
	if h.err != nil {
		return nil, h.err
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
	httpc := &httpFake{status: 200, bodyJSON: `{"success":true}`}

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
	if step.cfCfg == nil {
		t.Fatal("cfCfg nil despite cfEnabled")
	}
	if step.cfCfg.Mode != "lists" {
		t.Errorf("mode=%q, want lists", step.cfCfg.Mode)
	}
	if step.cfCfg.AccountID != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("account_id=%q", step.cfCfg.AccountID)
	}
	if step.cfCfg.ListName != "ezyshield_blocked" {
		t.Errorf("list_name=%q", step.cfCfg.ListName)
	}
	if string(step.cfCfg.APIToken) != "env:CLOUDFLARE_API_TOKEN" {
		t.Errorf("api_token=%q, want env:CLOUDFLARE_API_TOKEN", string(step.cfCfg.APIToken))
	}
	if step.cfTokenEnvVar != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("cfTokenEnvVar=%q", step.cfTokenEnvVar)
	}
	if step.cfWAFRuleExpression != "(ip.src in $ezyshield_blocked)" {
		t.Errorf("waf rule = %q", step.cfWAFRuleExpression)
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
	// Validation call must have hit /accounts/<id>.
	if len(httpc.requests) != 1 {
		t.Fatalf("http calls=%d, want 1", len(httpc.requests))
	}
	if got := httpc.requests[0].URL.Path; got != "/accounts/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("validation URL path = %q", got)
	}
	if got := httpc.requests[0].Header.Get("Authorization"); got != "Bearer cf-test-token" {
		t.Errorf("auth header wrong: %q", got)
	}
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
	httpc := &httpFake{status: 200, bodyJSON: `{"success":true}`}

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
	if step.cfCfg.Mode != "rulesets" {
		t.Errorf("mode=%q, want rulesets", step.cfCfg.Mode)
	}
	if step.cfCfg.Action != "challenge" {
		t.Errorf("action=%q", step.cfCfg.Action)
	}
	if len(step.cfCfg.ZoneIDs) != 2 {
		t.Fatalf("zone_ids len=%d, want 2", len(step.cfCfg.ZoneIDs))
	}
	// Rulesets mode should NOT print WAF rule instructions.
	if strings.Contains(out, "Custom Rules") {
		t.Errorf("rulesets mode leaked lists-mode instructions: %q", out)
	}
	// Validation hit the first zone.
	if got := httpc.requests[0].URL.Path; got != "/zones/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("validation URL path = %q", got)
	}
}

// ── Scope mismatch (401) ─────────────────────────────────────────────────────

func TestRunCDNStep_ScopeMismatch401(t *testing.T) {
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
		status:   401,
		bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"Invalid API token"}]}`,
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
			TokenReader:  func(string) (string, error) { return "bad-scope-token", nil },
			CFAPIBaseURL: "http://cf.example",
		})
	})

	if step.cfEnabled {
		t.Fatal("cfEnabled=true despite 401 scope mismatch")
	}
	if step.cfCfg != nil {
		t.Errorf("cfCfg was populated on failure: %+v", step.cfCfg)
	}
	if !strings.Contains(out, "scope") {
		t.Errorf("scope-mismatch message missing 'scope': %q", out)
	}
	if !strings.Contains(out, "401") {
		t.Errorf("scope-mismatch message missing HTTP 401: %q", out)
	}
	if !strings.Contains(out, "Account:Account Filter Lists:Edit") {
		t.Errorf("wizard didn't tell the operator which scope to enable: %q", out)
	}
	// The loud-skip warning should also fire.
	if !strings.Contains(out, "CDN detected but no edge enforcer configured") {
		t.Errorf("loud-skip warning missing after CF setup failure: %q", out)
	}
	// The token itself must NEVER appear.
	if strings.Contains(out, "bad-scope-token") {
		t.Error("token leaked on failure path")
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
		cfCfg: mustCFConfig(t,
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
		cfCfg: mustCFConfig(t,
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

// mustCFConfig builds a *config.CloudflareCfg for the tests. APIToken is
// always the fixed env:CLOUDFLARE_API_TOKEN reference (matching what the
// wizard writes in the single-account happy path).
func mustCFConfig(t *testing.T, mode, action, accountID, listName string, zoneIDs []string) *config.CloudflareCfg {
	t.Helper()
	return &config.CloudflareCfg{
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

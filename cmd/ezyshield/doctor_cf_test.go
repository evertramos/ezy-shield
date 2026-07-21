package main

// Tests for doctor's Cloudflare enforcer checks (issue #234) — the
// post-setup guard against configurations that stopped working: deleted
// list, rotated/expired token, quota consumed elsewhere.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

func doctorCFCfg(t *testing.T, mode string) *config.CloudflareCfg {
	t.Helper()
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-doctor-token")
	cfg := &config.CloudflareCfg{
		APIToken: config.SecretRef("env:CLOUDFLARE_API_TOKEN"),
		Mode:     mode,
	}
	switch mode {
	case "lists", "":
		cfg.AccountID = tAccount
		cfg.ListName = "ezyshield_blocked"
	case "rulesets":
		cfg.ZoneIDs = []string{tZone}
	}
	return cfg
}

func resultByName(results []CheckResult, name string) *CheckResult {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func TestCheckOneCloudflare_ListsHealthy(t *testing.T) {
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + tAccount + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":[
				{"id":"l1","name":"ezyshield_blocked","kind":"ip","num_items":128}]}`},
		},
	}
	results := checkOneCloudflare(context.Background(), httpc, tBase, t.TempDir(), doctorCFCfg(t, "lists"))

	for _, name := range []string{
		"cloudflare: token resolves",
		"cloudflare: token valid + scoped",
		"cloudflare: custom list",
	} {
		r := resultByName(results, name)
		if r == nil {
			t.Fatalf("missing check %q in %+v", name, results)
		}
		if r.Status != statusPass {
			t.Errorf("%s = %s (hint: %s), want PASS", name, r.Status, r.Hint)
		}
	}
	if r := resultByName(results, "cloudflare: custom list"); !strings.Contains(r.Hint, "128 item(s)") {
		t.Errorf("custom list hint should report item count, got %q", r.Hint)
	}
}

func TestCheckOneCloudflare_ListDeleted(t *testing.T) {
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + tAccount + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/" + tAccount + "/rules/lists":   {status: 200, bodyJSON: `{"success":true,"result":[]}`},
		},
	}
	results := checkOneCloudflare(context.Background(), httpc, tBase, t.TempDir(), doctorCFCfg(t, "lists"))

	r := resultByName(results, "cloudflare: custom list")
	if r == nil || r.Status != statusFail {
		t.Fatalf("custom list check = %+v, want FAIL", r)
	}
	for _, want := range []string{"not found", "quota", "single custom list"} {
		if !strings.Contains(r.Hint, want) {
			t.Errorf("hint missing %q: %q", want, r.Hint)
		}
	}
}

func TestCheckOneCloudflare_ExpiredToken(t *testing.T) {
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + tAccount + "/tokens/verify": {status: 401, bodyJSON: `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`},
			"/user/tokens/verify":                      {status: 401, bodyJSON: `{"success":false,"errors":[{"code":1000,"message":"Invalid API Token"}]}`},
		},
	}
	results := checkOneCloudflare(context.Background(), httpc, tBase, t.TempDir(), doctorCFCfg(t, "lists"))

	r := resultByName(results, "cloudflare: token valid + scoped")
	if r == nil || r.Status != statusFail {
		t.Fatalf("token check = %+v, want FAIL", r)
	}
	// The doctor must stop after a dead token — no list check can be
	// meaningful without one.
	if resultByName(results, "cloudflare: custom list") != nil {
		t.Errorf("list check ran despite dead token: %+v", results)
	}
}

func TestCheckOneCloudflare_RulesetsCounts(t *testing.T) {
	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/zones/" + tZone + "/rulesets": {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"/zones/" + tZone + "/rulesets/phases/http_request_firewall_custom/entrypoint": {
				status: 200, bodyJSON: `{"success":true,"result":{"rules":[{"id":"a"},{"id":"b"}]}}`},
		},
	}
	results := checkOneCloudflare(context.Background(), httpc, tBase, t.TempDir(), doctorCFCfg(t, "rulesets"))

	r := resultByName(results, "cloudflare: zone "+tZone)
	if r == nil || r.Status != statusPass {
		t.Fatalf("zone check = %+v, want PASS", r)
	}
	if !strings.Contains(r.Hint, "2 WAF custom rule(s) in use") {
		t.Errorf("zone hint should report rule count, got %q", r.Hint)
	}
}

func TestCheckOneCloudflare_TokenFromEnvFile(t *testing.T) {
	// The doctor CLI usually runs without the daemon's EnvironmentFile in
	// its process env; the token must be picked up from <configDir>/.env.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, envFileName), []byte("CLOUDFLARE_API_TOKEN=from-env-file\n"), 0o600); err != nil {
		t.Fatalf("writing env file: %v", err)
	}

	httpc := &httpFake{
		byPath: map[string]httpFakeResp{
			"/accounts/" + tAccount + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			"/accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":[
				{"id":"l1","name":"ezyshield_blocked","kind":"ip","num_items":1}]}`},
		},
	}
	cfg := &config.CloudflareCfg{
		APIToken:  config.SecretRef("env:CLOUDFLARE_API_TOKEN"),
		Mode:      "lists",
		AccountID: tAccount,
		ListName:  "ezyshield_blocked",
	}
	// Deliberately NOT setting the env var.
	results := checkOneCloudflare(context.Background(), httpc, tBase, dir, cfg)

	r := resultByName(results, "cloudflare: token resolves")
	if r == nil || r.Status != statusPass {
		t.Fatalf("token resolves = %+v, want PASS via env-file fallback", r)
	}
	// And the fallback token must actually be used on the wire.
	if len(httpc.requests) == 0 || httpc.requests[0].Header.Get("Authorization") != "Bearer from-env-file" {
		t.Errorf("env-file token not used in Authorization header")
	}
}

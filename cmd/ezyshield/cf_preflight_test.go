package main

// Tests for the Cloudflare capability preflight (issue #234). The canonical
// scenario: a free-plan account whose single custom-list slot is already
// taken — the create must fail AT SETUP TIME with the plan explanation, and
// the wizard must refuse to write the config.

import (
	"context"
	"strings"
	"testing"
)

const (
	tAccount = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	tZone    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tBase    = "http://cf.example"
)

func TestCFEnsureList_AdoptsExisting(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byMethodPath: map[string]httpFakeResp{
			"GET /accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":[
				{"id":"list1","name":"other_list","kind":"ip","num_items":3},
				{"id":"list2","name":"ezyshield_blocked","kind":"ip","num_items":42}]}`},
		},
	}
	res, err := cfEnsureList(context.Background(), httpc, tBase, tAccount, "ezyshield_blocked", "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Adopted || res.Items != 42 {
		t.Errorf("res=%+v, want Adopted=true Items=42", res)
	}
	// Adoption must not attempt a create.
	for _, r := range httpc.requests {
		if r.Method == "POST" {
			t.Errorf("adopt path issued a POST create")
		}
	}
}

func TestCFEnsureList_CreatesWhenAbsent(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byMethodPath: map[string]httpFakeResp{
			"GET /accounts/" + tAccount + "/rules/lists":  {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"POST /accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":{"id":"new1","name":"ezyshield_blocked"}}`},
		},
	}
	res, err := cfEnsureList(context.Background(), httpc, tBase, tAccount, "ezyshield_blocked", "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Adopted {
		t.Errorf("res=%+v, want a fresh create (Adopted=false)", res)
	}
}

func TestCFEnsureList_QuotaExceeded(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byMethodPath: map[string]httpFakeResp{
			"GET /accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"POST /accounts/" + tAccount + "/rules/lists": {status: 403, bodyJSON: `{"success":false,"errors":[
				{"code":10038,"message":"exceeded maximum number of lists allowed for the account"}]}`},
		},
	}
	res, err := cfEnsureList(context.Background(), httpc, tBase, tAccount, "ezyshield_blocked", "tok")
	if err == nil {
		t.Fatal("want error on quota refusal")
	}
	if !res.QuotaExceeded {
		t.Errorf("QuotaExceeded=false; err=%v", err)
	}
	if !strings.Contains(err.Error(), "10038") || !strings.Contains(err.Error(), "exceeded maximum") {
		t.Errorf("error should keep raw code+message greppable: %v", err)
	}
}

func TestCFEnsureList_NonQuotaCreateFailure(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byMethodPath: map[string]httpFakeResp{
			"GET /accounts/" + tAccount + "/rules/lists":  {status: 200, bodyJSON: `{"success":true,"result":[]}`},
			"POST /accounts/" + tAccount + "/rules/lists": {status: 400, bodyJSON: `{"success":false,"errors":[{"code":10014,"message":"invalid list name"}]}`},
		},
	}
	res, err := cfEnsureList(context.Background(), httpc, tBase, tAccount, "ezyshield_blocked", "tok")
	if err == nil {
		t.Fatal("want error")
	}
	if res.QuotaExceeded {
		t.Errorf("non-quota failure misclassified as quota: %v", err)
	}
}

func TestCFCountZoneRules(t *testing.T) {
	t.Parallel()
	entry := "/zones/" + tZone + "/rulesets/phases/http_request_firewall_custom/entrypoint"
	tests := []struct {
		name    string
		resp    httpFakeResp
		want    int
		wantErr bool
	}{
		{"three rules", httpFakeResp{status: 200, bodyJSON: `{"success":true,"result":{"rules":[{"id":"a"},{"id":"b"},{"id":"c"}]}}`}, 3, false},
		{"no entrypoint yet", httpFakeResp{status: 404, bodyJSON: `{"success":false,"errors":[{"code":7003,"message":"could not route"}]}`}, 0, false},
		{"forbidden", httpFakeResp{status: 403, bodyJSON: `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			httpc := &httpFake{byMethodPath: map[string]httpFakeResp{"GET " + entry: tt.resp}}
			n, err := cfCountZoneRules(context.Background(), httpc, tBase, tZone, "tok")
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, tt.wantErr)
			}
			if n != tt.want {
				t.Errorf("count=%d, want %d", n, tt.want)
			}
		})
	}
}

func TestCFLooksLikeQuotaError(t *testing.T) {
	t.Parallel()
	yes := []string{
		"exceeded maximum number of lists allowed for the account",
		"list quota reached",
		"you have reached the allowed number of lists",
		"account limit exceeded",
	}
	no := []string{"invalid list name", "authentication error", ""}
	for _, m := range yes {
		if !cfLooksLikeQuotaError(m) {
			t.Errorf("want quota classification for %q", m)
		}
	}
	for _, m := range no {
		if cfLooksLikeQuotaError(m) {
			t.Errorf("false positive quota classification for %q", m)
		}
	}
}

// TestRunCDNStep_ListsQuotaExhausted_AbortsWithGuidance is the end-to-end
// wizard behaviour for the reporting scenario: free plan, single list slot
// occupied — setup must abort with the plan explanation, fire the #93
// banner, and leave cfEnabled=false so no config is written.
func TestRunCDNStep_ListsQuotaExhausted_AbortsWithGuidance(t *testing.T) {
	t.Parallel()
	httpc := &httpFake{
		byMethodPath: map[string]httpFakeResp{
			"POST /accounts/" + tAccount + "/rules/lists": {status: 403, bodyJSON: `{"success":false,"errors":[
				{"code":10038,"message":"exceeded maximum number of lists allowed for the account"}]}`},
		},
		byPath: map[string]httpFakeResp{
			"/accounts/" + tAccount + "/tokens/verify": {status: 200, bodyJSON: `{"success":true}`},
			// Serves both the scope probe (per_page=1) and the preflight
			// find (per_page=100): a list exists, but not ours — the slot
			// is taken by someone else's list.
			"/accounts/" + tAccount + "/rules/lists": {status: 200, bodyJSON: `{"success":true,"result":[
				{"id":"other","name":"corporate_allowlist","kind":"ip","num_items":9}]}`},
		},
	}
	prompt := &scriptedPrompter{
		strings: []string{"lists", "block", tAccount, "ezyshield_blocked"},
		bools:   []bool{true},
	}
	step := &cdnStep{}
	out := captureStep(t, func(p *wPrinter) {
		runCDNStep(context.Background(), p, prompt, step, cdnDeps{
			DockerCLI:    &dockerFake{},
			Resolver:     &resolverFake{},
			HTTPClient:   httpc,
			TokenReader:  func(string) (string, error) { return "cf-test-token", nil },
			CFAPIBaseURL: tBase,
		})
	})

	if step.cfEnabled {
		t.Fatalf("cfEnabled=true despite quota refusal; out=%q", out)
	}
	for _, want := range []string{
		"custom-list quota",
		"free accounts get a single custom list",
		"rulesets",
		"Cloudflare enforcer setup did NOT complete", // #93 banner
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q; out=%q", want, out)
		}
	}
	if strings.Contains(out, "cf-test-token") {
		t.Errorf("wizard leaks the token on stdout")
	}
}

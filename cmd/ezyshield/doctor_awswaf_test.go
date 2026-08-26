// SPDX-License-Identifier: AGPL-3.0-only

package main

// Doctor tests for the AWS WAF enforcer checks (issue #201): N/A when not
// configured, pass/fail via the enforcer's read-only Preflight against a
// mock endpoint.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/enforce"
)

func TestCheckAWSWAF_NotConfiguredIsNA(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "data_dir: /tmp\n")
	results := checkAWSWAFEnforcer(dir)
	if len(results) != 1 || results[0].Status != statusNA {
		t.Fatalf("expected a single N/A result, got %+v", results)
	}
}

func TestAWSWAFPreflightResults_PassAndFail(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "doctor-secret")

	healthy := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !healthy {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","Message":"denied"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"IPSet": map[string]any{"Addresses": []string{}}, "LockToken": "t1",
		})
	}))
	defer srv.Close()

	newEnf := func() *enforce.AWSWAFEnforcer {
		enf, err := enforce.NewAWSWAFEnforcer(&enforce.AWSWAFConfig{
			Scope: "REGIONAL", Region: "eu-west-1",
			IPSetV4: &enforce.AWSIPSetRef{Name: "ez4", ID: "id4"},
		}, nil)
		if err != nil {
			t.Fatalf("NewAWSWAFEnforcer: %v", err)
		}
		enf.SetEndpointForTest(srv.URL)
		return enf
	}

	results := awsWAFPreflightResults(context.Background(), newEnf())
	if len(results) != 2 {
		t.Fatalf("expected credentials + one ipset check, got %+v", results)
	}
	for _, r := range results {
		if r.Status != statusPass {
			t.Errorf("healthy endpoint: %s = %v (%s)", r.Name, r.Status, r.Hint)
		}
	}

	healthy = false
	results = awsWAFPreflightResults(context.Background(), newEnf())
	sawFail := false
	for _, r := range results {
		if r.Status == statusFail && strings.Contains(r.Name, "ipset_v4") {
			sawFail = true
			if strings.Contains(r.Hint, "doctor-secret") {
				t.Errorf("hint leaks the secret: %s", r.Hint)
			}
		}
	}
	if !sawFail {
		t.Errorf("expected the GetIPSet failure to surface, got %+v", results)
	}
}

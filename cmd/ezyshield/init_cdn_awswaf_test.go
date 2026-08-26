// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the AWS WAF init subflow pieces (issue #201): the emitted YAML
// must round-trip through the strict loader, and the dry validation must
// gate on the enforcer's real read-only Preflight.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

func TestEmitAWSWAFYAML_RoundTrips(t *testing.T) {
	step := &cdnStep{
		awsWAFEnabled: true,
		awsWAF: &awsWAFSetup{cfg: config.AWSWAFCfg{
			Scope:   "regional",
			Region:  "eu-west-1",
			IPSetV4: &config.AWSIPSetRefCfg{Name: "ez4", ID: "id4"},
			IPSetV6: &config.AWSIPSetRefCfg{Name: "ez6", ID: "id6"},
		}},
	}
	var b strings.Builder
	b.WriteString("data_dir: /tmp\nenforce:\n")
	emitAWSWAFYAML(&b, step)

	cfg, err := config.LoadConfigReader(bytes.NewReader([]byte(b.String())), "emitted")
	if err != nil {
		t.Fatalf("emitted YAML failed the strict loader: %v\n%s", err, b.String())
	}
	a := cfg.Enforce.AWSWAF
	if a == nil || a.Scope != "regional" || a.Region != "eu-west-1" ||
		a.IPSetV4 == nil || a.IPSetV4.ID != "id4" || a.IPSetV6 == nil || a.IPSetV6.Name != "ez6" {
		t.Errorf("round-trip mismatch: %+v", a)
	}
}

func TestDryValidateAWSWAF_MockEndpoint(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wizard-secret")

	ok := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","Message":"nope"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"IPSet": map[string]any{"Addresses": []string{}}, "LockToken": "t1",
		})
	}))
	defer srv.Close()

	cfg := &config.AWSWAFCfg{
		Scope:   "regional",
		Region:  "eu-west-1",
		IPSetV4: &config.AWSIPSetRefCfg{Name: "ez4", ID: "id4"},
	}
	deps := cdnDeps{AWSWAFEndpoint: srv.URL}

	if err := dryValidateAWSWAF(context.Background(), deps, cfg); err != nil {
		t.Fatalf("dry validation against a healthy endpoint: %v", err)
	}

	ok = false
	err := dryValidateAWSWAF(context.Background(), deps, cfg)
	if err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("expected the auth failure to gate config writing, got %v", err)
	}
	if strings.Contains(err.Error(), "wizard-secret") {
		t.Errorf("validation error leaks the secret: %v", err)
	}
}

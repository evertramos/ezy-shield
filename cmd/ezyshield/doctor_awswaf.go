// SPDX-License-Identifier: AGPL-3.0-only

package main

// AWS WAF enforcer doctor checks (issue #201): credentials resolve through
// the standard AWS chain, and GetIPSet succeeds on every designated set
// (proving both the wafv2:GetIPSet permission and the set identity).
// Everything is read-only; credentials never appear in any output.

import (
	"context"
	"path/filepath"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
)

// checkAWSWAFEnforcer runs the read-only checks for the configured AWS WAF
// enforcer. Returns a single N/A result when none is configured.
func checkAWSWAFEnforcer(configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil || cfg.Enforce == nil || cfg.Enforce.AWSWAF == nil {
		return []CheckResult{{
			Name:   "awswaf: enforcer",
			Status: statusNA,
			Hint:   "no aws waf enforcer configured",
		}}
	}
	enf, err := enforce.NewAWSWAFEnforcer(awsWAFConfigFrom(cfg.Enforce.AWSWAF), nil)
	if err != nil {
		return []CheckResult{{
			Name:   "awswaf: config",
			Status: statusFail,
			Hint:   sanitizeErrorMessage(err.Error()),
		}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return awsWAFPreflightResults(ctx, enf)
}

// awsWAFPreflightResults renders enforcer preflight outcomes as doctor
// checks; the enforcer is injectable so tests point it at a mock endpoint.
func awsWAFPreflightResults(ctx context.Context, enf *enforce.AWSWAFEnforcer) []CheckResult {
	var out []CheckResult
	for _, r := range enf.Preflight(ctx) {
		cr := CheckResult{Name: "awswaf: " + r.Label, Status: statusPass}
		if r.Err != nil {
			cr.Status = statusFail
			cr.Hint = sanitizeErrorMessage(r.Err.Error())
			if r.Label == "credentials" {
				cr.Hint += " -- provide credentials via env vars, ~/.aws/credentials, or an instance role (never in config.yaml; see the aws-waf guide)"
			}
		}
		out = append(out, cr)
	}
	return out
}

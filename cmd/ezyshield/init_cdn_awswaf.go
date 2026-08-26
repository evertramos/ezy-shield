// SPDX-License-Identifier: AGPL-3.0-only

package main

// AWS WAF edge-enforcer subflow for `ezyshield init` (issue #201), sibling
// of the Cloudflare/bunny subflows: prompt for scope/region and the IPSet
// identities, dry-validate read-only via the enforcer's Preflight (the
// credential chain + GetIPSet permission), and refuse to write config for
// anything unvalidated. There is NO secret prompt — AWS credentials come
// from the standard chain (env vars, ~/.aws/credentials, IMDSv2) per
// ADR-0012 and never enter EzyShield config or .env files.

import (
	"context"
	"fmt"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/enforce"
)

// awsWAFSetup is the configured AWS WAF enforcer section. No secret
// material exists here, by design.
type awsWAFSetup struct {
	cfg config.AWSWAFCfg
}

// printAWSWAFSetupAbortedBanner mirrors the CF/bunny aborted banners: the
// specific error line scrolls past, so an explicit tail banner keeps the
// missing enforce.aws_waf section visible.
func printAWSWAFSetupAbortedBanner(p *wPrinter) {
	p.println("")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("  [!] AWS WAF enforcer setup did NOT complete.")
	p.println("      config.yaml will NOT contain enforce.aws_waf. See the")
	p.println("      specific reason printed above (invalid input, credentials,")
	p.println("      or IPSet validation).")
	p.println("")
	p.println("      To retry, re-run the wizard or add the section by hand")
	p.println("      (see docs guides/aws-waf).")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("")
}

// runAWSWAFSubflow drives the AWS WAF prompts and, on success, populates
// step.awsWAF and flips step.awsWAFEnabled. It never returns an error: on
// any failure it prints the reason and the aborted banner fires via the
// defer, leaving config.yaml untouched.
func runAWSWAFSubflow(
	ctx context.Context,
	p *wPrinter,
	pr prompter,
	step *cdnStep,
	deps cdnDeps,
) {
	step.awsWAFAttempted = true
	defer func() {
		if !step.awsWAFEnabled {
			printAWSWAFSetupAbortedBanner(p)
		}
	}()

	p.println("  The AWS WAF enforcer maintains dedicated WAFv2 IPSets that your")
	p.println("  WebACL rules reference. Create the (empty) IPSets first in the AWS")
	p.println("  console; EzyShield only ever updates their member addresses and")
	p.println("  never touches WebACLs. Credentials come from the standard AWS")
	p.println("  chain (env vars, ~/.aws/credentials, or an instance role) — they")
	p.println("  are NEVER written to EzyShield config files.")

	scope := strings.ToLower(strings.TrimSpace(pr.ask("AWS WAF scope (regional/cloudfront)", "regional")))
	region := ""
	switch scope {
	case "regional":
		region = strings.TrimSpace(pr.ask("AWS region of the IPSets (e.g. eu-west-1)", ""))
		if region == "" {
			p.println("  scope 'regional' needs a region; skipping AWS WAF setup.")
			return
		}
	case "cloudfront":
		// The WAFv2 API pins CLOUDFRONT to us-east-1; nothing to ask.
	default:
		p.printf("  scope %q is not regional/cloudfront; skipping AWS WAF setup.\n", scope)
		return
	}

	askSet := func(label string) *config.AWSIPSetRefCfg {
		name := strings.TrimSpace(pr.ask(label+" IPSet name (ENTER to skip)", ""))
		if name == "" {
			return nil
		}
		id := strings.TrimSpace(pr.ask(label+" IPSet Id (from the console/ARN)", ""))
		if id == "" {
			p.printf("  %s IPSet %q has no Id; skipping that set.\n", label, name)
			return nil
		}
		return &config.AWSIPSetRefCfg{Name: name, ID: id}
	}
	v4 := askSet("IPv4")
	v6 := askSet("IPv6")
	if v4 == nil && v6 == nil {
		p.println("  no IPSet given; skipping AWS WAF setup.")
		return
	}

	cfg := config.AWSWAFCfg{Scope: scope, Region: region, IPSetV4: v4, IPSetV6: v6}
	if err := dryValidateAWSWAF(ctx, deps, &cfg); err != nil {
		p.printf("  AWS WAF validation failed: %v\n", err)
		p.println("  Refusing to write config for an unvalidated enforcer.")
		return
	}
	p.println("  AWS WAF validated OK (credentials + GetIPSet on every designated set).")

	step.awsWAF = &awsWAFSetup{cfg: cfg}
	step.awsWAFEnabled = true
}

// dryValidateAWSWAF builds the real enforcer and runs its read-only
// Preflight: the credential chain must resolve and GetIPSet must succeed
// on every designated set. deps.AWSWAFEndpoint overrides the API endpoint
// in tests.
func dryValidateAWSWAF(ctx context.Context, deps cdnDeps, cfg *config.AWSWAFCfg) error {
	enf, err := enforce.NewAWSWAFEnforcer(awsWAFConfigFrom(cfg), nil)
	if err != nil {
		return err
	}
	if deps.AWSWAFEndpoint != "" {
		enf.SetEndpointForTest(deps.AWSWAFEndpoint)
	}
	for _, r := range enf.Preflight(ctx) {
		if r.Err != nil {
			return fmt.Errorf("%s: %s", r.Label, sanitizeErrorMessage(r.Err.Error()))
		}
	}
	return nil
}

// emitAWSWAFYAML appends the enforce.aws_waf section for the rendered
// config.yaml. Caller has already written the "enforce:" header.
func emitAWSWAFYAML(b *strings.Builder, step *cdnStep) {
	if step == nil || step.awsWAF == nil {
		return
	}
	cfg := step.awsWAF.cfg
	b.WriteString("  aws_waf:\n")
	fmt.Fprintf(b, "    scope: %s\n", cfg.Scope)
	if cfg.Region != "" {
		fmt.Fprintf(b, "    region: %s\n", cfg.Region)
	}
	if cfg.IPSetV4 != nil {
		fmt.Fprintf(b, "    ipset_v4:\n      name: %s\n      id: %s\n", cfg.IPSetV4.Name, cfg.IPSetV4.ID)
	}
	if cfg.IPSetV6 != nil {
		fmt.Fprintf(b, "    ipset_v6:\n      name: %s\n      id: %s\n", cfg.IPSetV6.Name, cfg.IPSetV6.ID)
	}
}

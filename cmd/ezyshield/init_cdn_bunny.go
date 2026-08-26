// SPDX-License-Identifier: AGPL-3.0-only

package main

// bunny.net edge-enforcer subflow for `ezyshield init` (issue #198), the
// sibling of the Cloudflare subflow in init_cdn.go: prompt for pull zones
// and the API key (masked, .env-only), dry-validate read-only against the
// bunny API, and refuse to write config for anything unvalidated.

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
)

// bunnyKeyEnvVar is the fixed env-var NAME the wizard writes to .env; the
// yaml gets `api_key: env:BUNNY_API_KEY` (issue #13 precedent: never prompt
// for the NAME, only the secret VALUE).
const bunnyKeyEnvVar = "BUNNY_API_KEY"

// bunnySetup is the configured bunny enforcer: the config.yaml entry plus
// the secret material that goes to .env instead.
type bunnySetup struct {
	// cfg is the entry the wizard will emit into enforce.bunny.
	cfg config.BunnyCfg
	// keyEnvVar is the env-var name written to .env (bunnyKeyEnvVar).
	keyEnvVar string
	// key holds the raw API key between the prompt and the .env write.
	// Same discipline as cfAccountSetup.token — never logged or printed,
	// redacted by String().
	key string
}

// String masks the key, mirroring cfAccountSetup.String().
func (b *bunnySetup) String() string {
	if b == nil {
		return "<nil bunnySetup>"
	}
	keyMark := "<empty>"
	if b.key != "" {
		keyMark = "<redacted>"
	}
	return fmt.Sprintf("bunnySetup{zones=%d keyEnvVar=%q key=%s}",
		len(b.cfg.PullZones), b.keyEnvVar, keyMark)
}

// printBunnySetupAbortedBanner mirrors printCFSetupAbortedBanner (issue
// #93): the specific error line scrolls past under later wizard output, so
// an explicit tail banner keeps the missing enforce.bunny section visible.
func printBunnySetupAbortedBanner(p *wPrinter) {
	p.println("")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("  [!] bunny.net enforcer setup did NOT complete.")
	p.println("      config.yaml will NOT contain enforce.bunny, and .env")
	p.println("      will NOT contain " + bunnyKeyEnvVar + ". See the specific")
	p.println("      reason printed above (invalid input, or key validation).")
	p.println("")
	p.println("      To retry, re-run the wizard or add the section by hand")
	p.println("      (see docs guides/bunny).")
	p.println("  ─────────────────────────────────────────────────────────────")
	p.println("")
}

// runBunnySubflow drives the bunny-specific prompts and, on success,
// populates step.bunny and flips step.bunnyEnabled. It never returns an
// error: on any failure it prints the reason and the aborted banner fires
// via the defer, leaving config.yaml untouched.
func runBunnySubflow(
	ctx context.Context,
	p *wPrinter,
	pr prompter,
	step *cdnStep,
	deps cdnDeps,
) {
	step.bunnyAttempted = true
	defer func() {
		if !step.bunnyEnabled {
			printBunnySetupAbortedBanner(p)
		}
	}()

	p.println("  The bunny.net enforcer manages each pull zone's blocked-IP list.")
	p.println("  NOTE: that list has no per-entry tagging, so EzyShield takes")
	p.println("  ownership of it — IPs blocked by hand in the bunny panel will be")
	p.println("  removed on reconcile for the zones configured here.")

	rawZones := pr.ask("bunny.net pull zone ID(s) (comma-separated numeric IDs)", "")
	zoneStrs := splitAndTrim(rawZones)
	if len(zoneStrs) == 0 {
		p.println("  no pull zone IDs given; skipping bunny setup.")
		return
	}
	zones := make([]int64, 0, len(zoneStrs))
	seen := make(map[int64]bool, len(zoneStrs))
	for _, zs := range zoneStrs {
		z, err := strconv.ParseInt(zs, 10, 64)
		if err != nil || z <= 0 {
			p.printf("  pull zone ID %q is not a positive number (see bunny panel → Pull Zone → the numeric ID in the URL); skipping bunny setup.\n", zs)
			return
		}
		if seen[z] {
			continue
		}
		seen[z] = true
		zones = append(zones, z)
	}

	// The API key, masked, via the same tty path the AI/CF steps use.
	reader := deps.TokenReader
	if reader == nil {
		reader = tokenReader
	}
	key, err := reader("  Paste the bunny.net API key (Account → API, input hidden, ENTER to skip): ")
	if err != nil || key == "" {
		p.println("  No bunny.net API key provided; skipping bunny setup.")
		return
	}

	// Dry validation before writing anything: one read-only GET per zone
	// proves the key works and every zone exists under this account.
	if err := dryValidateBunnyKey(ctx, deps, zones, key); err != nil {
		p.printf("  bunny.net key validation failed: %v\n", err)
		p.println("  Refusing to write config with an unvalidated key.")
		return
	}
	p.println("  bunny.net key validated OK (all pull zones reachable).")

	step.bunny = &bunnySetup{
		cfg: config.BunnyCfg{
			APIKey:    config.SecretRef("env:" + bunnyKeyEnvVar),
			PullZones: zones,
		},
		keyEnvVar: bunnyKeyEnvVar,
		key:       key,
	}
	step.bunnyEnabled = true
}

// dryValidateBunnyKey performs a read-only GET /pullzone/{id} per zone. The
// key goes only into the AccessKey header; error messages carry the zone ID
// and HTTP status, never the key (response bodies pass through
// sanitizeErrorMessage like the CF path).
func dryValidateBunnyKey(ctx context.Context, deps cdnDeps, zones []int64, key string) error {
	base := deps.BunnyAPIBaseURL
	if base == "" {
		base = "https://api.bunny.net"
	}
	client := deps.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	for _, zone := range zones {
		url := base + "/pullzone/" + strconv.FormatInt(zone, 10)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build request for zone %d: %w", zone, err)
		}
		req.Header.Set("AccessKey", key)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("zone %d: %s", zone, sanitizeErrorMessage(err.Error()))
		}
		_ = resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusUnauthorized:
			return fmt.Errorf("the API key was rejected (HTTP 401) — copy it from the bunny panel under Account → API")
		case http.StatusNotFound:
			return fmt.Errorf("pull zone %d not found (HTTP 404) — check the numeric ID in the bunny panel", zone)
		default:
			return fmt.Errorf("zone %d: unexpected HTTP %d from the bunny API", zone, resp.StatusCode)
		}
	}
	return nil
}

// emitBunnyYAML appends the enforce.bunny section for the rendered
// config.yaml. Caller has already written the "enforce:" header.
func emitBunnyYAML(b *strings.Builder, step *cdnStep) {
	if step == nil || step.bunny == nil {
		return
	}
	b.WriteString("  bunny:\n")
	fmt.Fprintf(b, "    api_key: env:%s\n", step.bunny.keyEnvVar)
	b.WriteString("    pull_zones:\n")
	for _, z := range step.bunny.cfg.PullZones {
		fmt.Fprintf(b, "      - %d\n", z)
	}
}

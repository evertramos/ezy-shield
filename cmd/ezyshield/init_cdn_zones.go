package main

// Zone-coverage prompt + automatic WAF rule rollout for the Cloudflare
// lists-mode wizard (issue #121).
//
// The lists enforcer already auto-manages one WAF Custom Rule per zone when
// enforce.cloudflare.zone_ids is set (internal/enforce/cloudflare_lists.go,
// syncZoneRule). Before this file the wizard never collected zone_ids in
// lists mode — it ended with manual dashboard instructions, so bans reached
// the list but no zone actually blocked anything until the operator wired
// each zone by hand. Here the wizard asks which zones the block rule should
// cover (all / explicit IDs / manual), persists the resolved set, and
// creates-or-verifies the rule per zone right away, reporting per zone.
//
// Idempotency contract with the enforcer: rules are found by their
// description ("ezyshield-list-block", enforce's cfListRuleDescPattern) in
// the http_request_firewall_custom phase ruleset. A rule the wizard creates
// is adopted by the enforcer's sync (and vice versa); re-running the wizard
// reports "already present" instead of duplicating.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/evertramos/ezy-shield/internal/config"
)

const (
	// cfZoneRulePhase / cfZoneRuleDesc mirror the enforcer's constants; the
	// values are part of the idempotency contract described above.
	cfZoneRulePhase = "http_request_firewall_custom"
	cfZoneRuleDesc  = "ezyshield-list-block"

	// cfZonesPerPage is the page size for zone enumeration. 50 keeps
	// responses small while covering most accounts in one or two pages.
	cfZonesPerPage = 50
	// cfZonesMaxPages hard-caps enumeration so a hostile/broken API cannot
	// keep the wizard paging forever (50×40 = 2000 zones, far beyond any
	// realistic account).
	cfZonesMaxPages = 40
)

// cfZoneCoverage is the operator's answer to the coverage prompt.
type cfZoneCoverage struct {
	// all means "enumerate every zone the token can see and cover those".
	all bool
	// ids holds explicit zone IDs (validated 32-hex); empty with all=false
	// means "manual setup" — today's behaviour.
	ids []string
}

// promptCFZoneCoverage asks which zones the WAF block rule should cover in
// lists mode. ENTER keeps the manual-instructions path. Returns ok=false on
// an invalid explicit ID (fails this account, same as the rulesets prompt).
func promptCFZoneCoverage(p *wPrinter, pr prompter) (cfZoneCoverage, bool) {
	raw := strings.TrimSpace(pr.ask(
		"Zones the block rule should cover ('all', comma-separated zone IDs, or ENTER for manual setup)", ""))
	if raw == "" {
		return cfZoneCoverage{}, true
	}
	if strings.EqualFold(raw, "all") {
		return cfZoneCoverage{all: true}, true
	}
	ids := splitAndTrim(raw)
	for _, z := range ids {
		if !cfHexIDRe.MatchString(z) {
			p.printf("  zone_id %q is not 32 hex chars; skipping this account.\n", z)
			return cfZoneCoverage{}, false
		}
	}
	return cfZoneCoverage{ids: ids}, true
}

// cfZone is one zone in the rollout target set. Name is empty for explicit
// IDs (not enumerated) and is treated as untrusted API output otherwise.
type cfZone struct {
	ID   string
	Name string
}

// cfConfigureZoneCoverage resolves the coverage answer into concrete zones,
// persists them on cfg.ZoneIDs, and rolls the WAF rule out per zone with a
// per-zone report. Runs after the capability preflight, so the Custom List
// already exists. Never fails the account: enumeration failure degrades to
// the manual path with a clear message, and per-zone failures are loud in
// the report while the config still persists the full target set (the
// enforcer keeps reconciling those zones at sync time).
func cfConfigureZoneCoverage(
	ctx context.Context,
	p *wPrinter,
	deps cdnDeps,
	cfg *config.CloudflareCfg,
	token string,
	cov cfZoneCoverage,
) {
	if !cov.all && len(cov.ids) == 0 {
		return // manual path — printCFListsManualStep fires as before
	}
	base := deps.CFAPIBaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}

	var zones []cfZone
	if cov.all {
		zs, err := cfEnumerateZones(ctx, deps, base, cfg.AccountID, token)
		if err != nil {
			p.printf("  could not enumerate zones: %v\n", err)
			p.println("  The token likely lacks Zone:Zone:Read. Falling back to manual WAF")
			p.println("  rule setup — the list still works once you add the rule per zone.")
			return
		}
		if len(zs) == 0 {
			p.println("  the token can see no zones on this account; falling back to manual WAF rule setup.")
			return
		}
		zones = zs
		p.printf("  %d zone(s) enumerated — this snapshot is what gets persisted; re-run\n", len(zones))
		p.println("  this setup to pick up domains added to the account later.")
	} else {
		for _, id := range cov.ids {
			zones = append(zones, cfZone{ID: id})
		}
	}

	// Persist the full resolved target set: the config stays explicit
	// (config show reflects reality) and the enforcer manages these zones
	// from now on — including any that fail below.
	cfg.ZoneIDs = make([]string, 0, len(zones))
	for _, z := range zones {
		cfg.ZoneIDs = append(cfg.ZoneIDs, z.ID)
	}

	action := cfg.Action
	if action == "" {
		action = "block"
	}
	expr := buildCFWAFRuleExpression(cfg.ListName)

	p.println("")
	p.println("  Zone coverage report:")
	var failed []cfZone
	for _, zone := range zones {
		status, err := cfEnsureZoneRule(ctx, deps, base, token, zone.ID, action, expr)
		label := zone.ID
		if zone.Name != "" {
			label = zone.ID + " (" + sanitizeErrorMessage(zone.Name) + ")"
		}
		if err != nil {
			p.printf("    ✗ %s — FAILED (%v)\n", label, err)
			failed = append(failed, zone)
			continue
		}
		p.printf("    ✓ %s — %s\n", label, status)
	}
	if len(failed) > 0 {
		p.println("")
		p.printf("  %d zone(s) could not be configured automatically. Finish them by hand:\n", len(failed))
		p.println("    1. Open that zone in the CF dashboard → Security → WAF → Custom Rules.")
		p.printf("    2. Create a rule with expression %s and your chosen action.\n", expr)
		for _, z := range failed {
			p.printf("       • zone %s\n", z.ID)
		}
		p.println("  The daemon will also retry these zones on every sync.")
	}
	p.println("")
}

// cfEnumerateZones pages through GET /zones?account.id=… and returns every
// zone the token can read, scoped to the configured account.
func cfEnumerateZones(ctx context.Context, deps cdnDeps, base, accountID, token string) ([]cfZone, error) {
	var out []cfZone
	for page := 1; page <= cfZonesMaxPages; page++ {
		url := fmt.Sprintf("%s/zones?account.id=%s&per_page=%d&page=%d",
			base, accountID, cfZonesPerPage, page)
		var resp cfZonesResp
		status, errMsg, err := doCFZoneJSON(ctx, deps, http.MethodGet, url, token, nil, &resp)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK || !resp.Success {
			if errMsg == "" {
				errMsg = cfFirstErrMsg(resp.Errors)
			}
			return nil, fmt.Errorf("zones list HTTP %d: %s", status, errMsg)
		}
		for _, z := range resp.Result {
			if !cfHexIDRe.MatchString(z.ID) {
				// An ID outside Cloudflare's own format is either API drift
				// or tampering — refuse to persist it into config.yaml.
				return nil, fmt.Errorf("zones list returned a malformed zone id")
			}
			out = append(out, cfZone{ID: z.ID, Name: z.Name})
		}
		if resp.ResultInfo.TotalPages == 0 || page >= resp.ResultInfo.TotalPages {
			return out, nil
		}
	}
	return nil, fmt.Errorf("zones list did not terminate after %d pages", cfZonesMaxPages)
}

// cfEnsureZoneRule creates-or-verifies the ezyshield WAF rule in one zone.
// Returns a short status string ("configured" / "already present") on
// success. Mirrors the enforcer's discover→create flow so a later sync
// adopts whatever the wizard created.
func cfEnsureZoneRule(ctx context.Context, deps cdnDeps, base, token, zoneID, action, expr string) (string, error) {
	rulesetID, ruleFound, err := cfFindZoneRule(ctx, deps, base, token, zoneID)
	if err != nil {
		return "", err
	}
	if ruleFound {
		return "already present", nil
	}

	rule := cfWizardRuleReq{Action: action, Expression: expr, Description: cfZoneRuleDesc}
	if rulesetID == "" {
		// No custom-firewall ruleset yet: create it with the rule inline.
		req := cfWizardCreateRulesetReq{
			Name: "Custom rules", Kind: "zone", Phase: cfZoneRulePhase,
			Rules: []cfWizardRuleReq{rule},
		}
		url := fmt.Sprintf("%s/zones/%s/rulesets", base, zoneID)
		if err := cfPostRule(ctx, deps, url, token, req); err != nil {
			return "", err
		}
		return "configured", nil
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules", base, zoneID, rulesetID)
	if err := cfPostRule(ctx, deps, url, token, rule); err != nil {
		return "", err
	}
	return "configured", nil
}

// cfFindZoneRule locates the zone's http_request_firewall_custom ruleset and
// reports whether it already contains an ezyshield rule (by description).
func cfFindZoneRule(ctx context.Context, deps cdnDeps, base, token, zoneID string) (rulesetID string, ruleFound bool, err error) {
	var list cfRulesetsListResp
	url := fmt.Sprintf("%s/zones/%s/rulesets", base, zoneID)
	status, errMsg, err := doCFZoneJSON(ctx, deps, http.MethodGet, url, token, nil, &list)
	if err != nil {
		return "", false, err
	}
	if status != http.StatusOK || !list.Success {
		if errMsg == "" {
			errMsg = cfFirstErrMsg(list.Errors)
		}
		return "", false, fmt.Errorf("HTTP %d: %s", status, errMsg)
	}
	for _, rs := range list.Result {
		if rs.Phase == cfZoneRulePhase {
			rulesetID = rs.ID
			break
		}
	}
	if rulesetID == "" {
		return "", false, nil
	}

	var got cfRulesetGetResp
	url = fmt.Sprintf("%s/zones/%s/rulesets/%s", base, zoneID, rulesetID)
	status, errMsg, err = doCFZoneJSON(ctx, deps, http.MethodGet, url, token, nil, &got)
	if err != nil {
		return "", false, err
	}
	if status != http.StatusOK || !got.Success {
		if errMsg == "" {
			errMsg = cfFirstErrMsg(got.Errors)
		}
		return "", false, fmt.Errorf("HTTP %d: %s", status, errMsg)
	}
	for _, r := range got.Result.Rules {
		if strings.Contains(r.Description, cfZoneRuleDesc) {
			return rulesetID, true, nil
		}
	}
	return rulesetID, false, nil
}

// cfPostRule POSTs a rule (or ruleset-with-rule) payload and checks the
// success envelope.
func cfPostRule(ctx context.Context, deps cdnDeps, url, token string, payload any) error {
	var resp cfWriteResp
	status, errMsg, err := doCFZoneJSON(ctx, deps, http.MethodPost, url, token, payload, &resp)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !resp.Success {
		if errMsg == "" {
			errMsg = cfFirstErrMsg(resp.Errors)
		}
		return fmt.Errorf("HTTP %d: %s", status, errMsg)
	}
	return nil
}

// ── request/response shapes (Cloudflare v4 envelope subset) ────────────────

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfFirstErrMsg extracts a sanitized errors[0].message for terminal output.
func cfFirstErrMsg(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "no error detail"
	}
	return sanitizeErrorMessage(errs[0].Message)
}

type cfZonesResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type cfRulesetsListResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  []struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
	} `json:"result"`
}

type cfRulesetGetResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  struct {
		Rules []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
		} `json:"rules"`
	} `json:"result"`
}

type cfWriteResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
}

type cfWizardRuleReq struct {
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
}

type cfWizardCreateRulesetReq struct {
	Name  string            `json:"name"`
	Kind  string            `json:"kind"`
	Phase string            `json:"phase"`
	Rules []cfWizardRuleReq `json:"rules"`
}

// doCFZoneJSON wraps the shared doCFJSON transport (cf_preflight.go —
// bounded read, token only in the Authorization header) and decodes the
// success envelope into out. On non-200 it returns the sanitized
// errors[0].message alongside the status.
func doCFZoneJSON(ctx context.Context, deps cdnDeps, method, url, token string, payload, out any) (int, string, error) {
	status, body, err := doCFJSON(ctx, deps.HTTPClient, method, url, token, payload)
	if err != nil {
		return status, "", err
	}
	if status != http.StatusOK {
		return status, readCFErrorMessage(bytes.NewReader(body)), nil
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return status, "", fmt.Errorf("decode response: %w", err)
		}
	}
	return status, "", nil
}

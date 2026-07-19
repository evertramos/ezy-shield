package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
)

// runTestEnforce backs `test enforcer <name>` (and its deprecated
// `test-enforce` alias); the cobra wiring lives in testcmd.go.
func runTestEnforce(cmd *cobra.Command, configDir, backend string) error {
	switch backend {
	case "cloudflare", "nftables", "all":
	default:
		return fmt.Errorf("unknown backend %q: must be cloudflare, nftables, or all", backend)
	}

	cfgPath := filepath.Join(configDir, "config.yaml")
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	results := &testEnforceResults{
		Backends: make(map[string]*backendResult),
	}

	if (backend == "cloudflare" || backend == "all") && cfg.Enforce != nil && len(cfg.Enforce.Cloudflare) > 0 {
		for _, cfcfg := range cfg.Enforce.Cloudflare {
			result := testCloudflareBackend(context.Background(), &cfcfg)
			name := cfcfg.Name
			if name == "" {
				name = "default"
			}
			results.Backends[name] = result
		}
	}

	if (backend == "nftables" || backend == "all") && cfg.Enforce != nil && cfg.Enforce.NFTables != nil {
		results.Backends["nftables"] = &backendResult{
			Status: "skipped",
			Notes:  "nftables testing not yet implemented",
		}
	}

	if len(results.Backends) == 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No %s enforcer configured in %s\n", backend, cfgPath)
		return nil
	}

	if jsonOutput {
		return writeJSON(cmd.OutOrStdout(), results)
	}

	if err := printEnforceResults(cmd.OutOrStdout(), results); err != nil {
		return err
	}

	// Check if any backend failed and return error for non-zero exit code
	for _, result := range results.Backends {
		if result.Status == "fail" {
			return fmt.Errorf("one or more checks failed")
		}
	}

	return nil
}

type testEnforceResults struct {
	Backends map[string]*backendResult `json:"backends"`
}

type backendResult struct {
	Status  string        `json:"status"`
	Mode    string        `json:"mode,omitempty"`
	Checks  []checkResult `json:"checks,omitempty"`
	Notes   string        `json:"notes,omitempty"`
	Passed  int           `json:"passed,omitempty"`
	Failed  int           `json:"failed,omitempty"`
	Message string        `json:"message,omitempty"`
}

type checkResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details,omitempty"`
	Fix     string `json:"fix,omitempty"`
}

func testCloudflareBackend(ctx context.Context, cfcfg *config.CloudflareCfg) *backendResult {
	result := &backendResult{
		Mode:   cfcfg.Mode,
		Checks: []checkResult{},
	}

	if result.Mode == "" {
		result.Mode = "lists"
	}

	token, err := cfcfg.APIToken.Resolve()
	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Failed to resolve API token: %v", err)
		return result
	}

	// Check 1: Token validity
	tokenID, status, err := checkTokenValidity(ctx, token, cfcfg.AccountID)
	if err != nil {
		result.Status = "error"
		result.Message = fmt.Sprintf("Token validation failed: %v", err)
		result.Failed = 1
		return result
	}
	if status != "active" {
		result.Checks = append(result.Checks, checkResult{
			Name:    "Token validity",
			Status:  "fail",
			Details: fmt.Sprintf("Token status is %q, expected active", status),
			Fix:     "Check the token in Cloudflare dashboard; it may be expired or disabled",
		})
		result.Failed++
	} else {
		result.Checks = append(result.Checks, checkResult{
			Name:    "Token validity",
			Status:  "pass",
			Details: fmt.Sprintf("Token ID: %s, status: %s", tokenID, status),
		})
		result.Passed++
	}

	switch result.Mode {
	case "lists":
		testCloudflareListsMode(ctx, token, cfcfg, result)
	case "rulesets":
		testCloudflareRulesetsMode(ctx, token, cfcfg, result)
	}

	if result.Failed > 0 {
		result.Status = "fail"
	} else {
		result.Status = "pass"
	}

	return result
}

func testCloudflareListsMode(ctx context.Context, token string, cfcfg *config.CloudflareCfg, result *backendResult) {
	const baseURL = "https://api.cloudflare.com/client/v4"

	// Check 2: Account access
	if err := checkAccountAccess(ctx, token, baseURL, cfcfg.AccountID); err != nil {
		result.Checks = append(result.Checks, checkResult{
			Name:    "Account access",
			Status:  "fail",
			Details: err.Error(),
			Fix:     "Verify the account_id in config.yaml; ensure token has Account access",
		})
		result.Failed++
		return
	}
	result.Checks = append(result.Checks, checkResult{
		Name:    "Account access",
		Status:  "pass",
		Details: fmt.Sprintf("Account ID: %s", cfcfg.AccountID),
	})
	result.Passed++

	// Check 3: List access (read)
	listID, itemCount, err := checkListAccess(ctx, token, baseURL, cfcfg.AccountID, cfcfg.ListName)
	if err != nil {
		result.Checks = append(result.Checks, checkResult{
			Name:    "List access (read)",
			Status:  "fail",
			Details: err.Error(),
			Fix:     fmt.Sprintf("Ensure token has Account Filter Lists:Edit. If the list does not exist, re-run '%s config enforcer cloudflare' to create or adopt it — note your plan's custom-list quota (free accounts: a single custom list); if exhausted, delete an unused list, upgrade, or switch to rulesets mode", progName),
		})
		result.Failed++
	} else {
		listName := cfcfg.ListName
		if listName == "" {
			listName = "ezyshield_blocked"
		}
		result.Checks = append(result.Checks, checkResult{
			Name:    "List access (read)",
			Status:  "pass",
			Details: fmt.Sprintf("List %q found (ID: %s, %d items)", listName, listID, itemCount),
		})
		result.Passed++
	}

	// Check 4: Zone WAF access (if zone_ids configured)
	if len(cfcfg.ZoneIDs) > 0 {
		for _, zoneID := range cfcfg.ZoneIDs {
			ok, ruleCount, errMsg := checkZoneWAFAccess(ctx, token, baseURL, zoneID)
			if ok {
				result.Checks = append(result.Checks, checkResult{
					Name:    "Zone WAF access",
					Status:  "pass",
					Details: fmt.Sprintf("Zone %s — WAF rule access OK (%d custom rule(s) in use)", zoneID, ruleCount),
				})
				result.Passed++
			} else {
				result.Checks = append(result.Checks, checkResult{
					Name:    "Zone WAF access",
					Status:  "fail",
					Details: fmt.Sprintf("Zone %s — %s", zoneID, errMsg),
					Fix:     "Ensure token has Zone:Firewall Services:Edit on this zone",
				})
				result.Failed++
			}
		}
	}
}

func testCloudflareRulesetsMode(ctx context.Context, token string, cfcfg *config.CloudflareCfg, result *backendResult) {
	const baseURL = "https://api.cloudflare.com/client/v4"

	if len(cfcfg.ZoneIDs) == 0 {
		result.Checks = append(result.Checks, checkResult{
			Name:    "Zone configuration",
			Status:  "fail",
			Details: "No zone_ids configured for rulesets mode",
			Fix:     "Add zone_ids to your cloudflare config block",
		})
		result.Failed++
		return
	}

	for _, zoneID := range cfcfg.ZoneIDs {
		// Check 2: Zone access
		if err := checkZoneAccess(ctx, token, baseURL, zoneID); err != nil {
			result.Checks = append(result.Checks, checkResult{
				Name:    "Zone access",
				Status:  "fail",
				Details: fmt.Sprintf("Zone %s — %v", zoneID, err),
				Fix:     "Verify the zone_id and ensure token has Zone access",
			})
			result.Failed++
			continue
		}
		result.Checks = append(result.Checks, checkResult{
			Name:    "Zone access",
			Status:  "pass",
			Details: fmt.Sprintf("Zone %s — accessible", zoneID),
		})
		result.Passed++

		// Check 3: Zone WAF access + slot headroom (issue #234)
		ok, ruleCount, errMsg := checkZoneWAFAccess(ctx, token, baseURL, zoneID)
		if ok {
			result.Checks = append(result.Checks, checkResult{
				Name:    "Zone WAF access",
				Status:  "pass",
				Details: fmt.Sprintf("Zone %s — WAF rule access OK (%d custom rule(s) in use; free-plan zones allow 5)", zoneID, ruleCount),
			})
			result.Passed++
		} else {
			result.Checks = append(result.Checks, checkResult{
				Name:    "Zone WAF access",
				Status:  "fail",
				Details: fmt.Sprintf("Zone %s — %s", zoneID, errMsg),
				Fix:     "Ensure token has Zone:Firewall:Edit on this zone",
			})
			result.Failed++
		}
	}
}

// checkTokenValidity verifies a Cloudflare API token. Detects the token type:
// - cfat_ prefix → Account API Token → verify via /accounts/{account_id}/tokens/verify
// - Otherwise → User API Token → verify via /user/tokens/verify
func checkTokenValidity(ctx context.Context, token, accountID string) (string, string, error) {
	verifyURL := "https://api.cloudflare.com/client/v4/user/tokens/verify"

	// Detect Account API Token by cfat_ prefix
	if strings.HasPrefix(token, "cfat_") {
		if accountID == "" {
			return "", "", fmt.Errorf("account_id is required for Account API Tokens (cfat_ prefix)")
		}
		verifyURL = fmt.Sprintf("https://api.cloudflare.com/client/v4/accounts/%s/tokens/verify", accountID)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", verifyURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var data struct {
		Result struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"result"`
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", "", fmt.Errorf("decode error: %w", err)
	}

	if !data.Success {
		return "", "", fmt.Errorf("API returned success=false")
	}

	return data.Result.ID, data.Result.Status, nil
}

func checkAccountAccess(ctx context.Context, token, baseURL, accountID string) error {
	url := fmt.Sprintf("%s/accounts/%s", baseURL, accountID)
	return checkAPIAccess(ctx, token, url)
}

func checkListAccess(ctx context.Context, token, baseURL, accountID, listName string) (string, int, error) {
	if listName == "" {
		listName = "ezyshield_blocked"
	}

	url := fmt.Sprintf("%s/accounts/%s/rules/lists", baseURL, accountID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var data struct {
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", 0, fmt.Errorf("decode error: %w", err)
	}

	var listID string
	for _, l := range data.Result {
		if l.Name == listName {
			listID = l.ID
			break
		}
	}

	if listID == "" {
		return "", 0, fmt.Errorf("list %q not found (will be created on first Sync)", listName)
	}

	// Fetch item count
	itemsURL := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items?per_page=1", baseURL, accountID, listID)
	itemReq, err := http.NewRequestWithContext(ctx, "GET", itemsURL, nil)
	if err != nil {
		return listID, 0, nil
	}
	itemReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	itemResp, err := client.Do(itemReq)
	if err != nil {
		return listID, 0, nil
	}
	defer func() { _ = itemResp.Body.Close() }()

	var itemData struct {
		ResultInfo struct {
			Count int `json:"count"`
		} `json:"result_info"`
	}

	if err := json.NewDecoder(itemResp.Body).Decode(&itemData); err != nil {
		return listID, 0, nil
	}

	return listID, itemData.ResultInfo.Count, nil
}

func checkZoneAccess(ctx context.Context, token, baseURL, zoneID string) error {
	url := fmt.Sprintf("%s/zones/%s", baseURL, zoneID)
	return checkAPIAccess(ctx, token, url)
}

// checkZoneWAFAccess probes the zone's custom-rules entrypoint. On success
// it also reports how many WAF custom rules are already in use, so the
// operator can see slot headroom (issue #234 — free-plan zones allow 5 and
// EzyShield needs one free slot). 404 means the entrypoint ruleset was
// never created: zero rules in use.
func checkZoneWAFAccess(ctx context.Context, token, baseURL, zoneID string) (bool, int, string) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/http_request_firewall_custom/entrypoint", baseURL, zoneID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, fmt.Sprintf("request error: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, fmt.Sprintf("network error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case 200:
		var data struct {
			Result struct {
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"result"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&data); err != nil {
			// Access is proven by the 200; a parse hiccup only loses the
			// informational count.
			return true, 0, ""
		}
		return true, len(data.Result.Rules), ""
	case 404:
		return true, 0, ""
	case 403:
		return false, 0, "403 Forbidden — missing Zone:Firewall Services:Edit permission"
	default:
		return false, 0, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
}

func checkAPIAccess(ctx context.Context, token, url string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func printEnforceResults(w io.Writer, results *testEnforceResults) error {
	for _, result := range results.Backends {
		mode := ""
		if result.Mode != "" {
			mode = fmt.Sprintf(" (mode: %s)", result.Mode)
		}
		_, _ = fmt.Fprintf(w, "\nCloudflare enforcer%s: %s\n", mode, result.Status)
		_, _ = fmt.Fprintf(w, "%s\n", repeatStr("─", 40))

		if result.Message != "" {
			_, _ = fmt.Fprintf(w, "✗ Error: %s\n", result.Message)
			return nil
		}

		if result.Notes != "" {
			_, _ = fmt.Fprintf(w, "%s\n", result.Notes)
			return nil
		}

		for _, check := range result.Checks {
			symbol := "✓"
			if check.Status == "fail" {
				symbol = "✗"
			}
			_, _ = fmt.Fprintf(w, "%s %s: %s\n", symbol, check.Name, check.Details)
			if check.Fix != "" {
				_, _ = fmt.Fprintf(w, "  └─ %s\n", check.Fix)
			}
		}

		if result.Passed > 0 || result.Failed > 0 {
			_, _ = fmt.Fprintf(w, "\nResult: %d/%d checks passed", result.Passed, result.Passed+result.Failed)
			if result.Failed > 0 {
				_, _ = fmt.Fprintf(w, ", %d failed", result.Failed)
			}
			_, _ = fmt.Fprintln(w)
		}
	}
	return nil
}

func repeatStr(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

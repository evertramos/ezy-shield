package main

// Cloudflare capability preflight (issue #234).
//
// Token/scope validation (init_cdn.go dryValidateCFToken) proves the token
// is alive and correctly scoped — but not that the chosen configuration can
// actually WORK. The canonical failure: a free-plan account whose single
// custom-list slot is already taken. The token validates, the config is
// written, and the first armed sync fails with an opaque API error days
// later. The helpers here close that gap:
//
//   - cfEnsureList: find the configured Custom IP List or create it on the
//     spot, mapping plan-quota refusals to an actionable explanation. Used
//     by the wizard (create-or-adopt before any config is written) and, in
//     find-only form, by doctor.
//   - cfCountZoneRules: count the WAF custom rules already occupying a
//     zone's http_request_firewall_custom entrypoint, so rulesets-mode
//     users see their remaining slot headroom (free-plan zones allow 5).
//
// All calls send the token exclusively as an Authorization header, cap
// response reads, and route error bodies through readCFErrorMessage /
// sanitizeErrorMessage (§1/§4 SECURITY-REVIEW.md).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cfPreflightReadCap bounds every success-body read. The largest response we
// parse is one page of 100 list summaries — far below this cap.
const cfPreflightReadCap = 1 << 20 // 1 MiB

// cfListInfo is the subset of a Cloudflare list object the preflight needs.
type cfListInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
}

// cfFindList looks the named Custom List up on the account. Returns nil (no
// error) when the list does not exist. A single page of 100 covers every
// current Cloudflare plan's list quota with room to spare.
func cfFindList(ctx context.Context, client cfClient, base, accountID, listName, token string) (*cfListInfo, error) {
	url := fmt.Sprintf("%s/accounts/%s/rules/lists?per_page=100", base, accountID)
	status, body, err := doCFJSON(ctx, client, http.MethodGet, url, token, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		_, msg := readCFErrorCodeMessage(bytes.NewReader(body))
		if msg == "" {
			return nil, fmt.Errorf("listing Custom Lists failed (HTTP %d)", status)
		}
		return nil, fmt.Errorf("listing Custom Lists failed (HTTP %d: %s)", status, msg)
	}
	var envelope struct {
		Success bool         `json:"success"`
		Result  []cfListInfo `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("parsing Custom Lists response: %w", err)
	}
	for i := range envelope.Result {
		if envelope.Result[i].Name == listName {
			return &envelope.Result[i], nil
		}
	}
	return nil, nil
}

// cfEnsureListResult reports what cfEnsureList did.
type cfEnsureListResult struct {
	// Adopted is true when a list with the configured name already existed
	// and will be reused; false when a fresh list was created.
	Adopted bool
	// Items is the current item count of an adopted list (0 for created).
	Items int
	// QuotaExceeded is set alongside a non-nil error when Cloudflare
	// refused the create in a way that looks like a plan-quota limit —
	// the caller renders the "free accounts get a single custom list"
	// explanation instead of a bare API error.
	QuotaExceeded bool
}

// cfEnsureList implements create-or-adopt for lists mode: if the configured
// list exists it is adopted as-is; otherwise the preflight creates it right
// now, so a quota refusal surfaces while the operator is still at the
// prompt instead of during the first armed sync.
func cfEnsureList(ctx context.Context, client cfClient, base, accountID, listName, token string) (cfEnsureListResult, error) {
	var res cfEnsureListResult

	existing, err := cfFindList(ctx, client, base, accountID, listName, token)
	if err != nil {
		return res, err
	}
	if existing != nil {
		res.Adopted = true
		res.Items = existing.NumItems
		return res, nil
	}

	payload := map[string]string{
		"name":        listName,
		"kind":        "ip",
		"description": "EzyShield managed blocklist — do not edit manually",
	}
	url := fmt.Sprintf("%s/accounts/%s/rules/lists", base, accountID)
	status, body, err := doCFJSON(ctx, client, http.MethodPost, url, token, payload)
	if err != nil {
		return res, err
	}
	if status == http.StatusOK || status == http.StatusCreated {
		return res, nil
	}

	code, msg := readCFErrorCodeMessage(bytes.NewReader(body))
	res.QuotaExceeded = cfLooksLikeQuotaError(msg)
	if msg == "" {
		return res, fmt.Errorf("creating Custom List %q failed (HTTP %d)", listName, status)
	}
	return res, fmt.Errorf("creating Custom List %q failed (HTTP %d, code %d: %s)", listName, status, code, msg)
}

// cfLooksLikeQuotaError classifies a create-refusal message as "plan quota
// exhausted". Cloudflare does not document a stable error code for the
// list-quota case, so this is a deliberately conservative keyword match on
// the (sanitized) message; a false negative just means the operator sees
// the raw API message without the plan explanation.
func cfLooksLikeQuotaError(msg string) bool {
	m := strings.ToLower(msg)
	for _, kw := range []string{"quota", "limit", "maximum", "exceed", "allowed number"} {
		if strings.Contains(m, kw) {
			return true
		}
	}
	return false
}

// cfCountZoneRules returns how many WAF custom rules currently occupy the
// zone's http_request_firewall_custom entrypoint ruleset. A 404 means the
// entrypoint ruleset was never created — zero rules in use.
func cfCountZoneRules(ctx context.Context, client cfClient, base, zoneID, token string) (int, error) {
	url := fmt.Sprintf("%s/zones/%s/rulesets/phases/http_request_firewall_custom/entrypoint", base, zoneID)
	status, body, err := doCFJSON(ctx, client, http.MethodGet, url, token, nil)
	if err != nil {
		return 0, err
	}
	switch status {
	case http.StatusOK:
		var envelope struct {
			Result struct {
				Rules []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"result"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			return 0, fmt.Errorf("parsing zone ruleset response: %w", err)
		}
		return len(envelope.Result.Rules), nil
	case http.StatusNotFound:
		return 0, nil
	default:
		_, msg := readCFErrorCodeMessage(bytes.NewReader(body))
		if msg == "" {
			return 0, fmt.Errorf("reading zone %s WAF rules failed (HTTP %d)", zoneID, status)
		}
		return 0, fmt.Errorf("reading zone %s WAF rules failed (HTTP %d: %s)", zoneID, status, msg)
	}
}

// doCFJSON issues one Cloudflare API call and returns the status plus the
// bounded response body. The token travels only in the Authorization
// header (never URL or query), matching doCFGet. Body is returned raw so
// callers can parse success envelopes or route failures through
// readCFErrorCodeMessage.
func doCFJSON(ctx context.Context, client cfClient, method, url, token string, payload any) (int, []byte, error) {
	var reqBody io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, fmt.Errorf("encoding request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody) //nolint:gosec // G107: url is compile-time base + IDs validated to [a-f0-9]{32} / [A-Za-z0-9_]+
	if err != nil {
		return 0, nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ezyshield-cf-preflight")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if client == nil {
		client = defaultCFPreflightClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("cloudflare API unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfPreflightReadCap))
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// defaultCFPreflightClient is the production HTTP client for preflight
// calls; tests always inject a fake via the cfClient parameter.
var defaultCFPreflightClient cfClient = &http.Client{Timeout: 8 * time.Second}

// readCFErrorCodeMessage is readCFErrorMessage's sibling that also surfaces
// the first error code, needed to keep raw Cloudflare codes greppable in
// actionable messages.
func readCFErrorCodeMessage(body io.Reader) (int, string) {
	const maxBytes = 4 << 10
	buf, err := io.ReadAll(io.LimitReader(body, maxBytes))
	if err != nil {
		return 0, ""
	}
	var e cfErrorResponse
	if err := json.Unmarshal(buf, &e); err != nil {
		return 0, ""
	}
	if len(e.Errors) == 0 {
		return 0, ""
	}
	return e.Errors[0].Code, sanitizeErrorMessage(e.Errors[0].Message)
}

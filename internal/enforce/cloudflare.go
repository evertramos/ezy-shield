package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	cfBaseURL      = "https://api.cloudflare.com/client/v4"
	cfMaxRPS       = 4.0 // 1200 req/5 min = 4 req/s
	cfRulePhase    = "http_request_firewall_custom"
	cfDescBase     = "ezyshield-blocklist"
	cfExprMax      = 3900 // split rule when expression would exceed this byte count
	cfDebounceTime = 5 * time.Second
)

// cfRateLimiter enforces a minimum interval between outbound API calls.
type cfRateLimiter struct {
	mu       sync.Mutex
	last     time.Time
	interval time.Duration
}

func newCFRateLimiter(rps float64) *cfRateLimiter {
	return &cfRateLimiter{interval: time.Duration(float64(time.Second) / rps)}
}

func (r *cfRateLimiter) wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()
	var wait time.Duration
	if next := r.last.Add(r.interval); next.After(now) {
		wait = next.Sub(now)
		r.last = next
	} else {
		r.last = now
	}
	r.mu.Unlock()
	if wait == 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

// zoneState tracks the desired IP set and CF identifiers for one zone.
type zoneState struct {
	mu         sync.Mutex
	discovered bool              // true after first CF discovery query
	rulesetID  string            // empty until discovered or created
	ruleIDs    map[string]string // description → CF rule ID
	ips        map[string]struct{}
	timer      *time.Timer
}

func newZoneState() *zoneState {
	return &zoneState{
		ruleIDs: make(map[string]string),
		ips:     make(map[string]struct{}),
	}
}

// CloudflareEnforcer maintains a single WAF Custom Rule per zone (phase=http_request_firewall_custom)
// containing all blocked IPs in one expression: (ip.src in {ip1 ip2 cidr3}).
// When the expression exceeds cfExprMax bytes (~200 IPs), additional rules are created
// with descriptions ezyshield-blocklist-2, ezyshield-blocklist-3, …
// The API token is resolved once at construction time and never appears in logs or errors.
type CloudflareEnforcer struct {
	client           *http.Client
	token            string // never logged or included in error messages
	zoneIDs          []string
	action           string
	baseURL          string
	limiter          *cfRateLimiter
	allowlist        []netip.Prefix
	debounceInterval time.Duration   // 0 = push synchronously (test mode)
	exprMax          int             // max expression bytes; 0 uses cfExprMax
	svcCtx           context.Context // service lifetime context for background debounce flushes

	zmu   sync.Mutex
	zones map[string]*zoneState
}

// NewCloudflareEnforcer constructs a Cloudflare enforcer from cfg. It dispatches
// on cfg.Mode: empty or "lists" → CloudflareListsEnforcer (account-level Lists
// API, default), "rulesets" → CloudflareEnforcer (per-zone WAF Custom Rules,
// legacy). ctx is the service lifetime context; background debounce flushes
// are bounded by it.
func NewCloudflareEnforcer(ctx context.Context, cfg *config.CloudflareCfg, allowlist []netip.Prefix) (sdk.Enforcer, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = "lists"
	}
	switch mode {
	case "lists":
		return NewCloudflareListsEnforcer(ctx, cfg, allowlist)
	case "rulesets":
		return newCloudflareRulesetsEnforcer(ctx, cfg, allowlist)
	default:
		// Validation should have caught this; fail safely (no API calls).
		return nil, fmt.Errorf("enforce/cloudflare: unknown mode %q", cfg.Mode)
	}
}

// newCloudflareRulesetsEnforcer constructs the legacy per-zone Rulesets
// enforcer from cfg.
func newCloudflareRulesetsEnforcer(ctx context.Context, cfg *config.CloudflareCfg, allowlist []netip.Prefix) (*CloudflareEnforcer, error) {
	token, err := cfg.APIToken.Resolve()
	if err != nil {
		return nil, fmt.Errorf("enforce/cloudflare: resolve api_token: %w", err)
	}
	action := cfg.Action
	if action == "" {
		action = "block"
	}
	return &CloudflareEnforcer{
		client:           &http.Client{Timeout: 10 * time.Second},
		token:            token,
		zoneIDs:          cfg.ZoneIDs,
		action:           action,
		baseURL:          cfBaseURL,
		limiter:          newCFRateLimiter(cfMaxRPS),
		allowlist:        allowlist,
		debounceInterval: cfDebounceTime,
		exprMax:          cfExprMax,
		zones:            make(map[string]*zoneState),
		svcCtx:           ctx,
	}, nil
}

// newCFEnforcerForTest constructs an enforcer pointed at a test base URL with
// synchronous push (debounceInterval=0) and no rate limiting.
func newCFEnforcerForTest(token, baseURL string, zoneIDs []string) *CloudflareEnforcer {
	return newCFEnforcerForTestWithCtx(context.Background(), token, baseURL, zoneIDs)
}

func newCFEnforcerForTestWithCtx(ctx context.Context, token, baseURL string, zoneIDs []string) *CloudflareEnforcer {
	return &CloudflareEnforcer{
		client:           &http.Client{Timeout: 5 * time.Second},
		token:            token,
		zoneIDs:          zoneIDs,
		action:           "block",
		baseURL:          baseURL,
		limiter:          newCFRateLimiter(1000), // no throttle in tests
		debounceInterval: 0,                      // synchronous push
		exprMax:          cfExprMax,
		zones:            make(map[string]*zoneState),
		svcCtx:           ctx,
	}
}

// Name implements sdk.Enforcer.
func (e *CloudflareEnforcer) Name() string { return "cloudflare" }

// Ban adds the target IP/CIDR to every configured zone's ezyshield WAF rule.
// Returns an error without touching the API if the target is allowlisted.
// ASN/Country targets are not supported.
func (e *CloudflareEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	if e.isAllowlisted(t) {
		k, _ := targetKey(t)
		return fmt.Errorf("enforce/cloudflare: refusing to ban allowlisted target %s", k)
	}
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/cloudflare Ban: %w", err)
	}
	for _, zone := range e.zoneIDs {
		z := e.getOrCreateZone(zone)
		z.mu.Lock()
		z.ips[ip] = struct{}{}
		z.mu.Unlock()
		if err := e.scheduleFlush(ctx, zone, z); err != nil {
			return fmt.Errorf("enforce/cloudflare Ban zone %s: %w", zone, err)
		}
	}
	return nil
}

// Unban removes the target IP/CIDR from every zone's ezyshield WAF rule.
func (e *CloudflareEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/cloudflare Unban: %w", err)
	}
	for _, zone := range e.zoneIDs {
		z := e.getOrCreateZone(zone)
		z.mu.Lock()
		delete(z.ips, ip)
		z.mu.Unlock()
		if err := e.scheduleFlush(ctx, zone, z); err != nil {
			return fmt.Errorf("enforce/cloudflare Unban zone %s: %w", zone, err)
		}
	}
	return nil
}

// Sync replaces each zone's ezyshield blocklist with exactly the given targets.
// Allowlisted targets are silently skipped. Push is always synchronous.
func (e *CloudflareEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	wantSet := make(map[string]struct{}, len(want))
	for _, t := range want {
		if e.isAllowlisted(t) {
			continue
		}
		k, err := targetKey(t)
		if err != nil {
			slog.WarnContext(ctx, "enforce/cloudflare Sync: skip unsupported target", "err", err)
			continue
		}
		wantSet[k] = struct{}{}
	}
	for _, zone := range e.zoneIDs {
		z := e.getOrCreateZone(zone)
		z.mu.Lock()
		// Copy wantSet so concurrent Ban calls can safely modify z.ips later.
		ipsCopy := make(map[string]struct{}, len(wantSet))
		for k := range wantSet {
			ipsCopy[k] = struct{}{}
		}
		z.ips = ipsCopy
		if z.timer != nil {
			z.timer.Stop()
			z.timer = nil
		}
		z.mu.Unlock()
		if err := e.pushZone(ctx, zone, z); err != nil {
			return fmt.Errorf("enforce/cloudflare Sync zone %s: %w", zone, err)
		}
	}
	return nil
}

// scheduleFlush either pushes immediately (debounceInterval==0) or resets
// a per-zone debounce timer so that rapid Ban/Unban calls are coalesced
// into a single CF API push after cfDebounceTime of silence.
func (e *CloudflareEnforcer) scheduleFlush(ctx context.Context, zone string, z *zoneState) error {
	if e.debounceInterval == 0 {
		return e.pushZone(ctx, zone, z)
	}
	z.mu.Lock()
	if z.timer != nil {
		z.timer.Stop()
	}
	z.timer = time.AfterFunc(e.debounceInterval, func() {
		if e.svcCtx.Err() != nil {
			return // service is shutting down; skip the flush
		}
		flushCtx, cancel := context.WithTimeout(e.svcCtx, 30*time.Second)
		defer cancel()
		if err := e.pushZone(flushCtx, zone, z); err != nil {
			slog.Error("enforce/cloudflare: debounced push failed", "zone", zone, "err", err)
		}
	})
	z.mu.Unlock()
	return nil
}

// pushZone builds expressions from z.ips and reconciles them against CF.
func (e *CloudflareEnforcer) pushZone(ctx context.Context, zone string, z *zoneState) error {
	// Snapshot current IP set and cached CF identifiers.
	z.mu.Lock()
	ipsCopy := make(map[string]struct{}, len(z.ips))
	for ip := range z.ips {
		ipsCopy[ip] = struct{}{}
	}
	needsDiscover := !z.discovered
	rulesetID := z.rulesetID
	ruleIDsCopy := make(map[string]string, len(z.ruleIDs))
	for k, v := range z.ruleIDs {
		ruleIDsCopy[k] = v
	}
	z.mu.Unlock()

	// Discover current CF state if we haven't yet (at most once per zone per daemon run).
	if needsDiscover {
		rsID, rIDs, err := e.discoverZone(ctx, zone)
		if err != nil {
			return err
		}
		z.mu.Lock()
		if !z.discovered {
			z.discovered = true
			z.rulesetID = rsID
			for d, id := range rIDs {
				z.ruleIDs[d] = id
			}
		}
		rulesetID = z.rulesetID
		for k, v := range z.ruleIDs {
			ruleIDsCopy[k] = v
		}
		z.mu.Unlock()
	}

	exprs := e.buildExpressions(ipsCopy)

	// Empty set: delete all our managed rules.
	if len(exprs) == 0 {
		for desc, ruleID := range ruleIDsCopy {
			slog.InfoContext(ctx, "enforce/cloudflare: deleting rule (empty blocklist)", "zone", zone, "desc", desc)
			if err := e.deleteRulesetRule(ctx, zone, rulesetID, ruleID); err != nil {
				return err
			}
			z.mu.Lock()
			delete(z.ruleIDs, desc)
			z.mu.Unlock()
		}
		return nil
	}

	// Build desired state: description → expression.
	desired := make(map[string]string, len(exprs))
	for i, expr := range exprs {
		desired[ruleDesc(i)] = expr
	}

	newRuleIDs := make(map[string]string, len(desired))

	// Create or patch each desired rule.
	for desc, expr := range desired {
		if ruleID, ok := ruleIDsCopy[desc]; ok {
			if err := e.patchRule(ctx, zone, rulesetID, ruleID, desc, expr); err != nil {
				return err
			}
			newRuleIDs[desc] = ruleID
		} else if rulesetID != "" {
			id, err := e.createRule(ctx, zone, rulesetID, desc, expr)
			if err != nil {
				return err
			}
			newRuleIDs[desc] = id
			z.mu.Lock()
			z.ruleIDs[desc] = id
			z.mu.Unlock()
		} else {
			// No ruleset at all: create the ruleset with the first rule inline.
			rsID, rID, err := e.createRulesetWithRule(ctx, zone, desc, expr)
			if err != nil {
				return err
			}
			rulesetID = rsID
			newRuleIDs[desc] = rID
			z.mu.Lock()
			z.rulesetID = rsID
			z.ruleIDs[desc] = rID
			z.mu.Unlock()
		}
	}

	// Delete any rules that are no longer needed (e.g. blocklist shrank below split threshold).
	for desc, ruleID := range ruleIDsCopy {
		if _, ok := desired[desc]; !ok {
			slog.InfoContext(ctx, "enforce/cloudflare: deleting obsolete split rule", "zone", zone, "desc", desc)
			if err := e.deleteRulesetRule(ctx, zone, rulesetID, ruleID); err != nil {
				return err
			}
		}
	}

	z.mu.Lock()
	z.ruleIDs = newRuleIDs
	z.mu.Unlock()
	return nil
}

// ── CF API discovery ──────────────────────────────────────────────────────────

// discoverZone returns the zone's custom-firewall ruleset ID and the IDs of
// any ezyshield-managed rules within it. Returns ("", {}, nil) when CF has no
// custom firewall ruleset yet.
func (e *CloudflareEnforcer) discoverZone(ctx context.Context, zone string) (rulesetID string, ruleIDs map[string]string, err error) {
	ruleIDs = make(map[string]string)

	// Step 1: find phase=http_request_firewall_custom ruleset.
	if err := e.limiter.wait(ctx); err != nil {
		return "", nil, err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets", e.baseURL, zone)
	resp, err := e.doRequest(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var ls cfListRulesetsResp
	if err := json.NewDecoder(resp.Body).Decode(&ls); err != nil {
		return "", nil, fmt.Errorf("decode list rulesets: %w", err)
	}
	if !ls.Success {
		return "", nil, fmt.Errorf("cloudflare list rulesets: %s", cfErrMsg(ls.Errors))
	}
	for _, rs := range ls.Result {
		if rs.Phase == cfRulePhase {
			rulesetID = rs.ID
			break
		}
	}
	if rulesetID == "" {
		return "", ruleIDs, nil
	}

	// Step 2: scan the ruleset for our managed rules.
	if err := e.limiter.wait(ctx); err != nil {
		return "", nil, err
	}
	url2 := fmt.Sprintf("%s/zones/%s/rulesets/%s", e.baseURL, zone, rulesetID)
	resp2, err := e.doRequest(ctx, http.MethodGet, url2, nil)
	if err != nil {
		return "", nil, err
	}
	defer resp2.Body.Close() //nolint:errcheck
	var gr cfGetRulesetResp
	if err := json.NewDecoder(resp2.Body).Decode(&gr); err != nil {
		return "", nil, fmt.Errorf("decode ruleset: %w", err)
	}
	if !gr.Success {
		return "", nil, fmt.Errorf("cloudflare get ruleset: %s", cfErrMsg(gr.Errors))
	}
	for _, rule := range gr.Result.Rules {
		if isEzyshieldDesc(rule.Description) {
			ruleIDs[rule.Description] = rule.ID
		}
	}
	return rulesetID, ruleIDs, nil
}

// ── CF API mutators ───────────────────────────────────────────────────────────

func (e *CloudflareEnforcer) createRulesetWithRule(ctx context.Context, zone, desc, expr string) (rulesetID, ruleID string, err error) {
	body, err := json.Marshal(cfCreateRulesetReq{
		Name:  "Custom rules",
		Kind:  "zone",
		Phase: cfRulePhase,
		Rules: []cfRuleReq{{Action: e.action, Expression: expr, Description: desc}},
	})
	if err != nil {
		return "", "", fmt.Errorf("marshal create ruleset: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return "", "", err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets", e.baseURL, zone)
	resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfCreateRulesetResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", fmt.Errorf("decode create ruleset: %w", err)
	}
	if !out.Success {
		return "", "", fmt.Errorf("cloudflare create ruleset: %s", cfErrMsg(out.Errors))
	}
	if len(out.Result.Rules) == 0 {
		return "", "", fmt.Errorf("cloudflare create ruleset: no rule in response")
	}
	slog.InfoContext(ctx, "enforce/cloudflare: created ruleset+rule",
		"zone", zone, "ruleset_id", out.Result.ID, "rule_id", out.Result.Rules[0].ID, "desc", desc)
	return out.Result.ID, out.Result.Rules[0].ID, nil
}

func (e *CloudflareEnforcer) createRule(ctx context.Context, zone, rulesetID, desc, expr string) (string, error) {
	body, err := json.Marshal(cfRuleReq{Action: e.action, Expression: expr, Description: desc})
	if err != nil {
		return "", fmt.Errorf("marshal create rule: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules", e.baseURL, zone, rulesetID)
	resp, err := e.doRequest(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfRuleWriteResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode create rule: %w", err)
	}
	if !out.Success {
		return "", fmt.Errorf("cloudflare create rule: %s", cfErrMsg(out.Errors))
	}
	if out.Result == nil {
		return "", fmt.Errorf("cloudflare create rule: empty response")
	}
	slog.InfoContext(ctx, "enforce/cloudflare: created rule", "zone", zone, "desc", desc, "rule_id", out.Result.ID)
	return out.Result.ID, nil
}

func (e *CloudflareEnforcer) patchRule(ctx context.Context, zone, rulesetID, ruleID, desc, expr string) error {
	body, err := json.Marshal(cfRuleReq{Action: e.action, Expression: expr, Description: desc})
	if err != nil {
		return fmt.Errorf("marshal patch rule: %w", err)
	}
	if err := e.limiter.wait(ctx); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules/%s", e.baseURL, zone, rulesetID, ruleID)
	resp, err := e.doRequest(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfRuleWriteResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode patch rule: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("cloudflare patch rule: %s", cfErrMsg(out.Errors))
	}
	slog.InfoContext(ctx, "enforce/cloudflare: patched rule", "zone", zone, "desc", desc, "rule_id", ruleID)
	return nil
}

func (e *CloudflareEnforcer) deleteRulesetRule(ctx context.Context, zone, rulesetID, ruleID string) error {
	if err := e.limiter.wait(ctx); err != nil {
		return err
	}
	url := fmt.Sprintf("%s/zones/%s/rulesets/%s/rules/%s", e.baseURL, zone, rulesetID, ruleID)
	resp, err := e.doRequest(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out cfRuleWriteResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("decode delete rule: %w", err)
	}
	if !out.Success {
		return fmt.Errorf("cloudflare delete rule: %s", cfErrMsg(out.Errors))
	}
	slog.InfoContext(ctx, "enforce/cloudflare: deleted rule", "zone", zone, "rule_id", ruleID)
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildExpressions converts the IP set into one or more Cloudflare filter
// expressions of the form (ip.src in {a b c …}), splitting at e.exprMax bytes.
func (e *CloudflareEnforcer) buildExpressions(ips map[string]struct{}) []string {
	if len(ips) == 0 {
		return nil
	}
	sorted := make([]string, 0, len(ips))
	for ip := range ips {
		sorted = append(sorted, ip)
	}
	sort.Strings(sorted)

	const prefix = "(ip.src in {"
	const suffix = "})"
	limit := e.exprMax
	if limit == 0 {
		limit = cfExprMax
	}

	var exprs []string
	var cur strings.Builder
	cur.WriteString(prefix)
	empty := true

	for _, ip := range sorted {
		addLen := len(ip)
		if !empty {
			addLen++ // space separator
		}
		// Would exceed limit when we close the expression?
		if !empty && cur.Len()+addLen+len(suffix) > limit {
			cur.WriteString(suffix)
			exprs = append(exprs, cur.String())
			cur.Reset()
			cur.WriteString(prefix)
			cur.WriteString(ip)
			// empty stays false; first entry in new chunk
		} else {
			if !empty {
				cur.WriteByte(' ')
			}
			cur.WriteString(ip)
			empty = false
		}
	}
	if !empty {
		cur.WriteString(suffix)
		exprs = append(exprs, cur.String())
	}
	return exprs
}

func (e *CloudflareEnforcer) getOrCreateZone(zone string) *zoneState {
	e.zmu.Lock()
	defer e.zmu.Unlock()
	if z, ok := e.zones[zone]; ok {
		return z
	}
	z := newZoneState()
	e.zones[zone] = z
	return z
}

// doRequest sets auth headers and executes the HTTP request.
// The token never appears in returned errors.
func (e *CloudflareEnforcer) doRequest(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("create request %s %s: %w", method, url, err)
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http %s %s: %w", method, url, err)
	}
	return resp, nil
}

func (e *CloudflareEnforcer) isAllowlisted(t sdk.Target) bool {
	addr, ok := targetAddr(t)
	if !ok {
		return false
	}
	for _, p := range e.allowlist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ruleDesc returns the CF rule description for the i-th (0-based) chunk.
// Chunk 0 → "ezyshield-blocklist"; chunk 1 → "ezyshield-blocklist-2"; etc.
func ruleDesc(i int) string {
	if i == 0 {
		return cfDescBase
	}
	return fmt.Sprintf("%s-%d", cfDescBase, i+1)
}

// isEzyshieldDesc returns true when desc is one of our managed rule descriptions.
func isEzyshieldDesc(desc string) bool {
	if desc == cfDescBase {
		return true
	}
	if !strings.HasPrefix(desc, cfDescBase+"-") {
		return false
	}
	suffix := desc[len(cfDescBase)+1:]
	if len(suffix) == 0 {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func cfErrMsg(errs []cfAPIError) string {
	if len(errs) == 0 {
		return "unknown error"
	}
	parts := make([]string, len(errs))
	for i, ce := range errs {
		parts[i] = fmt.Sprintf("%d: %s", ce.Code, ce.Message)
	}
	return strings.Join(parts, "; ")
}

// ── Cloudflare Rulesets API wire types ───────────────────────────────────────

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfRulesetInfo struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

type cfListRulesetsResp struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  []cfRulesetInfo `json:"result"`
}

type cfWAFRule struct {
	ID          string `json:"id"`
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
}

type cfRulesetDetail struct {
	ID    string      `json:"id"`
	Phase string      `json:"phase"`
	Rules []cfWAFRule `json:"rules"`
}

type cfGetRulesetResp struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  cfRulesetDetail `json:"result"`
}

type cfRuleReq struct {
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
}

type cfCreateRulesetReq struct {
	Name  string      `json:"name"`
	Kind  string      `json:"kind"`
	Phase string      `json:"phase"`
	Rules []cfRuleReq `json:"rules"`
}

type cfCreateRulesetResp struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  cfRulesetDetail `json:"result"`
}

type cfRuleWriteResp struct {
	Success bool         `json:"success"`
	Errors  []cfAPIError `json:"errors"`
	Result  *cfWAFRule   `json:"result"`
}

// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// bunny.net edge enforcer (issue #197): applies bans at the CDN edge via the
// Pull Zone blocked-IPs API, following the Cloudflare enforcer's contract
// (reconciling Sync, per-zone failure isolation, env-only secrets, throttle
// backoff, secret-leak discipline).
//
// API (verified 2026-08-25, documented in issue #197):
//   GET  https://api.bunny.net/pullzone/{id}            → {BlockedIps: []string}
//   POST https://api.bunny.net/pullzone/{id}/addBlockedIp    {"BlockedIp": ip} → 204
//   POST https://api.bunny.net/pullzone/{id}/removeBlockedIp {"BlockedIp": ip} → 204
// Auth: AccessKey header. The Bunny Shield access lists were rejected: they
// need a separate shield zone and gate custom lists/rules behind paid tiers,
// while the pull-zone API works on every plan and maps 1:1 onto Ban/Unban.
//
// OWNERSHIP: bunny's BlockedIps is a flat string list with no way to tag
// entries, so EzyShield takes ownership of the whole list on the configured
// zones — Sync removes every entry it does not manage, including IPs an
// operator added by hand in the bunny panel. This is documented operator-
// facing in the follow-up config/docs issue (#198).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	bunnyBaseURL = "https://api.bunny.net"
	// bunnyMaxRPS is a conservative self-imposed outbound rate — bunny does
	// not document an API quota.
	bunnyMaxRPS = 4.0
	// DefaultBunnyZoneCap bounds the blocked-IP set per pull zone. bunny
	// does not document a provider limit, so this is a deliberate,
	// conservative cap: beyond it the enforcer keeps the most recent bans
	// (evicting the oldest) and logs a clear warning.
	DefaultBunnyZoneCap = 500
	// bunnyMaxRespBytes bounds how much of an API response is ever read —
	// responses are untrusted input.
	bunnyMaxRespBytes = 1 << 20
	// bunnyErrSnippet caps how much of an error body makes it into wrapped
	// error messages.
	bunnyErrSnippet = 256
)

// bunnyRetryDelays is the backoff schedule between throttled/5xx mutation
// attempts (len+1 attempts total; jittered and stretched to Retry-After by
// cfBackoffWait, which is provider-agnostic).
var bunnyRetryDelays = []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}

// BunnyConfig configures one bunny.net enforcer. The config-file section,
// wizard, and docs wiring live in the follow-up issue (#198) — until then
// this struct is constructed programmatically.
type BunnyConfig struct {
	// AccessKey is the bunny.net account API key — env-reference only,
	// resolved once at construction and never logged.
	AccessKey config.SecretRef
	// PullZoneIDs are the pull zones the blocklist applies to.
	PullZoneIDs []int64
	// Name optionally labels this instance (multi-account deployments);
	// surfaces as "bunny[<name>]" in logs.
	Name string
}

// bunnyZoneState tracks, per pull zone, the entries this enforcer manages —
// insertion-ordered so the capacity guard can evict oldest-first. It is a
// cache of remote state: authoritative only after the first successful Sync.
type bunnyZoneState struct {
	mu      sync.Mutex
	synced  bool
	order   []string // oldest → newest
	present map[string]struct{}
}

// BunnyEnforcer implements sdk.Enforcer against the bunny.net pull-zone
// blocked-IPs API. The AccessKey never appears in logs or error messages.
type BunnyEnforcer struct {
	client       *http.Client
	accessKey    string // never logged or included in error messages
	instanceName string
	pullZoneIDs  []int64
	baseURL      string
	limiter      *cfRateLimiter
	allowlist    []netip.Prefix
	retryDelays  []time.Duration
	zoneCap      int

	zmu   sync.Mutex
	zones map[int64]*bunnyZoneState
}

// NewBunnyEnforcer constructs a bunny.net enforcer. The access key is
// resolved once here; a missing env var fails construction, not enforcement.
func NewBunnyEnforcer(cfg *BunnyConfig, allowlist []netip.Prefix) (*BunnyEnforcer, error) {
	key, err := cfg.AccessKey.Resolve()
	if err != nil {
		return nil, fmt.Errorf("enforce/bunny: resolve access key: %w", err)
	}
	if len(cfg.PullZoneIDs) == 0 {
		return nil, fmt.Errorf("enforce/bunny: at least one pull zone id is required")
	}
	return &BunnyEnforcer{
		client:       &http.Client{Timeout: 10 * time.Second},
		accessKey:    key,
		instanceName: cfg.Name,
		pullZoneIDs:  cfg.PullZoneIDs,
		baseURL:      bunnyBaseURL,
		limiter:      newCFRateLimiter(bunnyMaxRPS),
		allowlist:    allowlist,
		retryDelays:  bunnyRetryDelays,
		zoneCap:      DefaultBunnyZoneCap,
		zones:        make(map[int64]*bunnyZoneState),
	}, nil
}

// newBunnyEnforcerForTest constructs an enforcer against a test base URL
// with a pre-resolved key and no meaningful rate limiting.
func newBunnyEnforcerForTest(key, baseURL string, zoneIDs []int64) *BunnyEnforcer {
	return &BunnyEnforcer{
		client:      &http.Client{Timeout: 5 * time.Second},
		accessKey:   key,
		pullZoneIDs: zoneIDs,
		baseURL:     baseURL,
		limiter:     newCFRateLimiter(1000),
		retryDelays: nil, // no backoff waits in tests unless set explicitly
		zoneCap:     DefaultBunnyZoneCap,
		zones:       make(map[int64]*bunnyZoneState),
	}
}

// Name implements sdk.Enforcer: "bunny", or "bunny[<name>]" when an instance
// name disambiguates multi-account deployments.
func (e *BunnyEnforcer) Name() string {
	if e.instanceName == "" {
		return "bunny"
	}
	return "bunny[" + e.instanceName + "]"
}

// Ban adds the target to every configured pull zone's blocked list.
// Allowlisted targets are refused without touching the API (belt-and-braces;
// the enforcement gate is the authoritative guard). At the per-zone capacity
// cap, the oldest managed entry is evicted first (most-recent-first policy).
func (e *BunnyEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	if e.isAllowlisted(t) {
		k, _ := targetKey(t)
		return fmt.Errorf("enforce/bunny: refusing to ban allowlisted target %s", k)
	}
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/bunny Ban: %w", err)
	}
	var errs []error
	for _, zone := range e.pullZoneIDs {
		if err := e.banZone(ctx, zone, ip); err != nil {
			errs = append(errs, fmt.Errorf("enforce/bunny Ban zone %d: %w", zone, err))
		}
	}
	return errors.Join(errs...)
}

func (e *BunnyEnforcer) banZone(ctx context.Context, zone int64, ip string) error {
	z := e.getOrCreateZone(zone)
	z.mu.Lock()
	defer z.mu.Unlock()
	if _, ok := z.present[ip]; ok {
		return nil // already managed: the API list is a set, skip the call
	}
	if len(z.order) >= e.zoneCap {
		oldest := z.order[0]
		slog.Warn("enforce/bunny: zone at blocked-IP capacity; evicting oldest ban (most-recent-first)",
			"zone", zone, "cap", e.zoneCap, "evicted", oldest)
		if err := e.mutateBlockedIP(ctx, zone, "removeBlockedIp", oldest); err != nil {
			return fmt.Errorf("evict oldest %s: %w", oldest, err)
		}
		z.order = z.order[1:]
		delete(z.present, oldest)
	}
	if err := e.mutateBlockedIP(ctx, zone, "addBlockedIp", ip); err != nil {
		return err
	}
	z.order = append(z.order, ip)
	z.present[ip] = struct{}{}
	return nil
}

// Unban removes the target from every configured pull zone's blocked list.
func (e *BunnyEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	ip, err := targetKey(t)
	if err != nil {
		return fmt.Errorf("enforce/bunny Unban: %w", err)
	}
	var errs []error
	for _, zone := range e.pullZoneIDs {
		z := e.getOrCreateZone(zone)
		z.mu.Lock()
		if err := e.mutateBlockedIP(ctx, zone, "removeBlockedIp", ip); err != nil {
			errs = append(errs, fmt.Errorf("enforce/bunny Unban zone %d: %w", zone, err))
		} else {
			delete(z.present, ip)
			for i, v := range z.order {
				if v == ip {
					z.order = append(z.order[:i], z.order[i+1:]...)
					break
				}
			}
		}
		z.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Sync reconciles every pull zone's blocked list to exactly the given
// targets: reads the remote list, adds what is missing, removes what is
// stale. Idempotent. A zone that fails is reported in the joined error while
// the remaining zones still reconcile (same semantics as the Cloudflare
// enforcer). Allowlisted targets are silently skipped. Beyond the capacity
// cap only the newest targets are kept (Sync input arrives in store
// insertion order, oldest first) with a clear warning.
func (e *BunnyEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	keys := make([]string, 0, len(want))
	seen := make(map[string]struct{}, len(want))
	for _, t := range want {
		if e.isAllowlisted(t) {
			continue
		}
		k, err := targetKey(t)
		if err != nil {
			slog.WarnContext(ctx, "enforce/bunny Sync: skip unsupported target", "err", err)
			continue
		}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	if len(keys) > e.zoneCap {
		dropped := len(keys) - e.zoneCap
		keys = keys[len(keys)-e.zoneCap:] // keep the newest (tail of insertion order)
		slog.WarnContext(ctx, "enforce/bunny Sync: desired set exceeds per-zone capacity; keeping most recent bans only",
			"cap", e.zoneCap, "dropped_oldest", dropped)
	}

	var errs []error
	for _, zone := range e.pullZoneIDs {
		if err := e.syncZone(ctx, zone, keys); err != nil {
			errs = append(errs, fmt.Errorf("enforce/bunny Sync zone %d: %w", zone, err))
		}
	}
	return errors.Join(errs...)
}

func (e *BunnyEnforcer) syncZone(ctx context.Context, zone int64, keys []string) error {
	remote, err := e.fetchBlockedIPs(ctx, zone)
	if err != nil {
		return err
	}
	wantSet := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		wantSet[k] = struct{}{}
	}

	z := e.getOrCreateZone(zone)
	z.mu.Lock()
	defer z.mu.Unlock()

	var opErrs []error
	// Remove stale entries first so the add pass never trips the capacity
	// cap against IPs that are about to leave anyway.
	for ip := range remote {
		if _, keep := wantSet[ip]; keep {
			continue
		}
		if err := e.mutateBlockedIP(ctx, zone, "removeBlockedIp", ip); err != nil {
			opErrs = append(opErrs, fmt.Errorf("remove stale %s: %w", ip, err))
		} else {
			delete(remote, ip)
		}
	}
	// Add missing entries in want order (oldest of the kept window first),
	// so in-memory order mirrors ban recency for future evictions.
	order := make([]string, 0, len(keys))
	present := make(map[string]struct{}, len(keys))
	for _, ip := range keys {
		if _, ok := remote[ip]; !ok {
			if err := e.mutateBlockedIP(ctx, zone, "addBlockedIp", ip); err != nil {
				opErrs = append(opErrs, fmt.Errorf("add %s: %w", ip, err))
				continue
			}
		}
		order = append(order, ip)
		present[ip] = struct{}{}
	}

	if len(opErrs) == 0 {
		z.synced = true
	}
	z.order = order
	z.present = present
	return errors.Join(opErrs...)
}

// fetchBlockedIPs reads the pull zone's current BlockedIps list. The
// response is untrusted: bounded read, typed decode, entries that do not
// parse as IPs or prefixes are ignored with a warning (they cannot have
// come from this enforcer).
func (e *BunnyEnforcer) fetchBlockedIPs(ctx context.Context, zone int64) (map[string]struct{}, error) {
	url := e.baseURL + "/pullzone/" + strconv.FormatInt(zone, 10)
	body, status, err := e.doWithRetry(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get pull zone: %s", bunnyStatusErr(status, body))
	}
	var pz struct {
		BlockedIps []string `json:"BlockedIps"`
	}
	if err := json.Unmarshal(body, &pz); err != nil {
		return nil, fmt.Errorf("get pull zone: malformed response: %w", err)
	}
	out := make(map[string]struct{}, len(pz.BlockedIps))
	for _, raw := range pz.BlockedIps {
		if _, err := netip.ParseAddr(raw); err != nil {
			if _, err2 := netip.ParsePrefix(raw); err2 != nil {
				slog.Warn("enforce/bunny: ignoring non-IP entry in remote blocked list", "zone", zone)
				continue
			}
		}
		out[raw] = struct{}{}
	}
	return out, nil
}

// mutateBlockedIP calls addBlockedIp/removeBlockedIp for one IP on one zone.
func (e *BunnyEnforcer) mutateBlockedIP(ctx context.Context, zone int64, verb, ip string) error {
	url := e.baseURL + "/pullzone/" + strconv.FormatInt(zone, 10) + "/" + verb
	payload, err := json.Marshal(map[string]string{"BlockedIp": ip})
	if err != nil {
		return fmt.Errorf("%s: encode: %w", verb, err)
	}
	body, status, err := e.doWithRetry(ctx, http.MethodPost, url, payload)
	if err != nil {
		return fmt.Errorf("%s: %w", verb, err)
	}
	if status != http.StatusNoContent && status != http.StatusOK {
		return fmt.Errorf("%s: %s", verb, bunnyStatusErr(status, body))
	}
	return nil
}

// doWithRetry performs one API call with the outbound rate limiter and a
// bounded retry-with-backoff on 429/5xx (len(retryDelays)+1 attempts).
// Returns the bounded response body and status; err covers transport-level
// failures and retry exhaustion by context. The AccessKey goes only into the
// request header — never into errors.
func (e *BunnyEnforcer) doWithRetry(ctx context.Context, method, url string, payload []byte) ([]byte, int, error) {
	attempts := len(e.retryDelays) + 1
	var (
		body   []byte
		status int
		err    error
	)
	for attempt := 0; attempt < attempts; attempt++ {
		var retryAfter time.Duration
		body, status, retryAfter, err = e.doOnce(ctx, method, url, payload)
		if err == nil && status != http.StatusTooManyRequests && status < 500 {
			return body, status, nil
		}
		if attempt == attempts-1 {
			break
		}
		if werr := cfBackoffWait(ctx, e.retryDelays, attempt, retryAfter); werr != nil {
			return nil, 0, werr
		}
	}
	if err != nil {
		return nil, 0, err
	}
	return body, status, nil
}

func (e *BunnyEnforcer) doOnce(ctx context.Context, method, url string, payload []byte) (respBody []byte, status int, retryAfter time.Duration, err error) {
	if err := e.limiter.wait(ctx); err != nil {
		return nil, 0, 0, err
	}
	var rdr io.Reader
	if payload != nil {
		rdr = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("AccessKey", e.accessKey)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		// Transport errors from net/http include the URL but never request
		// headers, so the AccessKey cannot leak here.
		return nil, 0, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, bunnyMaxRespBytes))
	if err != nil {
		return nil, resp.StatusCode, 0, fmt.Errorf("read response: %w", err)
	}
	return body, resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// bunnyStatusErr renders an API failure for error wrapping: status code plus
// the decoded ApiErrorData message when present, else a capped raw snippet.
// Response bodies are server-controlled and never contain the AccessKey.
func bunnyStatusErr(status int, body []byte) string {
	var apiErr struct {
		ErrorKey string `json:"ErrorKey"`
		Message  string `json:"Message"`
	}
	if err := json.Unmarshal(body, &apiErr); err == nil && (apiErr.Message != "" || apiErr.ErrorKey != "") {
		return fmt.Sprintf("HTTP %d: %s %s", status, apiErr.ErrorKey, apiErr.Message)
	}
	snippet := body
	if len(snippet) > bunnyErrSnippet {
		snippet = snippet[:bunnyErrSnippet]
	}
	return fmt.Sprintf("HTTP %d: %s", status, string(snippet))
}

func (e *BunnyEnforcer) getOrCreateZone(zone int64) *bunnyZoneState {
	e.zmu.Lock()
	defer e.zmu.Unlock()
	z, ok := e.zones[zone]
	if !ok {
		z = &bunnyZoneState{present: make(map[string]struct{})}
		e.zones[zone] = z
	}
	return z
}

// isAllowlisted reports whether the target's address falls inside any
// allowlist prefix (Hard Rule §1 belt-and-braces; the gate is authoritative).
func (e *BunnyEnforcer) isAllowlisted(t sdk.Target) bool {
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

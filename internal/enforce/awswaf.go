// SPDX-License-Identifier: AGPL-3.0-only

package enforce

// AWS WAFv2 IPSet enforcer (issue #200, per ADR-0012): applies bans at the
// AWS edge by maintaining two dedicated IPSets (IPv4 and IPv6) that the
// operator references from their WebACL rules. EzyShield mutates ONLY the
// member addresses of the IPSets designated in config — it never creates,
// lists, or touches WebACLs, and only the two API operations GetIPSet and
// UpdateIPSet exist in this file (the minimal IAM policy in ADR-0012 is
// exactly what this code needs).
//
// Wire protocol: WAFv2 is JSON-RPC over POST to
// https://wafv2.{region}.amazonaws.com/ with X-Amz-Target headers
// (AWSWAF_20190729.GetIPSet / UpdateIPSet), signed with SigV4 (sigv4.go).
// Credentials come from the standard AWS chain (awscreds.go) — never from
// EzyShield config files.
//
// Concurrency model: every mutation is read(Get + LockToken) → mutate →
// UpdateIPSet, retried on WAFOptimisticLockException (another writer won)
// and on 429/5xx with the shared bounded backoff. Context is honored
// throughout.

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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// awsWAFTargetPrefix is the JSON-RPC target header prefix for WAFv2.
	awsWAFTargetPrefix = "AWSWAF_20190729."
	// awsIPSetCap is the AWS-documented maximum addresses per IPSet.
	awsIPSetCap = 10000
	// awsWAFMaxRespBytes bounds how much of an API response is ever read.
	awsWAFMaxRespBytes = 1 << 20
	// awsWAFErrSnippet caps how much of an error body reaches wrapped errors.
	awsWAFErrSnippet = 256
	// awsWAFMaxRPS is a conservative self-imposed outbound rate.
	awsWAFMaxRPS = 4.0
	// awsLockRetries is how many times a mutation re-reads and retries after
	// losing the optimistic-lock race.
	awsLockRetries = 3
)

// awsWAFRetryDelays is the backoff schedule for throttled/5xx attempts.
var awsWAFRetryDelays = []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}

// AWSIPSetRef designates one IPSet this enforcer is allowed to mutate.
// Name+ID identify the set (both appear in the console/ARN); EzyShield
// only ever touches sets explicitly designated here.
type AWSIPSetRef struct {
	Name string
	ID   string
}

// AWSWAFConfig configures the AWS WAF enforcer. Credentials are NOT here —
// they come from the standard AWS chain, by ADR-0012.
type AWSWAFConfig struct {
	// Scope is "REGIONAL" or "CLOUDFRONT". CLOUDFRONT pins the region to
	// us-east-1, per the WAFv2 API contract.
	Scope string
	// Region for REGIONAL scope (e.g. "eu-west-1").
	Region string
	// IPSetV4/IPSetV6 designate the sets to maintain. At least one must be
	// set; a family with no set is skipped with a warning at ban time.
	IPSetV4 *AWSIPSetRef
	IPSetV6 *AWSIPSetRef
	// Name optionally labels this instance in logs ("awswaf[<name>]").
	Name string
}

// awsIPSetState caches the managed entries per set, insertion-ordered so
// the capacity guard keeps most-recent-first.
type awsIPSetState struct {
	mu      sync.Mutex
	order   []string
	present map[string]struct{}
}

// AWSWAFEnforcer implements sdk.Enforcer against AWS WAFv2 IPSets.
type AWSWAFEnforcer struct {
	client       *http.Client
	creds        *awsCredProvider
	endpoint     string // https://wafv2.{region}.amazonaws.com — overridable in tests
	region       string
	scope        string // "REGIONAL" | "CLOUDFRONT"
	instanceName string
	limiter      *cfRateLimiter
	allowlist    []netip.Prefix
	retryDelays  []time.Duration
	setCap       int
	now          func() time.Time

	v4, v6 *awsIPSetRuntime
}

// awsIPSetRuntime pairs one designated set with its local state.
type awsIPSetRuntime struct {
	ref   AWSIPSetRef
	state awsIPSetState
}

// NewAWSWAFEnforcer validates the config and constructs the enforcer.
// Credential resolution is lazy (first API call): on EC2 the IMDS route
// may need the network up, and a doctor check covers preflight (#201).
func NewAWSWAFEnforcer(cfg *AWSWAFConfig, allowlist []netip.Prefix) (*AWSWAFEnforcer, error) {
	scope := strings.ToUpper(cfg.Scope)
	region := cfg.Region
	switch scope {
	case "CLOUDFRONT":
		// The WAFv2 API contract: CLOUDFRONT-scoped calls go to us-east-1.
		region = "us-east-1"
	case "REGIONAL":
		if region == "" {
			return nil, fmt.Errorf("enforce/awswaf: scope REGIONAL requires a region")
		}
	default:
		return nil, fmt.Errorf("enforce/awswaf: scope must be REGIONAL or CLOUDFRONT, got %q", cfg.Scope)
	}
	if cfg.IPSetV4 == nil && cfg.IPSetV6 == nil {
		return nil, fmt.Errorf("enforce/awswaf: at least one of the v4/v6 IPSets must be designated")
	}
	e := &AWSWAFEnforcer{
		client:       &http.Client{Timeout: 15 * time.Second},
		creds:        newAWSCredProvider(),
		endpoint:     "https://wafv2." + region + ".amazonaws.com",
		region:       region,
		scope:        scope,
		instanceName: cfg.Name,
		limiter:      newCFRateLimiter(awsWAFMaxRPS),
		allowlist:    allowlist,
		retryDelays:  awsWAFRetryDelays,
		setCap:       awsIPSetCap,
		now:          time.Now,
	}
	if cfg.IPSetV4 != nil {
		e.v4 = &awsIPSetRuntime{ref: *cfg.IPSetV4, state: awsIPSetState{present: map[string]struct{}{}}}
	}
	if cfg.IPSetV6 != nil {
		e.v6 = &awsIPSetRuntime{ref: *cfg.IPSetV6, state: awsIPSetState{present: map[string]struct{}{}}}
	}
	return e, nil
}

// Name implements sdk.Enforcer.
func (e *AWSWAFEnforcer) Name() string {
	if e.instanceName == "" {
		return "awswaf"
	}
	return "awswaf[" + e.instanceName + "]"
}

// awsCIDR normalizes a target to the CIDR form WAFv2 requires: a bare
// address becomes /32 (v4) or /128 (v6); prefixes pass through unmapped.
// ASN/Country targets are unsupported.
func awsCIDR(t sdk.Target) (cidr string, v6 bool, err error) {
	if t.IP.IsValid() {
		a := t.IP.Unmap()
		return netip.PrefixFrom(a, a.BitLen()).String(), a.Is6(), nil
	}
	if t.Prefix.IsValid() {
		p := t.Prefix
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return "", false, fmt.Errorf("IPv4-mapped prefix %s broader than /96 has no IPv4 equivalent", p)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked().String(), p.Addr().Unmap().Is6(), nil
	}
	return "", false, fmt.Errorf("target must have IP or Prefix set (ASN/Country not supported by the AWS WAF enforcer)")
}

// setFor returns the runtime for the target's address family, or nil when
// no IPSet is designated for it.
func (e *AWSWAFEnforcer) setFor(v6 bool) *awsIPSetRuntime {
	if v6 {
		return e.v6
	}
	return e.v4
}

// Ban adds the target to its family's IPSet. Allowlisted targets are
// refused without touching the API (belt-and-braces; the enforcement gate
// is the authoritative guard). At capacity, the oldest managed entry is
// evicted (most-recent-first policy) with a loud warning.
func (e *AWSWAFEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	if e.isAllowlisted(t) {
		k, _ := targetKey(t)
		return fmt.Errorf("enforce/awswaf: refusing to ban allowlisted target %s", k)
	}
	cidr, v6, err := awsCIDR(t)
	if err != nil {
		return fmt.Errorf("enforce/awswaf Ban: %w", err)
	}
	rt := e.setFor(v6)
	if rt == nil {
		slog.WarnContext(ctx, "enforce/awswaf: no IPSet designated for this address family; ban skipped",
			"cidr", cidr, "v6", v6)
		return nil
	}
	rt.state.mu.Lock()
	defer rt.state.mu.Unlock()
	if _, ok := rt.state.present[cidr]; ok {
		return nil
	}
	drop := ""
	if len(rt.state.order) >= e.setCap {
		drop = rt.state.order[0]
		slog.WarnContext(ctx, "enforce/awswaf: IPSet at capacity; evicting oldest ban (most-recent-first)",
			"ipset", rt.ref.Name, "cap", e.setCap, "evicted", drop)
	}
	err = e.mutateIPSet(ctx, rt.ref, func(addrs map[string]struct{}) {
		if drop != "" {
			delete(addrs, drop)
		}
		addrs[cidr] = struct{}{}
	})
	if err != nil {
		return fmt.Errorf("enforce/awswaf Ban %s: %w", cidr, err)
	}
	if drop != "" {
		rt.state.order = rt.state.order[1:]
		delete(rt.state.present, drop)
	}
	rt.state.order = append(rt.state.order, cidr)
	rt.state.present[cidr] = struct{}{}
	return nil
}

// Unban removes the target from its family's IPSet.
func (e *AWSWAFEnforcer) Unban(ctx context.Context, t sdk.Target) error {
	cidr, v6, err := awsCIDR(t)
	if err != nil {
		return fmt.Errorf("enforce/awswaf Unban: %w", err)
	}
	rt := e.setFor(v6)
	if rt == nil {
		return nil
	}
	rt.state.mu.Lock()
	defer rt.state.mu.Unlock()
	if err := e.mutateIPSet(ctx, rt.ref, func(addrs map[string]struct{}) {
		delete(addrs, cidr)
	}); err != nil {
		return fmt.Errorf("enforce/awswaf Unban %s: %w", cidr, err)
	}
	delete(rt.state.present, cidr)
	for i, v := range rt.state.order {
		if v == cidr {
			rt.state.order = append(rt.state.order[:i], rt.state.order[i+1:]...)
			break
		}
	}
	return nil
}

// Sync reconciles each designated IPSet to exactly the given targets for
// its address family. Idempotent; allowlisted targets are skipped. Beyond
// capacity only the newest targets are kept (input arrives in store
// insertion order, oldest first) with a loud warning.
func (e *AWSWAFEnforcer) Sync(ctx context.Context, want []sdk.Target) error {
	var v4Keys, v6Keys []string
	seen := map[string]struct{}{}
	for _, t := range want {
		if e.isAllowlisted(t) {
			continue
		}
		cidr, v6, err := awsCIDR(t)
		if err != nil {
			slog.WarnContext(ctx, "enforce/awswaf Sync: skip unsupported target", "err", err)
			continue
		}
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		if v6 {
			v6Keys = append(v6Keys, cidr)
		} else {
			v4Keys = append(v4Keys, cidr)
		}
	}

	var errs []error
	if e.v4 != nil {
		if err := e.syncSet(ctx, e.v4, v4Keys); err != nil {
			errs = append(errs, fmt.Errorf("enforce/awswaf Sync %s: %w", e.v4.ref.Name, err))
		}
	}
	if e.v6 != nil {
		if err := e.syncSet(ctx, e.v6, v6Keys); err != nil {
			errs = append(errs, fmt.Errorf("enforce/awswaf Sync %s: %w", e.v6.ref.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (e *AWSWAFEnforcer) syncSet(ctx context.Context, rt *awsIPSetRuntime, keys []string) error {
	if len(keys) > e.setCap {
		dropped := len(keys) - e.setCap
		keys = keys[len(keys)-e.setCap:] // keep the newest (tail of insertion order)
		slog.WarnContext(ctx, "enforce/awswaf Sync: desired set exceeds IPSet capacity; keeping most recent bans only",
			"ipset", rt.ref.Name, "cap", e.setCap, "dropped_oldest", dropped)
	}
	rt.state.mu.Lock()
	defer rt.state.mu.Unlock()
	if err := e.mutateIPSet(ctx, rt.ref, func(addrs map[string]struct{}) {
		for a := range addrs {
			delete(addrs, a)
		}
		for _, k := range keys {
			addrs[k] = struct{}{}
		}
	}); err != nil {
		return err
	}
	rt.state.order = append([]string(nil), keys...)
	rt.state.present = make(map[string]struct{}, len(keys))
	for _, k := range keys {
		rt.state.present[k] = struct{}{}
	}
	return nil
}

// mutateIPSet is the read → mutate → write core: GetIPSet (addresses +
// LockToken), apply fn, UpdateIPSet with the token. On an optimistic-lock
// conflict (another writer won the race) it re-reads and retries, bounded.
func (e *AWSWAFEnforcer) mutateIPSet(ctx context.Context, ref AWSIPSetRef, fn func(map[string]struct{})) error {
	var lastErr error
	for attempt := 0; attempt <= awsLockRetries; attempt++ {
		addrs, lockToken, err := e.getIPSet(ctx, ref)
		if err != nil {
			return err
		}
		fn(addrs)
		err = e.updateIPSet(ctx, ref, addrs, lockToken)
		if err == nil {
			return nil
		}
		if !isAWSLockConflict(err) {
			return err
		}
		lastErr = err
		slog.DebugContext(ctx, "enforce/awswaf: optimistic-lock conflict; re-reading",
			"ipset", ref.Name, "attempt", attempt+1)
	}
	return fmt.Errorf("optimistic-lock retries exhausted: %w", lastErr)
}

// getIPSet performs AWSWAF_20190729.GetIPSet.
func (e *AWSWAFEnforcer) getIPSet(ctx context.Context, ref AWSIPSetRef) (map[string]struct{}, string, error) {
	payload := map[string]string{"Name": ref.Name, "Id": ref.ID, "Scope": e.scope}
	body, err := e.callWAF(ctx, "GetIPSet", payload)
	if err != nil {
		return nil, "", fmt.Errorf("GetIPSet: %w", err)
	}
	var resp struct {
		IPSet struct {
			Addresses []string `json:"Addresses"`
		} `json:"IPSet"`
		LockToken string `json:"LockToken"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("GetIPSet: malformed response: %w", err)
	}
	addrs := make(map[string]struct{}, len(resp.IPSet.Addresses))
	for _, a := range resp.IPSet.Addresses {
		addrs[a] = struct{}{}
	}
	return addrs, resp.LockToken, nil
}

// updateIPSet performs AWSWAF_20190729.UpdateIPSet with the lock token.
func (e *AWSWAFEnforcer) updateIPSet(ctx context.Context, ref AWSIPSetRef, addrs map[string]struct{}, lockToken string) error {
	list := make([]string, 0, len(addrs))
	for a := range addrs {
		list = append(list, a)
	}
	payload := map[string]any{
		"Name":      ref.Name,
		"Id":        ref.ID,
		"Scope":     e.scope,
		"Addresses": list,
		"LockToken": lockToken,
	}
	if _, err := e.callWAF(ctx, "UpdateIPSet", payload); err != nil {
		return fmt.Errorf("UpdateIPSet: %w", err)
	}
	return nil
}

// awsAPIError carries the decoded __type of a WAFv2 error response so lock
// conflicts are distinguishable from real failures.
type awsAPIError struct {
	Type    string
	Status  int
	Message string
}

func (e *awsAPIError) Error() string {
	return fmt.Sprintf("HTTP %d: %s %s", e.Status, e.Type, e.Message)
}

func isAWSLockConflict(err error) bool {
	var apiErr *awsAPIError
	return errors.As(err, &apiErr) && strings.Contains(apiErr.Type, "WAFOptimisticLockException")
}

// callWAF performs one signed JSON-RPC call with the shared rate limiter
// and bounded 429/5xx backoff. Credentials go only into request headers —
// never into errors (response bodies are server-controlled and cannot
// contain the secret key).
func (e *AWSWAFEnforcer) callWAF(ctx context.Context, op string, payload any) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", op, err)
	}

	attempts := len(e.retryDelays) + 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		respBody, status, retryAfter, err := e.callOnce(ctx, op, body)
		switch {
		case err != nil:
			lastErr = err
		case status == http.StatusOK:
			return respBody, nil
		case status == http.StatusTooManyRequests || status >= 500:
			lastErr = awsStatusErr(status, respBody)
		default:
			// Client errors (auth failures, lock conflicts, validation)
			// never retry here — the caller decides (lock conflicts re-read).
			return nil, awsStatusErr(status, respBody)
		}
		if attempt == attempts-1 {
			break
		}
		if werr := cfBackoffWait(ctx, e.retryDelays, attempt, retryAfter); werr != nil {
			return nil, werr
		}
	}
	return nil, lastErr
}

func (e *AWSWAFEnforcer) callOnce(ctx context.Context, op string, body []byte) (respBody []byte, status int, retryAfter time.Duration, err error) {
	if err := e.limiter.wait(ctx); err != nil {
		return nil, 0, 0, err
	}
	cred, err := e.creds.credentials(ctx)
	if err != nil {
		return nil, 0, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", awsWAFTargetPrefix+op)
	signSigV4(req, body, cred, e.region, "wafv2", e.now())

	resp, err := e.client.Do(req)
	if err != nil {
		// Transport errors include the URL but never request headers, so
		// the signature/credentials cannot leak here.
		return nil, 0, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	rb, err := io.ReadAll(io.LimitReader(resp.Body, awsWAFMaxRespBytes))
	if err != nil {
		return nil, resp.StatusCode, 0, fmt.Errorf("read response: %w", err)
	}
	return rb, resp.StatusCode, parseRetryAfter(resp.Header.Get("Retry-After")), nil
}

// awsStatusErr decodes the WAFv2 error envelope ({"__type": ..., "message"
// or "Message": ...}) into a typed error; falls back to a capped snippet.
func awsStatusErr(status int, body []byte) error {
	var envelope struct {
		Type     string `json:"__type"`
		Message  string `json:"message"`
		MessageU string `json:"Message"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.Type != "" {
		msg := envelope.Message
		if msg == "" {
			msg = envelope.MessageU
		}
		return &awsAPIError{Type: envelope.Type, Status: status, Message: msg}
	}
	snippet := body
	if len(snippet) > awsWAFErrSnippet {
		snippet = snippet[:awsWAFErrSnippet]
	}
	return &awsAPIError{Status: status, Message: string(snippet)}
}

// PreflightResult is one read-only check outcome for doctor (#201).
type PreflightResult struct {
	Label string // "credentials", "ipset_v4:<name>", "ipset_v6:<name>"
	Err   error  // nil = pass
}

// Preflight verifies, read-only, what `ezyshield doctor` needs: the AWS
// credential chain resolves, and GetIPSet succeeds on every designated set
// (which proves both the wafv2:GetIPSet permission and the set identity).
// Never mutates anything.
func (e *AWSWAFEnforcer) Preflight(ctx context.Context) []PreflightResult {
	var out []PreflightResult
	if _, err := e.creds.credentials(ctx); err != nil {
		return append(out, PreflightResult{Label: "credentials", Err: err})
	}
	out = append(out, PreflightResult{Label: "credentials"})
	for label, rt := range map[string]*awsIPSetRuntime{"ipset_v4": e.v4, "ipset_v6": e.v6} {
		if rt == nil {
			continue
		}
		_, _, err := e.getIPSet(ctx, rt.ref)
		out = append(out, PreflightResult{Label: label + ":" + rt.ref.Name, Err: err})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// SetEndpointForTest overrides the API endpoint (mock servers in doctor
// and wizard tests).
func (e *AWSWAFEnforcer) SetEndpointForTest(url string) { e.endpoint = url }

// isAllowlisted reports whether the target's address falls inside any
// allowlist prefix (Hard Rule §1 belt-and-braces; the gate is
// authoritative).
func (e *AWSWAFEnforcer) isAllowlisted(t sdk.Target) bool {
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

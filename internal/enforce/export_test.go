package enforce

import (
	"context"
	"net/netip"
	"time"
)

// NewCFEnforcerForTest constructs a CloudflareEnforcer with a pre-resolved
// token and a custom base URL, for use in tests only.
func NewCFEnforcerForTest(token, baseURL string, zoneIDs []string) *CloudflareEnforcer {
	return newCFEnforcerForTest(token, baseURL, zoneIDs)
}

// NewCFEnforcerWithAllowlist constructs a CloudflareEnforcer for tests with
// an explicit allowlist.
func NewCFEnforcerWithAllowlist(token, baseURL string, zoneIDs []string, allowlist []netip.Prefix) *CloudflareEnforcer {
	e := newCFEnforcerForTest(token, baseURL, zoneIDs)
	e.allowlist = allowlist
	return e
}

// NewCFEnforcerWithExprMax constructs a CloudflareEnforcer for tests with a
// custom expression size limit, used to trigger expression splitting with few IPs.
func NewCFEnforcerWithExprMax(token, baseURL string, zoneIDs []string, exprMax int) *CloudflareEnforcer {
	e := newCFEnforcerForTest(token, baseURL, zoneIDs)
	e.exprMax = exprMax
	return e
}

// NewCFEnforcerWithDebounce constructs a CloudflareEnforcer with a custom
// debounce interval for testing batched-push behaviour.
func NewCFEnforcerWithDebounce(token, baseURL string, zoneIDs []string, debounce time.Duration) *CloudflareEnforcer {
	e := newCFEnforcerForTest(token, baseURL, zoneIDs)
	e.debounceInterval = debounce
	return e
}

// NewCFEnforcerWithDebounceAndCtx constructs a CloudflareEnforcer with a custom
// debounce interval and a service context, for testing context-cancellation behaviour.
func NewCFEnforcerWithDebounceAndCtx(ctx context.Context, token, baseURL string, zoneIDs []string, debounce time.Duration) *CloudflareEnforcer {
	e := newCFEnforcerForTestWithCtx(ctx, token, baseURL, zoneIDs)
	e.debounceInterval = debounce
	return e
}

// ── CloudflareListsEnforcer test helpers ─────────────────────────────────────

// NewCFListsEnforcerForTest constructs a CloudflareListsEnforcer with a
// pre-resolved token and a custom base URL, for use in tests only.
func NewCFListsEnforcerForTest(token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	return newCFListsEnforcerForTest(token, baseURL, accountID, listName)
}

// NewCFListsEnforcerWithInstance constructs a CloudflareListsEnforcer with a
// specific per-daemon instance identity and legacy-adoption flag, for the
// shared-list multi-instance tests (issue #486).
func NewCFListsEnforcerWithInstance(token, baseURL, accountID, listName, instance string, adoptLegacy bool) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTest(token, baseURL, accountID, listName)
	e.ownTag = cfOwnTag(instance)
	e.adoptLegacy = adoptLegacy
	return e
}

// NewCFListsEnforcerWithAllowlist constructs a CloudflareListsEnforcer with an
// explicit allowlist for tests.
func NewCFListsEnforcerWithAllowlist(token, baseURL, accountID, listName string, allowlist []netip.Prefix) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTest(token, baseURL, accountID, listName)
	e.allowlist = allowlist
	return e
}

// NewCFListsEnforcerWithDebounce constructs a CloudflareListsEnforcer with a
// custom debounce interval for testing batched-push behaviour.
func NewCFListsEnforcerWithDebounce(token, baseURL, accountID, listName string, debounce time.Duration) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTest(token, baseURL, accountID, listName)
	e.debounceInterval = debounce
	return e
}

// NewCFListsEnforcerWithDebounceAndCtx constructs a CloudflareListsEnforcer
// bound to a custom service context, for testing context-cancellation behaviour.
func NewCFListsEnforcerWithDebounceAndCtx(ctx context.Context, token, baseURL, accountID, listName string, debounce time.Duration) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTestWithCtx(ctx, token, baseURL, accountID, listName)
	e.debounceInterval = debounce
	return e
}

// NewCFListsEnforcerWithName constructs a CloudflareListsEnforcer with an
// operator-style instance name, used to verify that Name() disambiguates
// multi-account deployments (issue #90).
func NewCFListsEnforcerWithName(name, token, baseURL, accountID, listName string) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTest(token, baseURL, accountID, listName)
	e.instanceName = name
	return e
}

// NewCFListsEnforcerWithRetryDelays constructs a CloudflareListsEnforcer with
// a custom throttle backoff schedule, for testing retry behaviour (issue #445).
func NewCFListsEnforcerWithRetryDelays(token, baseURL, accountID, listName string, delays []time.Duration) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTest(token, baseURL, accountID, listName)
	e.retryDelays = delays
	return e
}

// NewCFListsEnforcerWithExpireFlush constructs a CloudflareListsEnforcer with
// deferred removals on the given cadence and starts the removal flusher, for
// testing the expire-flush batching (issue #445).
func NewCFListsEnforcerWithExpireFlush(ctx context.Context, token, baseURL, accountID, listName string, flush time.Duration) *CloudflareListsEnforcer {
	e := newCFListsEnforcerForTestWithCtx(ctx, token, baseURL, accountID, listName)
	e.expireFlushInterval = flush
	go e.runRemovalFlusher()
	return e
}

// FlushRemovalsForTest triggers one deferred-removal flush deterministically,
// without waiting for the background ticker (issue #445).
func (e *CloudflareListsEnforcer) FlushRemovalsForTest(ctx context.Context) error {
	return e.flushRemovals(ctx)
}

// ── BunnyEnforcer test helpers ───────────────────────────────────────────────

// NewBunnyEnforcerForTest constructs a BunnyEnforcer with a pre-resolved
// access key and a custom base URL, for use in tests only.
func NewBunnyEnforcerForTest(key, baseURL string, zoneIDs []int64) *BunnyEnforcer {
	return newBunnyEnforcerForTest(key, baseURL, zoneIDs)
}

// NewBunnyEnforcerWithAllowlist constructs a BunnyEnforcer for tests with an
// explicit allowlist.
func NewBunnyEnforcerWithAllowlist(key, baseURL string, zoneIDs []int64, allowlist []netip.Prefix) *BunnyEnforcer {
	e := newBunnyEnforcerForTest(key, baseURL, zoneIDs)
	e.allowlist = allowlist
	return e
}

// NewBunnyEnforcerWithZoneCap constructs a BunnyEnforcer for tests with a
// small per-zone capacity, to exercise the most-recent-first guard.
func NewBunnyEnforcerWithZoneCap(key, baseURL string, zoneIDs []int64, cap int) *BunnyEnforcer {
	e := newBunnyEnforcerForTest(key, baseURL, zoneIDs)
	e.zoneCap = cap
	return e
}

// NewBunnyEnforcerWithRetryDelays constructs a BunnyEnforcer for tests with
// a custom (short) backoff schedule, to exercise 429/5xx retries.
func NewBunnyEnforcerWithRetryDelays(key, baseURL string, zoneIDs []int64, delays []time.Duration) *BunnyEnforcer {
	e := newBunnyEnforcerForTest(key, baseURL, zoneIDs)
	e.retryDelays = delays
	return e
}

// NewBunnyEnforcerWithName constructs a BunnyEnforcer with an operator-style
// instance name, to verify Name() disambiguation.
func NewBunnyEnforcerWithName(name, key, baseURL string, zoneIDs []int64) *BunnyEnforcer {
	e := newBunnyEnforcerForTest(key, baseURL, zoneIDs)
	e.instanceName = name
	return e
}

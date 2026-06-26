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

// Package enforce implements sdk.Enforcer backed by nftables.
//
// Privilege separation: the NftablesEnforcer (this package) runs inside the
// main daemon as an unprivileged user. It communicates with the
// ezyshield-enforcer helper (CAP_NET_ADMIN) over a unix socket using
// newline-delimited JSON. The helper accepts only the fixed verb set
// {add, del, flush, list, ping, caps, netcheck, allow_add, allow_del,
// allow_list, allow_flush} with typed, validated arguments — no raw nft
// syntax is ever
// passed from caller to helper (the authoritative list is validVerbs in
// cmd/ezyshield-enforcer/server.go; issue #351 caught this doc understating
// the privilege surface).
package enforce

// Request is sent from the main daemon to the privileged enforcer helper.
// IP must be a valid netip.Addr or netip.Prefix string; raw nft syntax
// is never accepted and will be rejected by the helper.
//
// Table/Set carry the operator-configured nftables names (issue #268).
// Empty means "helper defaults" — requests from older daemons therefore keep
// working unchanged. The helper re-validates the names itself via
// internal/nftnames (it never trusts the daemon), pins the first resolved
// name set for its lifetime, and rejects requests naming anything else.
type Request struct {
	Verb       string `json:"verb"`
	IP         string `json:"ip,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"` // 0 = permanent
	Table      string `json:"table,omitempty"`
	Set        string `json:"set,omitempty"`
	// Elements carries the full desired state for the "feeds_sync" verb
	// (issue #195): the helper atomically replaces the reputation-feed
	// sets (blocked_feeds/blocked_feeds6) with exactly these entries.
	// Capped at MaxFeedElements; every IP is re-validated by the helper.
	Elements []FeedElement `json:"elements,omitempty"`
}

// FeedElement is one reputation-feed entry for the "feeds_sync" verb.
type FeedElement struct {
	// IP is a netip.Addr or netip.Prefix string.
	IP string `json:"ip"`
	// TTLSeconds is the nft per-element timeout; must be > 0 — feed
	// entries are never permanent (a dead feed must drain, not linger).
	TTLSeconds int64 `json:"ttl_seconds"`
}

// MaxFeedElements caps one feeds_sync request. Shared by both sides of the
// privilege boundary: the daemon truncates before sending (with a warning),
// the helper rejects anything larger outright.
const MaxFeedElements = 100_000

// Response is returned by the helper for every request.
//
// Code is an optional, stable machine-readable annotation that lets the
// client distinguish "informational" outcomes without parsing the free-form
// Error text (or nft's raw stderr, which shifts across versions — see issue
// #39). Only well-known constants below are ever set; unknown codes should
// be treated by the client as "no annotation".
type Response struct {
	OK    bool     `json:"ok"`
	Error string   `json:"error,omitempty"`
	Code  string   `json:"code,omitempty"`
	IPs   []string `json:"ips,omitempty"` // populated for "list" verb
	// Features is populated for the "caps" verb: the helper's supported
	// optional capabilities. The daemon probes this before relying on a
	// capability an older helper would silently ignore (issue #268 — a
	// custom table name must never silently fall back to the default).
	Features []string `json:"features,omitempty"`
}

// FeatureCustomNames is advertised by helpers that honor Request.Table /
// Request.Set. Daemons configured with non-default names require it.
const FeatureCustomNames = "custom_names"

// FeatureFeedsSync is advertised by helpers that support the "feeds_sync"
// verb (issue #195). The daemon refuses to enforce feeds against an older
// helper instead of silently doing nothing.
const FeatureFeedsSync = "feeds_sync"

// CodeAlreadyAbsent is returned on a successful "del" or "allow_del" when the
// target element was already gone from the nftables set — for example because
// nft's native per-element `timeout` fired between the client's list and
// delete. The end state (absent) is what the caller wanted, so OK is still
// true; the code lets the client log this at DEBUG instead of ERROR.
const CodeAlreadyAbsent = "already_absent"

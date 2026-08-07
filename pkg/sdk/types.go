// Package sdk is the public API surface for EzyShield native modules.
// All types here are stable contracts; changes require an ADR in docs/internal/adr/.
package sdk

import (
	"net/netip"
	"time"
)

// RawLine is a single log line as collected, before parsing.
type RawLine struct {
	Source string    // collector ID (path, unit name, ...)
	Line   []byte    // raw bytes; treat as untrusted, attacker-controlled
	At     time.Time // wall time when collected, not necessarily log time
}

// Enrichment holds geo/ASN/reputation metadata attached to an IP.
type Enrichment struct {
	Country    string // ISO 3166-1 alpha-2, e.g. "US"
	ASN        uint32
	ASNOrg     string
	IsKnownBot bool // reverse-DNS confirmed crawler (Googlebot, Bingbot, ...)
	IsTorExit  bool
	IsProxy    bool
}

// Event is the parsed, structured representation of one log entry.
// Fields is a heterogeneous bag; keys are defined per-Kind in each parser's docs.
type Event struct {
	Time     time.Time
	SourceIP netip.Addr
	Kind     string            // "ssh_fail", "http_request", "port_probe", ...
	Fields   map[string]string // method, path, status, ua, port, ...
	Origin   string            // collector id
}

// Aggregate is the per-IP summary produced by the Aggregator over a time window.
type Aggregate struct {
	IP     netip.Addr
	Window time.Duration
	Count  int
	Kinds  map[string]int
	Sample []Event    // capped, redacted; never send raw to AI
	Enrich Enrichment // asn, country, reputation flags
}

// Verdict is a threat assessment, from the rule engine or an AI provider.
// SuggestTTL is advisory only; the policy engine decides the final TTL.
type Verdict struct {
	IP         netip.Addr
	Score      int     // 0-100; ≥ ban_threshold (default 70) → strike
	Category   string  // "bruteforce", "scraper", "scanner", "benign", ...
	Confidence float64 // 0.0-1.0
	Reason     string
	Source     string        // "rules", "ai:anthropic", "ai:ollama", ...
	SuggestTTL time.Duration // suggestion only; policy decides
}

// Action is what the decision engine decides to do about an IP.
type Action struct {
	IP  netip.Addr
	Op  string // "ban", "unban", "ratelimit", "notify_only"
	TTL time.Duration
	// Permanent marks a ban with no expiry (expires_at NULL in the store).
	// It exists because TTL alone is lossy: a remaining-time that reached
	// zero and "no expiry at all" must never be conflated (issue #279 — an
	// expired ban rendered and re-synced as permanent). Additive field on
	// the §3 contract; TTL is 0 whenever Permanent is true.
	Permanent bool
	Strike    int // 1..5
	Reason    string
	Verdicts  []Verdict
}

// Target is the subject of a ban/unban operation.
// Exactly one of IP, Prefix, ASN, or Country must be set.
type Target struct {
	IP      netip.Addr    // single address (non-zero → single-IP mode)
	Prefix  netip.Prefix  // CIDR range (Valid() → CIDR mode)
	ASN     uint32        // if non-zero → ASN-wide mode (requires rule corroboration)
	Country string        // ISO 3166-1 alpha-2 (non-empty → country mode)
	TTL     time.Duration // zero = permanent
}

// TokenBudget carries the remaining AI token budget for a single analysis call.
type TokenBudget struct {
	Remaining  int // tokens left in current daily budget
	DailyLimit int
}

// Usage reports the actual tokens consumed by an AI provider call.
type Usage struct {
	InputTokens  int
	OutputTokens int
	CostUSD      float64
}

// Notification is the message sent to a Notifier channel.
type Notification struct {
	Severity string // "info", "warn", "critical"
	Title    string
	Body     string
	Action   *Action // optional: the action that triggered this notification
}

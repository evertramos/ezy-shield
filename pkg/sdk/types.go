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
	// Raw is a bounded copy of the originating log line (ADR-0011, issue
	// #127), attached by the daemon after parsing — parsers never set or
	// read it. Capped at EvidenceRawCap bytes; may be nil (synthetic
	// events, tests). Hostile input: sanitize at render time only.
	Raw []byte
}

// Evidence bounds (ADR-0011): the per-event raw-line cap applied at attach
// time, and the maximum triggering lines a firing rule attaches to its
// verdict.
const (
	EvidenceRawCap   = 512
	EvidenceMaxLines = 5
)

// Aggregate is the per-IP summary produced by the Aggregator over a time window.
type Aggregate struct {
	IP     netip.Addr
	Window time.Duration
	Count  int
	Kinds  map[string]int
	Sample []Event    // capped, redacted; never send raw to AI
	Enrich Enrichment // asn, country, reputation flags
	// Behavior is the compact behavioral summary derived from Sample
	// (issue #222): distributions and top-N lists only, never raw log
	// lines — it is the ONLY sample-derived data AI payloads may carry.
	Behavior *BehaviorSummary
}

// BehaviorSummary condenses an aggregate's sampled events into the compact
// fields an AI analysis needs (issue #222): path/method/status
// distributions and a user-agent summary. Every string is length-capped
// and control-stripped at construction; lists are top-N by frequency.
type BehaviorSummary struct {
	// TopPaths lists the most-requested paths as "path (xN)" entries.
	TopPaths []string `json:"top_paths,omitempty"`
	// Methods counts requests per HTTP method.
	Methods map[string]int `json:"methods,omitempty"`
	// StatusClasses counts responses per class ("2xx", "4xx", ...).
	StatusClasses map[string]int `json:"status_classes,omitempty"`
	// TopUserAgents lists the most-seen user agents as "ua (xN)" entries.
	TopUserAgents []string `json:"top_user_agents,omitempty"`
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
	// Evidence holds up to EvidenceMaxLines raw log lines that produced
	// this verdict, captured at detection time (ADR-0011, issue #127).
	// Only rule verdicts carry it; persisted with the strike via the
	// strikes.verdicts JSON column. Hostile input — render-time sanitizing
	// only.
	Evidence []string `json:"evidence,omitempty"`
}

// Action is what the decision engine decides to do about an IP.
type Action struct {
	IP netip.Addr
	// Op is the closed action vocabulary (ADR-0010; extending it requires a
	// new ADR — §3 contract):
	//
	//	"ban"            enforceable ban (armed)
	//	"dry_ban"        simulated ban — recorded, never enforced (ADR-0009 §5)
	//	"unban"          ban lifted (manual or via expiry handling)
	//	"expired"        ban TTL elapsed and was removed
	//	"record"         observed below the notify band, or an anti-lockout
	//	                 refusal (Reason distinguishes; see
	//	                 decision.ReasonAntiLockoutSSHPeer)
	//	"notify_only"    notify band — alert, no ban
	//	"already_banned" suppressed: the IP already has an active ban
	//	"allow_add"      allowlist entry added
	Op  string
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

// Package daemon wires all EzyShield subsystems into the long-running watch
// daemon and exposes a unix-socket control API.
package daemon

import "encoding/json"

// SocketRequest is sent by CLI commands to the daemon over the unix socket.
// It is serialised as a single newline-terminated JSON object.
//
// Security: the socket is owned root:ezyshield, mode 0660; only members of the
// ezyshield group (or root) can connect. Mutating verbs (ban, unban, allow)
// are logged to the append-only audit_log.
type SocketRequest struct {
	// Verb selects the operation: "status", "list", "list_allow", "events",
	// "subscribe", "report", "ban", "unban", "allow".
	Verb string `json:"verb"`
	// IP is the target for ban/unban/allow/report. ban/unban/allow accept
	// either a bare address ("1.2.3.4") or a CIDR ("203.0.113.0/24"); a bare
	// address is treated as a host prefix (/32 or /128). report accepts only
	// a bare address; an empty IP selects the offender-listing mode. events
	// accepts an optional bare address that filters the audit history to that
	// one IP (exact match); an empty IP returns all recent actions.
	IP string `json:"ip,omitempty"`
	// TTL is a Go duration string (e.g. "5m", "24h") for the ban verb.
	// Zero or absent means the policy strike table decides.
	TTL string `json:"ttl,omitempty"`
	// For is a duration string (e.g. "24h", "7d") for the allow verb, and
	// the auto-revert window for the arm verb. Mutually exclusive with
	// Until. Empty = permanent allow / unconditional arm.
	For string `json:"for,omitempty"`
	// Force lets the arm verb proceed past failing pre-flight checks
	// (except the self-ban check, which is never bypassable).
	Force bool `json:"force,omitempty"`
	// Peer is the operator's own client IP, derived by the CLI from
	// SSH_CLIENT: the arm verb uses it for the self-ban pre-flight, the ban
	// verb for the manual-ban anti-lockout guard (issue #211). Used only to
	// make safety checks stricter; never stored.
	Peer string `json:"peer,omitempty"`
	// Until is an absolute time for the allow verb in ISO 8601 form
	// ("2026-07-15" or "2026-07-15T18:00:00[Z]"). Mutually exclusive with For.
	Until string `json:"until,omitempty"`
	// Reason is an operator-supplied free-text note, surfaced in list output
	// and the audit log.
	Reason string `json:"reason,omitempty"`
	// Limit caps the number of rows returned by list-shaped verbs ("events",
	// "report"). Zero or negative means "server default" (100). The daemon
	// also enforces an upper bound to avoid ballooning memory.
	Limit int `json:"limit,omitempty"`
	// Filter narrows the report verb's listing mode (IP empty): "" or "all"
	// returns every offender, "permanent" only those with a permanent active
	// ban. Other values are rejected.
	Filter string `json:"filter,omitempty"`
	// Evidence asks the per-IP report verb to also extract matching raw log
	// lines from the configured log sources (bounded, read-only, never
	// persisted). Ignored by every other verb and by the listing mode.
	Evidence bool `json:"evidence,omitempty"`
}

// SocketResponse is returned by the daemon for every request.
// Data is a raw JSON value; its schema depends on the verb (see below).
type SocketResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// StatusData is the Data payload for a successful "status" response.
type StatusData struct {
	// Uptime is a human-readable duration since daemon start (e.g. "3h2m").
	Uptime string `json:"uptime"`
	// Armed mirrors policy.Armed: true means bans are enforced, false = dry-run.
	Armed bool `json:"armed"`
	// EnforcementState is the honest enforcement health (issue #174):
	// ACTIVE / DRY-RUN / DEGRADED / DISABLED. Derived from real enforcer
	// Ban/Sync outcomes, not config alone — status must never claim
	// protection that is not real.
	EnforcementState string `json:"enforcement_state"`
	// EnforcementDetail carries the failure detail when DEGRADED.
	EnforcementDetail string `json:"enforcement_detail,omitempty"`
	// ActiveBans is the count of IPs currently in bans_active that are
	// really enforced. Simulated dry-run bans are excluded — counting them
	// as "active" would overstate protection.
	ActiveBans int `json:"active_bans"`
	// SimulatedBans is the count of dry-run simulated bans (ADR-0009 §5):
	// IPs that WOULD be banned right now if the daemon were armed.
	SimulatedBans int `json:"simulated_bans,omitempty"`
	// ArmedUntil is the RFC3339 auto-revert deadline when an arm window is
	// active (issue #228); empty otherwise.
	ArmedUntil string `json:"armed_until,omitempty"`
	// Version is the daemon binary version string.
	Version string `json:"version"`
	// AISpendToday is the estimated USD cost of AI provider calls today.
	// Zero when the AI provider is not configured.
	AISpendToday float64 `json:"ai_spend_today_usd,omitempty"`
}

// BanEntry is one element in the array returned by the "list" verb.
type BanEntry struct {
	IP string `json:"ip"`
	// TTL is "permanent" or a Go duration string for the remaining time.
	TTL    string `json:"ttl"`
	Strike int    `json:"strike"`
	Reason string `json:"reason"`
	// Country is the ISO 3166-1 alpha-2 code from GeoIP enrichment, or "" when
	// enrichment is not configured.
	Country string `json:"country,omitempty"`
	// ASN is the autonomous system number string (e.g. "AS12345"), or "" when
	// enrichment is not configured.
	ASN string `json:"asn,omitempty"`
	// Simulated is true for dry-run bans (ADR-0009 §5): recorded for
	// escalation/suppression while armed=false, never enforced.
	Simulated bool `json:"simulated,omitempty"`
}

// EventEntry is one element in the array returned by the "events" verb.
// It mirrors the audit_log row in the store; recorded_at is an RFC 3339
// UTC timestamp string, ttl_seconds is 0 for verbs that carry no TTL
// (unban, allow_expire, etc.). ID is the monotonic audit_log primary key
// used by consumers (dashboard bus, future CLI --since flag) to dedupe.
type EventEntry struct {
	ID         int64  `json:"id"`
	RecordedAt string `json:"recorded_at"`
	Op         string `json:"op"`
	IP         string `json:"ip"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Strike     int    `json:"strike"`
	Reason     string `json:"reason,omitempty"`
}

// StreamEvent is one live event pushed to "subscribe" clients (`watch`).
// After the SocketResponse acknowledgement, the daemon writes one StreamEvent
// JSON object per line until the client disconnects.
//
// Security: Category, Rule, and Reason may derive from hostile log content
// (usernames, request paths, rule descriptions). Consumers MUST strip control
// characters and ANSI escapes before rendering to a terminal.
type StreamEvent struct {
	// Time is an RFC 3339 UTC timestamp of when the event was published.
	Time string `json:"time"`
	// Kind is the event kind: "detection" (rule/AI/geo verdict), or a daemon
	// op — "record", "notify_only", "dry_ban", "ban", "already_banned",
	// "unban", "allow".
	Kind string `json:"kind"`
	// IP is the address (or CIDR for manual prefix ops) the event refers to.
	IP string `json:"ip,omitempty"`
	// Score is the verdict score (detection events only).
	Score int `json:"score,omitempty"`
	// Category is the verdict category, e.g. "ssh_bruteforce" (detections).
	Category string `json:"category,omitempty"`
	// Rule identifies the verdict source, e.g. "rules:ssh_bruteforce" (detections).
	Rule string `json:"rule,omitempty"`
	// Strike is the escalation level (1..5) on ban/dry_ban events.
	Strike int `json:"strike,omitempty"`
	// TTL is the remaining ban duration as a Go duration string; empty when
	// the event carries no TTL.
	TTL string `json:"ttl,omitempty"`
	// Enforcer names the enforcer backend(s) in effect (e.g. "nftables",
	// "nftables+cloudflare"); empty when no enforcer is configured.
	Enforcer string `json:"enforcer,omitempty"`
	// Reason is free text explaining the event.
	Reason string `json:"reason,omitempty"`
	// Source is "pipeline" for automatic events and "cli" for socket verbs.
	Source string `json:"source,omitempty"`
}

// ReportSummaryEntry is one element in the array returned by the "report"
// verb's listing mode (request IP empty). The single-IP mode returns an
// sdk.AbuseReport instead. Timestamps are RFC 3339 UTC strings.
type ReportSummaryEntry struct {
	IP           string `json:"ip"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	TotalStrikes int    `json:"total_strikes"`
	Banned       bool   `json:"banned"`
	Permanent    bool   `json:"permanent,omitempty"`
	// Country/ASN come from GeoIP enrichment; empty when not configured.
	Country string `json:"country,omitempty"`
	ASN     string `json:"asn,omitempty"`
}

// AllowEntry is one element in the array returned by the "list_allow" verb.
type AllowEntry struct {
	// Prefix is the canonical CIDR string (single hosts are /32 or /128).
	Prefix string `json:"prefix"`
	// Expires is one of: "never" (permanent), an ISO 8601 timestamp (more than
	// 24 h remaining), or a "<n>h remaining" string for short TTLs. Clients
	// should treat the value as already formatted for display.
	Expires string `json:"expires"`
	Reason  string `json:"reason,omitempty"`
}

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
	// Verb selects the operation: "status", "list", "list_allow", "ban",
	// "unban", "allow".
	Verb string `json:"verb"`
	// IP is the target for ban/unban/allow. Accepts either a bare address
	// ("1.2.3.4") or a CIDR ("203.0.113.0/24"). A bare address is treated
	// as a host prefix (/32 or /128).
	IP string `json:"ip,omitempty"`
	// TTL is a Go duration string (e.g. "5m", "24h") for the ban verb.
	// Zero or absent means the policy strike table decides.
	TTL string `json:"ttl,omitempty"`
	// For is a duration string (e.g. "24h", "7d") for the allow verb.
	// Mutually exclusive with Until. Empty = permanent allow.
	For string `json:"for,omitempty"`
	// Until is an absolute time for the allow verb in ISO 8601 form
	// ("2026-07-15" or "2026-07-15T18:00:00[Z]"). Mutually exclusive with For.
	Until string `json:"until,omitempty"`
	// Reason is an operator-supplied free-text note, surfaced in list output
	// and the audit log.
	Reason string `json:"reason,omitempty"`
	// Limit caps the number of rows returned by list-shaped verbs (currently
	// "events"). Zero or negative means "server default" (100 for events).
	// The daemon also enforces an upper bound to avoid ballooning memory.
	Limit int `json:"limit,omitempty"`
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
	// ActiveBans is the count of IPs currently in bans_active.
	ActiveBans int `json:"active_bans"`
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

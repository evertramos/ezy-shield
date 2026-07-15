package sdk

// AbuseReportSchemaVersion is the schema_version emitted in every AbuseReport.
// Bump only for breaking changes; new fields must be additive (omitempty) so
// external consumers parsing version 1 keep working.
const AbuseReportSchemaVersion = 1

// AbuseReport is the stable, machine-consumable summary of everything
// EzyShield knows about one offending IP: identity, enrichment, current ban,
// strike escalation history, and the action trail. It is the payload of the
// daemon's "report" socket verb and of `ezyshield report --json`.
//
// All timestamps are RFC 3339 strings in UTC. Reason and category fields may
// derive from hostile log content — terminal consumers MUST strip control
// characters and ANSI escapes before rendering (see ADR-0008).
type AbuseReport struct {
	SchemaVersion int    `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	IP            string `json:"ip"`
	// FirstSeen/LastSeen are empty when the IP has an active manual ban but
	// no recorded offender history.
	FirstSeen    string `json:"first_seen,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"`
	TotalStrikes int    `json:"total_strikes"`
	// Country is the ISO 3166-1 alpha-2 code; ASN is "AS<n>". All three are
	// empty when GeoIP enrichment is not configured.
	Country string `json:"country,omitempty"`
	ASN     string `json:"asn,omitempty"`
	ASNOrg  string `json:"asn_org,omitempty"`
	// CurrentBan is nil when the IP is not actively banned.
	CurrentBan *AbuseReportBan `json:"current_ban,omitempty"`
	// Strikes is the escalation history, newest first.
	Strikes []AbuseReportStrike `json:"strikes,omitempty"`
	// Actions is the audit trail for this IP (bans, unbans, expiries),
	// newest first.
	Actions []AbuseReportAction `json:"actions,omitempty"`
	// Evidence holds raw log excerpts mentioning the IP, extracted on demand
	// from the configured log sources at report time (never persisted). Only
	// present when evidence was requested. Lines are hostile input — see the
	// type doc.
	Evidence []AbuseReportEvidence `json:"evidence,omitempty"`
}

// AbuseReportBan describes the active ban on the reported IP.
type AbuseReportBan struct {
	BannedAt string `json:"banned_at"`
	// ExpiresAt is empty for permanent bans.
	ExpiresAt string `json:"expires_at,omitempty"`
	Permanent bool   `json:"permanent"`
	Strike    int    `json:"strike"`
	Reason    string `json:"reason,omitempty"`
}

// AbuseReportStrike is one recorded strike in the escalation history.
type AbuseReportStrike struct {
	RecordedAt string `json:"recorded_at"`
	Strike     int    `json:"strike"`
	// TTLSeconds is the ban duration applied by this strike; 0 = permanent.
	TTLSeconds int64  `json:"ttl_seconds"`
	Reason     string `json:"reason,omitempty"`
	// Verdicts are the assessments that produced this strike.
	Verdicts []AbuseReportVerdict `json:"verdicts,omitempty"`
}

// AbuseReportVerdict is the wire form of a Verdict inside an AbuseReport.
// It intentionally drops the IP (redundant) and SuggestTTL (advisory,
// policy-internal) fields of Verdict.
type AbuseReportVerdict struct {
	Score      int     `json:"score"`
	Category   string  `json:"category,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	Source     string  `json:"source,omitempty"`
}

// AbuseReportEvidence is one log source's excerpt in an AbuseReport. Lines
// are copied verbatim from log sources and are therefore hostile input:
// terminal consumers MUST strip control characters and ANSI escapes before
// rendering, and markdown consumers must neutralize formatting (EzyShield's
// own CLI renders them as indented code blocks after sanitizing).
type AbuseReportEvidence struct {
	// Source identifies the log source, e.g. "file:/var/log/nginx/access.log"
	// or "journald:sshd". The value comes from the operator's own config,
	// not from log content.
	Source string `json:"source"`
	// Lines are the matching raw log lines, oldest first (the tail of the
	// file), capped in count and per-line length.
	Lines []string `json:"lines,omitempty"`
	// Truncated is true when any cap was applied (scan window, line count,
	// or line length).
	Truncated bool `json:"truncated,omitempty"`
	// Note explains degraded extraction in plain words, e.g. the log was
	// rotated away, the journal has no matching entries, or the Docker
	// engine socket was unreachable.
	Note string `json:"note,omitempty"`
}

// AbuseReportAction is one audit-log row scoped to the reported IP.
type AbuseReportAction struct {
	RecordedAt string `json:"recorded_at"`
	// Op is "ban", "dry_ban", "unban", "expire", or "notify_only".
	Op         string `json:"op"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	Strike     int    `json:"strike,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

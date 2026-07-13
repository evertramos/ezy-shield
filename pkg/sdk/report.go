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

// AbuseReportAction is one audit-log row scoped to the reported IP.
type AbuseReportAction struct {
	RecordedAt string `json:"recorded_at"`
	// Op is "ban", "dry_ban", "unban", "expire", or "notify_only".
	Op         string `json:"op"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	Strike     int    `json:"strike,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

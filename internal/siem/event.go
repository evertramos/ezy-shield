// Package siem renders EzyShield audit events into the wire formats that
// security information and event management systems (Wazuh, Splunk, generic
// syslog collectors) ingest natively: JSON, ArcSight CEF, and RFC 5424
// structured-data syslog.
//
// The package is pure: every exported function is a deterministic formatter
// with no I/O, no network, no configuration, and no daemon wiring — that
// belongs to the transport layer (issue #203). The security-critical core is
// per-format escaping. Every string field on an [Event] must be treated as
// untrusted, attacker-influenced data (AGENTS.md Hard Rule 4): usernames,
// rule names, reasons and paths all derive, directly or transitively, from
// hostile log content. Each formatter escapes its own delimiters and
// neutralises control characters so a crafted field can never forge a log
// line, break out of a field, or inject a second event.
//
// Raw log lines are NEVER carried in an [Event] and never rendered — only the
// already-parsed, structured audit vocabulary crosses this boundary.
package siem

import (
	"net/netip"
	"time"
	"unicode/utf8"
)

// maxFieldLen bounds every rendered string field, in bytes, applied BEFORE
// encoding so total output size is bounded regardless of input. 512 bytes is
// generous for a username, rule name, reason or hostname while capping a
// 4 MB "path" attack (SECURITY-REVIEW §1) long before it reaches a SIEM. The
// same cap is documented for the JSON schema in docs/schemas/siem/.
const maxFieldLen = 512

// Default identity fields used when an [Event] leaves Vendor/Product/Version
// unset. The real values are injected by the transport wiring (#203) from the
// binary's ldflags build info; this package stays pure and cannot import the
// main package, so it falls back to well-formed placeholders rather than
// emitting empty header fields.
const (
	defaultVendor  = "ezy"
	defaultProduct = "EzyShield"
	defaultVersion = "unknown"
)

// Event is the neutral, transport-agnostic representation of a single
// EzyShield audit event to be forwarded to a SIEM. Its fields mirror the
// audit write path's vocabulary (see internal/store: RecordStrike / Audit /
// AuditOp / AuditSystem and the audit_log columns), so the future transport
// (#203) can build one from a store.AuditEntry plus the surrounding decision
// context:
//
//	Action  ← audit_log.op          ("ban", "dry_ban", "unban", "expire", …)
//	IP      ← audit_log.ip          (parsed back into netip.Addr)
//	Rule    ← audit_log.reason      (the matched rule / reason text)
//	TTL     ← audit_log.ttl_seconds (0 ⇒ permanent or not applicable)
//	Strike  ← audit_log.strike_num  (0..5; 0 when not a strike event)
//	Time    ← audit_log.recorded_at (parsed back into time.Time, UTC)
//
// Score and Actor are NOT persisted in audit_log; the caller supplies them
// from the decision context (sdk.Verdict.Score / .Source) or leaves them
// zero. Node is the reporting host's name, supplied by the caller. Vendor,
// Product and Version are build-info identity fields the caller injects.
//
// Every string field is untrusted: Rule and Actor in particular may embed
// hostile bytes copied from a log line. No field is trusted by any formatter.
type Event struct {
	// Time is the moment the event was recorded. Rendered as an RFC 3339
	// timestamp in UTC; a zero value renders as the format's null value.
	Time time.Time

	// Action is the audit operation (audit_log.op). A short, engine-defined
	// token, but still escaped defensively by every formatter.
	Action string

	// IP is the target address. The zero (invalid) value means "no IP"
	// (system-level events such as arm/disarm) and is omitted from output
	// rather than rendered as the literal "invalid IP".
	IP netip.Addr

	// Rule is the matched rule name or reason text (audit_log.reason).
	// Attacker-influenced — may contain any bytes.
	Rule string

	// Score is the threat score 0..100 (sdk.Verdict.Score); 0 when unknown.
	Score int

	// Strike is the escalation level 1..5 for ban events; 0 otherwise.
	Strike int

	// TTL is the ban duration; 0 means permanent or not applicable.
	TTL time.Duration

	// Actor identifies what produced the verdict ("rules", "ai:anthropic",
	// "manual", …). Treated as untrusted.
	Actor string

	// Node is the reporting host's name. Treated as untrusted (it can be
	// operator-set to arbitrary text); tokenised for syslog HOSTNAME.
	Node string

	// Product, Vendor and Version identify the emitting software in CEF and
	// JSON output. Caller-injected build info; empty values fall back to the
	// package defaults so header fields are never blank.
	Product string
	Vendor  string
	Version string
}

// vendor, product and version return the Event's identity fields or the
// package default when a field is unset, so no formatter emits a blank
// mandatory header field.
func (e Event) vendor() string  { return orDefault(e.Vendor, defaultVendor) }
func (e Event) product() string { return orDefault(e.Product, defaultProduct) }
func (e Event) version() string { return orDefault(e.Version, defaultVersion) }

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ipString returns the canonical string form of the Event's IP, or "" when
// the IP is the zero (invalid) value. Returning "" rather than the netip
// "invalid IP" sentinel lets each formatter omit the field cleanly for
// system-level events that have no target address.
func (e Event) ipString() string {
	if !e.IP.IsValid() {
		return ""
	}
	return e.IP.String()
}

// capField truncates s to at most maxFieldLen bytes without splitting a
// multi-byte UTF-8 rune at the boundary. The cut point is backed up to the
// nearest rune start (at most three bytes), so a valid trailing rune is never
// chopped into a lone continuation byte. Genuinely invalid UTF-8 already in s
// is left untouched — capping bounds size, it does not sanitise encoding; the
// per-format escapers handle dangerous bytes.
func capField(s string) string {
	if len(s) <= maxFieldLen {
		return s
	}
	end := maxFieldLen
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}

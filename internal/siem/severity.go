package siem

// sevTier is EzyShield's internal, format-independent notion of "how serious
// is this event". Each formatter maps it onto that format's own severity
// scale (CEF 0..10, syslog 0..7) so the two stay consistent by construction.
type sevTier int

const (
	sevInfo     sevTier = iota // reversal / expiry / informational bookkeeping
	sevLow                     // notice: simulated ban, notify-only
	sevMedium                  // an active ban, early strikes
	sevHigh                    // an active ban, late strikes
	sevCritical                // a permanent ban (final strike)
)

// tier maps an event to its severity tier from the action and, for bans, the
// strike level. The escalation ladder is 5min → 1h → 24h → 7d → permanent
// (AGENTS.md), so strike 5 is the permanent, most-severe ban.
//
// The mapping is intentionally small and total; unknown actions fall through
// to sevLow so a new audit op is never silently treated as harmless-info.
func tier(e Event) sevTier {
	switch e.Action {
	case "ban":
		switch {
		case e.Strike >= 5:
			return sevCritical
		case e.Strike >= 3:
			return sevHigh
		default:
			return sevMedium
		}
	case "dry_ban", "notify_only":
		return sevLow
	case "unban", "expire", "allow", "allow_expire", "arm", "disarm", "arm_revert":
		return sevInfo
	default:
		return sevLow
	}
}

// cefSeverity maps the event onto CEF's 0..10 severity scale (0 = least
// severe, 10 = most). Documented in docs/schemas/siem/README.md.
func cefSeverity(e Event) int {
	switch tier(e) {
	case sevCritical:
		return 10
	case sevHigh:
		return 8
	case sevMedium:
		return 6
	case sevLow:
		return 4
	default: // sevInfo
		return 2
	}
}

// syslogSeverity maps the event onto RFC 5424's 0..7 severity scale, where
// LOWER is more severe (0 = Emergency, 7 = Debug). It mirrors cefSeverity's
// tiers so a ban that is CEF-severity 10 is syslog-severity 2 (Critical).
func syslogSeverity(e Event) int {
	switch tier(e) {
	case sevCritical:
		return 2 // Critical
	case sevHigh:
		return 3 // Error
	case sevMedium:
		return 4 // Warning
	case sevLow:
		return 5 // Notice
	default: // sevInfo
		return 6 // Informational
	}
}

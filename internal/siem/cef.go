// SPDX-License-Identifier: AGPL-3.0-only

package siem

import (
	"strconv"
	"strings"
)

// FormatCEF renders e as a single ArcSight Common Event Format line:
//
//	CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
//
// The seven header fields are pipe-delimited; header values escape "\" and "|"
// so an attacker-controlled field can never introduce a new header column.
// The extension is a space-separated list of key=value pairs; extension values
// escape "\" and "=" and represent CR/LF as "\r"/"\n". All control characters
// (including ANSI ESC) are neutralised to spaces, so the output is always a
// single line with no raw newline. Severity comes from [cefSeverity]; Vendor,
// Product and Version come from the Event (defaulted when unset). Escaping is
// per the CEF specification (§ "Character encoding").
func FormatCEF(e Event) string {
	var ext strings.Builder
	writeExt := func(key, val string) {
		if ext.Len() > 0 {
			ext.WriteByte(' ')
		}
		ext.WriteString(key)
		ext.WriteByte('=')
		ext.WriteString(cefEscapeExtension(val))
	}

	if ip := e.ipString(); ip != "" {
		writeExt("src", ip)
	}
	writeExt("act", capField(e.Action))
	if !e.Time.IsZero() {
		// rt: CEF device-receipt-time, milliseconds since the Unix epoch.
		writeExt("rt", strconv.FormatInt(e.Time.UTC().UnixMilli(), 10))
	}
	if e.Rule != "" {
		writeExt("cs1Label", "rule")
		writeExt("cs1", capField(e.Rule))
	}
	if e.Actor != "" {
		writeExt("cs2Label", "actor")
		writeExt("cs2", capField(e.Actor))
	}
	writeExt("cn1Label", "score")
	writeExt("cn1", strconv.Itoa(e.Score))
	writeExt("cn2Label", "strike")
	writeExt("cn2", strconv.Itoa(e.Strike))
	writeExt("cn3Label", "ttlSeconds")
	writeExt("cn3", strconv.FormatInt(int64(e.TTL.Seconds()), 10))
	if e.Node != "" {
		writeExt("dvchost", capField(e.Node))
	}

	header := strings.Join([]string{
		"CEF:0",
		cefEscapeHeader(capField(e.vendor())),
		cefEscapeHeader(capField(e.product())),
		cefEscapeHeader(capField(e.version())),
		cefEscapeHeader(capField(cefSignatureID(e))),
		cefEscapeHeader(capField(cefName(e))),
		strconv.Itoa(cefSeverity(e)),
	}, "|")

	return header + "|" + ext.String()
}

// cefSignatureID is the stable per-event-kind identifier (CEF header field 5).
// It is the audit op, or "unknown" for the zero event so the field is never
// blank.
func cefSignatureID(e Event) string {
	if e.Action == "" {
		return "unknown"
	}
	return e.Action
}

// cefName is the human-readable event name (CEF header field 6), mapped from
// the audit op. Unknown ops fall back to the raw op text (escaped by the
// caller); the zero event gets a generic name so the field is never blank.
func cefName(e Event) string {
	switch e.Action {
	case "ban":
		return "IP banned"
	case "dry_ban":
		return "IP ban simulated"
	case "unban":
		return "IP unbanned"
	case "expire":
		return "Ban expired"
	case "allow":
		return "IP allowlisted"
	case "allow_expire":
		return "Allowlist entry expired"
	case "notify_only":
		return "Threat noticed (no ban)"
	case "arm":
		return "Enforcement armed"
	case "disarm":
		return "Enforcement disarmed"
	case "arm_revert":
		return "Enforcement auto-reverted"
	case "":
		return "EzyShield event"
	default:
		return e.Action
	}
}

// cefEscapeHeader escapes a CEF header field: "\" → "\\" and "|" → "\|" (the
// two header metacharacters), CR/LF rendered as "\r"/"\n", and every other C0
// control or DEL neutralised to a space. The result contains no raw newline
// and cannot introduce a new pipe-delimited header column.
func cefEscapeHeader(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '|':
			b.WriteString(`\|`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// cefEscapeExtension escapes a CEF extension value: "\" → "\\" and "=" → "\="
// (the key/value separator), CR/LF rendered as "\r"/"\n", and every other C0
// control or DEL neutralised to a space. Pipe is NOT a metacharacter inside
// the extension (it follows the final header pipe) so it is passed through.
func cefEscapeExtension(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '=':
			b.WriteString(`\=`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

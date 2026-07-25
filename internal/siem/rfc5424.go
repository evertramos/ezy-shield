package siem

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// facilityLocal0 is the syslog facility used for EzyShield audit events.
	// local0 (16) is the conventional facility for application-level security
	// tooling. PRI = facility*8 + severity (RFC 5424 §6.2.1).
	facilityLocal0 = 16

	// sdID is the RFC 5424 STRUCTURED-DATA SD-ID. The enterprise number 32473
	// is IANA's reserved example/documentation Private Enterprise Number
	// (RFC 5612 §3) — a deliberate placeholder until EzyShield registers its
	// own PEN, so the format is valid without claiming an unassigned number.
	sdID = "ezyShield@32473"

	// RFC 5424 length ceilings for the header tokens (§6).
	maxHostname = 255
	maxAppName  = 48
	maxMsgID    = 32
)

// FormatRFC5424 renders e as a single RFC 5424 syslog line:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
//
// PRI encodes facility local0 (16) and a severity mapped from the event
// (see [syslogSeverity]); VERSION is 1; TIMESTAMP is RFC 3339 in UTC (or the
// NILVALUE "-" for a zero time). HOSTNAME/APP-NAME/MSGID are reduced to
// printable-ASCII tokens within their RFC length limits. The event fields are
// carried as STRUCTURED-DATA SD-PARAMs under the enterprise SD-ID, with values
// escaped per RFC 5424 §6.3.3 ('"', '\' and ']' backslash-escaped) and all
// control characters neutralised, so the line never contains a raw newline and
// no field can terminate the SD element or the quoted value early.
func FormatRFC5424(e Event) string {
	pri := facilityLocal0*8 + syslogSeverity(e)

	ts := rfc3339UTC(e.Time)
	if ts == "" {
		ts = "-" // NILVALUE
	}
	hostname := syslogToken(e.Node, maxHostname)
	appName := syslogToken(e.product(), maxAppName)
	const procID = "-" // no PID at this layer
	msgID := syslogToken(e.Action, maxMsgID)

	var sd strings.Builder
	sd.WriteByte('[')
	sd.WriteString(sdID)
	writeParam := func(name, val string) {
		sd.WriteByte(' ')
		sd.WriteString(name)
		sd.WriteString(`="`)
		sd.WriteString(sdEscape(val))
		sd.WriteByte('"')
	}
	writeParam("action", capField(e.Action))
	if ip := e.ipString(); ip != "" {
		writeParam("ip", ip)
	}
	if e.Rule != "" {
		writeParam("rule", capField(e.Rule))
	}
	if e.Actor != "" {
		writeParam("actor", capField(e.Actor))
	}
	writeParam("score", strconv.Itoa(e.Score))
	writeParam("strike", strconv.Itoa(e.Strike))
	writeParam("ttlSeconds", strconv.FormatInt(int64(e.TTL.Seconds()), 10))
	if e.Node != "" {
		writeParam("node", capField(e.Node))
	}
	sd.WriteByte(']')

	line := fmt.Sprintf("<%d>1 %s %s %s %s %s %s",
		pri, ts, hostname, appName, procID, msgID, sd.String())
	if msg := syslogMSG(e); msg != "" {
		line += " " + msg
	}
	return line
}

// syslogMSG builds the free-text MSG part: a compact, human-readable summary
// with all control characters neutralised (no raw newline / ANSI) and the
// whole thing length-capped. MSG is not structured, so no delimiter escaping
// is needed — only control-character neutralisation and bounding.
func syslogMSG(e Event) string {
	action := e.Action
	if action == "" {
		action = "event"
	}
	parts := []string{action}
	if ip := e.ipString(); ip != "" {
		parts = append(parts, ip)
	}
	if e.Rule != "" {
		parts = append(parts, "rule="+e.Rule)
	}
	return capField(stripControls(strings.Join(parts, " ")))
}

// syslogToken reduces s to an RFC 5424 header token: only printable ASCII
// (%d33-126, i.e. no spaces or control characters) is kept, bounded to max
// bytes. Empty results become the NILVALUE "-".
func syslogToken(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r > 0x20 && r < 0x7f { // printable ASCII, excludes space and DEL
			b.WriteByte(byte(r))
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// sdEscape escapes an RFC 5424 SD-PARAM value per §6.3.3: '"', '\' and ']' are
// backslash-escaped so they cannot terminate the quoted value or the SD
// element. Every other control character (including CR/LF and ANSI ESC) is
// neutralised to a space, guaranteeing no raw newline in the output.
func sdEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r == ']':
			b.WriteString(`\]`)
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripControls replaces every C0 control character and DEL with a space and
// normalises invalid UTF-8 to U+FFFD (via the range-over-string decoding),
// leaving other bytes intact. Used for the free-text MSG part.
func stripControls(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

// hostileEvent carries terminal-injection payloads in every untrusted field,
// mimicking a StreamEvent built from a hostile log line.
func hostileEvent() daemon.StreamEvent {
	return daemon.StreamEvent{
		Time:     "\x1b[2Jnot-a-time",
		Kind:     "ban\x1b[31m",
		IP:       "203.0.113.7\x07",
		Category: "brute\x1b]0;owned\x07force",
		Rule:     "ssh\rd",
		TTL:      "1h\x00",
		Enforcer: "nft\x9bables",
		Reason:   "user \x1b[1;31madmin\x1b[0m failed\r\nlogin",
		Source:   "pipe\x7fline",
		Score:    85,
		Strike:   2,
	}
}

// TestFormatEventLine_HostileFieldsInert: with color disabled, the rendered
// line must contain zero bytes a terminal could interpret (issue #105
// acceptance criterion; §1 SECURITY-REVIEW).
func TestFormatEventLine_HostileFieldsInert(t *testing.T) {
	line := formatEventLine(hostileEvent(), false)
	for _, r := range line {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Errorf("line contains control rune %U: %q", r, line)
		}
	}
	// The payload text survives, defanged.
	for _, want := range []string{"ban", "203.0.113.7", "score=85", "strike=2"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %q", want, line)
		}
	}
}

// TestFormatEventLine_ColorOnlySelfEmitted: with color enabled, the only ESC
// sequences allowed are the ones kindColor/reset emit — hostile ESCs from
// event fields must still be gone.
func TestFormatEventLine_ColorOnlySelfEmitted(t *testing.T) {
	ev := hostileEvent()
	line := formatEventLine(ev, true)
	stripped := strings.ReplaceAll(line, kindColor(ev.Kind), "")
	stripped = strings.ReplaceAll(stripped, "\x1b[0m", "")
	if strings.ContainsRune(stripped, '\x1b') {
		t.Errorf("hostile ESC leaked past the self-emitted color codes: %q", line)
	}
}

// TestWatchNDJSON_SingleInertLine: in --json mode events are emitted via
// encoding/json, which guarantees one line of valid JSON per event with every
// C0 control byte — ESC, CR, LF included — escaped as \uXXXX, never raw. That
// is the security property NDJSON mode relies on: hostile bytes cannot break
// line framing or start an escape sequence.
func TestWatchNDJSON_SingleInertLine(t *testing.T) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(hostileEvent()); err != nil {
		t.Fatalf("encode: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
		t.Errorf("NDJSON must be exactly one newline-terminated line, got %q", out)
	}
	for _, b := range []byte(strings.TrimSuffix(out, "\n")) {
		if b < 0x20 {
			t.Errorf("raw control byte 0x%02x in NDJSON output: %q", b, out)
		}
	}
	var back daemon.StreamEvent
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if back.Score != 85 || back.Strike != 2 {
		t.Errorf("round trip lost fields: %+v", back)
	}
}

func TestNewEventFilter_Validation(t *testing.T) {
	if _, err := newEventFilter([]string{"ban", "detection"}, ""); err != nil {
		t.Errorf("valid kinds rejected: %v", err)
	}
	if _, err := newEventFilter([]string{"bogus"}, ""); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := newEventFilter(nil, "203.0.113.7"); err != nil {
		t.Errorf("valid addr rejected: %v", err)
	}
	if _, err := newEventFilter(nil, "192.0.2.0/24"); err != nil {
		t.Errorf("valid cidr rejected: %v", err)
	}
	if _, err := newEventFilter(nil, "not-an-ip"); err == nil {
		t.Error("garbage --ip accepted")
	}
}

func TestEventFilter_Match(t *testing.T) {
	ev := func(kind, ip string) daemon.StreamEvent {
		return daemon.StreamEvent{Kind: kind, IP: ip}
	}
	tests := []struct {
		name  string
		kinds []string
		ip    string
		event daemon.StreamEvent
		want  bool
	}{
		{"no filters pass all", nil, "", ev("detection", "203.0.113.7"), true},
		{"kind match", []string{"ban"}, "", ev("ban", "203.0.113.7"), true},
		{"kind mismatch", []string{"ban"}, "", ev("detection", "203.0.113.7"), false},
		{"addr match", nil, "203.0.113.7", ev("ban", "203.0.113.7"), true},
		{"addr mismatch", nil, "203.0.113.7", ev("ban", "203.0.113.8"), false},
		{"cidr contains addr", nil, "192.0.2.0/24", ev("ban", "192.0.2.55"), true},
		{"cidr excludes addr", nil, "192.0.2.0/24", ev("ban", "198.51.100.1"), false},
		{"cidr overlaps event prefix", nil, "192.0.2.0/24", ev("allow", "192.0.2.0/26"), true},
		{"event prefix wider than filter", nil, "192.0.2.10", ev("allow", "192.0.2.0/24"), true},
		{"unparseable event ip dropped", nil, "192.0.2.0/24", ev("ban", "\x1b[31mnope"), false},
		{"empty event ip dropped when filtering", nil, "192.0.2.0/24", ev("detection", ""), false},
		{"both filters must match", []string{"ban"}, "192.0.2.0/24", ev("ban", "192.0.2.1"), true},
		{"kind ok ip not", []string{"ban"}, "192.0.2.0/24", ev("ban", "203.0.113.1"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := newEventFilter(tc.kinds, tc.ip)
			if err != nil {
				t.Fatalf("newEventFilter: %v", err)
			}
			if got := f.match(tc.event); got != tc.want {
				t.Errorf("match = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestEventClock_HostileFallback: a non-RFC3339 timestamp (untrusted) must be
// sanitized, not printed raw.
func TestEventClock_HostileFallback(t *testing.T) {
	got := eventClock("\x1b[31mevil")
	if strings.ContainsRune(got, '\x1b') {
		t.Errorf("eventClock leaked ESC: %q", got)
	}
	if got != "evil" {
		t.Errorf("eventClock = %q, want %q", got, "evil")
	}
}

func TestSortedEventKinds_MatchesVocabulary(t *testing.T) {
	kinds := sortedEventKinds()
	if len(kinds) != len(validEventKinds) {
		t.Fatalf("got %d kinds, want %d", len(kinds), len(validEventKinds))
	}
	for i := 1; i < len(kinds); i++ {
		if kinds[i-1] >= kinds[i] {
			t.Errorf("kinds not sorted: %q before %q", kinds[i-1], kinds[i])
		}
	}
}

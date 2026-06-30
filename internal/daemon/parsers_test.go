package daemon

import (
	"testing"
	"time"
)

func TestParseExtendedDuration(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"5m", 5 * time.Minute, false},
		{"24h", 24 * time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"0d", 0, false},
		{"-1d", 0, true},
		{"banana", 0, true},
		{"d", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, err := parseExtendedDuration(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseExtendedDuration(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("parseExtendedDuration(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseUntil(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"2026-07-15", false},
		{"2026-07-15T18:00:00", false},
		{"2026-07-15T18:00:00Z", false},
		{"2026-07-15T18:00:00+02:00", false},
		{"yesterday", true},
		{"", true},
	}
	for _, tc := range cases {
		_, err := parseUntil(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseUntil(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
		}
	}
}

func TestParseSocketTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantBits int // expected prefix Bits()
		wantErr  bool
	}{
		{"1.2.3.4", 32, false},
		{"2001:db8::1", 128, false},
		{"203.0.113.0/24", 24, false},
		{"10.0.0.0/8", 8, false},
		{"", 0, true},
		{"not-an-ip", 0, true},
	}
	for _, tc := range cases {
		p, err := parseSocketTarget(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseSocketTarget(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && p.Bits() != tc.wantBits {
			t.Errorf("parseSocketTarget(%q) bits=%d, want %d", tc.in, p.Bits(), tc.wantBits)
		}
	}
}

func TestFormatExpires(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)

	if got := formatExpires(time.Time{}, now); got != "never" {
		t.Errorf("zero time should format as 'never', got %q", got)
	}
	if got := formatExpires(now.Add(-time.Hour), now); got != "expired" {
		t.Errorf("past time should format as 'expired', got %q", got)
	}
	if got := formatExpires(now.Add(2*time.Hour), now); got != "2h0m0s remaining" {
		t.Errorf("short-ttl should format as remaining hours, got %q", got)
	}
	if got := formatExpires(now.Add(48*time.Hour), now); got != "2026-06-30" {
		t.Errorf("long-ttl should format as ISO date, got %q", got)
	}
}

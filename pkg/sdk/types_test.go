package sdk_test

// pkg/sdk is the only public SDK surface and is declarations-only — there are
// no executable statements to cover (issue #361). What IS load-bearing about
// these declarations is their JSON serialization: the store persists
// []Verdict as a JSON column on strikes rows, and community plugins speak the
// same shapes over JSON/stdio. This test pins that round-trip, including the
// netip.Addr text encoding and the ADR-0010 Permanent field, so a field
// rename or type change cannot silently corrupt persisted history.

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestActionJSONRoundTrip(t *testing.T) {
	t.Parallel()
	in := sdk.Action{
		IP:        netip.MustParseAddr("192.0.2.9"),
		Op:        "ban",
		TTL:       0,
		Permanent: true, // ADR-0010 invariant: Permanent ⇒ TTL == 0
		Strike:    5,
		Reason:    "score=95 category=bruteforce source=rules",
		Verdicts: []sdk.Verdict{{
			IP:         netip.MustParseAddr("192.0.2.9"),
			Score:      95,
			Category:   "bruteforce",
			Confidence: 0.9,
			Reason:     "24 failed logins in 60s",
			Source:     "rules",
			SuggestTTL: 24 * time.Hour,
		}},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out sdk.Action
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("Action does not survive a JSON round-trip:\n in: %+v\nout: %+v", in, out)
	}
	if !out.IP.IsValid() || out.IP.String() != "192.0.2.9" {
		t.Errorf("netip.Addr must round-trip as text, got %q", out.IP)
	}
	if !out.Permanent || out.TTL != 0 {
		t.Errorf("Permanent/TTL lost in round-trip: %+v", out)
	}
}

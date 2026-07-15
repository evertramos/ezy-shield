package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newReportTestDaemon wires a daemon around an in-memory store and returns
// both so tests can seed fixtures directly.
func newReportTestDaemon(t *testing.T) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}
	d, err := New(Config{Policy: policy, Store: db})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

// seedStrike records one strike with a single rules verdict.
func seedStrike(t *testing.T, db *store.DB, ip netip.Addr, strike int, ttl time.Duration, reason string) {
	t.Helper()
	err := db.RecordStrike(context.Background(), sdk.Action{
		IP:     ip,
		Op:     "ban",
		TTL:    ttl,
		Strike: strike,
		Reason: reason,
		Verdicts: []sdk.Verdict{
			{IP: ip, Score: 92, Category: "ssh_bruteforce", Confidence: 0.9, Reason: reason, Source: "rules"},
		},
	})
	if err != nil {
		t.Fatalf("RecordStrike %s: %v", ip, err)
	}
}

// TestHandleReport_SingleIP covers the full per-IP happy path, including
// enrichment and the versioned schema envelope.
func TestHandleReport_SingleIP(t *testing.T) {
	d, db := newReportTestDaemon(t)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{Country: "NL", ASN: 12345, ASNOrg: "Example BV"}}

	ip := netip.MustParseAddr("203.0.113.7")
	seedStrike(t, db, ip, 1, 5*time.Minute, "ssh brute force")
	seedStrike(t, db, ip, 2, time.Hour, "ssh brute force again")

	resp := callSocket(t, d, SocketRequest{Verb: "report", IP: ip.String()})
	if !resp.OK {
		t.Fatalf("report failed: %s", resp.Error)
	}

	var rep sdk.AbuseReport
	if err := json.Unmarshal(resp.Data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if rep.SchemaVersion != sdk.AbuseReportSchemaVersion {
		t.Errorf("SchemaVersion: want %d, got %d", sdk.AbuseReportSchemaVersion, rep.SchemaVersion)
	}
	if rep.IP != ip.String() || rep.TotalStrikes != 2 {
		t.Errorf("identity: want ip=%s strikes=2, got ip=%s strikes=%d", ip, rep.IP, rep.TotalStrikes)
	}
	if rep.GeneratedAt == "" || rep.FirstSeen == "" || rep.LastSeen == "" {
		t.Errorf("timestamps must be set: %+v", rep)
	}
	if rep.Country != "NL" || rep.ASN != "AS12345" || rep.ASNOrg != "Example BV" {
		t.Errorf("enrichment: got country=%q asn=%q org=%q", rep.Country, rep.ASN, rep.ASNOrg)
	}
	if rep.CurrentBan == nil || rep.CurrentBan.Strike != 2 || rep.CurrentBan.Permanent {
		t.Errorf("current ban: want temp strike-2 ban, got %+v", rep.CurrentBan)
	}
	if len(rep.Strikes) != 2 || rep.Strikes[0].Strike != 2 {
		t.Fatalf("strikes: want 2 newest-first, got %+v", rep.Strikes)
	}
	if len(rep.Strikes[0].Verdicts) != 1 || rep.Strikes[0].Verdicts[0].Category != "ssh_bruteforce" {
		t.Errorf("verdicts: want ssh_bruteforce, got %+v", rep.Strikes[0].Verdicts)
	}
	if len(rep.Actions) != 2 || rep.Actions[0].Op != "ban" {
		t.Errorf("actions: want 2 ban rows, got %+v", rep.Actions)
	}
}

// TestHandleReport_ManualBanOnly: an IP banned manually (no offender row,
// no strikes) must still produce a report from the ban + audit trail.
func TestHandleReport_ManualBanOnly(t *testing.T) {
	d, db := newReportTestDaemon(t)

	ip := netip.MustParseAddr("198.51.100.9")
	if err := db.RecordManualBan(context.Background(), ip, 0, "manual permanent ban"); err != nil {
		t.Fatalf("RecordManualBan: %v", err)
	}

	resp := callSocket(t, d, SocketRequest{Verb: "report", IP: ip.String()})
	if !resp.OK {
		t.Fatalf("report failed: %s", resp.Error)
	}
	var rep sdk.AbuseReport
	if err := json.Unmarshal(resp.Data, &rep); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if rep.CurrentBan == nil || !rep.CurrentBan.Permanent {
		t.Errorf("want permanent current ban, got %+v", rep.CurrentBan)
	}
	if rep.TotalStrikes != 0 || len(rep.Strikes) != 0 {
		t.Errorf("manual ban must not carry strikes, got %+v", rep)
	}
	if len(rep.Actions) != 1 || rep.Actions[0].Op != "ban" {
		t.Errorf("actions: want the manual ban audit row, got %+v", rep.Actions)
	}
}

// TestHandleReport_Errors covers unknown IPs and malformed targets.
func TestHandleReport_Errors(t *testing.T) {
	d, _ := newReportTestDaemon(t)

	tests := []struct {
		name string
		ip   string
	}{
		{"unknown ip", "192.0.2.1"},
		{"cidr rejected", "203.0.113.0/24"},
		{"garbage rejected", "not-an-ip\x1b[31m"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := callSocket(t, d, SocketRequest{Verb: "report", IP: tc.ip})
			if resp.OK {
				t.Fatalf("want error for %q, got OK", tc.ip)
			}
			if resp.Error == "" {
				t.Error("error message must not be empty")
			}
		})
	}
}

// TestHandleReport_List covers the listing mode, the permanent filter, and
// filter validation.
func TestHandleReport_List(t *testing.T) {
	d, db := newReportTestDaemon(t)

	tempIP := netip.MustParseAddr("203.0.113.7")
	permIP := netip.MustParseAddr("198.51.100.9")
	seedStrike(t, db, tempIP, 1, time.Hour, "temp offender")
	seedStrike(t, db, permIP, 5, 0, "permanent offender")

	decode := func(t *testing.T, resp SocketResponse) []ReportSummaryEntry {
		t.Helper()
		if !resp.OK {
			t.Fatalf("report list failed: %s", resp.Error)
		}
		var out []ReportSummaryEntry
		if err := json.Unmarshal(resp.Data, &out); err != nil {
			t.Fatalf("unmarshal summaries: %v", err)
		}
		return out
	}

	all := decode(t, callSocket(t, d, SocketRequest{Verb: "report"}))
	if len(all) != 2 {
		t.Fatalf("all: want 2 offenders, got %d", len(all))
	}

	perm := decode(t, callSocket(t, d, SocketRequest{Verb: "report", Filter: "permanent"}))
	if len(perm) != 1 || perm[0].IP != permIP.String() || !perm[0].Permanent {
		t.Errorf("permanent filter: want only %s, got %+v", permIP, perm)
	}

	if resp := callSocket(t, d, SocketRequest{Verb: "report", Filter: "bogus"}); resp.OK {
		t.Error("want error for invalid filter, got OK")
	}
}

package daemon

import (
	"context"
	"net/netip"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fakeGeoLookup satisfies geoLookup and returns a fixed Enrichment for every IP.
type fakeGeoLookup struct {
	enrich sdk.Enrichment
}

func (f *fakeGeoLookup) Lookup(_ netip.Addr) sdk.Enrichment { return f.enrich }

// mustNewDaemon builds a minimal Daemon for unit testing. Parsers, collectors,
// enforcer and notifier are all nil (not needed for geoblock tests).
func mustNewDaemon(t *testing.T, pol *config.Policy) *Daemon {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Policy:     pol,
		Store:      db,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}
	return d
}

func armedGeoPolicy(countries, asns []string) *config.Policy {
	return &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
		BlockCountries:   countries,
		BlockASNs:        asns,
	}
}

var testIP = netip.MustParseAddr("203.0.113.42") // TEST-NET-3

// TestMaybeInjectGeoVerdict_NoEnricher verifies that without an enricher the
// verdicts slice is returned unchanged.
func TestMaybeInjectGeoVerdict_NoEnricher(t *testing.T) {
	pol := armedGeoPolicy([]string{"CN"}, []string{"AS16276"})
	d := mustNewDaemon(t, pol)
	// d.enricher is nil by default

	in := []sdk.Verdict{{IP: testIP, Score: 50, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != len(in) {
		t.Errorf("got %d verdicts, want %d (enricher=nil must be a no-op)", len(out), len(in))
	}
}

// TestMaybeInjectGeoVerdict_NoBlockLists verifies that with empty block lists the
// verdicts slice is returned unchanged even when enricher is active.
func TestMaybeInjectGeoVerdict_NoBlockLists(t *testing.T) {
	pol := armedGeoPolicy(nil, nil)
	d := mustNewDaemon(t, pol)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{Country: "CN", ASN: 16276}}

	in := []sdk.Verdict{{IP: testIP, Score: 50, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != len(in) {
		t.Errorf("got %d verdicts, want %d (empty block lists must be a no-op)", len(out), len(in))
	}
}

// TestMaybeInjectGeoVerdict_BlockedCountry verifies that an IP from a blocked
// country gets a geo_block verdict appended.
func TestMaybeInjectGeoVerdict_BlockedCountry(t *testing.T) {
	pol := armedGeoPolicy([]string{"CN", "RU"}, nil)
	d := mustNewDaemon(t, pol)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{Country: "CN"}}

	in := []sdk.Verdict{{IP: testIP, Score: 30, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != 2 {
		t.Fatalf("got %d verdicts, want 2 (original + geo_block)", len(out))
	}
	geo := out[1]
	if geo.Category != "geo_block" {
		t.Errorf("injected verdict Category = %q, want geo_block", geo.Category)
	}
	if geo.Score != config.GeoBlockScore {
		t.Errorf("injected verdict Score = %d, want %d", geo.Score, config.GeoBlockScore)
	}
	if geo.Source != "policy:block_countries" {
		t.Errorf("injected verdict Source = %q, want policy:block_countries", geo.Source)
	}
}

// TestMaybeInjectGeoVerdict_BlockedASN verifies that an IP from a blocked ASN
// gets a geo_block verdict appended.
func TestMaybeInjectGeoVerdict_BlockedASN(t *testing.T) {
	pol := armedGeoPolicy(nil, []string{"AS14061"})
	d := mustNewDaemon(t, pol)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{ASN: 14061, ASNOrg: "DigitalOcean"}}

	in := []sdk.Verdict{{IP: testIP, Score: 30, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != 2 {
		t.Fatalf("got %d verdicts, want 2 (original + geo_block)", len(out))
	}
	geo := out[1]
	if geo.Category != "geo_block" {
		t.Errorf("injected verdict Category = %q, want geo_block", geo.Category)
	}
	if geo.Score != config.GeoBlockScore {
		t.Errorf("injected verdict Score = %d, want %d", geo.Score, config.GeoBlockScore)
	}
	if geo.Source != "policy:block_asns" {
		t.Errorf("injected verdict Source = %q, want policy:block_asns", geo.Source)
	}
}

// TestMaybeInjectGeoVerdict_UnblockedCountry verifies that an IP from an
// allowlisted country does not get an injected verdict.
func TestMaybeInjectGeoVerdict_UnblockedCountry(t *testing.T) {
	pol := armedGeoPolicy([]string{"CN", "RU"}, nil)
	d := mustNewDaemon(t, pol)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{Country: "US"}}

	in := []sdk.Verdict{{IP: testIP, Score: 30, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != 1 {
		t.Errorf("got %d verdicts, want 1 (US is not blocked)", len(out))
	}
}

// TestMaybeInjectGeoVerdict_EmptyEnrichment verifies that an IP with empty
// enrichment (lookup returned nothing) does not get an injected verdict.
func TestMaybeInjectGeoVerdict_EmptyEnrichment(t *testing.T) {
	pol := armedGeoPolicy([]string{"CN"}, []string{"AS16276"})
	d := mustNewDaemon(t, pol)
	d.enricher = &fakeGeoLookup{enrich: sdk.Enrichment{}} // empty: no country, no ASN

	in := []sdk.Verdict{{IP: testIP, Score: 50, Source: "rules"}}
	out := d.maybeInjectGeoVerdict(context.Background(), testIP, in)
	if len(out) != 1 {
		t.Errorf("got %d verdicts, want 1 (empty enrichment must skip)", len(out))
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Tests for the daemon half of the verified-bot guard (issue #215):
// UA-claim extraction from in-memory aggregates, the injected check, and
// that DNS never runs when nothing claimed a bot.

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/botverify"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

type countingResolver struct {
	ptr   map[string][]string
	fwd   map[string][]string
	calls atomic.Int32
}

func (r *countingResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	r.calls.Add(1)
	return r.ptr[addr], nil
}

func (r *countingResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	return r.fwd[host], nil
}

func newBotDaemon(t *testing.T, rs botverify.Resolver) *Daemon {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Cfg: &config.Config{VerifiedBots: &config.VerifiedBotsCfg{Enabled: true}},
		Policy: &config.Policy{
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Swap the production resolver for the stub (initVerifiedBots wired the
	// rest — providers table and the decision-engine callback).
	d.botVerifier = botverify.New(rs)
	return d
}

func addHTTPEvent(d *Daemon, ip netip.Addr, ua string) {
	d.agg.Add(sdk.Event{
		Time:     time.Now(),
		SourceIP: ip,
		Kind:     "http_request",
		Fields:   map[string]string{"path": "/", "status": "200", "ua": ua},
	})
}

func TestVerifiedBotCheck_GenuineCrawlerSpared(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.70")
	rs := &countingResolver{
		ptr: map[string][]string{ip.String(): {"crawl-70.googlebot.com."}},
		fwd: map[string][]string{"crawl-70.googlebot.com": {ip.String()}},
	}
	d := newBotDaemon(t, rs)
	addHTTPEvent(d, ip, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

	provider, spared := d.verifiedBotCheck(context.Background(), ip)
	if !spared || provider != "googlebot" {
		t.Fatalf("check = (%q, %v), want (googlebot, true)", provider, spared)
	}
}

func TestVerifiedBotCheck_SpooferNotSpared(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.71")
	rs := &countingResolver{
		ptr: map[string][]string{ip.String(): {"vps-71.evil.example."}},
		fwd: map[string][]string{"vps-71.evil.example": {ip.String()}},
	}
	d := newBotDaemon(t, rs)
	addHTTPEvent(d, ip, "Googlebot/2.1 (totally real)")

	if provider, spared := d.verifiedBotCheck(context.Background(), ip); spared {
		t.Fatalf("spoofed claim must not spare, got (%q, %v)", provider, spared)
	}
	if rs.calls.Load() == 0 {
		t.Fatal("a claimed UA must trigger the FCrDNS lookup")
	}
}

func TestVerifiedBotCheck_NoClaimMeansNoDNS(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.72")
	rs := &countingResolver{}
	d := newBotDaemon(t, rs)
	addHTTPEvent(d, ip, "curl/8.0")

	if _, spared := d.verifiedBotCheck(context.Background(), ip); spared {
		t.Fatal("no bot claim must never spare")
	}
	if rs.calls.Load() != 0 {
		t.Fatalf("DNS ran %d times with no bot claim — lookups must be claim-gated", rs.calls.Load())
	}
}

func TestInitVerifiedBots_DisabledLeavesEngineUntouched(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Cfg: &config.Config{}, // no verified_bots section
		Policy: &config.Policy{
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d.botVerifier != nil || d.botProviders != nil {
		t.Fatal("verified-bots must stay dormant unless enabled")
	}
}

func TestBotProvidersFromConfig_MergesCustom(t *testing.T) {
	got := botProvidersFromConfig(&config.VerifiedBotsCfg{
		Enabled: true,
		Providers: []config.VerifiedBotProviderCfg{
			{Name: "mymonitor", UAContains: []string{"MyMonitor"}, Domains: []string{"monitor.example.com"}},
		},
	})
	var found *botverify.Provider
	for i := range got {
		if got[i].Name == "mymonitor" {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatalf("custom provider missing from %v", got)
	}
	if found.UAContains[0] != "mymonitor" {
		t.Fatalf("UA substrings must be lowercased, got %v", found.UAContains)
	}
	if p := botverify.ClaimedProvider(got, "MyMonitor/1.0 uptime check"); p == nil || p.Name != "mymonitor" {
		t.Fatalf("custom UA claim not recognized: %v", p)
	}
}

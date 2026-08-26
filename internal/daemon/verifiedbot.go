package daemon

// Verified-bot wiring (issue #215): the daemon owns UA-claim extraction
// (from the in-memory aggregates' event samples) and the FCrDNS verifier;
// the decision engine only sees an injected callback. DNS never runs in the
// hot parse path — the callback fires solely when Decide reaches the ban
// band for an IP, and the verifier caches results either way.

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/botverify"
	"github.com/evertramos/ezy-shield/internal/config"
)

// botProvidersFromConfig converts the config section into the effective
// provider table (defaults merged with operator entries by name).
func botProvidersFromConfig(cfg *config.VerifiedBotsCfg) []botverify.Provider {
	custom := make([]botverify.Provider, 0, len(cfg.Providers))
	for _, p := range cfg.Providers {
		ua := make([]string, 0, len(p.UAContains))
		for _, s := range p.UAContains {
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
				ua = append(ua, s)
			}
		}
		custom = append(custom, botverify.Provider{Name: p.Name, UAContains: ua, Domains: p.Domains})
	}
	return botverify.Merge(botverify.DefaultProviders(), custom)
}

// botUAClaim scans the IP's in-window event samples for a User-Agent that
// claims a known bot. Read-only over the in-memory aggregates; returns nil
// when nothing claims a bot (the common case — no DNS happens then).
func (d *Daemon) botUAClaim(ip netip.Addr) *botverify.Provider {
	now := time.Now()
	for _, w := range d.agg.Windows() {
		agg := d.agg.Aggregate(ip, w, now)
		for _, ev := range agg.Sample {
			if ua, ok := ev.Fields["ua"]; ok && ua != "" {
				if p := botverify.ClaimedProvider(d.botProviders, ua); p != nil {
					return p
				}
			}
		}
	}
	return nil
}

// verifiedBotCheck is the callback injected into the decision engine. It
// reports (provider, true) only when the IP's traffic claimed a known bot
// AND FCrDNS confirmed the claim; every other outcome — no claim, PTR or
// forward mismatch, DNS timeout — returns false and the normal ban path
// proceeds (a spoofer is banned like any attacker).
func (d *Daemon) verifiedBotCheck(ctx context.Context, ip netip.Addr) (string, bool) {
	p := d.botUAClaim(ip)
	if p == nil {
		return "", false
	}
	if d.botVerifier.Verify(ctx, ip, p) {
		return p.Name, true
	}
	return "", false
}

// initVerifiedBots wires the guard when the config enables it. Called from
// New before any goroutine starts.
func (d *Daemon) initVerifiedBots(cfg *config.VerifiedBotsCfg) {
	if cfg == nil || !cfg.Enabled {
		return
	}
	d.botProviders = botProvidersFromConfig(cfg)
	d.botVerifier = botverify.New(net.DefaultResolver)
	d.decEng.SetBotVerifier(d.verifiedBotCheck)
}

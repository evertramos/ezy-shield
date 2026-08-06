// AI-boundary chokepoint tests (issue #402, SECURITY-REVIEW §5).
//
// Providers already bound verdicts to the analyzed batch (boundToBatch, #312)
// and the cache re-targets replayed verdicts (#311), but both are per-component
// obligations. These tests pin the daemon-side invariant: no verdict leaves
// maybeConsultAI targeting an IP other than the one whose aggregates were
// analyzed — whatever the provider (present or future) returned — and
// allowlist-clamped verdicts are never cached.
package daemon

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// rawAIProvider returns its verdicts verbatim — no boundToBatch, no clamp.
// It simulates a future/broken provider implementation that forgot the
// provider-level bound, which is exactly the class of bug the daemon-side
// chokepoint must absorb.
type rawAIProvider struct {
	mu       sync.Mutex
	calls    int
	verdicts []sdk.Verdict
}

func (r *rawAIProvider) Name() string { return "raw-ai" }

func (r *rawAIProvider) Analyze(_ context.Context, _ []sdk.Aggregate, _ sdk.TokenBudget) ([]sdk.Verdict, sdk.Usage, error) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	out := make([]sdk.Verdict, len(r.verdicts))
	copy(out, r.verdicts)
	return out, sdk.Usage{InputTokens: 10, OutputTokens: 5}, nil
}

func (r *rawAIProvider) CallCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// newAIDaemon builds a daemon with AI wired to the given raw provider and a
// live cache, ambiguous band [30,95]. The store is in-memory; no goroutines
// are started (tests call maybeConsultAI directly).
func newAIDaemon(t *testing.T, prov sdk.AIProvider) *Daemon {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	d, err := New(Config{
		Cfg: &config.Config{
			AI: &config.AICfg{AmbiguousBand: [2]int{30, 95}},
		},
		Policy:     policy,
		Store:      db,
		AIProvider: prov,
		AIBudget:   ai.NewBudget("raw-ai", 0, &fakeBudgetStore{}),
		AICache:    ai.NewCache(time.Minute),
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// inBandVerdicts returns a rules-style verdict slice whose top score sits
// inside the [30,95] ambiguous band so maybeConsultAI consults the provider.
func inBandVerdicts(ip netip.Addr) []sdk.Verdict {
	return []sdk.Verdict{{IP: ip, Score: 50, Category: "scanner", Source: "rules"}}
}

// TestMaybeConsultAI_OffRequestVerdictIP_Dropped is the fresh-verdict leg of
// issue #402: a provider (here one with no boundToBatch, standing in for a
// prompt-injected or future unbound implementation) names an IP that was never
// part of the request. The daemon must drop that verdict at its own boundary —
// the model must not be able to steer a strike onto a model-chosen victim.
func TestMaybeConsultAI_OffRequestVerdictIP_Dropped(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	victim := netip.MustParseAddr("203.0.113.9")

	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: victim, Score: 95, Category: "bruteforce", Reason: "never observed", Source: "ai:raw-ai"},
		{IP: requested, Score: 60, Category: "scanner", Reason: "observed", Source: "ai:raw-ai"},
	}}
	d := newAIDaemon(t, prov)

	out := d.maybeConsultAI(context.Background(), requested, inBandVerdicts(requested))

	for _, v := range out {
		if v.IP == victim {
			t.Fatalf("off-request verdict for %s survived the daemon boundary: %+v", victim, v)
		}
	}
	// The in-request AI verdict must survive (score 60 from ai:raw-ai).
	found := false
	for _, v := range out {
		if v.Source == "ai:raw-ai" && v.IP == requested && v.Score == 60 {
			found = true
		}
	}
	if !found {
		t.Errorf("in-request AI verdict was lost; got %+v", out)
	}
}

// TestMaybeConsultAI_OffRequestVerdictIP_NotCachedForReplay verifies the
// poisoned verdict also never reaches the cache: a second consult for a
// different IP with the same behavior signature must not replay the
// model-chosen victim (nor, post-#311 re-targeting, any residue of it).
func TestMaybeConsultAI_OffRequestVerdictIP_NotCachedForReplay(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")
	victim := netip.MustParseAddr("203.0.113.9")

	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: victim, Score: 95, Category: "bruteforce", Source: "ai:raw-ai"},
	}}
	d := newAIDaemon(t, prov)

	ctx := context.Background()
	_ = d.maybeConsultAI(ctx, requested, inBandVerdicts(requested))
	out := d.maybeConsultAI(ctx, other, inBandVerdicts(other))

	for _, v := range out {
		if v.IP == victim {
			t.Fatalf("victim IP %s replayed from cache: %+v", victim, v)
		}
		if v.Source == "ai:raw-ai" && v.Score == 95 {
			t.Fatalf("poisoned verdict (score 95) replayed onto %s: %+v", v.IP, v)
		}
	}
}

// TestMaybeConsultAI_MappedFormRebound verifies the daemon-side check is
// representation-insensitive: a verdict carrying the IPv4-mapped IPv6 form of
// the requested address is kept and rewritten to the canonical request IP
// (cf. #314), so the decision engine's single-IP invariant holds.
func TestMaybeConsultAI_MappedFormRebound(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	mapped := netip.MustParseAddr("::ffff:192.0.2.1")

	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: mapped, Score: 60, Category: "scanner", Source: "ai:raw-ai"},
	}}
	d := newAIDaemon(t, prov)

	out := d.maybeConsultAI(context.Background(), requested, inBandVerdicts(requested))

	found := false
	for _, v := range out {
		if v.Source == "ai:raw-ai" {
			found = true
			if v.IP != requested {
				t.Errorf("verdict IP = %s, want canonical %s", v.IP, requested)
			}
		}
	}
	if !found {
		t.Error("mapped-form verdict for the requested IP must be kept, got none")
	}
}

// TestMaybeConsultAI_ZonedVerdictIP_FailsClosed verifies zone handling fails
// closed in both directions: a zoned verdict for an unzoned request (and vice
// versa) is dropped, never "close enough"-rebound.
func TestMaybeConsultAI_ZonedVerdictIP_FailsClosed(t *testing.T) {
	unzoned := netip.MustParseAddr("2001:db8::1")
	zoned := unzoned.WithZone("eth0")

	cases := []struct {
		name      string
		requested netip.Addr
		fromModel netip.Addr
	}{
		{"zoned verdict, unzoned request", unzoned, zoned},
		{"unzoned verdict, zoned request", zoned, unzoned},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prov := &rawAIProvider{verdicts: []sdk.Verdict{
				{IP: tc.fromModel, Score: 60, Category: "scanner", Source: "ai:raw-ai"},
			}}
			d := newAIDaemon(t, prov)

			out := d.maybeConsultAI(context.Background(), tc.requested, inBandVerdicts(tc.requested))
			for _, v := range out {
				if v.Source == "ai:raw-ai" {
					t.Fatalf("zone-mismatched verdict survived: requested %s, got verdict for %s",
						tc.requested, v.IP)
				}
			}
		})
	}
}

// TestMaybeConsultAI_ClampedVerdictNotCached is the cache leg of issue #402 at
// the daemon level: an allowlist-clamped (Score-0) verdict must not be written
// to the behavior-signature cache, so a same-signature consult for a different
// IP goes back to the provider instead of inheriting the clamp (evasion window).
func TestMaybeConsultAI_ClampedVerdictNotCached(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("203.0.113.66")

	// Source carries the clamp marker exactly as a real provider clamp stamps
	// it — Reason alone is model-controlled text and must not read as a clamp
	// (Strix on #414, CWE-345; forgery is covered in internal/ai's tests).
	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: requested, Score: 0, Reason: ai.ReasonAllowlistClamped,
			Source: "ai:raw-ai" + ai.AllowlistClampSourceSuffix},
	}}
	d := newAIDaemon(t, prov)

	ctx := context.Background()
	_ = d.maybeConsultAI(ctx, requested, inBandVerdicts(requested))
	if got := prov.CallCount(); got != 1 {
		t.Fatalf("provider calls after first consult = %d, want 1", got)
	}

	// Same behavior signature (same empty aggregator state), different IP:
	// must MISS the cache and consult the provider again.
	prov.verdicts = []sdk.Verdict{
		{IP: other, Score: 80, Category: "bruteforce", Source: "ai:raw-ai"},
	}
	_ = d.maybeConsultAI(ctx, other, inBandVerdicts(other))
	if got := prov.CallCount(); got != 2 {
		t.Fatalf("clamped verdict was cached: provider calls = %d, want 2 (cache must miss)", got)
	}
}

// TestMaybeConsultAI_GenuineVerdictStillCached guards the flip side: a genuine
// (non-clamped) verdict is still cached, so the second same-signature consult
// does NOT call the provider again. The #402 fix must not disable caching.
func TestMaybeConsultAI_GenuineVerdictStillCached(t *testing.T) {
	requested := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")

	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: requested, Score: 60, Category: "scanner", Reason: "probing", Source: "ai:raw-ai"},
	}}
	d := newAIDaemon(t, prov)

	ctx := context.Background()
	_ = d.maybeConsultAI(ctx, requested, inBandVerdicts(requested))
	out := d.maybeConsultAI(ctx, other, inBandVerdicts(other))

	if got := prov.CallCount(); got != 1 {
		t.Fatalf("provider calls = %d, want 1 (second consult should hit cache)", got)
	}
	// The cached verdict must be re-targeted to the second IP (issue #311)
	// and pass the daemon boundary.
	found := false
	for _, v := range out {
		if v.Source == "ai:raw-ai" {
			found = true
			if v.IP != other {
				t.Errorf("cached verdict IP = %s, want re-targeted %s", v.IP, other)
			}
		}
	}
	if !found {
		t.Error("cached verdict lost at the daemon boundary")
	}
}

// TestEndToEnd_AI_InjectedVerdict_NoStrikeOnVictim runs the full pipeline with
// a provider that names an off-request victim at ban-worthy score. The victim
// must receive no action and no strike; the observed attacker is handled on
// rules evidence alone.
func TestEndToEnd_AI_InjectedVerdict_NoStrikeOnVictim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     90, // rules alone stay below; only the injected 95 could cross
		ObserveThreshold: 10,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	attacker := netip.MustParseAddr("198.51.100.55")
	victim := netip.MustParseAddr("203.0.113.9")

	prov := &rawAIProvider{verdicts: []sdk.Verdict{
		{IP: victim, Score: 95, Category: "bruteforce", Reason: "injected", Source: "ai:raw-ai"},
	}}

	fc := &fakeCollector{lines: bruteforceLines(attacker, 6)}
	actionsCh := make(chan sdk.Action, 32)

	d, err := New(Config{
		Cfg: &config.Config{
			AI: &config.AICfg{AmbiguousBand: [2]int{30, 95}},
		},
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Collectors: []sdk.Collector{fc},
		AIProvider: prov,
		AIBudget:   ai.NewBudget("raw-ai", 0, &fakeBudgetStore{}),
		AICache:    ai.NewCache(time.Minute),
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.SetActionsSink(actionsCh)

	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(ctx) }()

	var got sdk.Action
	select {
	case got = <-actionsCh:
	case <-ctx.Done():
		t.Fatal("timeout: no action received within deadline")
	}

	cancel()
	<-daemonDone

	if got.IP == victim {
		t.Fatalf("action targeted the model-chosen victim %s: %+v", victim, got)
	}
	if got.IP != attacker {
		t.Errorf("action IP = %s, want observed attacker %s", got.IP, attacker)
	}

	// Drain any further actions: none may name the victim.
	for {
		select {
		case a := <-actionsCh:
			if a.IP == victim {
				t.Fatalf("late action targeted victim %s: %+v", victim, a)
			}
			continue
		default:
		}
		break
	}

	strikes, err := db.StrikesForIP(context.Background(), victim, 10)
	if err != nil {
		t.Fatalf("StrikesForIP: %v", err)
	}
	if len(strikes) != 0 {
		t.Fatalf("victim %s received %d strike(s) from an injected verdict", victim, len(strikes))
	}
}

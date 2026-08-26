// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Async second-layer AI tests (issue #222): the worker end to end (queue →
// cleaner → provider → decision engine), queue bounds (drop-oldest,
// per-IP dedupe, non-blocking enqueue), allowlist supremacy over async
// verdicts, agreement metric, and rules-only degradation on provider
// failure.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// slowOrFailingProvider simulates a dead provider: every call errors.
type failingProvider struct {
	mu    sync.Mutex
	calls int
}

func (f *failingProvider) Name() string { return "raw-ai" }
func (f *failingProvider) Analyze(context.Context, []sdk.Aggregate, sdk.TokenBudget) ([]sdk.Verdict, sdk.Usage, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return nil, sdk.Usage{}, errors.New("provider is down")
}

// newAIDaemonAllowlisted mirrors newAIDaemon with a policy allowlist entry,
// for the allowlist-supremacy leg of the async path.
func newAIDaemonAllowlisted(t *testing.T, prov sdk.AIProvider, cidr string) *Daemon {
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
		Allowlist:        []string{cidr},
	}
	d, err := New(Config{
		Cfg:        &config.Config{AI: &config.AICfg{AmbiguousBand: [2]int{30, 95}}},
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

// seedHTTPActivity puts sampled HTTP events for ip into the aggregator so
// collectAIAggregates has something to clean and send.
func seedHTTPActivity(d *Daemon, ip netip.Addr, n int) {
	for i := 0; i < n; i++ {
		d.agg.Add(sdk.Event{
			Time:     time.Now(),
			SourceIP: ip,
			Kind:     "http_404",
			Fields:   map[string]string{"path": "/wp-login.php", "method": "POST", "status": "404", "ua": "curl"},
		})
	}
}

// startAsync arms the queue + worker on a test daemon.
func startAsync(t *testing.T, d *Daemon, capacity int) context.CancelFunc {
	t.Helper()
	d.aiQueue = newAIAsyncQueue(capacity)
	ctx, cancel := context.WithCancel(context.Background())
	go d.runAIAsync(ctx)
	t.Cleanup(cancel)
	return cancel
}

func waitForCond(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// TestAIAsync_EndToEnd: a grey-zone enqueue reaches the provider and the
// returned verdict flows through the decision engine into a recorded
// (dry-run) action.
func TestAIAsync_EndToEnd(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.80")
	prov := &rawAIProvider{verdicts: []sdk.Verdict{{
		IP: ip, Score: 90, Category: "scanner", Source: "ai:raw-ai", Confidence: 0.9,
	}}}
	d := newAIDaemon(t, prov)
	seedHTTPActivity(d, ip, 5)
	startAsync(t, d, 8)

	d.maybeEnqueueAI(context.Background(), ip, 50)

	if !waitForCond(t, 10*time.Second, func() bool { return prov.CallCount() >= 1 }) {
		t.Fatalf("worker never called the provider")
	}
	// Score 90 >= ban threshold (70), daemon disarmed → a dry_ban strike
	// lands in the store via the decision engine.
	ok := waitForCond(t, 10*time.Second, func() bool {
		bans, err := d.store.ActiveBans(context.Background())
		return err == nil && len(bans) == 1
	})
	if !ok {
		t.Fatalf("async verdict never produced a decision-engine action")
	}
}

// TestAIAsync_AllowlistWins: an async AI verdict against an allowlisted IP
// is clamped by the decision engine — the async path gets the exact same
// guardrails as every other verdict source.
func TestAIAsync_AllowlistWins(t *testing.T) {
	ip := netip.MustParseAddr("198.51.100.80")
	prov := &rawAIProvider{verdicts: []sdk.Verdict{{
		IP: ip, Score: 99, Category: "scanner", Source: "ai:raw-ai", Confidence: 1,
	}}}
	d := newAIDaemonAllowlisted(t, prov, "198.51.100.0/24")
	seedHTTPActivity(d, ip, 5)
	startAsync(t, d, 8)

	d.maybeEnqueueAI(context.Background(), ip, 50)
	if !waitForCond(t, 10*time.Second, func() bool { return prov.CallCount() >= 1 }) {
		t.Fatalf("worker never called the provider")
	}
	time.Sleep(200 * time.Millisecond) // let the decide path finish
	bans, err := d.store.ActiveBans(context.Background())
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("allowlisted IP was banned via the async AI path: %+v", bans)
	}
}

// TestAIAsync_QueueBounds: per-IP dedupe, drop-oldest on overflow, and a
// non-blocking enqueue regardless of queue state.
func TestAIAsync_QueueBounds(t *testing.T) {
	q := newAIAsyncQueue(2)

	ipA := netip.MustParseAddr("203.0.113.81")
	q.push(aiAsyncItem{ip: ipA})
	q.push(aiAsyncItem{ip: ipA}) // dedupe
	if q.depth() != 1 {
		t.Fatalf("dedupe failed: depth=%d", q.depth())
	}

	ipB := netip.MustParseAddr("203.0.113.82")
	ipC := netip.MustParseAddr("203.0.113.83")
	q.push(aiAsyncItem{ip: ipB})
	start := time.Now()
	q.push(aiAsyncItem{ip: ipC}) // overflow: drops ipA (oldest)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("push blocked on a full queue")
	}
	if q.dropped.Load() != 1 {
		t.Fatalf("dropped = %d, want 1", q.dropped.Load())
	}
	item, ok := q.pop()
	if !ok || item.ip != ipB {
		t.Fatalf("oldest surviving item should be ipB, got %v", item.ip)
	}
	// The dropped IP can enqueue again (its pending mark was cleared).
	q.push(aiAsyncItem{ip: ipA})
	if q.depth() != 2 {
		t.Fatalf("re-enqueue after drop failed: depth=%d", q.depth())
	}
}

// TestAIAsync_DeadProviderDegradesToRules: provider failures never stall
// anything — the worker keeps draining, detection stays rules-only.
func TestAIAsync_DeadProviderDegradesToRules(t *testing.T) {
	prov := &failingProvider{}
	d := newAIDaemon(t, prov)
	ip := netip.MustParseAddr("203.0.113.84")
	seedHTTPActivity(d, ip, 5)
	startAsync(t, d, 8)

	d.maybeEnqueueAI(context.Background(), ip, 50)
	if !waitForCond(t, 10*time.Second, func() bool {
		prov.mu.Lock()
		defer prov.mu.Unlock()
		return prov.calls >= 1
	}) {
		t.Fatalf("worker never attempted the provider")
	}
	time.Sleep(200 * time.Millisecond)
	bans, err := d.store.ActiveBans(context.Background())
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Fatalf("a failing provider must not produce actions: %+v", bans)
	}
}

// TestAIAsync_AgreementMetric: the agree/disagree counter reflects the
// ban-threshold side comparison between rules and the AI.
func TestAIAsync_AgreementMetric(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.85")
	prov := &rawAIProvider{verdicts: []sdk.Verdict{{
		IP: ip, Score: 90, Category: "scanner", Source: "ai:raw-ai", Confidence: 0.9,
	}}}
	d := newAIDaemon(t, prov)
	seedHTTPActivity(d, ip, 5)
	startAsync(t, d, 8)

	// Rules said 50 (below threshold 70); AI says 90 (above) → disagree.
	d.maybeEnqueueAI(context.Background(), ip, 50)
	ok := waitForCond(t, 10*time.Second, func() bool {
		return strings.Contains(d.metrics.reg.Snapshot(), `ezyshield_ai_agreement_total{outcome="raw-ai_disagree"} 1`)
	})
	if !ok {
		t.Fatalf("agreement metric missing:\n%s", d.metrics.reg.Snapshot())
	}
}

// TestAIAsync_EnqueueRespectsGates: out-of-band scores never enqueue.
func TestAIAsync_EnqueueRespectsGates(t *testing.T) {
	prov := &rawAIProvider{}
	d := newAIDaemon(t, prov)
	d.aiQueue = newAIAsyncQueue(8) // queue armed, worker NOT running

	d.maybeEnqueueAI(context.Background(), netip.MustParseAddr("203.0.113.86"), 10) // below band
	d.maybeEnqueueAI(context.Background(), netip.MustParseAddr("203.0.113.87"), 99) // above band
	if d.aiQueue.depth() != 0 {
		t.Fatalf("out-of-band scores must not enqueue: depth=%d", d.aiQueue.depth())
	}
	d.maybeEnqueueAI(context.Background(), netip.MustParseAddr("203.0.113.88"), 50)
	if d.aiQueue.depth() != 1 {
		t.Fatalf("in-band score must enqueue: depth=%d", d.aiQueue.depth())
	}
}

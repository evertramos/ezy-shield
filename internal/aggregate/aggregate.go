// Package aggregate provides per-IP sliding-window event aggregation.
// The Aggregator is safe for concurrent use. All methods honour context
// cancellation where a loop is involved.
package aggregate

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// DefaultMaxSamples is the default cap on events stored in sdk.Aggregate.Sample.
// The cap is intentionally large so that rule-engine field-level matching
// (e.g. counting 404s within the sample) remains accurate at typical thresholds.
// The AI layer must further reduce / redact the sample before sending it to a
// language model; never forward Sample directly to an LLM.
const DefaultMaxSamples = 4096

type entry struct {
	at time.Time
	ev sdk.Event
}

type ipBucket struct {
	entries  []entry
	lastSeen time.Time
}

// Aggregator maintains per-IP sliding-window event counts and capped samples.
// Events older than the longest configured window are evicted on every Add call.
// When maxIPs > 0 the bucket for the least-recently-seen IP is evicted once the
// count exceeds the cap, bounding memory growth regardless of attack breadth.
type Aggregator struct {
	windows   []time.Duration // all configured windows
	maxWindow time.Duration   // longest window; controls eviction horizon
	maxSamp   int             // sample cap
	maxIPs    int             // LRU cap; 0 = unlimited
	mu        sync.Mutex
	buckets   map[netip.Addr]*ipBucket
}

// New creates an Aggregator with the given sliding windows and sample cap.
// windows must be non-empty and contain only positive durations.
// maxSamples ≤ 0 falls back to DefaultMaxSamples.
func New(windows []time.Duration, maxSamples int) *Aggregator {
	if maxSamples <= 0 {
		maxSamples = DefaultMaxSamples
	}
	maxW := windows[0]
	for _, w := range windows[1:] {
		if w > maxW {
			maxW = w
		}
	}
	return &Aggregator{
		windows:   windows,
		maxWindow: maxW,
		maxSamp:   maxSamples,
		buckets:   make(map[netip.Addr]*ipBucket),
	}
}

// WithMaxIPs sets the maximum number of per-IP buckets retained in memory.
// When the limit is exceeded, the bucket least-recently-seen is evicted.
// A value ≤ 0 disables the cap (the default).
// WithMaxIPs returns the receiver for chaining with New().
func (a *Aggregator) WithMaxIPs(maxIPs int) *Aggregator {
	a.maxIPs = maxIPs
	return a
}

// Len returns the number of distinct IPs currently tracked.
func (a *Aggregator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.buckets)
}

// Windows returns the configured sliding windows.
// Useful for callers that need to know which window durations to request.
func (a *Aggregator) Windows() []time.Duration {
	return a.windows
}

// Add records ev in the per-IP bucket, then evicts events older than the
// longest configured window relative to ev.Time.
func (a *Aggregator) Add(ev sdk.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.buckets[ev.SourceIP]
	if b == nil {
		b = &ipBucket{}
		a.buckets[ev.SourceIP] = b
	}

	b.entries = append(b.entries, entry{at: ev.Time, ev: ev})
	b.lastSeen = ev.Time

	// Evict entries outside the longest window.
	cutoff := ev.Time.Add(-a.maxWindow)
	trim := 0
	for trim < len(b.entries) && b.entries[trim].at.Before(cutoff) {
		trim++
	}
	if trim > 0 {
		b.entries = b.entries[trim:]
	}

	// LRU IP cap: evict the least-recently-seen bucket when over the limit.
	if a.maxIPs > 0 && len(a.buckets) > a.maxIPs {
		a.evictLRU()
	}
}

// evictLRU removes the bucket with the oldest lastSeen timestamp.
// Must be called with a.mu held.
func (a *Aggregator) evictLRU() {
	var lruIP netip.Addr
	var lruTime time.Time
	first := true
	for ip, b := range a.buckets {
		if first || b.lastSeen.Before(lruTime) {
			lruIP = ip
			lruTime = b.lastSeen
			first = false
		}
	}
	if lruIP.IsValid() {
		delete(a.buckets, lruIP)
	}
}

// Aggregate returns the event summary for ip over window as of now.
//
// Kinds contains exact counts per event kind for all events in [now-window, now].
// Sample holds up to maxSamples of those events in arrival order; it is used
// by the rule engine for field-level matching. The caller must cap and redact
// Sample before forwarding it to an AI provider.
func (a *Aggregator) Aggregate(ip netip.Addr, window time.Duration, now time.Time) sdk.Aggregate {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-window)
	b := a.buckets[ip]

	kinds := make(map[string]int)
	var samples []sdk.Event

	if b != nil {
		for _, e := range b.entries {
			if e.at.Before(cutoff) {
				continue
			}
			kinds[e.ev.Kind]++
			if len(samples) < a.maxSamp {
				samples = append(samples, e.ev)
			}
		}
	}

	total := 0
	for _, n := range kinds {
		total += n
	}

	return sdk.Aggregate{
		IP:     ip,
		Window: window,
		Count:  total,
		Kinds:  kinds,
		Sample: samples,
	}
}

// Flush evicts stale entries and removes IP buckets with no remaining events.
// cutoff should typically be time.Now().Add(-maxWindow).
// Call periodically to bound memory growth (e.g. once per maxWindow).
func (a *Aggregator) Flush(ctx context.Context, cutoff time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for ip, b := range a.buckets {
		if ctx.Err() != nil {
			break
		}
		trim := 0
		for trim < len(b.entries) && b.entries[trim].at.Before(cutoff) {
			trim++
		}
		b.entries = b.entries[trim:]
		if len(b.entries) == 0 {
			delete(a.buckets, ip)
		}
	}
}

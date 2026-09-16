// SPDX-License-Identifier: AGPL-3.0-only

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

// overflowBucket is the width of the per-kind counters that keep the exact
// event count once a busy IP's raw sample is full (issue #622). Counts of
// events evicted from the sample are folded into the minute their event
// time falls in; a window boundary inside such a minute therefore counts up
// to one minute of extra evicted history — only for IPs that exceeded the
// sample cap, i.e. more than maxSamp events inside the longest window.
const overflowBucket = time.Minute

type ipBucket struct {
	// entries is the raw sample: the NEWEST events within the horizon, in
	// arrival order, at most maxSamp of them. Field-level rules and
	// evidence read it, so it must show current traffic, not the oldest
	// (the pre-#622 oldest-first cap hid a busy client's attack).
	entries []entry
	// overflow counts, per minute bucket start (unix seconds) and kind,
	// the events the sample cap evicted — kind-level counts stay exact for
	// any rate at O(minutes) cost. Nil until the cap is first hit.
	overflow map[int64]map[string]int
	// overflowMin is the oldest overflow slot; trimBefore skips the map
	// scan while it is still inside the horizon (Add runs per event).
	overflowMin int64
	lastSeen    time.Time
}

// Aggregator maintains per-IP sliding-window event counts and capped samples.
// Events older than the longest configured window are evicted on every Add call.
// When maxIPs > 0 the bucket for the least-recently-seen IP is evicted once the
// count exceeds the cap, bounding memory growth regardless of attack breadth.
//
// Per-IP memory is bounded by the sample cap (issue #622): at most maxSamp
// raw events are retained per IP whatever the client's rate; events beyond
// the cap are counted, per kind, in minute buckets (see overflowBucket), so
// Aggregate().Kinds stays exact over the retained horizon while a busy
// client costs at most ~maxSamp × event size (≈ 4 MB at the default cap
// with 1 kB events) instead of rate × horizon.
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

// Entries returns the number of raw events retained for ip (tests and
// observability): the per-IP memory footprint is Entries × event size plus
// a few minute buckets of counters once the sample cap has been hit.
func (a *Aggregator) Entries(ip netip.Addr) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if b := a.buckets[ip]; b != nil {
		return len(b.entries)
	}
	return 0
}

// Windows returns the configured sliding windows, in configuration order
// (not sorted — use MaxWindow for the eviction horizon).
func (a *Aggregator) Windows() []time.Duration {
	return a.windows
}

// MaxWindow returns the longest configured window: the horizon before
// which no rule can still see an event, hence the only correct flush
// cutoff (issue #610 — flushing with any shorter window silently blinds
// every rule with a longer one).
func (a *Aggregator) MaxWindow() time.Duration {
	return a.maxWindow
}

// Add records ev in the per-IP bucket, then evicts events older than the
// longest configured window relative to ev.Time. When the raw sample is
// full the OLDEST entries are folded into the per-minute overflow counters,
// so the sample always holds the newest events (issue #622).
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

	cutoff := ev.Time.Add(-a.maxWindow)
	b.trimBefore(cutoff)

	// Sample cap: fold the oldest surplus into the overflow counters.
	if surplus := len(b.entries) - a.maxSamp; surplus > 0 {
		if b.overflow == nil {
			b.overflow = make(map[int64]map[string]int)
		}
		for _, e := range b.entries[:surplus] {
			slot := e.at.Truncate(overflowBucket).Unix()
			kinds := b.overflow[slot]
			if kinds == nil {
				kinds = make(map[string]int)
				b.overflow[slot] = kinds
				if len(b.overflow) == 1 || slot < b.overflowMin {
					b.overflowMin = slot
				}
			}
			kinds[e.ev.Kind]++
		}
		// Reslice instead of copying: append reallocates (and drops the
		// consumed prefix) once the spare capacity is used up, so the
		// per-Add cost stays amortised O(1) and the live array stays
		// within a constant factor of maxSamp.
		b.entries = b.entries[surplus:]
	}

	// LRU IP cap: evict the least-recently-seen bucket when over the limit.
	if a.maxIPs > 0 && len(a.buckets) > a.maxIPs {
		a.evictLRU()
	}
}

// trimBefore drops raw entries and overflow buckets older than cutoff.
// Overflow buckets are keyed by their minute start; a bucket is dropped
// only once its whole minute is before the cutoff.
func (b *ipBucket) trimBefore(cutoff time.Time) {
	trim := 0
	for trim < len(b.entries) && b.entries[trim].at.Before(cutoff) {
		trim++
	}
	if trim > 0 {
		b.entries = b.entries[trim:]
	}
	if b.overflow == nil {
		return
	}
	limit := cutoff.Truncate(overflowBucket).Unix()
	if b.overflowMin >= limit {
		return
	}
	minSlot := int64(0)
	for slot := range b.overflow {
		if slot < limit {
			delete(b.overflow, slot)
			continue
		}
		if minSlot == 0 || slot < minSlot {
			minSlot = slot
		}
	}
	b.overflowMin = minSlot
	if len(b.overflow) == 0 {
		b.overflow = nil
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
// Kinds contains exact counts per event kind for all events in [now-window, now]
// — raw sample entries counted individually, plus the per-minute overflow
// counters for events the sample cap evicted (their minute bucket must start
// at or after the window cutoff, so a boundary inside a minute can include
// up to one minute of extra evicted history — see overflowBucket). Sample
// holds the newest in-window events, at most maxSamples, in arrival order;
// it is used by the rule engine for field-level matching. The caller must
// cap and redact Sample before forwarding it to an AI provider.
func (a *Aggregator) Aggregate(ip netip.Addr, window time.Duration, now time.Time) sdk.Aggregate {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-window)
	b := a.buckets[ip]

	kinds := make(map[string]int)
	var samples []sdk.Event

	if b != nil {
		samples = make([]sdk.Event, 0, len(b.entries))
		for _, e := range b.entries {
			if e.at.Before(cutoff) {
				continue
			}
			kinds[e.ev.Kind]++
			samples = append(samples, e.ev)
		}
		if b.overflow != nil {
			limit := cutoff.Truncate(overflowBucket).Unix()
			for slot, perKind := range b.overflow {
				if slot < limit {
					continue
				}
				for k, n := range perKind {
					kinds[k] += n
				}
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

// Reset drops every retained event of ip. The daemon calls it when a strike
// is recorded for ip (issue #621): the events that earned the strike are
// consumed by it, so once the ban expires only NEW evidence can earn the
// next rung — otherwise the same hour of history re-fired the hourly rules
// on the first request after expiry, benign or not, climbing the ladder
// without any new offence. Long-window counters are not touched: they hold
// kind-level or rule-matched hits only, which a benign request never adds.
func (a *Aggregator) Reset(ip netip.Addr) {
	a.mu.Lock()
	delete(a.buckets, ip)
	a.mu.Unlock()
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
		b.trimBefore(cutoff)
		if len(b.entries) == 0 && b.overflow == nil {
			delete(a.buckets, ip)
		}
	}
}

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
	// counters are the extra counter kinds the Classifier assigned to ev
	// at Add time (rule-derived kinds of the field-level rules it
	// matches); nil for most events.
	counters []string
}

// Classifier returns the extra counter kinds an event increments besides
// ev.Kind — in the daemon, one rule-derived kind per in-memory field-level
// rule the event matches (rules.MemoryCounterKinds). It runs once per event
// at Add time; the result is counted in Kinds like a parser kind, so an
// IP's count for such a rule stays exact after the sample cap evicted the
// matching events (issue #622, E3-2). Must be pure and cheap; may be nil.
type Classifier func(ev sdk.Event) []string

// Overflow-bucket bounds (issue #622). Once a busy IP's raw sample is full,
// evicted events are counted per kind in fixed-width time buckets. A bucket
// is counted only when its WHOLE span lies inside the window, so a bucket
// can never add events older than the window (no false fire); a window
// cutoff inside a bucket under-counts at most that bucket's evicted events.
// The width is min(shortest window / 12, maxOverflowBucket), never below
// minOverflowBucket: 5 s for the default 60 s tier, ≤ 720 buckets per IP
// over a 1 h horizon.
const (
	minOverflowBucket = time.Second
	maxOverflowBucket = time.Minute
	overflowBucketDiv = 12
)

// overflowSlot holds the events the sample cap evicted inside one bucket.
type overflowSlot struct {
	events int            // raw events (drives Count)
	kinds  map[string]int // per parser kind and per classifier counter kind
}

type ipBucket struct {
	// entries is the raw sample: the NEWEST events within the horizon, in
	// arrival order, at most maxSamp of them. Field-level rules and
	// evidence read it, so it must show current traffic, not the oldest
	// (the pre-#622 oldest-first cap hid a busy client's attack).
	entries []entry
	// overflow counts, per bucket start (unix seconds), the events the
	// sample cap evicted — kind-level counts stay exact for any rate at
	// O(buckets) cost. Nil until the cap is first hit.
	overflow map[int64]*overflowSlot
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
// raw events are retained per IP whatever the client's rate (the backing
// array may hold up to ~1.25× that until append reallocates); events beyond
// the cap are counted, per kind, in fixed-width buckets (see Bucket), so
// Aggregate().Kinds stays exact over the retained horizon up to one bucket
// of under-count at the window edge, while a busy client costs at most
// ~maxSamp × event size (≈ 4–6 MB at the default cap with 1 kB events)
// instead of rate × horizon. The bound is per IP: the global worst case is
// that figure × the MaxIPs LRU cap.
type Aggregator struct {
	windows   []time.Duration // all configured windows
	maxWindow time.Duration   // longest window; controls eviction horizon
	bucket    time.Duration   // overflow bucket width
	maxSamp   int             // sample cap
	maxIPs    int             // LRU cap; 0 = unlimited
	classify  Classifier      // extra counter kinds per event; may be nil
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
	maxW, minW := windows[0], windows[0]
	for _, w := range windows[1:] {
		if w > maxW {
			maxW = w
		}
		if w < minW {
			minW = w
		}
	}
	bucket := (minW / overflowBucketDiv).Truncate(time.Second)
	if bucket > maxOverflowBucket {
		bucket = maxOverflowBucket
	}
	if bucket < minOverflowBucket {
		bucket = minOverflowBucket
	}
	return &Aggregator{
		windows:   windows,
		maxWindow: maxW,
		bucket:    bucket,
		maxSamp:   maxSamples,
		buckets:   make(map[netip.Addr]*ipBucket),
	}
}

// WithClassifier sets the Classifier run on every added event; see
// Classifier. Returns the receiver for chaining with New().
func (a *Aggregator) WithClassifier(fn Classifier) *Aggregator {
	a.classify = fn
	return a
}

// Bucket returns the overflow bucket width: the maximum under-count of
// evicted events at a window edge for an IP past the sample cap.
func (a *Aggregator) Bucket() time.Duration { return a.bucket }

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
// at most maxWindow/Bucket() slots of counters once the sample cap has
// been hit.
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
// full the OLDEST entries are folded into the overflow counters, so the
// sample always holds the newest events (issue #622).
func (a *Aggregator) Add(ev sdk.Event) {
	var counters []string
	if a.classify != nil {
		counters = a.classify(ev) // outside the lock: pure, may be slow-ish
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.buckets[ev.SourceIP]
	if b == nil {
		b = &ipBucket{}
		a.buckets[ev.SourceIP] = b
	}

	b.entries = append(b.entries, entry{at: ev.Time, ev: ev, counters: counters})
	b.lastSeen = ev.Time

	cutoff := ev.Time.Add(-a.maxWindow)
	b.trimBefore(cutoff)

	// Sample cap: fold the oldest surplus into the overflow counters.
	if surplus := len(b.entries) - a.maxSamp; surplus > 0 {
		if b.overflow == nil {
			b.overflow = make(map[int64]*overflowSlot)
		}
		for _, e := range b.entries[:surplus] {
			key := e.at.Truncate(a.bucket).Unix()
			slot := b.overflow[key]
			if slot == nil {
				slot = &overflowSlot{kinds: make(map[string]int)}
				b.overflow[key] = slot
				if len(b.overflow) == 1 || key < b.overflowMin {
					b.overflowMin = key
				}
			}
			slot.events++
			slot.kinds[e.ev.Kind]++
			for _, k := range e.counters {
				slot.kinds[k]++
			}
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

// trimBefore drops raw entries older than cutoff and every overflow slot
// that starts before cutoff (the same whole-bucket rule Aggregate applies,
// so a kept slot is always fully inside the horizon). A bucket whose raw
// sample is empty keeps no counters either: Count can never be non-zero
// with an empty Sample.
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
	if len(b.entries) == 0 {
		b.overflow, b.overflowMin = nil, 0
		return
	}
	if !slotBefore(b.overflowMin, cutoff) {
		return
	}
	var minKey int64
	first := true
	for key := range b.overflow {
		if slotBefore(key, cutoff) {
			delete(b.overflow, key)
			continue
		}
		if first || key < minKey {
			minKey, first = key, false
		}
	}
	b.overflowMin = minKey
	if len(b.overflow) == 0 {
		b.overflow = nil
	}
}

// slotBefore reports whether the overflow slot starting at key (unix
// seconds) starts before cutoff — i.e. is not wholly inside a window that
// begins at cutoff.
func slotBefore(key int64, cutoff time.Time) bool {
	return time.Unix(key, 0).Before(cutoff)
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
// Kinds contains the counts per event kind — and per Classifier counter
// kind — for the events in [now-window, now]: raw sample entries counted
// individually, plus the overflow slots of events the sample cap evicted
// whose whole bucket lies inside the window (a slot straddling the cutoff
// is left out, so Kinds never includes an event older than the window and
// under-counts evicted events by at most one Bucket()). Count is the number
// of events (parser kinds only). Sample holds the newest in-window events,
// at most maxSamples, in arrival order; it is used by the rule engine for
// field-level matching and evidence. The caller must cap and redact Sample
// before forwarding it to an AI provider.
func (a *Aggregator) Aggregate(ip netip.Addr, window time.Duration, now time.Time) sdk.Aggregate {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := now.Add(-window)
	b := a.buckets[ip]

	kinds := make(map[string]int)
	var samples []sdk.Event
	total := 0

	if b != nil {
		// Count first so the sample slice is sized exactly (no zeroed
		// slack on this per-event, per-window path).
		inWindow := 0
		for i := range b.entries {
			if !b.entries[i].at.Before(cutoff) {
				inWindow++
			}
		}
		if inWindow > 0 {
			samples = make([]sdk.Event, 0, inWindow)
		}
		for i := range b.entries {
			e := &b.entries[i]
			if e.at.Before(cutoff) {
				continue
			}
			kinds[e.ev.Kind]++
			for _, k := range e.counters {
				kinds[k]++
			}
			samples = append(samples, e.ev)
		}
		total = inWindow
		for key, slot := range b.overflow {
			if slotBefore(key, cutoff) {
				continue
			}
			total += slot.events
			for k, n := range slot.kinds {
				kinds[k] += n
			}
		}
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
		if len(b.entries) == 0 {
			delete(a.buckets, ip)
		}
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Async second-layer AI analysis (issue #222). With ai.async: true the
// pipeline never waits for a provider: grey-zone IPs are ENQUEUED and a
// single background worker drains them — batched by IP, rate-capped,
// budget-gated, and fed through the Log Cleaner so only cleaned, compact
// aggregates ever reach a provider. A slow or dead provider degrades to
// rules-only detection; it can never stall the pipeline (bounded queue,
// drop-oldest with a counter).
//
// Verdicts coming back are advisory exactly like inline AI verdicts: they
// are bound to the requested IP (consultProvider → bindVerdictsToIP) and
// then flow through the decision engine, where allowlist-wins,
// anti-lockout and policy clamps gate them like any other verdict source.

import (
	"context"
	"log/slog"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/evertramos/ezy-shield/internal/ai"
)

const (
	// defaultAIQueueCap bounds the grey-zone queue when the config leaves
	// async_queue_size unset.
	defaultAIQueueCap = 256
	// aiAsyncMinInterval is the floor between provider calls — the token
	// spend rate cap.
	aiAsyncMinInterval = time.Second
	// aiAsyncPerIPCooldown is the floor between two analyses of the SAME
	// IP (issue #648): a burst that stays in the grey zone after a verdict
	// is the same episode on the same evidence, not a new question. A ban
	// verdict ends the episode anyway; a runtime allowlist skips it.
	aiAsyncPerIPCooldown = time.Minute
	// aiAsyncErrorBackoff is the per-IP floor after an analysis that got NO
	// answer (provider error/timeout, budget query failure): long enough not
	// to hammer a failing provider on every line, short enough that a burst
	// is still analysed while it lasts.
	aiAsyncErrorBackoff = 10 * time.Second
)

// aiAsyncItem is one queued grey-zone episode.
type aiAsyncItem struct {
	ip        netip.Addr
	ruleScore int
	queuedAt  time.Time
}

// aiAsyncQueue is the bounded drop-oldest queue. One entry per IP at a
// time (pending map, held from push until the analysis is DONE — issue
// #648): a brute-force burst enqueues once, not per line, and not again
// while its analysis is in flight. lastDone enforces a per-IP cooldown
// between analyses of the same IP.
type aiAsyncQueue struct {
	mu       sync.Mutex
	items    []aiAsyncItem
	pending  map[netip.Addr]bool
	lastDone map[netip.Addr]time.Time
	cap      int
	signal   chan struct{}
	dropped  atomic.Uint64
	now      func() time.Time // injectable clock (tests)
}

func newAIAsyncQueue(capacity int) *aiAsyncQueue {
	if capacity <= 0 {
		capacity = defaultAIQueueCap
	}
	return &aiAsyncQueue{
		pending:  map[netip.Addr]bool{},
		lastDone: map[netip.Addr]time.Time{},
		cap:      capacity,
		signal:   make(chan struct{}, 1),
		now:      time.Now,
	}
}

// push enqueues ip unless it is pending (queued or in flight) or inside
// its per-IP cooldown. On overflow the OLDEST entry is dropped (counted) —
// recent activity is the analyzable activity. Cooldown skips are not
// drops: nothing analyzable was lost.
func (q *aiAsyncQueue) push(item aiAsyncItem) {
	q.mu.Lock()
	if q.pending[item.ip] {
		q.mu.Unlock()
		return
	}
	now := q.now()
	if last, ok := q.lastDone[item.ip]; ok && now.Sub(last) < aiAsyncPerIPCooldown {
		q.mu.Unlock()
		return
	}
	q.pruneCooldownsLocked(now)
	if len(q.items) >= q.cap {
		oldest := q.items[0]
		q.items = q.items[1:]
		delete(q.pending, oldest.ip)
		q.dropped.Add(1)
	}
	q.items = append(q.items, item)
	q.pending[item.ip] = true
	q.mu.Unlock()

	select {
	case q.signal <- struct{}{}:
	default:
	}
}

// pop removes the oldest entry; ok=false when empty. The IP stays pending
// until done(ip) — the analysis is in flight, not finished.
func (q *aiAsyncQueue) pop() (aiAsyncItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return aiAsyncItem{}, false
	}
	item := q.items[0]
	q.items = q.items[1:]
	return item, true
}

// done ends ip's episode. answered=true (a verdict set came back, from
// the cache or the provider) arms the full per-IP cooldown; answered=false
// (no answer) arms only the short error backoff, so the burst is retried
// while it still lasts.
func (q *aiAsyncQueue) done(ip netip.Addr, answered bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.pending, ip)
	if answered {
		q.lastDone[ip] = q.now()
		return
	}
	q.lastDone[ip] = q.now().Add(aiAsyncErrorBackoff - aiAsyncPerIPCooldown)
}

// isPending reports whether ip is queued or in flight (tests).
func (q *aiAsyncQueue) isPending(ip netip.Addr) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pending[ip]
}

// pruneCooldownsLocked drops expired cooldown marks once the map holds
// 1 024 entries, so it stays bounded by the IPs analysed in the last
// cooldown window. Called with q.mu held.
func (q *aiAsyncQueue) pruneCooldownsLocked(now time.Time) {
	if len(q.lastDone) < 1024 {
		return
	}
	for ip, t := range q.lastDone {
		if now.Sub(t) >= aiAsyncPerIPCooldown {
			delete(q.lastDone, ip)
		}
	}
}

func (q *aiAsyncQueue) depth() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// maybeEnqueueAI is the async twin of maybeConsultAI's inline call site:
// same eligibility gates, but the outcome is a queue entry, never a wait.
func (d *Daemon) maybeEnqueueAI(ctx context.Context, ip netip.Addr, ruleScore int) {
	if d.aiQueue == nil {
		return
	}
	if !d.aiEligible(ctx, ip, ruleScore) {
		return
	}
	d.aiQueue.push(aiAsyncItem{ip: ip, ruleScore: ruleScore, queuedAt: time.Now()})
}

// runAIAsync is the background worker: ctx-honoring, one provider call at
// a time, floor of aiAsyncMinInterval between calls.
func (d *Daemon) runAIAsync(ctx context.Context) {
	if d.aiQueue == nil {
		return
	}
	slog.InfoContext(ctx, "daemon: async AI worker started", "queue_cap", d.aiQueue.cap)
	var lastCall time.Time
	for {
		item, ok := d.aiQueue.pop()
		if !ok {
			select {
			case <-ctx.Done():
				return
			case <-d.aiQueue.signal:
				continue
			}
		}

		// Rate cap between provider calls.
		if wait := aiAsyncMinInterval - time.Since(lastCall); wait > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		if ctx.Err() != nil {
			return
		}
		called, answered := d.runAIAsyncItem(ctx, item)
		if called {
			lastCall = time.Now()
		}
		_ = answered
	}
}

// runAIAsyncItem runs one episode and ALWAYS ends it in the queue — done is
// deferred so no early return (or a future recover) can leave the IP
// pending forever. Returns (provider called, provider answered).
func (d *Daemon) runAIAsyncItem(ctx context.Context, item aiAsyncItem) (called, answered bool) {
	defer func() { d.aiQueue.done(item.ip, answered) }()
	return d.processAIAsyncItem(ctx, item)
}

// processAIAsyncItem runs one queued episode end to end. Returns whether a
// provider call actually happened (for the rate cap) and whether the AI
// layer answered (cache hit or successful call — arms the per-IP cooldown).
func (d *Daemon) processAIAsyncItem(ctx context.Context, item aiAsyncItem) (called, answered bool) {
	ip := item.ip

	// Log Cleaner front gates: an episode decided since it was queued —
	// banned or (runtime-)allowlisted — must not spend tokens.
	if d.isRuntimeAllowlisted(ip) {
		slog.DebugContext(ctx, "daemon: async ai skip — runtime allowlisted", "ip", ip)
		return false, false
	}
	if !d.aiEligible(ctx, ip, item.ruleScore) {
		return false, false
	}

	aggs := d.collectAIAggregates(ip)
	cleaned, stats := ai.CleanAggregates(aggs)
	d.aiCleanReduction.Store(math.Float64bits(stats.ReductionRatio()))
	if len(cleaned) == 0 {
		slog.DebugContext(ctx, "daemon: async ai skip — cleaner removed everything", "ip", ip)
		return false, false
	}

	verdicts, answered := d.consultProvider(ctx, ip, cleaned)
	if d.metrics != nil && d.aiQueue != nil {
		// Export the drop counter lazily alongside each processed item.
		// The clamp is unreachable in practice (2^63 drops), but keeps the
		// uint64→int64 conversion overflow-proof.
		dropped := d.aiQueue.dropped.Load()
		if dropped > math.MaxInt64 {
			dropped = math.MaxInt64
		}
		d.metrics.aiQueueDropped.Set(int64(dropped))
	}
	if len(verdicts) == 0 {
		return true, answered // called; answered only if the layer replied with nothing to say
	}

	// Agreement-rate metric: does the AI land on the same side of the ban
	// threshold as the rules did? This is the published proof the layer
	// earns its tokens.
	if d.metrics != nil && d.aiProvider != nil {
		aiHigh := highestScore(verdicts)
		outcome := "agree"
		if (aiHigh >= d.policy.BanThreshold) != (item.ruleScore >= d.policy.BanThreshold) {
			outcome = "disagree"
		}
		d.metrics.aiAgreement.With(d.aiProvider.Name() + "_" + outcome).Inc()
	}

	// Verdicts flow back through the SAME downstream as the inline path:
	// live detections, runtime allowlist, then the decision engine — where
	// allowlist supremacy, anti-lockout and policy clamps apply to AI
	// verdicts exactly like any other source.
	d.publishDetections(verdicts)
	if d.isRuntimeAllowlisted(ip) {
		slog.DebugContext(ctx, "daemon: async ai verdicts suppressed — runtime allowlisted", "ip", ip)
		return true, true
	}
	action, err := d.decEng.Decide(ctx, verdicts)
	if err != nil {
		slog.WarnContext(ctx, "daemon: async ai decide error", "ip", ip, "err", err)
		return true, true
	}
	d.dispatch(ctx, action)
	return true, true
}

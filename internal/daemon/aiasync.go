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
)

// aiAsyncItem is one queued grey-zone episode.
type aiAsyncItem struct {
	ip        netip.Addr
	ruleScore int
	queuedAt  time.Time
}

// aiAsyncQueue is the bounded drop-oldest queue. One entry per IP at a
// time (pending map): a brute-force burst enqueues once, not per line.
type aiAsyncQueue struct {
	mu      sync.Mutex
	items   []aiAsyncItem
	pending map[netip.Addr]bool
	cap     int
	signal  chan struct{}
	dropped atomic.Uint64
}

func newAIAsyncQueue(capacity int) *aiAsyncQueue {
	if capacity <= 0 {
		capacity = defaultAIQueueCap
	}
	return &aiAsyncQueue{
		pending: map[netip.Addr]bool{},
		cap:     capacity,
		signal:  make(chan struct{}, 1),
	}
}

// push enqueues ip unless already pending. On overflow the OLDEST entry
// is dropped (counted) — recent activity is the analyzable activity.
func (q *aiAsyncQueue) push(item aiAsyncItem) {
	q.mu.Lock()
	if q.pending[item.ip] {
		q.mu.Unlock()
		return
	}
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

// pop removes the oldest entry; ok=false when empty.
func (q *aiAsyncQueue) pop() (aiAsyncItem, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return aiAsyncItem{}, false
	}
	item := q.items[0]
	q.items = q.items[1:]
	delete(q.pending, item.ip)
	return item, true
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
		if d.processAIAsyncItem(ctx, item) {
			lastCall = time.Now()
		}
	}
}

// processAIAsyncItem runs one queued episode end to end. Returns whether a
// provider call actually happened (for the rate cap).
func (d *Daemon) processAIAsyncItem(ctx context.Context, item aiAsyncItem) bool {
	ip := item.ip

	// Log Cleaner front gates: an episode decided since it was queued —
	// banned or (runtime-)allowlisted — must not spend tokens.
	if d.isRuntimeAllowlisted(ip) {
		slog.DebugContext(ctx, "daemon: async ai skip — runtime allowlisted", "ip", ip)
		return false
	}
	if !d.aiEligible(ctx, ip, item.ruleScore) {
		return false
	}

	aggs := d.collectAIAggregates(ip)
	cleaned, stats := ai.CleanAggregates(aggs)
	d.aiCleanReduction.Store(math.Float64bits(stats.ReductionRatio()))
	if len(cleaned) == 0 {
		slog.DebugContext(ctx, "daemon: async ai skip — cleaner removed everything", "ip", ip)
		return false
	}

	verdicts := d.consultProvider(ctx, ip, cleaned)
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
		return true // provider was called (or cache hit); nothing came back
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
		return true
	}
	action, err := d.decEng.Decide(ctx, verdicts)
	if err != nil {
		slog.WarnContext(ctx, "daemon: async ai decide error", "ip", ip, "err", err)
		return true
	}
	d.dispatch(ctx, action)
	return true
}

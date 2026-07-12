package daemon

import (
	"net/netip"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// subscriberBuf is the per-subscriber channel capacity. When a subscriber
// falls behind, publish drops events for that subscriber instead of blocking:
// the pipeline (a security-critical hot path) must never wait on a slow
// `watch` client.
const subscriberBuf = 256

// eventBus fans StreamEvents out to live "subscribe" connections.
// It is an in-memory, best-effort broadcast: no history, no replay
// (the persisted audit trail remains the "events" verb / audit_log).
type eventBus struct {
	mu   sync.Mutex
	subs map[chan StreamEvent]struct{}
}

func newEventBus() *eventBus {
	return &eventBus{subs: make(map[chan StreamEvent]struct{})}
}

// subscribe registers and returns a new subscriber channel.
func (b *eventBus) subscribe() chan StreamEvent {
	ch := make(chan StreamEvent, subscriberBuf)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

// unsubscribe removes ch from the fan-out set. The channel is intentionally
// not closed: publish may hold a reference concurrently, and an unreferenced
// open channel is simply garbage-collected.
func (b *eventBus) unsubscribe(ch chan StreamEvent) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

// hasSubscribers reports whether anyone is listening — used as a fast path so
// the pipeline skips event construction entirely when nobody watches.
func (b *eventBus) hasSubscribers() bool {
	b.mu.Lock()
	n := len(b.subs)
	b.mu.Unlock()
	return n > 0
}

// publish delivers ev to every subscriber without blocking; subscribers whose
// buffer is full miss the event (see subscriberBuf).
func (b *eventBus) publish(ev StreamEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop rather than stall the daemon
		}
	}
}

// eventTime returns the stream-event timestamp format (RFC 3339 UTC).
func eventTime() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// ttlString renders a TTL for stream events; zero or negative means the
// event carries no TTL and the field is omitted from the JSON.
func ttlString(ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	return ttl.Round(time.Second).String()
}

// prefixDisplay renders a target for stream events: bare address for
// single-host prefixes ("203.0.113.7", matching pipeline events), CIDR
// notation for wider ranges.
func prefixDisplay(p netip.Prefix) string {
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String()
	}
	return p.String()
}

// publishActionEvent emits one stream event for a decided or manual action.
// kind is the daemon op vocabulary ("ban", "dry_ban", "unban", "allow", ...);
// source is "pipeline" for rule/AI-driven actions and "cli" for socket verbs.
func (d *Daemon) publishActionEvent(kind, ip string, strike int, ttl time.Duration, reason, source string) {
	if !d.events.hasSubscribers() {
		return
	}
	enforcer := ""
	if d.enforcer != nil {
		enforcer = d.enforcer.Name()
	}
	d.events.publish(StreamEvent{
		Time:     eventTime(),
		Kind:     kind,
		IP:       ip,
		Strike:   strike,
		TTL:      ttlString(ttl),
		Enforcer: enforcer,
		Reason:   reason,
		Source:   source,
	})
}

// publishDetections emits one "detection" stream event per verdict. Verdict
// fields (Category, Source, Reason) may derive from hostile log content;
// consumers MUST sanitize before rendering to a terminal.
func (d *Daemon) publishDetections(verdicts []sdk.Verdict) {
	if len(verdicts) == 0 || !d.events.hasSubscribers() {
		return
	}
	now := eventTime()
	for _, v := range verdicts {
		d.events.publish(StreamEvent{
			Time:     now,
			Kind:     "detection",
			IP:       v.IP.String(),
			Score:    v.Score,
			Category: v.Category,
			Rule:     v.Source,
			Reason:   v.Reason,
			Source:   "pipeline",
		})
	}
}

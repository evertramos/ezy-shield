package dashboard

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

const (
	// defaultPollInterval is how often the bus asks the daemon for the
	// latest audit entries. 3 s balances freshness against RPC load:
	// with a handful of concurrent operators it stays under one request
	// per second on the daemon side.
	defaultPollInterval = 3 * time.Second

	// broadcastBurstCap bounds how many discrete "audit" messages a
	// single poll cycle can emit to a client. A bigger burst is coalesced
	// into one "refresh" message so the browser reloads instead of
	// flooding the DOM. Combined with the 3 s poll cadence this keeps
	// the per-client wire rate well under the 10 messages/second budget
	// called out in AGENTS.md §2 for the dashboard control surface.
	broadcastBurstCap = 10

	// clientSendBuf sizes the per-client outbound queue. A slow reader
	// is dropped after this many pending messages so a stalled browser
	// tab cannot back up the whole bus.
	clientSendBuf = 32
)

// wsClient is one connected websocket subscriber. The bus owns the queue;
// the connection handler owns the actual WS write loop.
type wsClient struct {
	send chan []byte
}

// eventBus fans daemon audit events out to any number of subscribed
// websocket clients. It polls the daemon on a fixed cadence, diffs
// against the last seen audit_log id, and pushes new rows to every live
// subscriber via a non-blocking send.
type eventBus struct {
	poll    time.Duration
	fetcher func(ctx context.Context) ([]daemon.EventEntry, error)
	logger  *slog.Logger

	mu      sync.Mutex
	clients map[*wsClient]struct{}
	lastID  int64
}

func newEventBus(fetcher func(ctx context.Context) ([]daemon.EventEntry, error), logger *slog.Logger) *eventBus {
	if logger == nil {
		logger = slog.Default()
	}
	return &eventBus{
		poll:    defaultPollInterval,
		fetcher: fetcher,
		logger:  logger,
		clients: make(map[*wsClient]struct{}),
	}
}

// subscribe registers c so it receives every subsequent broadcast. The
// returned pointer must be passed to unsubscribe when the connection
// closes.
func (b *eventBus) subscribe() *wsClient {
	c := &wsClient{send: make(chan []byte, clientSendBuf)}
	b.mu.Lock()
	b.clients[c] = struct{}{}
	b.mu.Unlock()
	return c
}

func (b *eventBus) unsubscribe(c *wsClient) {
	b.mu.Lock()
	delete(b.clients, c)
	b.mu.Unlock()
	// Drain the queue so a blocked writer can exit its select.
	select {
	case <-c.send:
	default:
	}
}

// clientCount is used by tests only.
func (b *eventBus) clientCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.clients)
}

// Run drives the poll loop until ctx is cancelled. It seeds lastID from
// the first fetch so already-persisted audit rows are not replayed to
// clients that connect after the daemon has been running for a while.
func (b *eventBus) Run(ctx context.Context) {
	// Seed lastID with the current head so newly-connected clients only
	// see events that happen *after* they open the page.
	if b.fetcher != nil {
		seedCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
		if events, err := b.fetcher(seedCtx); err == nil {
			b.lastID = maxAuditID(events)
		}
		cancel()
	}

	t := time.NewTicker(b.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			b.tick(ctx)
		}
	}
}

// tick performs one poll → diff → broadcast pass. It is exported through
// the type for tests that want to drive the bus without a ticker.
func (b *eventBus) tick(ctx context.Context) {
	if b.fetcher == nil {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	events, err := b.fetcher(callCtx)
	cancel()
	if err != nil {
		// A daemon-offline error is expected sometimes; log at debug.
		b.logger.Debug("dashboard bus poll", "err", err)
		return
	}
	fresh := b.freshEvents(events)
	if len(fresh) == 0 {
		return
	}
	b.broadcast(fresh)
}

// freshEvents returns rows with id > lastID in chronological order and
// updates lastID to the highest id seen. The daemon returns rows newest-
// first; we reverse so subscribers receive events in the order they
// happened.
func (b *eventBus) freshEvents(events []daemon.EventEntry) []daemon.EventEntry {
	if len(events) == 0 {
		return nil
	}
	last := b.lastID
	out := make([]daemon.EventEntry, 0)
	for _, e := range events {
		if e.ID <= last {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil
	}
	// Reverse to chronological (oldest first).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	b.lastID = out[len(out)-1].ID
	return out
}

// broadcast sends fresh events to every client, coalescing bursts into
// a single "refresh" message when the burst exceeds broadcastBurstCap.
func (b *eventBus) broadcast(fresh []daemon.EventEntry) {
	var payloads [][]byte
	if len(fresh) > broadcastBurstCap {
		if raw, err := json.Marshal(wsMessage{Type: "refresh"}); err == nil {
			payloads = append(payloads, raw)
		}
	} else {
		for i := range fresh {
			raw, err := json.Marshal(wsMessage{Type: "audit", Entry: &fresh[i]})
			if err != nil {
				continue
			}
			payloads = append(payloads, raw)
		}
	}
	if len(payloads) == 0 {
		return
	}
	b.mu.Lock()
	clients := make([]*wsClient, 0, len(b.clients))
	for c := range b.clients {
		clients = append(clients, c)
	}
	b.mu.Unlock()
	for _, c := range clients {
		for _, p := range payloads {
			select {
			case c.send <- p:
			default:
				// Client queue full — drop the message. The client's
				// heartbeat + reconnect handshake will re-sync state.
			}
		}
	}
}

// wsMessage is the wire envelope every websocket frame carries. Only the
// listed fields ever leave the server, so a browser tab receives a
// stable JSON schema even as the internal daemon.EventEntry evolves.
type wsMessage struct {
	Type  string              `json:"type"` // "audit" | "refresh" | "hello"
	Entry *daemon.EventEntry  `json:"entry,omitempty"`
}

func maxAuditID(events []daemon.EventEntry) int64 {
	var max int64
	for _, e := range events {
		if e.ID > max {
			max = e.ID
		}
	}
	return max
}

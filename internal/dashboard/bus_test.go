package dashboard

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/daemon"
)

func TestBus_FreshEventsChronologicalOrder(t *testing.T) {
	bus := newEventBus(nil, nil)
	// Daemon returns rows newest-first (matches ListAuditLog DESC id).
	rows := []daemon.EventEntry{
		{ID: 5, Op: "unban"},
		{ID: 4, Op: "ban"},
		{ID: 3, Op: "ban"},
	}
	fresh := bus.freshEvents(rows)
	if len(fresh) != 3 {
		t.Fatalf("len = %d, want 3", len(fresh))
	}
	// Broadcast order must be oldest → newest so operator UIs prepend
	// events one by one in the right sequence.
	for i := 1; i < len(fresh); i++ {
		if fresh[i-1].ID >= fresh[i].ID {
			t.Errorf("fresh not ascending by id: %d then %d", fresh[i-1].ID, fresh[i].ID)
		}
	}
	if bus.lastID != 5 {
		t.Errorf("lastID = %d, want 5", bus.lastID)
	}

	// Second call with the same batch → no new events.
	if again := bus.freshEvents(rows); len(again) != 0 {
		t.Errorf("second call should yield 0 fresh; got %d", len(again))
	}
}

func TestBus_BroadcastEmitsPerClient(t *testing.T) {
	bus := newEventBus(nil, nil)
	c1 := bus.subscribe()
	c2 := bus.subscribe()
	defer bus.unsubscribe(c1)
	defer bus.unsubscribe(c2)

	rows := []daemon.EventEntry{
		{ID: 1, Op: "ban", IP: "203.0.113.1"},
		{ID: 2, Op: "unban", IP: "203.0.113.1"},
	}
	bus.broadcast(rows)

	// Each client must receive both audit messages, in order.
	for _, c := range []*wsClient{c1, c2} {
		for want := int64(1); want <= 2; want++ {
			select {
			case msg := <-c.send:
				var env wsMessage
				if err := json.Unmarshal(msg, &env); err != nil {
					t.Fatalf("bad json: %v", err)
				}
				if env.Type != "audit" || env.Entry == nil || env.Entry.ID != want {
					t.Errorf("want audit id=%d, got %+v", want, env)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("client did not receive event id=%d", want)
			}
		}
	}
}

func TestBus_CoalescesLargeBurstAsRefresh(t *testing.T) {
	bus := newEventBus(nil, nil)
	c := bus.subscribe()
	defer bus.unsubscribe(c)

	rows := make([]daemon.EventEntry, broadcastBurstCap+1)
	for i := range rows {
		rows[i] = daemon.EventEntry{ID: int64(i + 1), Op: "ban"}
	}
	bus.broadcast(rows)

	select {
	case msg := <-c.send:
		var env wsMessage
		if err := json.Unmarshal(msg, &env); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if env.Type != "refresh" {
			t.Errorf("want refresh envelope, got %+v", env)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no message received")
	}
	// No further messages should follow.
	select {
	case extra := <-c.send:
		t.Errorf("expected only 1 message; got extra: %s", extra)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBus_SlowClientDropsSilently(t *testing.T) {
	bus := newEventBus(nil, nil)
	c := bus.subscribe()
	defer bus.unsubscribe(c)

	// Fill the buffer beyond its capacity: additional sends must be
	// dropped instead of blocking the broadcast goroutine.
	overflow := clientSendBuf + 5
	rows := make([]daemon.EventEntry, overflow)
	for i := range rows {
		rows[i] = daemon.EventEntry{ID: int64(i + 1), Op: "ban"}
	}
	// Broadcast with too many rows → coalesces to a single "refresh",
	// which the queue must accept.
	bus.broadcast(rows)
	if len(c.send) > clientSendBuf {
		t.Errorf("client queue exceeded buffer: %d > %d", len(c.send), clientSendBuf)
	}
}

func TestBus_TickCallsFetcherAndBroadcasts(t *testing.T) {
	var callCount int
	fetcher := func(context.Context) ([]daemon.EventEntry, error) {
		callCount++
		if callCount == 1 {
			// First tick returns nothing; bus should not broadcast.
			return nil, nil
		}
		return []daemon.EventEntry{{ID: 1, Op: "ban", IP: "1.1.1.1"}}, nil
	}
	bus := newEventBus(fetcher, nil)
	c := bus.subscribe()
	defer bus.unsubscribe(c)

	ctx := context.Background()
	bus.tick(ctx) // first tick: no events → nothing on the wire.
	select {
	case msg := <-c.send:
		t.Fatalf("did not expect a message on empty tick, got %s", msg)
	default:
	}
	bus.tick(ctx) // second tick: one new row → one broadcast.
	select {
	case msg := <-c.send:
		var env wsMessage
		if err := json.Unmarshal(msg, &env); err != nil {
			t.Fatalf("bad json: %v", err)
		}
		if env.Type != "audit" || env.Entry == nil || env.Entry.ID != 1 {
			t.Errorf("unexpected envelope: %+v", env)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("bus tick did not deliver expected event")
	}
}

func TestBus_SubscribeUnsubscribe(t *testing.T) {
	bus := newEventBus(nil, nil)
	if got := bus.clientCount(); got != 0 {
		t.Errorf("clientCount = %d, want 0", got)
	}
	a := bus.subscribe()
	b := bus.subscribe()
	if got := bus.clientCount(); got != 2 {
		t.Errorf("clientCount after subscribe = %d, want 2", got)
	}
	bus.unsubscribe(a)
	bus.unsubscribe(b)
	if got := bus.clientCount(); got != 0 {
		t.Errorf("clientCount after unsubscribe = %d, want 0", got)
	}
	// Unsubscribing a stale pointer is a no-op.
	bus.unsubscribe(a)
}

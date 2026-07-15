package daemon

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newTestDaemonWithSocket builds a daemon bound to a real unix socket in a
// temp dir and starts serveSocket, so tests can exercise the full wire path
// (Subscribe client → serveSocket → handleSubscribe). The context is
// cancelled on cleanup, which closes the listener.
func newTestDaemonWithSocket(t *testing.T) (*Daemon, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	// Keep the socket path short: unix socket paths are capped (~108 bytes)
	// and t.TempDir can be long on some runners.
	sock := filepath.Join(t.TempDir(), "s.sock")

	d, err := New(Config{Policy: policy, Store: db, SocketPath: sock})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go d.serveSocket(ctx)

	// Wait for the socket file to appear so clients don't race the bind.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(sock); err == nil {
			return d, sock
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestSubscribe_StreamsCLIBanEvent is the end-to-end round trip: a Subscribe
// client over the real unix socket receives the event published by a manual
// `ban` sent through Call on a second connection.
func TestSubscribe_StreamsCLIBanEvent(t *testing.T) {
	_ = captureSlog(t)
	_, sock := newTestDaemonWithSocket(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connected := make(chan struct{})
	events := make(chan StreamEvent, 16)
	subErr := make(chan error, 1)
	go func() {
		subErr <- Subscribe(ctx, sock, func() { close(connected) }, func(ev StreamEvent) {
			events <- ev
		})
	}()

	select {
	case <-connected:
	case err := <-subErr:
		t.Fatalf("Subscribe exited before ack: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("subscribe ack never arrived")
	}

	if _, err := Call(ctx, sock, SocketRequest{
		Verb: "ban", IP: "203.0.113.7", TTL: "1h", Reason: "abuse report",
	}); err != nil {
		t.Fatalf("ban via Call: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Kind != "ban" {
			t.Errorf("Kind = %q, want %q", ev.Kind, "ban")
		}
		if ev.IP != "203.0.113.7" {
			t.Errorf("IP = %q, want 203.0.113.7", ev.IP)
		}
		if ev.TTL != "1h0m0s" {
			t.Errorf("TTL = %q, want 1h0m0s", ev.TTL)
		}
		if ev.Source != "cli" {
			t.Errorf("Source = %q, want cli", ev.Source)
		}
		if ev.Reason != "abuse report" {
			t.Errorf("Reason = %q, want %q", ev.Reason, "abuse report")
		}
		if _, err := time.Parse(time.RFC3339, ev.Time); err != nil {
			t.Errorf("Time %q is not RFC 3339: %v", ev.Time, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event never arrived on subscription")
	}

	// Cancelling the context must end Subscribe cleanly (nil error) — this is
	// what gives `watch` its clean Ctrl-C exit.
	cancel()
	select {
	case err := <-subErr:
		if err != nil {
			t.Errorf("Subscribe after cancel = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe did not return after context cancel")
	}
}

// TestHandleSubscribe_ReadOnly guards §6 (control surfaces): a subscribe
// request carrying mutation-shaped fields (IP, TTL, Reason) must not create
// bans, allowlist entries, or audit rows — the fields are ignored.
func TestHandleSubscribe_ReadOnly(t *testing.T) {
	_ = captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)
	ctx := context.Background()

	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleConn(ctx, server)
	}()

	if err := json.NewEncoder(client).Encode(SocketRequest{
		Verb: "subscribe", IP: "203.0.113.9", TTL: "1h", Reason: "sneaky",
	}); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var ack SocketResponse
	if err := json.NewDecoder(client).Decode(&ack); err != nil {
		t.Fatalf("decode ack: %v", err)
	}
	if !ack.OK {
		t.Fatalf("subscribe ack not OK: %s", ack.Error)
	}
	_ = client.Close()
	<-done

	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Errorf("subscribe created %d ban(s); must be read-only", len(bans))
	}
	rows, err := d.store.ListAuditLog(ctx, 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("subscribe wrote %d audit row(s); must be read-only", len(rows))
	}
}

// TestHandleBan_DryRun_PublishesDryBanEvent asserts the dry-run path streams
// kind=dry_ban, so a watch client can tell simulated bans apart.
func TestHandleBan_DryRun_PublishesDryBanEvent(t *testing.T) {
	_ = captureSlog(t)
	d := newTestDaemonForSocket(t, false /* dry-run */)

	ch := d.events.subscribe()
	defer d.events.unsubscribe(ch)

	if resp := callSocket(t, d, SocketRequest{Verb: "ban", IP: "198.51.100.5"}); !resp.OK {
		t.Fatalf("ban failed: %s", resp.Error)
	}

	select {
	case ev := <-ch:
		if ev.Kind != "dry_ban" {
			t.Errorf("Kind = %q, want dry_ban", ev.Kind)
		}
		if ev.Source != "cli" {
			t.Errorf("Source = %q, want cli", ev.Source)
		}
	default:
		t.Fatal("no event published for dry-run ban")
	}
}

// TestPublishDetections_MapsVerdictFields checks the verdict → StreamEvent
// mapping (Rule carries Verdict.Source; Source marks the pipeline origin).
func TestPublishDetections_MapsVerdictFields(t *testing.T) {
	d := newTestDaemonForSocket(t, true)

	ch := d.events.subscribe()
	defer d.events.unsubscribe(ch)

	d.publishDetections([]sdk.Verdict{{
		IP:       netip.MustParseAddr("203.0.113.99"),
		Score:    85,
		Category: "bruteforce",
		Source:   "rules",
		Reason:   "12 failed logins in 30s",
	}})

	select {
	case ev := <-ch:
		if ev.Kind != "detection" {
			t.Errorf("Kind = %q, want detection", ev.Kind)
		}
		if ev.IP != "203.0.113.99" {
			t.Errorf("IP = %q, want 203.0.113.99", ev.IP)
		}
		if ev.Score != 85 {
			t.Errorf("Score = %d, want 85", ev.Score)
		}
		if ev.Category != "bruteforce" {
			t.Errorf("Category = %q, want bruteforce", ev.Category)
		}
		if ev.Rule != "rules" {
			t.Errorf("Rule = %q, want rules", ev.Rule)
		}
		if ev.Source != "pipeline" {
			t.Errorf("Source = %q, want pipeline", ev.Source)
		}
	default:
		t.Fatal("no detection event published")
	}
}

// TestEventBus_SlowSubscriberNeverBlocks guards the pipeline hot path: with a
// full subscriber buffer, publish must return immediately (drop) rather than
// stall the daemon.
func TestEventBus_SlowSubscriberNeverBlocks(t *testing.T) {
	bus := newEventBus()
	ch := bus.subscribe()
	defer bus.unsubscribe(ch)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < subscriberBuf+50; i++ {
			bus.publish(StreamEvent{Kind: "detection"})
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish blocked on a slow subscriber")
	}
	if got := len(ch); got != subscriberBuf {
		t.Errorf("buffered events = %d, want %d (overflow must be dropped)", got, subscriberBuf)
	}
}

// TestEventBus_NoSubscribers verifies the fast path: publishing with nobody
// listening is a no-op and hasSubscribers flips with subscribe/unsubscribe.
func TestEventBus_NoSubscribers(t *testing.T) {
	bus := newEventBus()
	if bus.hasSubscribers() {
		t.Error("fresh bus reports subscribers")
	}
	bus.publish(StreamEvent{Kind: "ban"}) // must not panic or block

	ch := bus.subscribe()
	if !bus.hasSubscribers() {
		t.Error("bus with one subscriber reports none")
	}
	bus.unsubscribe(ch)
	if bus.hasSubscribers() {
		t.Error("bus reports subscribers after unsubscribe")
	}
}

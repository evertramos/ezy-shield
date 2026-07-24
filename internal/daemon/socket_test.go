package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
)

// captureSlog swaps slog.Default() with a text-handler writing to buf for the
// duration of the test and restores the original on cleanup. It's the minimal
// scaffold we need: socket handlers use the package-level slog.InfoContext /
// slog.ErrorContext functions, which dispatch through slog.Default().
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// newTestDaemonForSocket wires the minimal daemon needed to exercise the
// socket handlers via handleConn: in-memory store, a policy, no enforcer,
// no notifier, no socket path.
func newTestDaemonForSocket(t *testing.T, armed bool) *Daemon {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policy := &config.Policy{
		Armed:            armed,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

// callSocket dispatches req through handleConn via net.Pipe, mirroring the
// scaffold TestSocketHandlers uses in daemon_test.go, and returns the response.
func callSocket(t *testing.T, d *Daemon, req SocketRequest) SocketResponse {
	t.Helper()
	ctx := context.Background()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.handleConn(ctx, server)
	}()
	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var resp SocketResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	_ = client.Close()
	<-done
	return resp
}

// containsAll verifies every needle appears in haystack (order-insensitive,
// substring match). Fails the test with a readable message otherwise.
func containsAll(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			t.Errorf("log missing substring %q\nfull line: %s", n, haystack)
		}
	}
}

// findActionLine returns the single "daemon: action" line from buf, failing
// the test if there is zero or more than one. This is what closes the issue:
// there must be exactly one INFO action line per CLI verb.
func findActionLine(t *testing.T, buf *bytes.Buffer) string {
	t.Helper()
	var matches []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, `msg="daemon: action"`) {
			matches = append(matches, l)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 'daemon: action' log line, got %d\nfull buffer:\n%s",
			len(matches), buf.String())
	}
	return matches[0]
}

// TestHandleBan_LogsCLIAction covers the armed happy-path: a manual ban of a
// single IPv4 host must emit one INFO line matching the pipeline shape, with
// source=cli so operators can tell CLI actions apart from rule-triggered ones.
// Issue #45.
func TestHandleBan_LogsCLIAction(t *testing.T) {
	buf := captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)

	resp := callSocket(t, d, SocketRequest{
		Verb:   "ban",
		IP:     "203.0.113.7",
		TTL:    "1h",
		Reason: "abuse report",
	})
	if !resp.OK {
		t.Fatalf("ban failed: %s", resp.Error)
	}

	line := findActionLine(t, buf)
	containsAll(t, line,
		"level=INFO",
		`msg="daemon: action"`,
		"op=ban",
		"ip=203.0.113.7",
		"ttl=1h0m0s",
		`reason="abuse report"`,
		"source=cli",
	)
}

// TestHandleBan_DryRun_LogsDryBan asserts that when policy.Armed=false, the
// same handler emits op=dry_ban so a dry-run CLI ban is visibly distinct in
// the journal.
func TestHandleBan_DryRun_LogsDryBan(t *testing.T) {
	buf := captureSlog(t)
	d := newTestDaemonForSocket(t, false /* dry-run */)

	resp := callSocket(t, d, SocketRequest{
		Verb: "ban",
		IP:   "198.51.100.5",
	})
	if !resp.OK {
		t.Fatalf("ban failed: %s", resp.Error)
	}

	line := findActionLine(t, buf)
	containsAll(t, line,
		"level=INFO",
		`msg="daemon: action"`,
		"op=dry_ban",
		"ip=198.51.100.5",
		"source=cli",
	)
	// Reason defaults to the placeholder when the CLI didn't supply one.
	if !strings.Contains(line, `reason="manual ban via CLI"`) {
		t.Errorf("expected default reason on dry_ban, got: %s", line)
	}
}

// TestHandleUnban_LogsCLIAction: a manual unban of a single IP emits one
// INFO line with op=unban, ttl=0s, source=cli. Reason is empty because the
// CLI doesn't send one today — issue #45 says leave that as-is.
func TestHandleUnban_LogsCLIAction(t *testing.T) {
	buf := captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)

	// Seed a ban so Unban has something to remove. Failure to seed shouldn't
	// hide the log we're really testing, but a clean pre-state makes the
	// assertion unambiguous.
	if resp := callSocket(t, d, SocketRequest{
		Verb: "ban", IP: "203.0.113.42", Reason: "seed",
	}); !resp.OK {
		t.Fatalf("seed ban failed: %s", resp.Error)
	}
	buf.Reset() // discard the ban log — we only care about the unban here.

	resp := callSocket(t, d, SocketRequest{Verb: "unban", IP: "203.0.113.42"})
	if !resp.OK {
		t.Fatalf("unban failed: %s", resp.Error)
	}

	line := findActionLine(t, buf)
	containsAll(t, line,
		"level=INFO",
		`msg="daemon: action"`,
		"op=unban",
		"ip=203.0.113.42",
		"ttl=0s",
		"source=cli",
	)
}

// TestHandleAllow_LogsCLIAction: a manual allow with --for emits one INFO
// line with op=allow, source=cli, and a positive ttl matching the requested
// duration (to within a small tolerance — we assert the numeric duration
// literal is present).
func TestHandleAllow_LogsCLIAction(t *testing.T) {
	buf := captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)

	resp := callSocket(t, d, SocketRequest{
		Verb:   "allow",
		IP:     "192.0.2.0/24",
		For:    "1h",
		Reason: "pentest",
	})
	if !resp.OK {
		t.Fatalf("allow failed: %s", resp.Error)
	}

	line := findActionLine(t, buf)
	containsAll(t, line,
		"level=INFO",
		`msg="daemon: action"`,
		"op=allow",
		"ip=192.0.2.0/24",
		`reason=pentest`,
		"source=cli",
	)
	// The TTL is computed from time.Until(expiresAt) — a hair less than 1h,
	// but never zero and never negative for a --for=1h request.
	if strings.Contains(line, "ttl=0s") {
		t.Errorf("expected non-zero ttl on --for=1h allow, got: %s", line)
	}
}

// TestHandleAllow_Permanent_LogsCLIAction: allow without --for/--until means
// a permanent entry. The pipeline convention is ttl=0 for permanent, matching
// the issue's spec.
func TestHandleAllow_Permanent_LogsCLIAction(t *testing.T) {
	buf := captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)

	resp := callSocket(t, d, SocketRequest{Verb: "allow", IP: "10.0.0.1"})
	if !resp.OK {
		t.Fatalf("allow failed: %s", resp.Error)
	}

	line := findActionLine(t, buf)
	containsAll(t, line,
		"level=INFO",
		`msg="daemon: action"`,
		"op=allow",
		"ip=10.0.0.1",
		"ttl=0s",
		"source=cli",
	)
}

// TestHandleEvents_RoundTrip verifies the "events" verb returns the audit
// rows written by previous CLI verbs in newest-first order and honours the
// per-request Limit.
func TestHandleEvents_RoundTrip(t *testing.T) {
	_ = captureSlog(t)
	d := newTestDaemonForSocket(t, true /* armed */)

	// Seed the audit_log via ban/unban/allow verbs so we exercise the real
	// audit path (not a raw store.Audit call).
	for _, req := range []SocketRequest{
		{Verb: "ban", IP: "203.0.113.1", TTL: "5m", Reason: "sshd"},
		{Verb: "unban", IP: "203.0.113.1"},
		{Verb: "allow", IP: "192.0.2.0/24", Reason: "office"},
	} {
		resp := callSocket(t, d, req)
		if !resp.OK {
			t.Fatalf("seed %q failed: %s", req.Verb, resp.Error)
		}
	}

	// Default limit (100) → all seeded rows visible.
	resp := callSocket(t, d, SocketRequest{Verb: "events"})
	if !resp.OK {
		t.Fatalf("events verb failed: %s", resp.Error)
	}
	var entries []EventEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one audit row, got 0")
	}
	// Newest first.
	for i := 1; i < len(entries); i++ {
		if entries[i-1].ID <= entries[i].ID {
			t.Errorf("rows not DESC: %d then %d", entries[i-1].ID, entries[i].ID)
		}
	}

	// Limit=1 → single row.
	resp2 := callSocket(t, d, SocketRequest{Verb: "events", Limit: 1})
	if !resp2.OK {
		t.Fatalf("events limit=1 failed: %s", resp2.Error)
	}
	var one []EventEntry
	if err := json.Unmarshal(resp2.Data, &one); err != nil {
		t.Fatalf("decode limit=1: %v", err)
	}
	if len(one) != 1 {
		t.Errorf("limit=1 returned %d rows, want 1", len(one))
	}
}

// TestHandleList_ExpiredNeverRendersPermanent (issue #279): `ezyshield list`
// must say "permanent" only for a genuine no-expiry ban. The expired-but-
// unreaped row is excluded by the store; the timed ban shows its remaining
// duration, never the permanent label.
func TestHandleList_ExpiredNeverRendersPermanent(t *testing.T) {
	d := newTestDaemonForSocket(t, true)
	ctx := context.Background()

	if err := d.store.RecordManualBan(ctx, netip.MustParseAddr("203.0.113.1"), time.Nanosecond, "expired"); err != nil {
		t.Fatalf("seed expired: %v", err)
	}
	if err := d.store.RecordManualBan(ctx, netip.MustParseAddr("203.0.113.2"), 0, "really permanent"); err != nil {
		t.Fatalf("seed permanent: %v", err)
	}
	if err := d.store.RecordManualBan(ctx, netip.MustParseAddr("203.0.113.3"), 5*time.Minute, "strike-1 style"); err != nil {
		t.Fatalf("seed timed: %v", err)
	}

	resp := callSocket(t, d, SocketRequest{Verb: "list"})
	if resp.Error != "" {
		t.Fatalf("list: %s", resp.Error)
	}
	var entries []BanEntry
	if err := json.Unmarshal(resp.Data, &entries); err != nil {
		t.Fatalf("decode: %v", err)
	}

	ttls := make(map[string]string, len(entries))
	for _, e := range entries {
		ttls[e.IP] = e.TTL
	}
	if _, ok := ttls["203.0.113.1"]; ok {
		t.Errorf("expired ban present in list output: ttl=%q", ttls["203.0.113.1"])
	}
	if ttls["203.0.113.2"] != "permanent" {
		t.Errorf("permanent ban ttl = %q, want \"permanent\"", ttls["203.0.113.2"])
	}
	if got := ttls["203.0.113.3"]; got == "permanent" || got == "expired" || got == "" {
		t.Errorf("timed ban ttl = %q, want a remaining duration", got)
	}
}

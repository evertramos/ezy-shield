package daemon

// Tests for the manual-ban guard wiring in handleBan (issue #211): refusals
// name the guard, are audited as ban_refused, never reach the enforcer or
// bans_active; legitimate manual bans still work end to end.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// newManualBanDaemon builds an armed daemon over a real in-memory store and
// a fake enforcer, with allowlist/admin_cidrs material for the guards.
func newManualBanDaemon(t *testing.T, maxBans int) (*Daemon, *store.DB, *fakeEnforcer) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	enf := &fakeEnforcer{}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: maxBans,
			Strikes:          config.DefaultStrikes,
			Allowlist:        []string{"198.51.100.0/25"},
			AdminCIDRs:       []string{"192.0.2.0/28"},
		},
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db, enf
}

// refusedOps returns the audit_log ops recorded as ban_refused.
func banRefusedReasons(t *testing.T, db *store.DB) []string {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var reasons []string
	for _, e := range entries {
		if e.Op == "ban_refused" {
			reasons = append(reasons, e.Reason)
		}
	}
	return reasons
}

func TestHandleBan_AllowlistedTargetRefused(t *testing.T) {
	d, db, enf := newManualBanDaemon(t, 30)
	ctx := context.Background()

	cases := []string{
		"198.51.100.7",    // inside allowlisted CIDR
		"198.51.100.0/24", // CIDR containing the allowlisted CIDR
		"192.0.2.5",       // inside admin_cidrs
	}
	for _, target := range cases {
		resp := d.handleBan(ctx, SocketRequest{Verb: "ban", IP: target})
		if resp.Error == "" {
			t.Fatalf("ban %s: want refusal, got OK", target)
		}
		if !strings.Contains(resp.Error, "allowlist") {
			t.Errorf("ban %s: error %q does not name the allowlist guard", target, resp.Error)
		}
	}
	if enf.BanCount() != 0 {
		t.Errorf("enforcer.Ban called %d time(s) for refused bans", enf.BanCount())
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 0 {
		t.Errorf("bans_active has %d row(s) after refusals", len(bans))
	}
	if got := banRefusedReasons(t, db); len(got) != len(cases) {
		t.Errorf("audit ban_refused rows = %d, want %d (every refusal audited)", len(got), len(cases))
	}
}

func TestHandleBan_ForwardedPeerRefused(t *testing.T) {
	d, db, enf := newManualBanDaemon(t, 30)

	resp := d.handleBan(context.Background(), SocketRequest{
		Verb: "ban", IP: "203.0.113.9", Peer: "203.0.113.9",
	})
	if resp.Error == "" || !strings.Contains(resp.Error, "SSH session") {
		t.Fatalf("banning own forwarded peer: error = %q, want SSH-session refusal", resp.Error)
	}
	if enf.BanCount() != 0 {
		t.Error("enforcer called despite anti-lockout refusal")
	}
	reasons := banRefusedReasons(t, db)
	if len(reasons) != 1 || !strings.Contains(reasons[0], "203.0.113.9") {
		t.Errorf("audit reasons = %v, want one naming the peer", reasons)
	}
}

func TestHandleBan_RuntimeAllowlistOverlapRefused(t *testing.T) {
	d, db, _ := newManualBanDaemon(t, 30)
	ctx := context.Background()

	if err := db.AddAllow(ctx, netip.MustParsePrefix("203.0.113.0/26"), nil, "test allow"); err != nil {
		t.Fatal(err)
	}
	if err := d.reloadAllowlist(ctx); err != nil {
		t.Fatal(err)
	}

	resp := d.handleBan(ctx, SocketRequest{Verb: "ban", IP: "203.0.113.0/24"})
	if resp.Error == "" || !strings.Contains(resp.Error, "runtime allowlist") {
		t.Fatalf("error = %q, want runtime-allowlist refusal", resp.Error)
	}
}

func TestHandleBan_RateLimited(t *testing.T) {
	d, db, enf := newManualBanDaemon(t, 2)
	ctx := context.Background()

	for i, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if resp := d.handleBan(ctx, SocketRequest{Verb: "ban", IP: ip}); resp.Error != "" {
			t.Fatalf("ban %d (%s): %s", i, ip, resp.Error)
		}
	}
	resp := d.handleBan(ctx, SocketRequest{Verb: "ban", IP: "203.0.113.3"})
	if resp.Error == "" || !strings.Contains(resp.Error, "rate limit") {
		t.Fatalf("third manual ban: error = %q, want rate-limit refusal", resp.Error)
	}
	if enf.BanCount() != 2 {
		t.Errorf("enforcer.Ban calls = %d, want 2 (refused ban never enforced)", enf.BanCount())
	}
	if got := banRefusedReasons(t, db); len(got) != 1 {
		t.Errorf("audit ban_refused rows = %d, want 1", len(got))
	}
}

func TestHandleBan_LegitimateBanStillWorks(t *testing.T) {
	d, db, enf := newManualBanDaemon(t, 30)
	ctx := context.Background()

	resp := d.handleBan(ctx, SocketRequest{Verb: "ban", IP: "203.0.113.99", TTL: "1h", Reason: "test", Peer: "192.0.2.1"})
	if resp.Error != "" {
		t.Fatalf("legitimate ban refused: %s", resp.Error)
	}
	if enf.BanCount() != 1 {
		t.Errorf("enforcer.Ban calls = %d, want 1", enf.BanCount())
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != netip.MustParseAddr("203.0.113.99") {
		t.Errorf("bans_active = %+v, want the banned IP", bans)
	}
	// The forwarded peer 192.0.2.1 sits inside admin_cidrs — the normal
	// situation of a real operator banning somebody else. The peer guard
	// protects the PEER from being banned; it must not block bans of other
	// targets, and no refusal may be audited here.
	if got := banRefusedReasons(t, db); len(got) != 0 {
		t.Errorf("unexpected ban_refused audit rows: %v", got)
	}
}

// ── issue #326: enforcer-boundary gating ─────────────────────────────────────

// failingEnforcer counts Ban attempts and always fails them.
type failingEnforcer struct {
	fakeEnforcer
}

func (f *failingEnforcer) Ban(ctx context.Context, t sdk.Target) error {
	_ = f.fakeEnforcer.Ban(ctx, t) // record the attempt
	return fmt.Errorf("nft exec: operation not permitted")
}

// newManualBanDaemonWith builds a manual-ban daemon with explicit armed state
// and enforcer, for boundary tests that need combinations newManualBanDaemon
// doesn't cover (it is always armed=true + fakeEnforcer).
func newManualBanDaemonWith(t *testing.T, armed bool, enf sdk.Enforcer) (*Daemon, *store.DB) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            armed,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db
}

// TestHandleBan_DryRun_NeverReachesEnforcer covers the missing half of the
// socket.go gate (issue #326): a daemon WITH an enforcer but armed=false. A
// regression dropping the IsArmed() condition — a dry-run manual ban reaching
// the firewall, violating Hard Rule 1 (dry-run is the default mode) — passed
// the entire suite before this test: every manual-ban test was armed=true and
// the only dry-run test had no enforcer at all.
func TestHandleBan_DryRun_NeverReachesEnforcer(t *testing.T) {
	enf := &fakeEnforcer{}
	d, _ := newManualBanDaemonWith(t, false /* armed */, enf)

	resp := callSocket(t, d, SocketRequest{Verb: "ban", IP: "203.0.113.9", Reason: "test"})
	if !resp.OK {
		t.Fatalf("dry-run manual ban should succeed as dry_ban: %s", resp.Error)
	}
	if got := enf.BanCount(); got != 0 {
		t.Fatalf("enforcer received %d Ban call(s) while disarmed — dry-run must never touch the firewall", got)
	}
}

// TestHandleBan_EnforcerFailure_ErrorsAndNoStoreRow covers the enforcer-fails
// branch: the operator gets the error and no bans_active row is written (list
// must not claim a ban the firewall refused).
func TestHandleBan_EnforcerFailure_ErrorsAndNoStoreRow(t *testing.T) {
	enf := &failingEnforcer{}
	d, db := newManualBanDaemonWith(t, true /* armed */, enf)
	ctx := context.Background()

	resp := callSocket(t, d, SocketRequest{Verb: "ban", IP: "203.0.113.9", Reason: "test"})
	if resp.OK {
		t.Fatal("manual ban must fail when the enforcer fails")
	}
	if !strings.Contains(resp.Error, "enforcer ban:") {
		t.Errorf("error should carry the enforcer failure, got: %s", resp.Error)
	}
	if got := enf.BanCount(); got != 1 {
		t.Errorf("expected exactly 1 Ban attempt, got %d", got)
	}

	ip := netip.MustParseAddr("203.0.113.9")
	_, _, _, active, err := db.GetBanInfo(ctx, ip)
	if err != nil {
		t.Fatalf("GetBanInfo: %v", err)
	}
	if active {
		t.Error("bans_active must not contain an IP the enforcer refused to ban")
	}
	for _, e := range mustAudit(t, db) {
		if e.Op == "ban" {
			t.Errorf("audit_log must not record op=ban for a failed enforcer ban, got %+v", e)
		}
	}
}

func mustAudit(t *testing.T, db *store.DB) []store.AuditEntry {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	return entries
}

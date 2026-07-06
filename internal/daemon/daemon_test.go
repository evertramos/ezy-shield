package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// fakeCollector sends a fixed list of RawLines then blocks until ctx is cancelled.
type fakeCollector struct {
	lines []sdk.RawLine
}

func (f *fakeCollector) Run(ctx context.Context, out chan<- sdk.RawLine) error {
	for _, l := range f.lines {
		select {
		case <-ctx.Done():
			return nil
		case out <- l:
		}
	}
	<-ctx.Done()
	return nil
}

// fakeNotifier records every notification it receives.
type fakeNotifier struct {
	mu   sync.Mutex
	msgs []sdk.Notification
}

func (f *fakeNotifier) Name() string { return "fake" }
func (f *fakeNotifier) Send(_ context.Context, msg sdk.Notification) error {
	f.mu.Lock()
	f.msgs = append(f.msgs, msg)
	f.mu.Unlock()
	return nil
}
func (f *fakeNotifier) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

// fakeEnforcer records Ban/Unban calls without touching nftables.
type fakeEnforcer struct {
	mu     sync.Mutex
	bans   []sdk.Target
	unbans []sdk.Target
}

func (f *fakeEnforcer) Name() string { return "fake" }
func (f *fakeEnforcer) Ban(_ context.Context, t sdk.Target) error {
	f.mu.Lock()
	f.bans = append(f.bans, t)
	f.mu.Unlock()
	return nil
}
func (f *fakeEnforcer) Unban(_ context.Context, t sdk.Target) error {
	f.mu.Lock()
	f.unbans = append(f.unbans, t)
	f.mu.Unlock()
	return nil
}
func (f *fakeEnforcer) Sync(_ context.Context, _ []sdk.Target) error { return nil }
func (f *fakeEnforcer) BanCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bans)
}

// fakeAllowSyncEnforcer additionally satisfies the daemon's allowlistSyncer
// interface (Allow / Unallow / SyncAllowlist). It records every SyncAllowlist
// call so tests can assert the union passed by the daemon.
type fakeAllowSyncEnforcer struct {
	fakeEnforcer
	mu           sync.Mutex
	syncCalls    [][]netip.Prefix // one entry per SyncAllowlist invocation
	allowCalls   []netip.Prefix
	unallowCalls []netip.Prefix
	syncErr      error // if set, SyncAllowlist returns this
}

func (f *fakeAllowSyncEnforcer) Allow(_ context.Context, prefix netip.Prefix) error {
	f.mu.Lock()
	f.allowCalls = append(f.allowCalls, prefix)
	f.mu.Unlock()
	return nil
}
func (f *fakeAllowSyncEnforcer) Unallow(_ context.Context, prefix netip.Prefix) error {
	f.mu.Lock()
	f.unallowCalls = append(f.unallowCalls, prefix)
	f.mu.Unlock()
	return nil
}
func (f *fakeAllowSyncEnforcer) SyncAllowlist(_ context.Context, want []netip.Prefix) error {
	f.mu.Lock()
	// Copy to protect against later mutation by the caller.
	c := make([]netip.Prefix, len(want))
	copy(c, want)
	f.syncCalls = append(f.syncCalls, c)
	err := f.syncErr
	f.mu.Unlock()
	return err
}
func (f *fakeAllowSyncEnforcer) SyncCalls() [][]netip.Prefix {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]netip.Prefix, len(f.syncCalls))
	for i, s := range f.syncCalls {
		c := make([]netip.Prefix, len(s))
		copy(c, s)
		out[i] = c
	}
	return out
}

// bruteforceLines produces n SSH failure lines from ip in journald format.
// The ssh_bruteforce rule fires at threshold ≥ 5 failures in 60 s.
func bruteforceLines(ip netip.Addr, n int) []sdk.RawLine {
	now := time.Now()
	lines := make([]sdk.RawLine, n)
	for i := range lines {
		lines[i] = sdk.RawLine{
			Source: "journald:sshd",
			Line:   []byte("Failed password for root from " + ip.String() + " port 40122 ssh2"),
			At:     now.Add(time.Duration(i) * time.Second),
		}
	}
	return lines
}

// TestEndToEnd_SSHBruteForce feeds fixture SSH lines through the full pipeline
// and asserts that a dry_ban action is produced and the notifier is called.
func TestEndToEnd_SSHBruteForce(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// In-memory SQLite store.
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Dry-run policy (armed=false, default thresholds).
	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	notif := &fakeNotifier{}
	disp := notify.New([]sdk.Notifier{notif}, 100, time.Hour, nil)
	enf := &fakeEnforcer{}

	// 6 failures from the same IP (threshold is 5).
	attacker := netip.MustParseAddr("192.0.2.99")
	fc := &fakeCollector{lines: bruteforceLines(attacker, 6)}

	actionsCh := make(chan sdk.Action, 32)

	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Collectors: []sdk.Collector{fc},
		Enforcer:   enf,
		Notifier:   disp,
		SocketPath: "", // disable socket server in tests
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.SetActionsSink(actionsCh)

	// Run daemon in background; cancel context to stop it after we get an action.
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(ctx) }()

	// Wait for at least one action (with timeout from ctx).
	var got sdk.Action
	select {
	case got = <-actionsCh:
	case <-ctx.Done():
		t.Fatal("timeout: no action received within deadline")
	}

	// Stop the daemon.
	cancel()
	<-daemonDone

	// Assert: dry_ban action for the attacker IP.
	if got.IP != attacker {
		t.Errorf("action IP = %v, want %v", got.IP, attacker)
	}
	if got.Op != "dry_ban" {
		t.Errorf("action Op = %q, want \"dry_ban\"", got.Op)
	}
	if got.Strike != 1 {
		t.Errorf("action Strike = %d, want 1", got.Strike)
	}

	// Assert: notifier was called.
	if notif.Count() == 0 {
		t.Error("notifier: expected at least one notification, got 0")
	}

	// Assert: enforcer was NOT called (dry_ban mode).
	if enf.BanCount() != 0 {
		t.Errorf("enforcer: expected 0 bans in dry-run, got %d", enf.BanCount())
	}
}

// TestEndToEnd_LRUCap verifies the aggregator LRU cap bounds memory.
func TestEndToEnd_LRUCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	const cap = 5
	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		SocketPath: "",
		MaxIPs:     cap,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Add events from 10 distinct IPs — the LRU cap should keep it to ≤ cap+1.
	for i := range 10 {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		d.agg.Add(sdk.Event{
			Time:     time.Now(),
			SourceIP: ip,
			Kind:     "ssh_fail",
			Fields:   map[string]string{},
		})
	}

	// After adding 10 IPs with cap=5, the aggregator should hold ≤ cap+1.
	// (+1 because eviction happens after insertion.)
	if got := d.agg.Len(); got > cap+1 {
		t.Errorf("aggregator Len = %d after LRU cap=%d; expected ≤ %d", got, cap, cap+1)
	}
}

// TestSocketHandlers exercises handleStatus / handleList / handleAllow using
// an in-process net.Pipe instead of a real socket.
func TestSocketHandlers(t *testing.T) {
	ctx := context.Background()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	policy := &config.Policy{
		Armed:            false,
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

	call := func(t *testing.T, req SocketRequest) SocketResponse {
		t.Helper()
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

	t.Run("status", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "status"})
		if !resp.OK {
			t.Fatalf("status failed: %s", resp.Error)
		}
		var sd StatusData
		if err := json.Unmarshal(resp.Data, &sd); err != nil {
			t.Fatalf("unmarshal StatusData: %v", err)
		}
		if sd.ActiveBans != 0 {
			t.Errorf("ActiveBans = %d, want 0", sd.ActiveBans)
		}
	})

	t.Run("allow_valid_ip", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "allow", IP: "10.0.0.1"})
		if !resp.OK {
			t.Fatalf("allow failed: %s", resp.Error)
		}
		// Verify the IP is now in the runtime allowlist.
		ip := netip.MustParseAddr("10.0.0.1")
		if !d.isRuntimeAllowlisted(ip) {
			t.Error("expected 10.0.0.1 to be runtime-allowlisted")
		}
	})

	t.Run("allow_invalid_ip", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "allow", IP: "not-an-ip"})
		if resp.OK {
			t.Error("expected error for invalid IP, got OK")
		}
	})

	t.Run("allow_cidr_covers_all_addrs_in_range", func(t *testing.T) {
		resp := call(t, SocketRequest{
			Verb:   "allow",
			IP:     "192.0.2.0/24",
			Reason: "pentest",
		})
		if !resp.OK {
			t.Fatalf("allow cidr failed: %s", resp.Error)
		}
		// Every IP in the range must now be allowlisted.
		for _, last := range []byte{1, 100, 254} {
			ip := netip.AddrFrom4([4]byte{192, 0, 2, last})
			if !d.isRuntimeAllowlisted(ip) {
				t.Errorf("expected %s to be runtime-allowlisted", ip)
			}
		}
		// An IP outside the range must NOT be allowlisted.
		outside := netip.MustParseAddr("192.0.3.1")
		if d.isRuntimeAllowlisted(outside) {
			t.Errorf("did not expect %s to be runtime-allowlisted", outside)
		}
	})

	t.Run("allow_for_duration_expires", func(t *testing.T) {
		resp := call(t, SocketRequest{
			Verb: "allow",
			IP:   "198.51.100.0/24",
			For:  "1h",
		})
		if !resp.OK {
			t.Fatalf("allow --for failed: %s", resp.Error)
		}
		ip := netip.MustParseAddr("198.51.100.42")
		if !d.isRuntimeAllowlisted(ip) {
			t.Errorf("expected %s to be runtime-allowlisted", ip)
		}

		// Sweep with "now" two hours from now: the temporal allow must vanish.
		if _, err := db.ExpireAllows(ctx, time.Now().Add(2*time.Hour)); err != nil {
			t.Fatalf("ExpireAllows: %v", err)
		}
		if err := d.reloadAllowlist(ctx); err != nil {
			t.Fatalf("reloadAllowlist: %v", err)
		}
		if d.isRuntimeAllowlisted(ip) {
			t.Errorf("%s should no longer be allowlisted after expiry sweep", ip)
		}
	})

	t.Run("allow_for_invalid_duration", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "allow", IP: "10.99.0.0/24", For: "banana"})
		if resp.OK {
			t.Error("expected error for invalid --for, got OK")
		}
	})

	t.Run("allow_for_and_until_mutually_exclusive", func(t *testing.T) {
		resp := call(t, SocketRequest{
			Verb: "allow", IP: "10.98.0.0/24",
			For: "24h", Until: "2099-01-01",
		})
		if resp.OK {
			t.Error("expected error when both --for and --until are set, got OK")
		}
	})

	t.Run("allow_until_in_past_rejected", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "allow", IP: "10.97.0.0/24", Until: "2000-01-01"})
		if resp.OK {
			t.Error("expected error for past --until, got OK")
		}
	})

	t.Run("list_allow_returns_entries", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "list_allow"})
		if !resp.OK {
			t.Fatalf("list_allow failed: %s", resp.Error)
		}
		var entries []AllowEntry
		if err := json.Unmarshal(resp.Data, &entries); err != nil {
			t.Fatalf("unmarshal AllowEntry: %v", err)
		}
		if len(entries) == 0 {
			t.Error("list_allow returned 0 entries; expected at least one from earlier sub-tests")
		}
	})

	t.Run("ban_cidr_accepted", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "ban", IP: "203.0.113.0/24"})
		if !resp.OK {
			t.Errorf("ban cidr failed: %s", resp.Error)
		}
	})

	t.Run("unban_cidr_accepted", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "unban", IP: "203.0.113.0/24"})
		if !resp.OK {
			t.Errorf("unban cidr failed: %s", resp.Error)
		}
	})

	t.Run("unknown_verb", func(t *testing.T) {
		resp := call(t, SocketRequest{Verb: "explode"})
		if resp.OK {
			t.Error("expected error for unknown verb, got OK")
		}
	})
}

// TestEndToEnd_Armed_EnforcerBanCalled verifies that when armed=true and a mock
// enforcer is wired, Ban() is called on the enforcer for a triggered rule.
func TestEndToEnd_Armed_EnforcerBanCalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	enf := &fakeEnforcer{}
	attacker := netip.MustParseAddr("198.51.100.7")
	fc := &fakeCollector{lines: bruteforceLines(attacker, 6)}
	actionsCh := make(chan sdk.Action, 32)

	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Collectors: []sdk.Collector{fc},
		Enforcer:   enf,
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.SetActionsSink(actionsCh)

	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(ctx) }()

	var got sdk.Action
	select {
	case got = <-actionsCh:
	case <-ctx.Done():
		t.Fatal("timeout: no action received within deadline")
	}

	cancel()
	<-daemonDone

	if got.Op != "ban" {
		t.Errorf("action Op = %q, want \"ban\"", got.Op)
	}
	if got.IP != attacker {
		t.Errorf("action IP = %v, want %v", got.IP, attacker)
	}
	if enf.BanCount() == 0 {
		t.Error("enforcer: expected Ban() to be called at least once, got 0")
	}
}

// fakeAIProvider records Analyze calls and returns a configurable verdict.
type fakeAIProvider struct {
	mu       sync.Mutex
	calls    int
	verdicts []sdk.Verdict
}

func (f *fakeAIProvider) Name() string { return "fake-ai" }
func (f *fakeAIProvider) Analyze(_ context.Context, batch []sdk.Aggregate, _ sdk.TokenBudget) ([]sdk.Verdict, sdk.Usage, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if len(batch) == 0 {
		return nil, sdk.Usage{}, nil
	}
	out := make([]sdk.Verdict, len(f.verdicts))
	copy(out, f.verdicts)
	// Stamp each verdict with the IP from the first aggregate.
	for i := range out {
		out[i].IP = batch[0].IP
	}
	return out, sdk.Usage{InputTokens: 10, OutputTokens: 5}, nil
}
func (f *fakeAIProvider) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// fakeBudgetStore satisfies ai.BudgetStore without a real database.
type fakeBudgetStore struct{}

func (f *fakeBudgetStore) RecordUsage(_ context.Context, _ string, _ sdk.Usage) error {
	return nil
}
func (f *fakeBudgetStore) TodayUsage(_ context.Context, _ string) (sdk.Usage, error) {
	return sdk.Usage{}, nil
}

// TestEndToEnd_AI_CalledForAmbiguousScore verifies that the AI provider is
// consulted when rules return a score inside the configured ambiguous band.
func TestEndToEnd_AI_CalledForAmbiguousScore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Observe threshold set low so the rule scores reach the ambiguous band.
	// Ban threshold set high so rules alone never trigger a ban.
	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     90, // rules won't reach this
		ObserveThreshold: 10,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	// The ssh_bruteforce rule fires at ≥5 failures and scores ~80 (above our
	// ambiguous band [30,75]). We need a score between 30 and 75 to trigger AI.
	// Use the observe band (score ≥ 10, < 90) with a low ban threshold override:
	// Actually, set aiLo/aiHi wide enough to include the rule's score.
	// The simplest way: configure the band to include the rule score (80).
	aiLo, aiHi := 30, 95

	fakeAI := &fakeAIProvider{
		verdicts: []sdk.Verdict{
			{Score: 85, Category: "bruteforce", Confidence: 0.9, Reason: "ai says ban", Source: "fake-ai"},
		},
	}

	budget := ai.NewBudget("fake-ai", 0, &fakeBudgetStore{}) // 0 = unlimited
	cache := ai.NewCache(time.Minute)

	attacker := netip.MustParseAddr("198.51.100.55")
	fc := &fakeCollector{lines: bruteforceLines(attacker, 6)}
	actionsCh := make(chan sdk.Action, 32)

	d, err := New(Config{
		Cfg: &config.Config{
			AI: &config.AICfg{
				AmbiguousBand: [2]int{aiLo, aiHi},
			},
		},
		Policy:     policy,
		Store:      db,
		Parsers:    []sdk.Parser{parser.NewSSHParser(slog.Default())},
		Collectors: []sdk.Collector{fc},
		AIProvider: fakeAI,
		AIBudget:   budget,
		AICache:    cache,
		SocketPath: "",
		MaxIPs:     100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.SetActionsSink(actionsCh)

	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(ctx) }()

	select {
	case <-actionsCh:
	case <-ctx.Done():
		t.Fatal("timeout: no action received within deadline")
	}

	cancel()
	<-daemonDone

	if fakeAI.CallCount() == 0 {
		t.Error("AI provider Analyze was not called for ambiguous-band score")
	}
}

// ── Issue #37: enforcer @allowed set must reflect policy allowlist ────────

// prefixSet is a set-typed helper for order-independent slice comparison.
type prefixSet map[netip.Prefix]struct{}

func newPrefixSet(ps []netip.Prefix) prefixSet {
	s := make(prefixSet, len(ps))
	for _, p := range ps {
		s[p] = struct{}{}
	}
	return s
}

func (s prefixSet) equal(other prefixSet) bool {
	if len(s) != len(other) {
		return false
	}
	for p := range s {
		if _, ok := other[p]; !ok {
			return false
		}
	}
	return true
}

// TestSyncEnforcerAllowlist_UnionOfPolicyAndRuntime is the regression test for
// issue #37: at startup the daemon must push the union of
// policy.Allowlist + policy.AdminCIDRs + runtime store entries into the
// enforcer's @allowed / @allowed6 sets, not just the runtime entries.
//
// Guards AGENTS.md §2 (allowlist supremacy) at the raw/prerouting nftables
// hook: if the daemon drops static policy prefixes, the belt-and-suspenders
// `ip saddr @allowed accept` rule is unarmed and a stray Ban call could
// still lock the admin out.
func TestSyncEnforcerAllowlist_UnionOfPolicyAndRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Seed a runtime allowlist entry that persists across "restarts" (i.e. across
	// daemon.New) — this mimics an operator having previously run
	// `ezyshield allow 198.51.100.0/24`.
	runtimePfx := netip.MustParsePrefix("198.51.100.0/24")
	if err := db.AddAllow(ctx, runtimePfx, nil, "pentest"); err != nil {
		t.Fatalf("AddAllow: %v", err)
	}

	// Policy carries both `allowlist` (mix of bare IP + CIDR + IPv6) and
	// `admin_cidrs` (CIDR only). One admin_cidrs entry duplicates a policy
	// allowlist entry to exercise deduplication.
	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
		Allowlist: []string{
			"127.0.0.1",     // bare IPv4 → widened to /32
			"172.16.0.0/12", // IPv4 CIDR
			"::1/128",       // IPv6
		},
		AdminCIDRs: []string{
			"203.0.113.42/32",
			"2001:db8:404:200::8218/128",
			"127.0.0.1/32", // duplicate of the bare-IP allowlist entry above
		},
	}

	enf := &fakeAllowSyncEnforcer{}

	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Reproduce the startup sequence Run performs: reload the runtime allowlist
	// from the store, then push the union to the enforcer.
	if err := d.reloadAllowlist(ctx); err != nil {
		t.Fatalf("reloadAllowlist: %v", err)
	}
	if err := d.syncEnforcerAllowlist(ctx); err != nil {
		t.Fatalf("syncEnforcerAllowlist: %v", err)
	}

	calls := enf.SyncCalls()
	if len(calls) != 1 {
		t.Fatalf("SyncAllowlist call count = %d, want 1", len(calls))
	}
	got := newPrefixSet(calls[0])

	want := newPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),  // widened bare IP; dedup with admin_cidrs
		netip.MustParsePrefix("172.16.0.0/12"), // policy allowlist CIDR
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("203.0.113.42/32"),
		netip.MustParsePrefix("2001:db8:404:200::8218/128"),
		runtimePfx, // runtime store entry
	})

	if !got.equal(want) {
		t.Errorf("SyncAllowlist got prefixes = %v, want %v", calls[0], want)
	}

	// Deduplication check: 127.0.0.1 appears in both allowlist and admin_cidrs.
	// It must not be pushed twice.
	if len(calls[0]) != len(want) {
		t.Errorf("SyncAllowlist pushed %d prefixes, want %d (deduplication failed)",
			len(calls[0]), len(want))
	}

	// The runtime slice must remain "store-owned": it should hold ONLY the entry
	// added via db.AddAllow, not the static policy prefixes. Otherwise
	// `ezyshield list --allow` would leak static entries into runtime output
	// and `ezyshield unallow` semantics would drift (see issue #37 proposal).
	d.mu.RLock()
	runtime := make([]netip.Prefix, len(d.runtimeAllowlist))
	copy(runtime, d.runtimeAllowlist)
	d.mu.RUnlock()
	if len(runtime) != 1 || runtime[0] != runtimePfx {
		t.Errorf("runtimeAllowlist = %v, want [%v] only (static entries must NOT leak into runtime)",
			runtime, runtimePfx)
	}
}

// TestSyncEnforcerAllowlist_EmptyRuntimeStillPushesPolicy covers the fresh-boot
// case: no store entries yet, but policy allowlist + admin_cidrs must still
// reach the enforcer's @allowed set.
func TestSyncEnforcerAllowlist_EmptyRuntimeStillPushesPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	policy := &config.Policy{
		Armed:            true,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
		Allowlist:        []string{"10.0.0.0/8"},
		AdminCIDRs:       []string{"192.0.2.1/32"},
	}

	enf := &fakeAllowSyncEnforcer{}

	d, err := New(Config{
		Policy:     policy,
		Store:      db,
		Enforcer:   enf,
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.reloadAllowlist(ctx); err != nil {
		t.Fatalf("reloadAllowlist: %v", err)
	}
	if err := d.syncEnforcerAllowlist(ctx); err != nil {
		t.Fatalf("syncEnforcerAllowlist: %v", err)
	}

	calls := enf.SyncCalls()
	if len(calls) != 1 {
		t.Fatalf("SyncAllowlist call count = %d, want 1", len(calls))
	}
	got := newPrefixSet(calls[0])
	want := newPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.1/32"),
	})
	if !got.equal(want) {
		t.Errorf("SyncAllowlist got = %v, want %v", calls[0], want)
	}
}

// TestSyncEnforcerAllowlist_NoPolicyEntries_OnlyRuntime covers the pre-existing
// behaviour: with an empty policy allowlist and admin_cidrs, only runtime
// store entries are pushed. Ensures the fix doesn't accidentally invent
// prefixes from nowhere.
func TestSyncEnforcerAllowlist_NoPolicyEntries_OnlyRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	runtimePfx := netip.MustParsePrefix("203.0.113.7/32")
	if err := db.AddAllow(ctx, runtimePfx, nil, ""); err != nil {
		t.Fatalf("AddAllow: %v", err)
	}

	policy := &config.Policy{
		Armed:            false,
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}

	enf := &fakeAllowSyncEnforcer{}
	d, err := New(Config{Policy: policy, Store: db, Enforcer: enf, SocketPath: ""})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.reloadAllowlist(ctx); err != nil {
		t.Fatalf("reloadAllowlist: %v", err)
	}
	if err := d.syncEnforcerAllowlist(ctx); err != nil {
		t.Fatalf("syncEnforcerAllowlist: %v", err)
	}
	calls := enf.SyncCalls()
	if len(calls) != 1 || len(calls[0]) != 1 || calls[0][0] != runtimePfx {
		t.Errorf("SyncAllowlist got %v, want [%v]", calls, runtimePfx)
	}
}

// TestStaticAllowlistFromPolicy_UnitTable exercises the parser in isolation:
// bare IPs widen to host prefix, CIDRs pass through, invalid strings are
// dropped silently (Validate rejects them at config load, so this is
// defence-in-depth only).
func TestStaticAllowlistFromPolicy_UnitTable(t *testing.T) {
	tests := []struct {
		name     string
		policy   *config.Policy
		wantStrs []string
	}{
		{
			name:     "nil policy",
			policy:   nil,
			wantStrs: nil,
		},
		{
			name:     "empty",
			policy:   &config.Policy{},
			wantStrs: nil,
		},
		{
			name: "bare ipv4 widens to /32",
			policy: &config.Policy{
				Allowlist: []string{"127.0.0.1"},
			},
			wantStrs: []string{"127.0.0.1/32"},
		},
		{
			name: "bare ipv6 widens to /128",
			policy: &config.Policy{
				Allowlist: []string{"::1"},
			},
			wantStrs: []string{"::1/128"},
		},
		{
			name: "cidr passes through",
			policy: &config.Policy{
				Allowlist:  []string{"10.0.0.0/8"},
				AdminCIDRs: []string{"192.0.2.0/24"},
			},
			wantStrs: []string{"10.0.0.0/8", "192.0.2.0/24"},
		},
		{
			name: "invalid strings silently dropped (defence in depth)",
			policy: &config.Policy{
				Allowlist:  []string{"not-an-ip"},
				AdminCIDRs: []string{"also-not-a-cidr"},
			},
			wantStrs: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := staticAllowlistFromPolicy(tc.policy)
			gotStrs := make([]string, len(got))
			for i, p := range got {
				gotStrs[i] = p.String()
			}
			if len(gotStrs) != len(tc.wantStrs) {
				t.Fatalf("got %v, want %v", gotStrs, tc.wantStrs)
			}
			for i := range gotStrs {
				if gotStrs[i] != tc.wantStrs[i] {
					t.Errorf("prefix[%d] = %q, want %q", i, gotStrs[i], tc.wantStrs[i])
				}
			}
		})
	}
}

// TestUnionPrefixes_DeduplicatesAndPreservesOrder is a table-driven unit test
// for the set-union helper. netip.Prefix is comparable, but the caller may
// pass mixed static+runtime slices with overlaps (e.g. admin_cidrs contains
// an IP an operator later `ezyshield allow`ed at runtime).
func TestUnionPrefixes_DeduplicatesAndPreservesOrder(t *testing.T) {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	tests := []struct {
		name       string
		a, b, want []netip.Prefix
	}{
		{
			name: "both empty",
		},
		{
			name: "no overlap",
			a:    []netip.Prefix{p("10.0.0.0/8")},
			b:    []netip.Prefix{p("192.0.2.0/24")},
			want: []netip.Prefix{p("10.0.0.0/8"), p("192.0.2.0/24")},
		},
		{
			name: "overlap dedup",
			a:    []netip.Prefix{p("10.0.0.0/8"), p("192.0.2.0/24")},
			b:    []netip.Prefix{p("192.0.2.0/24"), p("203.0.113.7/32")},
			want: []netip.Prefix{p("10.0.0.0/8"), p("192.0.2.0/24"), p("203.0.113.7/32")},
		},
		{
			name: "duplicate within a",
			a:    []netip.Prefix{p("10.0.0.0/8"), p("10.0.0.0/8")},
			b:    nil,
			want: []netip.Prefix{p("10.0.0.0/8")},
		},
		{
			name: "static first, runtime second (order preserved)",
			a:    []netip.Prefix{p("127.0.0.1/32")},
			b:    []netip.Prefix{p("198.51.100.0/24")},
			want: []netip.Prefix{p("127.0.0.1/32"), p("198.51.100.0/24")},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unionPrefixes(tc.a, tc.b)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("prefix[%d] = %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

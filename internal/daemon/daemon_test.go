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

package decision_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// mockStore is a thread-safe test double for decision.Store.
type mockStore struct {
	mu      sync.Mutex
	strikes map[string]int
	banned  []sdk.Action // calls to RecordStrike
	audited []sdk.Action // calls to Audit
}

func newMock(initial map[string]int) *mockStore {
	s := &mockStore{strikes: make(map[string]int)}
	for k, v := range initial {
		s.strikes[k] = v
	}
	return s
}

func (m *mockStore) GetStrikeCount(_ context.Context, ip netip.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.strikes[ip.String()], nil
}

func (m *mockStore) RecordStrike(_ context.Context, a sdk.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strikes[a.IP.String()]++
	m.banned = append(m.banned, a)
	return nil
}

func (m *mockStore) Audit(_ context.Context, a sdk.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.audited = append(m.audited, a)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

var (
	ip1 = netip.MustParseAddr("203.0.113.1") // TEST-NET-3, safe for tests
	ip2 = netip.MustParseAddr("203.0.113.2")
	ip3 = netip.MustParseAddr("203.0.113.3")
)

func mkVerdict(ip netip.Addr, score int, category string) sdk.Verdict {
	return sdk.Verdict{
		IP:       ip,
		Score:    score,
		Category: category,
		Source:   "rules",
		Reason:   category + " detected",
	}
}

// armedPolicy returns a policy with Armed=true and standard defaults.
func armedPolicy() *config.Policy {
	return &config.Policy{
		Armed:            true,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: 30,
		Strikes:          config.DefaultStrikes,
	}
}

// mustEngine creates an Engine and fails t on error.
func mustEngine(t *testing.T, pol *config.Policy, st decision.Store) *decision.Engine {
	t.Helper()
	e, err := decision.New(pol, st)
	if err != nil {
		t.Fatalf("decision.New: %v", err)
	}
	return e
}

// ── main table-driven test ────────────────────────────────────────────────────

func TestDecide(t *testing.T) {
	perm := time.Duration(0) // permanent ban sentinel (TTL=0)

	cases := []struct {
		name       string
		policy     *config.Policy
		existing   int // pre-existing strike count for ip1
		verdicts   []sdk.Verdict
		sshEnv     string // value to set in SSH_CLIENT before calling New+Decide
		wantOp     string
		wantStrike int // checked when > 0
		checkTTL   bool
		wantTTL    time.Duration
		wantErr    bool
	}{
		// ── score bands ──────────────────────────────────────────────────────
		{
			name:     "score below observe threshold → record",
			policy:   armedPolicy(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 20, "benign")},
			wantOp:   "record",
		},
		{
			name:     "score at observe threshold → notify_only",
			policy:   armedPolicy(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 40, "scanner")},
			wantOp:   "notify_only",
		},
		{
			name:     "score mid observe band → notify_only",
			policy:   armedPolicy(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 55, "scanner")},
			wantOp:   "notify_only",
		},
		{
			name:     "score just below ban threshold → notify_only",
			policy:   armedPolicy(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 69, "scanner")},
			wantOp:   "notify_only",
		},
		// ── strike escalation ────────────────────────────────────────────────
		{
			name:       "strike 1: ban with 5m TTL",
			policy:     armedPolicy(),
			existing:   0,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 1,
			checkTTL:   true,
			wantTTL:    5 * time.Minute,
		},
		{
			name:       "strike 2: ban with 1h TTL",
			policy:     armedPolicy(),
			existing:   1,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 2,
			checkTTL:   true,
			wantTTL:    time.Hour,
		},
		{
			name:       "strike 3: ban with 24h TTL",
			policy:     armedPolicy(),
			existing:   2,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 3,
			checkTTL:   true,
			wantTTL:    24 * time.Hour,
		},
		{
			name:       "strike 4: ban with 7d TTL",
			policy:     armedPolicy(),
			existing:   3,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 4,
			checkTTL:   true,
			wantTTL:    168 * time.Hour,
		},
		{
			name:       "strike 5: permanent ban (TTL=0)",
			policy:     armedPolicy(),
			existing:   4,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 5,
			checkTTL:   true,
			wantTTL:    perm,
		},
		{
			name:       "strike beyond table: clamped to permanent",
			policy:     armedPolicy(),
			existing:   99,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "ban",
			wantStrike: 100,
			checkTTL:   true,
			wantTTL:    perm,
		},
		// ── allowlist ────────────────────────────────────────────────────────
		{
			name: "allowlisted single IP → record",
			policy: func() *config.Policy {
				p := armedPolicy()
				p.Allowlist = []string{ip1.String()}
				return p
			}(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")},
			wantOp:   "record",
		},
		{
			name: "allowlisted via CIDR → record",
			policy: func() *config.Policy {
				p := armedPolicy()
				p.Allowlist = []string{"203.0.113.0/24"}
				return p
			}(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")},
			wantOp:   "record",
		},
		{
			name: "allowlisted via AdminCIDR → record",
			policy: func() *config.Policy {
				p := armedPolicy()
				p.AdminCIDRs = []string{"203.0.113.0/24"}
				return p
			}(),
			verdicts: []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")},
			wantOp:   "record",
		},
		// ── anti-lockout ─────────────────────────────────────────────────────
		{
			name:     "anti-lockout: SSH peer added to static allowlist at startup",
			policy:   armedPolicy(),
			sshEnv:   ip1.String() + " 54321 22",
			verdicts: []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")},
			wantOp:   "record",
		},
		// ── dry-run ──────────────────────────────────────────────────────────
		{
			name: "dry-run: Op=dry_ban, no RecordStrike",
			policy: func() *config.Policy {
				p := armedPolicy()
				p.Armed = false
				return p
			}(),
			existing:   0,
			verdicts:   []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")},
			wantOp:     "dry_ban",
			wantStrike: 1,
			checkTTL:   true,
			wantTTL:    5 * time.Minute,
		},
		// ── multi-verdict handling ────────────────────────────────────────────
		{
			name:     "highest score wins among multiple verdicts",
			policy:   armedPolicy(),
			existing: 0,
			verdicts: []sdk.Verdict{
				mkVerdict(ip1, 50, "scanner"),
				mkVerdict(ip1, 90, "bruteforce"),
				mkVerdict(ip1, 70, "scraper"),
			},
			wantOp:     "ban",
			wantStrike: 1,
			checkTTL:   true,
			wantTTL:    5 * time.Minute,
		},
		// ── error cases ───────────────────────────────────────────────────────
		{
			name:     "empty verdicts → error",
			policy:   armedPolicy(),
			verdicts: nil,
			wantErr:  true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sshEnv != "" {
				t.Setenv("SSH_CLIENT", tc.sshEnv)
			}

			st := newMock(map[string]int{ip1.String(): tc.existing})
			engine := mustEngine(t, tc.policy, st)

			act, err := engine.Decide(context.Background(), tc.verdicts)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}

			if act.Op != tc.wantOp {
				t.Errorf("Op = %q, want %q", act.Op, tc.wantOp)
			}
			if tc.wantStrike > 0 && act.Strike != tc.wantStrike {
				t.Errorf("Strike = %d, want %d", act.Strike, tc.wantStrike)
			}
			if tc.checkTTL && act.TTL != tc.wantTTL {
				t.Errorf("TTL = %v, want %v", act.TTL, tc.wantTTL)
			}
			if len(tc.verdicts) > 0 && len(act.Verdicts) != len(tc.verdicts) {
				t.Errorf("Verdicts len = %d, want %d", len(act.Verdicts), len(tc.verdicts))
			}

			// Dry-run MUST NOT call RecordStrike.
			if tc.wantOp == "dry_ban" && len(st.banned) > 0 {
				t.Errorf("dry_ban called RecordStrike %d time(s); must be 0", len(st.banned))
			}
			// Real bans MUST call RecordStrike.
			if tc.wantOp == "ban" && len(st.banned) == 0 {
				t.Error("ban must call RecordStrike")
			}
		})
	}
}

// TestDecide_RateLimitExceeded verifies the global ban-rate cap.
func TestDecide_RateLimitExceeded(t *testing.T) {
	pol := armedPolicy()
	pol.MaxBansPerMinute = 2
	st := newMock(nil)
	engine := mustEngine(t, pol, st)

	makeV := func(ip netip.Addr) []sdk.Verdict {
		return []sdk.Verdict{mkVerdict(ip, 85, "bruteforce")}
	}

	// First two bans must succeed.
	for i, ip := range []netip.Addr{ip1, ip2} {
		if _, err := engine.Decide(context.Background(), makeV(ip)); err != nil {
			t.Fatalf("ban %d failed unexpectedly: %v", i+1, err)
		}
	}

	// Third ban must hit the rate limit.
	_, err := engine.Decide(context.Background(), makeV(ip3))
	if !errors.Is(err, decision.ErrRateLimited) {
		t.Errorf("expected ErrRateLimited, got %v", err)
	}

	// Only the first two bans should be stored.
	if len(st.banned) != 2 {
		t.Errorf("stored %d bans, want 2", len(st.banned))
	}
}

// TestDecide_AntiLockout_DynamicCheck verifies the SSH peer is re-derived in
// every Decide call, not only at startup — ensuring sessions started after the
// daemon is already running are still protected.
func TestDecide_AntiLockout_DynamicCheck(t *testing.T) {
	// Engine created with SSH_CLIENT unset → ip1 is not in the static allowlist.
	engine := mustEngine(t, armedPolicy(), newMock(nil))

	// Set SSH_CLIENT after New() to simulate a new SSH session.
	t.Setenv("SSH_CLIENT", ip1.String()+" 12345 22")

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 90, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" {
		t.Errorf("Op = %q, want record (anti-lockout for dynamic SSH peer)", act.Op)
	}
}

// TestDecide_AllowlistBeatsHighScore verifies the invariant that an allowlisted
// IP can never be banned regardless of score.
func TestDecide_AllowlistBeatsHighScore(t *testing.T) {
	pol := armedPolicy()
	pol.Allowlist = []string{ip1.String()}
	st := newMock(nil)
	engine := mustEngine(t, pol, st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 100, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "record" {
		t.Errorf("allowlisted IP got Op=%q, want record", act.Op)
	}
	if len(st.banned) > 0 {
		t.Errorf("RecordStrike was called %d time(s) for allowlisted IP", len(st.banned))
	}
}

// TestNew_InvalidAllowlist verifies that malformed allowlist entries are rejected.
func TestNew_InvalidAllowlist(t *testing.T) {
	pol := armedPolicy()
	pol.Allowlist = []string{"not-an-ip-or-cidr"}
	_, err := decision.New(pol, newMock(nil))
	if err == nil {
		t.Fatal("expected error for invalid allowlist entry, got nil")
	}
}

// TestDecide_DryRunEscalation verifies strike escalation is computed correctly
// in dry-run mode even though nothing is written to the store.
func TestDecide_DryRunEscalation(t *testing.T) {
	pol := armedPolicy()
	pol.Armed = false

	for i, want := range []struct {
		existing int
		ttl      time.Duration
	}{
		{0, 5 * time.Minute},
		{1, time.Hour},
		{2, 24 * time.Hour},
		{3, 168 * time.Hour},
		{4, 0}, // permanent
	} {
		t.Run("dry_ban_strike_"+string(rune('1'+i)), func(t *testing.T) {
			st := newMock(map[string]int{ip1.String(): want.existing})
			engine := mustEngine(t, pol, st)

			act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Op != "dry_ban" {
				t.Errorf("Op = %q, want dry_ban", act.Op)
			}
			if act.TTL != want.ttl {
				t.Errorf("TTL = %v, want %v", act.TTL, want.ttl)
			}
			if act.Strike != want.existing+1 {
				t.Errorf("Strike = %d, want %d", act.Strike, want.existing+1)
			}
			// Must not persist anything.
			if len(st.banned) > 0 {
				t.Error("dry_ban must not call RecordStrike")
			}
		})
	}
}

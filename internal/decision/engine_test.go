package decision_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// lastStrikeRow mirrors what store.LastStrike reads from the strikes table.
type lastStrikeRow struct {
	recordedAt time.Time
	ttl        time.Duration
}

// mockStore is a thread-safe test double for decision.Store. It mirrors the
// real store's semantics: ban presence = row in banBannedAt; suppression
// counters are per-ban (reset by RecordStrike, removed with the ban row);
// hadIneff is the permanent offenders.had_ineffective mirror.
type mockStore struct {
	mu                  sync.Mutex
	strikes             map[string]int
	banBannedAt         map[string]time.Time // ip → active ban start (presence = banned)
	banStrike           map[string]int       // ip → strike_num of active ban
	banDry              map[string]bool      // ip → dry_run flag of active ban
	supTotal            map[string]int       // ip → suppressed_total
	supAfter            map[string]int       // ip → suppressed_after_grace
	supFired            map[string]bool      // ip → ineffective_fired
	hadIneff            map[string]bool      // ip → offenders.had_ineffective
	lastStrike          map[string]lastStrikeRow
	lastStrikeErr       error        // forced error for LastStrike
	recordSuppressedErr error        // forced error for RecordSuppressed
	lastSeenBumps       []string     // IPs whose last_seen was bumped
	banned              []sdk.Action // calls to RecordStrike
	audited             []sdk.Action // calls to Audit
}

func newMock(initial map[string]int) *mockStore {
	s := &mockStore{
		strikes:     make(map[string]int),
		banBannedAt: make(map[string]time.Time),
		banStrike:   make(map[string]int),
		banDry:      make(map[string]bool),
		supTotal:    make(map[string]int),
		supAfter:    make(map[string]int),
		supFired:    make(map[string]bool),
		hadIneff:    make(map[string]bool),
		lastStrike:  make(map[string]lastStrikeRow),
	}
	for k, v := range initial {
		s.strikes[k] = v
	}
	return s
}

// setBanned marks ip as having (true) or not having (false) an active ban
// starting now at strike 1. Removing the ban also removes the per-ban
// suppression counters, mirroring row deletion by ExpireBans.
func (m *mockStore) setBanned(ip netip.Addr, active bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ip.String()
	if active {
		m.banBannedAt[k] = time.Now()
		m.banStrike[k] = 1
		m.banDry[k] = false
		return
	}
	delete(m.banBannedAt, k)
	delete(m.banStrike, k)
	delete(m.banDry, k)
	delete(m.supTotal, k)
	delete(m.supAfter, k)
	delete(m.supFired, k)
}

// setSimulatedBan seeds an active dry-run ban row (dry_run=1) for ip at the
// given strike, as if RecordStrike ran with Op="dry_ban" (ADR-0009 §5).
func (m *mockStore) setSimulatedBan(ip netip.Addr, strike int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ip.String()
	m.banBannedAt[k] = time.Now()
	m.banStrike[k] = strike
	m.banDry[k] = true
}

func (m *mockStore) GetBanInfo(_ context.Context, ip netip.Addr) (time.Time, int, bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ip.String()
	bannedAt, ok := m.banBannedAt[k]
	if !ok {
		return time.Time{}, 0, false, false, nil
	}
	return bannedAt, m.banStrike[k], m.banDry[k], true, nil
}

func (m *mockStore) RecordSuppressed(_ context.Context, ip netip.Addr, afterGrace bool) (int, int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.recordSuppressedErr != nil {
		return 0, 0, false, m.recordSuppressedErr
	}
	k := ip.String()
	if _, ok := m.banBannedAt[k]; !ok {
		return 0, 0, false, nil // no active ban row (expiry race)
	}
	m.supTotal[k]++
	if afterGrace {
		m.supAfter[k]++
	}
	return m.supTotal[k], m.supAfter[k], m.supFired[k], nil
}

func (m *mockStore) MarkBanIneffective(_ context.Context, ip netip.Addr) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := ip.String()
	if _, ok := m.banBannedAt[k]; !ok {
		return false, nil
	}
	if m.supFired[k] {
		return false, nil
	}
	m.supFired[k] = true
	m.hadIneff[k] = true
	return true, nil
}

func (m *mockStore) HadIneffectiveBan(_ context.Context, ip netip.Addr) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hadIneff[ip.String()], nil
}

func (m *mockStore) BumpLastSeen(_ context.Context, ip netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastSeenBumps = append(m.lastSeenBumps, ip.String())
	return nil
}

func (m *mockStore) GetStrikeCount(_ context.Context, ip netip.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.strikes[ip.String()], nil
}

func (m *mockStore) LastStrike(_ context.Context, ip netip.Addr) (time.Time, time.Duration, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastStrikeErr != nil {
		return time.Time{}, 0, false, m.lastStrikeErr
	}
	row, ok := m.lastStrike[ip.String()]
	if !ok {
		return time.Time{}, 0, false, nil
	}
	return row.recordedAt, row.ttl, true, nil
}

// setLastStrike seeds the most recent strike row for ip, as if a prior ban
// was recorded at recordedAt with the given TTL.
func (m *mockStore) setLastStrike(ip netip.Addr, recordedAt time.Time, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastStrike[ip.String()] = lastStrikeRow{recordedAt: recordedAt, ttl: ttl}
}

func (m *mockStore) RecordStrike(_ context.Context, a sdk.Action) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := a.IP.String()
	m.strikes[k]++
	// Mirror the real store's bans_active upsert: new ban resets counters;
	// dry_run mirrors the Op (ADR-0009 §5).
	m.banBannedAt[k] = time.Now()
	m.banStrike[k] = a.Strike
	m.banDry[k] = a.Op == "dry_ban"
	m.supTotal[k] = 0
	m.supAfter[k] = 0
	m.supFired[k] = false
	m.lastStrike[k] = lastStrikeRow{recordedAt: time.Now(), ttl: a.TTL}
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
	// Mirrors applyDefaults' floors so tests exercise production-reachable
	// config states.
	return &config.Policy{
		Armed:                   true,
		BanThreshold:            70,
		ObserveThreshold:        40,
		MaxBansPerMinute:        30,
		Strikes:                 config.DefaultStrikes,
		BanIneffectiveGrace:     config.Duration(config.DefaultBanIneffectiveGrace),
		BanIneffectiveMinEvents: config.DefaultBanIneffectiveMinEvents,
		EscalationExemptWindow:  config.Duration(config.DefaultEscalationExemptWindow),
	}
}

// captureLogs redirects slog's default logger to a buffer for the duration of
// the test, so tests can assert diagnostics were (or were not) emitted.
// Tests using it must not call t.Parallel().
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
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

			// Dry-run records its strike too (ADR-0009 §5), but the recorded
			// action MUST carry Op="dry_ban" so every enforcement path skips
			// it — an Op="ban" write from a dry-run engine would be enforced.
			if tc.wantOp == "dry_ban" {
				if len(st.banned) != 1 {
					t.Errorf("dry_ban called RecordStrike %d time(s); must be 1 (ADR-0009 §5)", len(st.banned))
				} else if st.banned[0].Op != "dry_ban" {
					t.Errorf("dry_ban recorded Op=%q; a dry-run write must never look enforceable", st.banned[0].Op)
				}
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

// ── Active-ban guard tests (issue #28, acceptance criteria a–f) ──────────────

// TestActiveBanGuard_FreshIP_Strike1 (a) verifies that a fresh, never-seen IP
// that crosses ban_threshold receives strike #1 with a 5-minute TTL.
func TestActiveBanGuard_FreshIP_Strike1(t *testing.T) {
	st := newMock(nil) // no pre-existing strikes, no active ban
	engine := mustEngine(t, armedPolicy(), st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "ban" {
		t.Errorf("Op = %q, want ban", act.Op)
	}
	if act.Strike != 1 {
		t.Errorf("Strike = %d, want 1", act.Strike)
	}
	if act.TTL != 5*time.Minute {
		t.Errorf("TTL = %v, want 5m", act.TTL)
	}
	if len(st.banned) != 1 {
		t.Errorf("RecordStrike called %d time(s), want 1", len(st.banned))
	}
}

// TestActiveBanGuard_RehitWhileBanned (b) verifies that re-hitting an already
// active-banned IP suppresses the strike, does not call RecordStrike or Audit,
// and only bumps offenders.last_seen.
func TestActiveBanGuard_RehitWhileBanned(t *testing.T) {
	st := newMock(map[string]int{ip1.String(): 1})
	st.setBanned(ip1, true) // 5-minute ban already active
	engine := mustEngine(t, armedPolicy(), st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "already_banned" {
		t.Errorf("Op = %q, want already_banned", act.Op)
	}
	// No new strike row.
	if len(st.banned) != 0 {
		t.Errorf("RecordStrike called %d time(s), want 0 (suppressed)", len(st.banned))
	}
	// No audit entry (Audit is only called for allowlist/anti-lockout/score-band paths).
	if len(st.audited) != 0 {
		t.Errorf("Audit called %d time(s), want 0 (suppressed)", len(st.audited))
	}
	// last_seen must have been bumped.
	if len(st.lastSeenBumps) != 1 || st.lastSeenBumps[0] != ip1.String() {
		t.Errorf("lastSeenBumps = %v, want [%s]", st.lastSeenBumps, ip1)
	}
}

// TestActiveBanGuard_BanExpiredThenStrike2 (c) verifies that once the 5-minute
// ban expires (simulated by removing the active ban entry), the next hit records
// strike #2 with a 1-hour TTL.
func TestActiveBanGuard_BanExpiredThenStrike2(t *testing.T) {
	// After expiry: 1 strike in DB, no active ban.
	st := newMock(map[string]int{ip1.String(): 1})
	// No setBanned call → HasActiveBan returns false.
	engine := mustEngine(t, armedPolicy(), st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "ban" {
		t.Errorf("Op = %q, want ban", act.Op)
	}
	if act.Strike != 2 {
		t.Errorf("Strike = %d, want 2", act.Strike)
	}
	if act.TTL != time.Hour {
		t.Errorf("TTL = %v, want 1h", act.TTL)
	}
	if len(st.banned) != 1 {
		t.Errorf("RecordStrike called %d time(s), want 1", len(st.banned))
	}
}

// TestActiveBanGuard_PermanentBanSuppressedForever (d) verifies that an IP
// holding a permanent ban (strike #5, TTL=0) is suppressed on every subsequent
// verdict, forever.
func TestActiveBanGuard_PermanentBanSuppressedForever(t *testing.T) {
	st := newMock(map[string]int{ip1.String(): 5})
	st.setBanned(ip1, true) // permanent — expires_at NULL
	engine := mustEngine(t, armedPolicy(), st)

	for i := range 3 {
		act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 100, "bruteforce")})
		if err != nil {
			t.Fatalf("Decide call %d: %v", i+1, err)
		}
		if act.Op != "already_banned" {
			t.Errorf("call %d: Op = %q, want already_banned", i+1, act.Op)
		}
	}
	if len(st.banned) != 0 {
		t.Errorf("RecordStrike called %d time(s), want 0", len(st.banned))
	}
	if len(st.lastSeenBumps) != 3 {
		t.Errorf("lastSeenBumps = %d, want 3", len(st.lastSeenBumps))
	}
}

// TestActiveBanGuard_StartupReplay (e) verifies that an IP that was permanent
// in the DB before a daemon restart is still suppressed after the engine is
// re-created — because the guard reads bans_active, not in-memory state.
func TestActiveBanGuard_StartupReplay(t *testing.T) {
	// Simulate restart: re-create the store and engine from scratch.
	st := newMock(map[string]int{ip1.String(): 5})
	st.setBanned(ip1, true) // permanent row survived restart (it's in bans_active)

	// New engine — no in-memory state carried over.
	engine := mustEngine(t, armedPolicy(), st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 100, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "already_banned" {
		t.Errorf("Op = %q, want already_banned (startup replay must read bans_active)", act.Op)
	}
	if len(st.banned) != 0 {
		t.Errorf("RecordStrike called despite permanent ban in bans_active")
	}
}

// TestActiveBanGuard_TwoConcurrentIPs_NoContamination (f) verifies that
// concurrent verdicts for two different IPs do not cross-contaminate the
// bansInWin rate-limit counter or the active-ban suppression logic.
func TestActiveBanGuard_TwoConcurrentIPs_NoContamination(t *testing.T) {
	st := newMock(nil)
	st.setBanned(ip1, true) // ip1 already banned
	// ip2 is fresh (no ban, no strikes)
	engine := mustEngine(t, armedPolicy(), st)

	// Process both IPs concurrently.
	var wg sync.WaitGroup
	results := make([]sdk.Action, 2)
	errs := make([]error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0], errs[0] = engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	}()
	go func() {
		defer wg.Done()
		results[1], errs[1] = engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip2, 85, "bruteforce")})
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Decide[%d]: %v", i, err)
		}
	}

	// ip1 must be suppressed.
	if results[0].Op != "already_banned" {
		t.Errorf("ip1: Op = %q, want already_banned", results[0].Op)
	}
	// ip2 must get strike #1.
	if results[1].Op != "ban" {
		t.Errorf("ip2: Op = %q, want ban", results[1].Op)
	}
	if results[1].Strike != 1 {
		t.Errorf("ip2: Strike = %d, want 1", results[1].Strike)
	}
	// Only ip2 should have called RecordStrike.
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.banned) != 1 || st.banned[0].IP != ip2 {
		t.Errorf("RecordStrike calls = %v, want exactly ip2", st.banned)
	}
}

// TestActiveBanGuard_DryRunSuppressesLikeArmed verifies that the active-ban
// guard IS applied in dry-run mode (ADR-0009 §5, issue #145): an active ban
// — here a real one left over from an armed period — suppresses further
// sentencing exactly as it would while armed, instead of stacking dry
// strikes inside one episode. (Pre-#145 semantics skipped the guard because
// dry-run wrote nothing; both halves changed together.)
func TestActiveBanGuard_DryRunSuppressesLikeArmed(t *testing.T) {
	pol := armedPolicy()
	pol.Armed = false

	st := newMock(map[string]int{ip1.String(): 1})
	st.setBanned(ip1, true)
	engine := mustEngine(t, pol, st)

	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "already_banned" {
		t.Errorf("dry-run Op = %q, want already_banned — the guard must mirror armed", act.Op)
	}
	// Suppression path: no new strike, but last_seen is bumped (same as armed).
	if len(st.banned) > 0 {
		t.Errorf("suppression: RecordStrike called %d time(s)", len(st.banned))
	}
	if len(st.lastSeenBumps) != 1 {
		t.Errorf("suppression: BumpLastSeen called %d time(s), want 1", len(st.lastSeenBumps))
	}
}

// TestDecide_DryRunEscalation verifies strike escalation is computed — and
// recorded (ADR-0009 §5) — correctly in dry-run mode, rung for rung.
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
			// The prior ban (that produced the existing strikes) has expired;
			// keep it recent so escalations stay rate-limit-exempt like armed.
			if want.existing > 0 {
				st.setLastStrike(ip1, time.Now().Add(-time.Minute), time.Second)
			}
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
			// The dry strike and simulated ban ARE persisted (ADR-0009 §5).
			if len(st.banned) != 1 {
				t.Fatalf("RecordStrike calls = %d, want 1 — dry_ban records its strike", len(st.banned))
			}
			if st.banned[0].Op != "dry_ban" {
				t.Errorf("recorded Op = %q, want dry_ban", st.banned[0].Op)
			}
		})
	}
}

// ── ban_ineffective tests (ADR-0009) ──────────────────────────────────────────

const (
	diagMsg     = "ban_ineffective — traffic flowing despite active ban"
	prePermMsg  = "ban_ineffective_permanent"
	suppressMsg = "already_banned"
)

// setBannedWithTime marks ip as having an active ban that started at bannedAt.
func (m *mockStore) setBannedWithTime(ip netip.Addr, bannedAt time.Time, strike int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.banBannedAt[ip.String()] = bannedAt
	m.banStrike[ip.String()] = strike
}

// suppressN sends n verdicts for a banned ip and asserts each is suppressed.
func suppressN(t *testing.T, engine *decision.Engine, ip netip.Addr, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip, 85, "bruteforce")})
		if err != nil {
			t.Fatalf("Decide[%d]: %v", i, err)
		}
		if act.Op != suppressMsg {
			t.Errorf("Decide[%d]: Op = %q, want %s", i, act.Op, suppressMsg)
		}
	}
}

// TestBanIneffective_GracePeriod verifies that events during the grace period
// are counted but never trigger the diagnostic.
func TestBanIneffective_GracePeriod(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	// Ban started 30 seconds ago — still inside the 90s grace period.
	st.setBannedWithTime(ip1, time.Now().Add(-30*time.Second), 1)
	engine := mustEngine(t, armedPolicy(), st)

	suppressN(t, engine, ip1, 5)

	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Errorf("ban_ineffective emitted %d time(s) during grace, want 0", got)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.supTotal[ip1.String()] != 5 {
		t.Errorf("suppressed_total = %d, want 5", st.supTotal[ip1.String()])
	}
	if st.supAfter[ip1.String()] != 0 {
		t.Errorf("suppressed_after_grace = %d, want 0 (all events in grace)", st.supAfter[ip1.String()])
	}
	if st.supFired[ip1.String()] {
		t.Error("ineffective_fired set during grace period")
	}
}

// TestBanIneffective_Threshold verifies the diagnostic fires exactly when the
// MinEvents-th event arrives after the grace period, and not before.
func TestBanIneffective_Threshold(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	// Ban started 10 minutes ago — past the 90s grace.
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 1)
	engine := mustEngine(t, armedPolicy(), st) // MinEvents = 3

	suppressN(t, engine, ip1, 2)
	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Errorf("ban_ineffective emitted %d time(s) below threshold, want 0", got)
	}

	suppressN(t, engine, ip1, 1) // 3rd event: threshold reached
	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Errorf("ban_ineffective emitted %d time(s) at threshold, want exactly 1", got)
	}
	// The WARN carries ladder context (strike 1 of 5 default rungs).
	if !strings.Contains(buf.String(), "strike=1/5") {
		t.Errorf("ban_ineffective WARN missing ladder context; log:\n%s", buf.String())
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.supFired[ip1.String()] {
		t.Error("ineffective_fired not persisted to ban row")
	}
	if !st.hadIneff[ip1.String()] {
		t.Error("offenders.had_ineffective not persisted")
	}
}

// TestBanIneffective_FiresOncePerBan verifies the diagnostic fires exactly
// once per ban no matter how many events follow.
func TestBanIneffective_FiresOncePerBan(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 1)
	engine := mustEngine(t, armedPolicy(), st)

	suppressN(t, engine, ip1, 10)

	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Errorf("ban_ineffective emitted %d time(s) over 10 events, want exactly 1", got)
	}
}

// TestBanIneffective_ResetsOnNewBan verifies the counters are per-ban: after
// the diagnostic fires, a new ban (next episode) starts fresh and the
// diagnostic can fire again for the new ban.
func TestBanIneffective_ResetsOnNewBan(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(map[string]int{ip1.String(): 1})
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 1)
	engine := mustEngine(t, armedPolicy(), st)

	// Ban #1: fire the diagnostic.
	suppressN(t, engine, ip1, 3)
	if got := strings.Count(buf.String(), diagMsg); got != 1 {
		t.Fatalf("ban #1: diagnostic fired %d time(s), want 1", got)
	}

	// Ban #1 expires; the re-offense escalates to strike #2 (new ban).
	st.setBanned(ip1, false)
	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("re-offense: %v", err)
	}
	if act.Op != "ban" || act.Strike != 2 {
		t.Fatalf("re-offense Op/Strike = %q/%d, want ban/2", act.Op, act.Strike)
	}

	// New ban starts fresh: counters were reset by RecordStrike's upsert.
	st.mu.Lock()
	if st.supTotal[ip1.String()] != 0 || st.supFired[ip1.String()] {
		t.Errorf("new ban inherited counters: total=%d fired=%v",
			st.supTotal[ip1.String()], st.supFired[ip1.String()])
	}
	st.mu.Unlock()

	// Age the new ban past grace; the diagnostic fires again for ban #2.
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 2)
	suppressN(t, engine, ip1, 3)
	if got := strings.Count(buf.String(), diagMsg); got != 2 {
		t.Errorf("after ban #2: diagnostic fired %d time(s) total, want 2 (once per ban)", got)
	}
}

// TestBanIneffective_StoreErrorNonFatal verifies a store failure in the
// diagnostic path never breaks the suppression path.
func TestBanIneffective_StoreErrorNonFatal(t *testing.T) {
	buf := captureLogs(t)
	st := newMock(nil)
	st.setBannedWithTime(ip1, time.Now().Add(-10*time.Minute), 1)
	st.recordSuppressedErr = errors.New("db locked")
	engine := mustEngine(t, armedPolicy(), st)

	suppressN(t, engine, ip1, 5) // still suppressed despite the store error

	if got := strings.Count(buf.String(), diagMsg); got != 0 {
		t.Errorf("diagnostic fired %d time(s) despite store errors, want 0", got)
	}
}

// TestBanIneffective_PrePermanentAlert verifies the louder warning fires when
// promoting to permanent an IP that had an ineffective ban — and stays silent
// for IPs that never had one.
func TestBanIneffective_PrePermanentAlert(t *testing.T) {
	cases := []struct {
		name     string
		hadIneff bool
		want     int
	}{
		{"had ineffective ban → alert", true, 1},
		{"clean history → no alert", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLogs(t)
			// 4 strikes in DB → next strike is #5, permanent in the default ladder.
			st := newMock(map[string]int{ip1.String(): 4})
			st.hadIneff[ip1.String()] = tc.hadIneff
			engine := mustEngine(t, armedPolicy(), st)

			act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip1, 85, "bruteforce")})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Strike != 5 || act.TTL != 0 {
				t.Fatalf("Strike/TTL = %d/%v, want 5/permanent", act.Strike, act.TTL)
			}
			if got := strings.Count(buf.String(), prePermMsg); got != tc.want {
				t.Errorf("pre-permanent alert emitted %d time(s), want %d", got, tc.want)
			}
		})
	}
}

// TestEscalation_RateLimitExemption verifies the recency-bounded exemption
// from max_bans_per_minute (ADR-0009 §3, amended): an escalation skips the
// cap only when the previous ban ended within escalation_exempt_window.
// Every uncertain case (stale history, no history, permanent last strike,
// store error) fails safe and counts against the cap.
func TestEscalation_RateLimitExemption(t *testing.T) {
	window := 24 * time.Hour

	tests := []struct {
		name     string
		seed     func(m *mockStore) // strike history for ip2
		wantErr  error              // expected error from the escalation Decide
		wantOp   string             // expected Op when wantErr == nil
		wantStrk int
	}{
		{
			name: "recent expiry → exempt",
			seed: func(m *mockStore) {
				// 1h ban recorded 90m ago: ended 30m ago, well inside the window.
				m.setLastStrike(ip2, time.Now().Add(-90*time.Minute), time.Hour)
			},
			wantOp:   "ban",
			wantStrk: 2,
		},
		{
			name: "ban end still in the future (early manual unban) → exempt",
			seed: func(m *mockStore) {
				// 24h ban recorded 1h ago: scheduled end is ahead of now.
				m.setLastStrike(ip2, time.Now().Add(-time.Hour), 24*time.Hour)
			},
			wantOp:   "ban",
			wantStrk: 2,
		},
		{
			name: "stale history → rate limited",
			seed: func(m *mockStore) {
				// 1h ban recorded 30 days ago: ended far outside the window.
				m.setLastStrike(ip2, time.Now().Add(-30*24*time.Hour), time.Hour)
			},
			wantErr: decision.ErrRateLimited,
		},
		{
			name:    "strike count without history row → rate limited",
			seed:    func(_ *mockStore) {},
			wantErr: decision.ErrRateLimited,
		},
		{
			name: "permanent last strike (operator unbanned) → rate limited",
			seed: func(m *mockStore) {
				m.setLastStrike(ip2, time.Now().Add(-time.Hour), 0)
			},
			wantErr: decision.ErrRateLimited,
		},
		{
			name: "store error → rate limited (fail-safe)",
			seed: func(m *mockStore) {
				m.lastStrikeErr = errors.New("db locked")
			},
			wantErr: decision.ErrRateLimited,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := armedPolicy()
			pol.MaxBansPerMinute = 1 // one ban exhausts the cap
			pol.EscalationExemptWindow = config.Duration(window)

			st := newMock(map[string]int{ip2.String(): 1}) // ip2 escalates to strike #2
			tc.seed(st)
			engine := mustEngine(t, pol, st)

			// Exhaust the cap with a strike #1 on a fresh IP.
			if _, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip3, 85, "bruteforce")}); err != nil {
				t.Fatalf("ip3 strike #1: %v", err)
			}

			act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip2, 85, "bruteforce")})
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Decide err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			if act.Op != tc.wantOp {
				t.Errorf("Op = %q, want %q", act.Op, tc.wantOp)
			}
			if act.Strike != tc.wantStrk {
				t.Errorf("Strike = %d, want %d", act.Strike, tc.wantStrk)
			}
		})
	}
}

// TestEscalation_StaleCountsAgainstCap verifies that a stale escalation is not
// dropped when the cap has room — it proceeds as a normal ban and consumes
// cap budget like any fresh ban.
func TestEscalation_StaleCountsAgainstCap(t *testing.T) {
	pol := armedPolicy()
	pol.MaxBansPerMinute = 1
	pol.EscalationExemptWindow = config.Duration(24 * time.Hour)

	st := newMock(map[string]int{ip2.String(): 1})
	st.setLastStrike(ip2, time.Now().Add(-30*24*time.Hour), time.Hour) // stale
	engine := mustEngine(t, pol, st)

	// Cap has room: the stale escalation bans normally.
	act, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip2, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("stale escalation with free cap: %v", err)
	}
	if act.Op != "ban" || act.Strike != 2 {
		t.Errorf("Op/Strike = %q/%d, want ban/2", act.Op, act.Strike)
	}

	// ...and it consumed the cap: the next fresh strike #1 is limited.
	if _, err := engine.Decide(context.Background(), []sdk.Verdict{mkVerdict(ip3, 85, "bruteforce")}); !errors.Is(err, decision.ErrRateLimited) {
		t.Fatalf("fresh ban after stale escalation: err = %v, want ErrRateLimited", err)
	}
}

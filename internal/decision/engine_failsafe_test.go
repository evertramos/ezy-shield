package decision

// Regression tests for issue #361 item 3: three deliberate fail-safe branches
// in Engine.Decide had no test and no injection hook — the GetBanInfo-error
// fall-through (a DB error must not suppress sentencing), the
// HadIneffectiveBan-error skip of the pre-permanent alert, and the rate-limit
// fixed-window reset after one minute. In-package (not decision_test) so the
// window test can rewind Engine.windowStart directly instead of sleeping.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// failStore is a minimal decision.Store whose GetBanInfo/HadIneffectiveBan
// can be forced to fail while everything else behaves benignly.
type failStore struct {
	getBanInfoErr error
	hadIneffErr   error

	strikes  int
	recorded []sdk.Action
}

func (f *failStore) GetBanInfo(context.Context, netip.Addr) (time.Time, int, bool, bool, error) {
	if f.getBanInfoErr != nil {
		return time.Time{}, 0, false, false, f.getBanInfoErr
	}
	return time.Time{}, 0, false, false, nil
}
func (f *failStore) RecordSuppressed(context.Context, netip.Addr, bool) (int, int, bool, error) {
	return 0, 0, false, nil
}
func (f *failStore) MarkBanIneffective(context.Context, netip.Addr) (bool, error) {
	return false, nil
}
func (f *failStore) HadIneffectiveBan(context.Context, netip.Addr) (bool, error) {
	if f.hadIneffErr != nil {
		return false, f.hadIneffErr
	}
	return false, nil
}
func (f *failStore) BumpLastSeen(context.Context, netip.Addr) error { return nil }
func (f *failStore) GetStrikeCount(context.Context, netip.Addr) (int, error) {
	return f.strikes, nil
}
func (f *failStore) LastStrike(context.Context, netip.Addr) (time.Time, time.Duration, bool, error) {
	return time.Time{}, 0, false, nil
}
func (f *failStore) RecordStrike(_ context.Context, a sdk.Action) error {
	f.recorded = append(f.recorded, a)
	return nil
}
func (f *failStore) Audit(context.Context, sdk.Action) error { return nil }

func failsafePolicy() *config.Policy {
	return &config.Policy{
		Armed:            false,
		BanThreshold:     70,
		ObserveThreshold: 40,
		MaxBansPerMinute: 3,
		Strikes:          config.DefaultStrikes,
	}
}

func banWorthyVerdict(ip netip.Addr) []sdk.Verdict {
	return []sdk.Verdict{{IP: ip, Score: 95, Category: "bruteforce", Reason: "test", Source: "rules"}}
}

// TestDecide_GetBanInfoErrorFallsThroughToSentencing: a DB error on the
// active-ban lookup must NOT suppress the verdict — the strike path still
// runs and the offense is sentenced.
func TestDecide_GetBanInfoErrorFallsThroughToSentencing(t *testing.T) {
	t.Parallel()
	st := &failStore{getBanInfoErr: errors.New("db exploded")}
	e, err := New(failsafePolicy(), st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.81")
	act, err := e.Decide(context.Background(), banWorthyVerdict(ip))
	if err != nil {
		t.Fatalf("Decide must not fail on a GetBanInfo error (fail-safe fall-through): %v", err)
	}
	if act.Op != "dry_ban" {
		t.Fatalf("verdict suppressed by a DB error — want a dry_ban action, got %+v", act)
	}
	if len(st.recorded) != 1 {
		t.Fatalf("strike not recorded despite fall-through: %d", len(st.recorded))
	}
}

// TestDecide_HadIneffectiveBanErrorSkipsAlertButStillBans: an error reading
// the had-ineffective flag skips only the pre-permanent alert — the permanent
// sentencing itself must proceed.
func TestDecide_HadIneffectiveBanErrorSkipsAlertButStillBans(t *testing.T) {
	t.Parallel()
	st := &failStore{
		hadIneffErr: errors.New("flag read failed"),
		strikes:     len(config.DefaultStrikes) - 1, // next strike is the permanent rung
	}
	e, err := New(failsafePolicy(), st)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ip := netip.MustParseAddr("192.0.2.82")
	act, err := e.Decide(context.Background(), banWorthyVerdict(ip))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.TTL != 0 || !act.Permanent {
		t.Fatalf("permanent sentencing must proceed when the alert flag read fails, got %+v", act)
	}
}

// TestCheckRateLimit_WindowResetsAfterOneMinute: the fixed-window counter
// must clear once the window ages out — otherwise a busy minute would
// rate-limit the daemon forever.
func TestCheckRateLimit_WindowResetsAfterOneMinute(t *testing.T) {
	t.Parallel()
	e, err := New(failsafePolicy(), &failStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Fill the window to the cap (3) and confirm the 4th is refused.
	for i := 0; i < 3; i++ {
		if err := e.checkRateLimit(); err != nil {
			t.Fatalf("ban %d unexpectedly rate-limited: %v", i+1, err)
		}
	}
	if err := e.checkRateLimit(); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cap breach must return ErrRateLimited, got %v", err)
	}

	// Age the window out (rewind its start instead of sleeping 60s).
	e.mu.Lock()
	e.windowStart = time.Now().Add(-61 * time.Second)
	e.mu.Unlock()

	if err := e.checkRateLimit(); err != nil {
		t.Fatalf("counter must reset after the window ages out, got %v", err)
	}
}

package ai

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// trackingBudgetStore records per-provider usage, unlike stubBudgetStore which
// ignores the provider key. Used to verify budget-key isolation (issue #79).
type trackingBudgetStore struct {
	mu    sync.Mutex
	usage map[string]sdk.Usage
}

func (t *trackingBudgetStore) RecordUsage(_ context.Context, provider string, u sdk.Usage, _ string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.usage == nil {
		t.usage = make(map[string]sdk.Usage)
	}
	cur := t.usage[provider]
	cur.InputTokens += u.InputTokens
	cur.OutputTokens += u.OutputTokens
	t.usage[provider] = cur
	return nil
}

func (t *trackingBudgetStore) TodayUsage(_ context.Context, provider string) (sdk.Usage, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.usage[provider], nil
}

// stubBudgetStore is an in-memory BudgetStore for tests.
type stubBudgetStore struct {
	recorded []sdk.Usage
	today    sdk.Usage // returned by TodayUsage
}

func (s *stubBudgetStore) RecordUsage(_ context.Context, _ string, u sdk.Usage, _ string) error {
	s.recorded = append(s.recorded, u)
	s.today.InputTokens += u.InputTokens
	s.today.OutputTokens += u.OutputTokens
	s.today.CostUSD += u.CostUSD
	return nil
}

func (s *stubBudgetStore) TodayUsage(_ context.Context, _ string) (sdk.Usage, error) {
	return s.today, nil
}

func TestBudget_ConsumeAndRemaining(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("anthropic", 1000, store)
	ctx := context.Background()

	budget, err := b.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if budget.Remaining != 1000 {
		t.Errorf("want remaining=1000, got %d", budget.Remaining)
	}

	exceeded, err := b.Consume(ctx, sdk.Usage{InputTokens: 300, OutputTokens: 100}, netip.Addr{})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if exceeded {
		t.Error("budget should not be exceeded after consuming 400/1000")
	}

	budget, _ = b.Current(ctx)
	if budget.Remaining != 600 {
		t.Errorf("want remaining=600, got %d", budget.Remaining)
	}
}

// TestBudget_Exceeded verifies the exceeded flag triggers once when the limit is hit.
func TestBudget_Exceeded(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("anthropic", 500, store)
	ctx := context.Background()

	// First consumption: 400 tokens (under limit).
	exceeded, err := b.Consume(ctx, sdk.Usage{InputTokens: 400}, netip.Addr{})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if exceeded {
		t.Error("should not be exceeded at 400/500")
	}

	// Second consumption: pushes over 500 → exceeded=true for the first time.
	exceeded, err = b.Consume(ctx, sdk.Usage{InputTokens: 200}, netip.Addr{})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !exceeded {
		t.Error("budget should be exceeded at 600/500")
	}

	// Third call: still exceeded but notification already sent → exceeded=false.
	exceeded, err = b.Consume(ctx, sdk.Usage{InputTokens: 1}, netip.Addr{})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if exceeded {
		t.Error("exceeded notification should only fire once per day")
	}
}

// TestBudget_NotificationRollsOverAtMidnight (issue #359): the notification
// flag is day-aware and clears itself at the UTC day boundary — no external
// ResetDay call needed (that API existed but no production code ever called
// it, so day-two breaches went unnotified until the daemon restarted).
func TestBudget_NotificationRollsOverAtMidnight(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("anthropic", 100, store)
	day := time.Date(2026, 8, 25, 23, 0, 0, 0, time.UTC)
	b.nowFn = func() time.Time { return day }
	ctx := context.Background()

	_, _ = b.Consume(ctx, sdk.Usage{InputTokens: 200}, netip.Addr{}) // exceeds
	exceeded, _ := b.Consume(ctx, sdk.Usage{InputTokens: 1}, netip.Addr{})
	if exceeded {
		t.Error("notification should not fire twice within one day")
	}

	// Midnight: the store's per-day totals reset naturally; the flag must too.
	day = day.Add(2 * time.Hour) // 2026-08-26 01:00 UTC
	store.today = sdk.Usage{}

	exceeded, _ = b.Consume(ctx, sdk.Usage{InputTokens: 200}, netip.Addr{})
	if !exceeded {
		t.Error("a breach on the NEXT day must notify again without any reset call")
	}
}

// TestBudget_DisabledWhenZero verifies a zero daily limit disables enforcement.
func TestBudget_DisabledWhenZero(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("anthropic", 0, store)
	ctx := context.Background()

	budget, err := b.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if budget.DailyLimit != 0 {
		t.Errorf("disabled budget should have DailyLimit=0, got %d", budget.DailyLimit)
	}

	exceeded, err := b.Consume(ctx, sdk.Usage{InputTokens: 9999999}, netip.Addr{})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if exceeded {
		t.Error("disabled budget should never report exceeded")
	}
}

// TestBudget_UsageRecorded verifies RecordUsage is called on each Consume.
func TestBudget_UsageRecorded(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("anthropic", 10000, store)
	ctx := context.Background()

	u := sdk.Usage{InputTokens: 123, OutputTokens: 45, CostUSD: 0.001}
	_, _ = b.Consume(ctx, u, netip.Addr{})
	_, _ = b.Consume(ctx, u, netip.Addr{})

	if len(store.recorded) != 2 {
		t.Errorf("expected 2 recorded usage entries, got %d", len(store.recorded))
	}
}

// TestBudget_SharedKeySharesBucket reproduces issue #79: two Budget instances
// with identical keys share the same store bucket and interfere with each other.
func TestBudget_SharedKeySharesBucket(t *testing.T) {
	store := &trackingBudgetStore{}
	b1 := NewBudget("openai", 500, store)
	b2 := NewBudget("openai", 500, store)
	ctx := context.Background()

	_, _ = b1.Consume(ctx, sdk.Usage{InputTokens: 400}, netip.Addr{})

	budget, err := b2.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	// Key collision: b2 sees b1's consumption (only 100 remaining instead of 500).
	if budget.Remaining == 500 {
		t.Error("same-key budgets must share the store bucket (remaining must not be 500)")
	}
}

// TestBudget_UniqueKeysIsolate verifies that Budget instances with different
// keys are independent — the desired state after the fix in buildAIChain.
func TestBudget_UniqueKeysIsolate(t *testing.T) {
	store := &trackingBudgetStore{}
	b1 := NewBudget("openai-0", 500, store)
	b2 := NewBudget("openai-1", 500, store)
	ctx := context.Background()

	_, _ = b1.Consume(ctx, sdk.Usage{InputTokens: 400}, netip.Addr{})

	budget, err := b2.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if budget.Remaining != 500 {
		t.Errorf("unique-key budgets must be isolated: want remaining=500, got %d", budget.Remaining)
	}
}

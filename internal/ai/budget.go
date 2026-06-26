package ai

import (
	"context"
	"fmt"
	"sync"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// BudgetStore is the persistence interface for AI token usage tracking.
// It is satisfied by *store.DB.
type BudgetStore interface {
	RecordUsage(ctx context.Context, provider string, usage sdk.Usage) error
	TodayUsage(ctx context.Context, provider string) (sdk.Usage, error)
}

// Budget enforces a daily token limit for an AI provider and persists usage
// to the ai_usage table via BudgetStore.
//
// When the daily limit is exceeded, Consume returns exceeded=true exactly once
// per day so the caller can send a single notification without spamming.
// It is safe for concurrent use.
type Budget struct {
	mu       sync.Mutex
	provider string
	daily    int
	store    BudgetStore
	notified bool // guards single-notification-per-day for budget exceeded
}

// NewBudget creates a Budget for provider with the given daily token limit.
// A daily limit of 0 disables the budget (Exceeded always returns false).
func NewBudget(provider string, dailyTokens int, store BudgetStore) *Budget {
	return &Budget{
		provider: provider,
		daily:    dailyTokens,
		store:    store,
	}
}

// Current returns the remaining token budget for today.
// Returns DailyLimit=0 when no limit is configured (budget disabled).
func (b *Budget) Current(ctx context.Context) (sdk.TokenBudget, error) {
	if b.daily == 0 {
		return sdk.TokenBudget{}, nil
	}
	used, err := b.store.TodayUsage(ctx, b.provider)
	if err != nil {
		return sdk.TokenBudget{}, fmt.Errorf("budget: today usage: %w", err)
	}
	spent := used.InputTokens + used.OutputTokens
	remaining := b.daily - spent
	if remaining < 0 {
		remaining = 0
	}
	return sdk.TokenBudget{
		Remaining:  remaining,
		DailyLimit: b.daily,
	}, nil
}

// Exceeded reports whether today's usage is at or above the daily limit.
// Returns false when the budget is disabled (daily == 0).
func (b *Budget) Exceeded(ctx context.Context) (bool, error) {
	budget, err := b.Current(ctx)
	if err != nil {
		return false, err
	}
	return budget.DailyLimit > 0 && budget.Remaining == 0, nil
}

// Consume records usage in the store.
// It returns exceeded=true the first time the daily budget is breached in
// the current day so the caller can emit exactly one critical notification.
func (b *Budget) Consume(ctx context.Context, usage sdk.Usage) (exceeded bool, err error) {
	if err := b.store.RecordUsage(ctx, b.provider, usage); err != nil {
		return false, fmt.Errorf("budget: record usage: %w", err)
	}

	if b.daily == 0 {
		return false, nil
	}

	budget, err := b.Current(ctx)
	if err != nil {
		return false, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if budget.Remaining == 0 && !b.notified {
		b.notified = true
		return true, nil
	}
	return false, nil
}

// ResetDay clears the single-notification flag so the next day's breach
// triggers a fresh notification. Call at midnight or daemon restart.
func (b *Budget) ResetDay() {
	b.mu.Lock()
	b.notified = false
	b.mu.Unlock()
}

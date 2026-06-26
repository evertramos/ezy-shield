package ai

import (
	"context"
	"errors"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// stubProvider is a minimal sdk.AIProvider for chain tests.
type stubProvider struct {
	name     string
	verdicts []sdk.Verdict
	usage    sdk.Usage
	err      error
	calls    int
}

func (s *stubProvider) Name() string { return s.name }

func (s *stubProvider) Analyze(_ context.Context, _ []sdk.Aggregate, _ sdk.TokenBudget) ([]sdk.Verdict, sdk.Usage, error) {
	s.calls++
	return s.verdicts, s.usage, s.err
}

// TestChain_PrimarySucceeds verifies that the first provider's result is returned
// and the second provider is never called.
func TestChain_PrimarySucceeds(t *testing.T) {
	primary := &stubProvider{
		name:     "primary",
		verdicts: []sdk.Verdict{{Score: 80}},
		usage:    sdk.Usage{InputTokens: 100, OutputTokens: 20},
	}
	secondary := &stubProvider{name: "secondary", verdicts: []sdk.Verdict{{Score: 50}}}

	chain := NewChainProvider([]ChainEntry{
		{Provider: primary},
		{Provider: secondary},
	})

	verdicts, usage, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("1.2.3.4")}, sdk.TokenBudget{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0].Score != 80 {
		t.Errorf("want primary verdict score=80, got %+v", verdicts)
	}
	if usage.InputTokens != 100 {
		t.Errorf("want usage from primary (100 input tokens), got %+v", usage)
	}
	if secondary.calls != 0 {
		t.Errorf("secondary must not be called when primary succeeds, got %d calls", secondary.calls)
	}
}

// TestChain_PrimaryFails_SecondaryUsed verifies fallthrough on error.
func TestChain_PrimaryFails_SecondaryUsed(t *testing.T) {
	primary := &stubProvider{name: "primary", err: errors.New("connection refused")}
	secondary := &stubProvider{
		name:     "secondary",
		verdicts: []sdk.Verdict{{Score: 55}},
		usage:    sdk.Usage{InputTokens: 50, OutputTokens: 10},
	}

	chain := NewChainProvider([]ChainEntry{
		{Provider: primary},
		{Provider: secondary},
	})

	verdicts, _, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("2.3.4.5")}, sdk.TokenBudget{})
	if err != nil {
		t.Fatalf("chain must not surface error when secondary succeeds: %v", err)
	}
	if primary.calls != 1 {
		t.Errorf("primary should have been called once, got %d", primary.calls)
	}
	if secondary.calls != 1 {
		t.Errorf("secondary should have been called once, got %d", secondary.calls)
	}
	if len(verdicts) != 1 || verdicts[0].Score != 55 {
		t.Errorf("want secondary verdict score=55, got %+v", verdicts)
	}
}

// TestChain_AllFail_RulesOnly verifies that nil/nil is returned when every
// provider fails, signalling rules-only to the pipeline.
func TestChain_AllFail_RulesOnly(t *testing.T) {
	p1 := &stubProvider{name: "a", err: errors.New("timeout")}
	p2 := &stubProvider{name: "b", err: errors.New("bad gateway")}

	chain := NewChainProvider([]ChainEntry{{Provider: p1}, {Provider: p2}})

	verdicts, usage, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("3.4.5.6")}, sdk.TokenBudget{})
	if err != nil {
		t.Fatalf("chain must not return error when all providers fail: %v", err)
	}
	if len(verdicts) != 0 {
		t.Errorf("want nil/empty verdicts for rules-only fallback, got %+v", verdicts)
	}
	if usage != (sdk.Usage{}) {
		t.Errorf("want zero usage when all fail, got %+v", usage)
	}
	if p1.calls != 1 || p2.calls != 1 {
		t.Errorf("both providers should each be called once, p1=%d p2=%d", p1.calls, p2.calls)
	}
}

// TestChain_BudgetExhausted_FallsThrough verifies that a provider whose budget
// is exhausted is skipped and the next provider is tried.
func TestChain_BudgetExhausted_FallsThrough(t *testing.T) {
	// Exhaust the first provider's budget.
	store1 := &stubBudgetStore{}
	store1.today = sdk.Usage{InputTokens: 1000} // already over daily limit of 500
	b1 := NewBudget("primary", 500, store1)

	store2 := &stubBudgetStore{}
	b2 := NewBudget("secondary", 500, store2)

	primary := &stubProvider{name: "primary", verdicts: []sdk.Verdict{{Score: 90}}}
	secondary := &stubProvider{
		name:     "secondary",
		verdicts: []sdk.Verdict{{Score: 40}},
		usage:    sdk.Usage{InputTokens: 20, OutputTokens: 5},
	}

	chain := NewChainProvider([]ChainEntry{
		{Provider: primary, Budget: b1},
		{Provider: secondary, Budget: b2},
	})

	verdicts, _, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("4.5.6.7")}, sdk.TokenBudget{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if primary.calls != 0 {
		t.Errorf("primary must be skipped when budget exhausted, got %d calls", primary.calls)
	}
	if secondary.calls != 1 {
		t.Errorf("secondary must be called when primary budget is exhausted, got %d calls", secondary.calls)
	}
	if len(verdicts) != 1 || verdicts[0].Score != 40 {
		t.Errorf("want secondary verdict score=40, got %+v", verdicts)
	}
}

// TestChain_ContextCanceled_Propagates verifies that context.Canceled stops
// the chain and is returned to the caller (not silenced like other errors).
func TestChain_ContextCanceled_Propagates(t *testing.T) {
	p1 := &stubProvider{name: "primary", err: context.Canceled}
	p2 := &stubProvider{name: "secondary", verdicts: []sdk.Verdict{{Score: 50}}}

	chain := NewChainProvider([]ChainEntry{{Provider: p1}, {Provider: p2}})

	_, _, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("5.6.7.8")}, sdk.TokenBudget{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled propagated, got %v", err)
	}
	if p2.calls != 0 {
		t.Errorf("secondary must not be called after context.Canceled, got %d calls", p2.calls)
	}
}

// TestChain_BudgetConsumedOnSuccess verifies that Consume is called for the
// provider that answered successfully.
func TestChain_BudgetConsumedOnSuccess(t *testing.T) {
	store := &stubBudgetStore{}
	b := NewBudget("primary", 10000, store)

	p := &stubProvider{
		name:     "primary",
		verdicts: []sdk.Verdict{{Score: 70}},
		usage:    sdk.Usage{InputTokens: 200, OutputTokens: 50},
	}

	chain := NewChainProvider([]ChainEntry{{Provider: p, Budget: b}})
	_, _, _ = chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("6.7.8.9")}, sdk.TokenBudget{})

	if len(store.recorded) != 1 {
		t.Fatalf("want 1 budget record, got %d", len(store.recorded))
	}
	if store.recorded[0].InputTokens != 200 {
		t.Errorf("want InputTokens=200, got %d", store.recorded[0].InputTokens)
	}
}

// TestChain_Name verifies the chain reports a stable name.
func TestChain_Name(t *testing.T) {
	c := NewChainProvider(nil)
	if c.Name() != "chain" {
		t.Errorf("Name: want chain, got %q", c.Name())
	}
}

// TestChain_EmptyEntries returns nil/nil without panicking.
func TestChain_EmptyEntries(t *testing.T) {
	chain := NewChainProvider(nil)
	verdicts, usage, err := chain.Analyze(context.Background(), []sdk.Aggregate{sampleAggregate("7.8.9.10")}, sdk.TokenBudget{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(verdicts) != 0 || usage != (sdk.Usage{}) {
		t.Errorf("want nil/zero for empty chain, got verdicts=%v usage=%+v", verdicts, usage)
	}
}

package ai

import (
	"context"
	"errors"
	"log/slog"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// ChainEntry pairs an AI provider with its per-provider daily budget.
// Budget may be nil when no token limiting is required for that provider.
type ChainEntry struct {
	Provider sdk.AIProvider
	Budget   *Budget
}

// ChainProvider implements sdk.AIProvider by trying a list of providers in order.
// On error, context deadline exceeded, or budget exhaustion it falls through to
// the next entry. context.Canceled stops the chain immediately.
// When every provider fails it returns nil, sdk.Usage{}, nil — rules-only, no
// error propagated to the pipeline.
type ChainProvider struct {
	entries []ChainEntry
}

// NewChainProvider creates a ChainProvider from entries already sorted by priority.
func NewChainProvider(entries []ChainEntry) *ChainProvider {
	return &ChainProvider{entries: entries}
}

// Name implements sdk.AIProvider.
func (c *ChainProvider) Name() string { return "chain" }

// Analyze iterates entries in priority order, returning the first successful
// result. The sdk.TokenBudget argument from the caller is ignored; per-entry
// budgets are fetched from each ChainEntry.Budget instead.
func (c *ChainProvider) Analyze(
	ctx context.Context,
	batch []sdk.Aggregate,
	_ sdk.TokenBudget,
) ([]sdk.Verdict, sdk.Usage, error) {
	for _, entry := range c.entries {
		name := entry.Provider.Name()

		// Skip this provider if its daily budget is exhausted.
		if entry.Budget != nil {
			exceeded, err := entry.Budget.Exceeded(ctx)
			if err != nil {
				slog.WarnContext(ctx, "ai: chain: budget check failed, skipping provider",
					"provider", name, "err", err)
				continue
			}
			if exceeded {
				slog.WarnContext(ctx, "ai: chain: budget exhausted, trying next",
					"provider", name)
				continue
			}
		}

		// Fetch the per-provider budget hint for prompt style selection.
		var budget sdk.TokenBudget
		if entry.Budget != nil {
			if b, err := entry.Budget.Current(ctx); err != nil {
				slog.WarnContext(ctx, "ai: chain: budget query failed, using zero budget",
					"provider", name, "err", err)
			} else {
				budget = b
			}
		}

		verdicts, usage, err := entry.Provider.Analyze(ctx, batch, budget)
		if err != nil {
			// Global cancellation — respect it; don't try further providers.
			if errors.Is(err, context.Canceled) {
				return nil, sdk.Usage{}, err
			}
			slog.WarnContext(ctx, "ai: chain: provider failed, trying next",
				"provider", name, "err", err)
			continue
		}

		// Record per-provider budget consumption.
		if entry.Budget != nil {
			if _, consumeErr := entry.Budget.Consume(ctx, usage); consumeErr != nil {
				slog.WarnContext(ctx, "ai: chain: budget consume failed",
					"provider", name, "err", consumeErr)
			}
		}

		slog.InfoContext(ctx, "ai: chain: provider succeeded",
			"provider", name,
			"input_tokens", usage.InputTokens,
			"output_tokens", usage.OutputTokens,
			"cost_usd", usage.CostUSD,
		)
		return verdicts, usage, nil
	}

	// All providers failed — signal rules-only without erroring the pipeline.
	slog.WarnContext(ctx, "ai: chain: all providers failed, falling back to rules-only",
		"providers", len(c.entries))
	return nil, sdk.Usage{}, nil
}

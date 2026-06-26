package main

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// keyCaptureBudgetStore records every provider key passed to TodayUsage so
// tests can assert that buildAIChain assigns unique budget keys per entry.
type keyCaptureBudgetStore struct {
	mu   sync.Mutex
	seen []string
}

func (k *keyCaptureBudgetStore) RecordUsage(_ context.Context, _ string, _ sdk.Usage) error {
	return nil
}

func (k *keyCaptureBudgetStore) TodayUsage(_ context.Context, provider string) (sdk.Usage, error) {
	k.mu.Lock()
	k.seen = append(k.seen, provider)
	k.mu.Unlock()
	return sdk.Usage{}, nil
}

func (k *keyCaptureBudgetStore) distinct() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	m := make(map[string]struct{}, len(k.seen))
	var out []string
	for _, p := range k.seen {
		if _, ok := m[p]; !ok {
			m[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// TestBuildAIChain_DuplicateNames_UniqueKeys is the regression test for issue #79.
// Two provider entries with identical names must receive distinct budget keys so
// they do not share a budget bucket in the store.
func TestBuildAIChain_DuplicateNames_UniqueKeys(t *testing.T) {
	store := &keyCaptureBudgetStore{}

	cfg := &config.AICfg{
		// Providers list: two ollama entries with the same name but different priorities.
		// Ollama needs no API key so construction succeeds without network access.
		Providers: []config.ProviderCfg{
			{Name: "ollama", Priority: 1, TokenBudgetDaily: 500},
			{Name: "ollama", Priority: 2, TokenBudgetDaily: 500},
		},
	}

	chain, err := buildAIChain(cfg, nil, 0, store)
	if err != nil {
		t.Fatalf("buildAIChain: %v", err)
	}

	// Trigger budget checks (TodayUsage) by running Analyze.
	// Ollama providers will fail (no server), which is fine — we only care
	// that each entry's budget queries the store with its assigned key.
	_, _, _ = chain.Analyze(context.Background(), []sdk.Aggregate{
		{IP: netip.MustParseAddr("10.0.0.1"), Count: 1},
	}, sdk.TokenBudget{})

	keys := store.distinct()
	if len(keys) < 2 {
		t.Fatalf("want ≥2 distinct budget keys for 2 same-name providers, got %d: %v", len(keys), keys)
	}
	if keys[0] == keys[1] {
		t.Errorf("budget keys must be unique, both entries share key %q", keys[0])
	}
}

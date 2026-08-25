package enforce

// Regression tests for issue #361: MultiEnforcer's all-enforcers-always-called
// semantics were only pinned for Ban — a refactor that early-returned on the
// first Unban/Sync error (leaving healthy backends unreconciled behind one
// dead edge account) would have passed the suite.

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// countingEnforcer records how many times each verb ran and optionally fails
// every call.
type countingEnforcer struct {
	name                string
	failWith            error
	bans, unbans, syncs int
}

func (c *countingEnforcer) Name() string { return c.name }
func (c *countingEnforcer) Ban(context.Context, sdk.Target) error {
	c.bans++
	return c.failWith
}
func (c *countingEnforcer) Unban(context.Context, sdk.Target) error {
	c.unbans++
	return c.failWith
}
func (c *countingEnforcer) Sync(context.Context, []sdk.Target) error {
	c.syncs++
	return c.failWith
}

func TestMultiEnforcer_PartialFailureStillCallsEveryBackend(t *testing.T) {
	t.Parallel()

	boom := errors.New("edge account down")
	target := sdk.Target{IP: netip.MustParseAddr("192.0.2.44")}

	verbs := []struct {
		name string
		call func(m *MultiEnforcer) error
		hits func(c *countingEnforcer) int
	}{
		{"Ban", func(m *MultiEnforcer) error { return m.Ban(context.Background(), target) },
			func(c *countingEnforcer) int { return c.bans }},
		{"Unban", func(m *MultiEnforcer) error { return m.Unban(context.Background(), target) },
			func(c *countingEnforcer) int { return c.unbans }},
		{"Sync", func(m *MultiEnforcer) error { return m.Sync(context.Background(), []sdk.Target{target}) },
			func(c *countingEnforcer) int { return c.syncs }},
	}
	for _, v := range verbs {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			first := &countingEnforcer{name: "dead-edge", failWith: boom}
			second := &countingEnforcer{name: "healthy-local"}
			third := &countingEnforcer{name: "healthy-edge"}
			m := NewMulti(first, second, third)

			err := v.call(m)

			if v.hits(second) != 1 || v.hits(third) != 1 {
				t.Fatalf("%s: healthy backends skipped after the first failure (hits: %d/%d) — all enforcers must always be called",
					v.name, v.hits(second), v.hits(third))
			}
			if !errors.Is(err, boom) {
				t.Errorf("%s: combined error must wrap the failing backend's error, got %v", v.name, err)
			}
			if err != nil && !containsAll(err.Error(), "dead-edge") {
				t.Errorf("%s: combined error must name the failing backend, got %q", v.name, err)
			}
		})
	}
}

// TestMultiEnforcer_AllFailuresJoined: every failing backend appears in the
// combined error, not just the first.
func TestMultiEnforcer_AllFailuresJoined(t *testing.T) {
	t.Parallel()
	a := &countingEnforcer{name: "backend-a", failWith: errors.New("a down")}
	b := &countingEnforcer{name: "backend-b", failWith: errors.New("b down")}
	m := NewMulti(a, b)

	err := m.Sync(context.Background(), nil)
	if err == nil || !containsAll(err.Error(), "backend-a", "backend-b") {
		t.Fatalf("combined Sync error must name every failing backend, got %v", err)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !strings.Contains(s, sub) {
			return false
		}
	}
	return true
}

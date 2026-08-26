// SPDX-License-Identifier: AGPL-3.0-only

package rules_test

// Tests for the built-in Vaultwarden rules (issue #191) against synthetic
// aggregates shaped like the parser produces.

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func vwFired(t *testing.T, window time.Duration, fails int) map[string]bool {
	t.Helper()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	agg := sdk.Aggregate{
		IP:     netip.MustParseAddr("203.0.113.120"),
		Window: window,
		Count:  fails,
		Kinds:  map[string]int{"vaultwarden_auth_fail": fails},
	}
	out := map[string]bool{}
	for _, v := range e.Evaluate(context.Background(), agg) {
		if name, ok := strings.CutPrefix(v.Reason, "rule/"); ok {
			if i := strings.IndexByte(name, ':'); i > 0 {
				out[name[:i]] = true
			}
		}
	}
	return out
}

func TestVaultwardenBruteforceRules(t *testing.T) {
	t.Parallel()
	if !vwFired(t, 300*time.Second, 5)["vaultwarden_bruteforce"] {
		t.Fatal("vaultwarden_bruteforce must fire at 5 fails in 300s")
	}
	if vwFired(t, 300*time.Second, 4)["vaultwarden_bruteforce"] {
		t.Fatal("vaultwarden_bruteforce fired below threshold")
	}
	if !vwFired(t, 3600*time.Second, 10)["vaultwarden_bruteforce_sustained"] {
		t.Fatal("sustained variant must fire at 10 fails in 1h")
	}
	if vwFired(t, 3600*time.Second, 9)["vaultwarden_bruteforce_sustained"] {
		t.Fatal("sustained variant fired below threshold")
	}
}

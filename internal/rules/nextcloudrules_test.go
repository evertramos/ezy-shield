package rules_test

// Tests for the built-in Nextcloud rules (issue #192).

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func ncFired(t *testing.T, window time.Duration, fails int) map[string]bool {
	t.Helper()
	e, err := rules.New("", "")
	if err != nil {
		t.Fatalf("rules.New: %v", err)
	}
	agg := sdk.Aggregate{
		IP:     netip.MustParseAddr("203.0.113.150"),
		Window: window,
		Count:  fails,
		Kinds:  map[string]int{"nextcloud_auth_fail": fails},
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

func TestNextcloudBruteforceRules(t *testing.T) {
	t.Parallel()
	if !ncFired(t, 300*time.Second, 5)["nextcloud_bruteforce"] {
		t.Fatal("nextcloud_bruteforce must fire at 5 fails in 300s")
	}
	if ncFired(t, 300*time.Second, 4)["nextcloud_bruteforce"] {
		t.Fatal("nextcloud_bruteforce fired below threshold")
	}
	if !ncFired(t, 3600*time.Second, 10)["nextcloud_bruteforce_sustained"] {
		t.Fatal("sustained variant must fire at 10 fails in 1h")
	}
}

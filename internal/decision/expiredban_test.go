// SPDX-License-Identifier: AGPL-3.0-only

package decision_test

// Regression test for issue #603 against the REAL store: a strike-1 ban
// whose TTL has elapsed but whose row the minute-cadence reaper has not
// removed yet must not suppress the next threshold-crossing burst as
// already_banned — the kernel already let the attacker back in, so the
// evidence has to become strike 2, not a false leak on an expired ban.

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestExpiredUnreapedBan_DoesNotSuppressNextStrike(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	engine, err := decision.New(armedPolicy(), db)
	if err != nil {
		t.Fatalf("decision.New: %v", err)
	}
	engine.SetSSHPeerProbe(func() []netip.Addr { return nil })
	attacker := netip.MustParseAddr("203.0.113.45")

	// Strike 1 with a TTL that elapses immediately; the reaper is NOT run.
	if err := db.RecordStrike(ctx, sdk.Action{IP: attacker, Op: "ban", Strike: 1, TTL: time.Millisecond, Reason: "test"}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	time.Sleep(5 * time.Millisecond)

	act, err := engine.Decide(ctx, []sdk.Verdict{mkVerdict(attacker, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "ban" || act.Strike != 2 {
		t.Fatalf("action = op=%s strike=%d, want a strike-2 ban (expired row must not read as active)", act.Op, act.Strike)
	}
	// The suppressed-event counters of the dead ban were not touched: the
	// new row starts clean.
	total, afterGrace, fired, err := db.RecordSuppressed(ctx, attacker, false)
	if err != nil {
		t.Fatalf("RecordSuppressed: %v", err)
	}
	if total != 1 || afterGrace != 0 || fired {
		t.Fatalf("counters after the new ban = total %d afterGrace %d fired %v, want 1/0/false", total, afterGrace, fired)
	}

	// Control: a ban still inside its TTL keeps suppressing.
	if err := db.RecordStrike(ctx, sdk.Action{IP: attacker, Op: "ban", Strike: 2, TTL: time.Hour, Reason: "test"}); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	act, err = engine.Decide(ctx, []sdk.Verdict{mkVerdict(attacker, 85, "bruteforce")})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if act.Op != "already_banned" {
		t.Fatalf("live ban: op = %s, want already_banned", act.Op)
	}
}

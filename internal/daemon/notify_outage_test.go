// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Regression test for issue #613 at the daemon level: during an enforcer
// outage, after a burst of ordinary strike warnings, the ONE
// "enforcement DEGRADED" critical must reach the notifier, and the per-IP
// "enforcer ban failed" criticals must not flood it.

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestEnforcerOutage_DegradedCriticalReachesNotifier(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	enf := &flakyEnforcer{}
	notif := &fakeNotifier{}
	d, err := New(Config{
		Policy: &config.Policy{
			Armed:            true,
			BanThreshold:     config.DefaultBanThreshold,
			ObserveThreshold: config.DefaultObserveThreshold,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:      db,
		Enforcer:   enf,
		Notifier:   notify.New([]sdk.Notifier{notif}, 5, 10*time.Minute, nil), // production defaults
		SocketPath: "",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Five ordinary bans: each sends a "[ban] … strike 1" warning and fills
	// the 5/min channel quota, as a scan wave does.
	for i := 1; i <= 5; i++ {
		ip := netip.MustParseAddr("203.0.113." + strconv.Itoa(i))
		d.dispatch(ctx, sdk.Action{IP: ip, Op: "ban", Strike: 1, TTL: 5 * time.Minute, Reason: "scan"})
	}
	// The enforcer dies; ten more bans fail within the same minute.
	enf.setFailing(true)
	for i := 10; i < 20; i++ {
		ip := netip.MustParseAddr("203.0.113." + strconv.Itoa(i))
		d.dispatch(ctx, sdk.Action{IP: ip, Op: "ban", Strike: 1, TTL: 5 * time.Minute, Reason: "scan"})
	}
	if s, _ := d.enforcementState(); s != EnfDegraded {
		t.Fatalf("state = %s, want DEGRADED", s)
	}

	notif.mu.Lock()
	defer notif.mu.Unlock()
	degraded, perIP := 0, 0
	for _, m := range notif.msgs {
		if m.Severity != "critical" {
			continue
		}
		switch {
		case strings.Contains(m.Title, "enforcement DEGRADED"):
			degraded++
		case strings.Contains(m.Title, "enforcer ban failed"):
			perIP++
		}
	}
	if degraded != 1 {
		t.Fatalf("DEGRADED critical delivered %d time(s), want exactly 1 — the operator hears nothing exactly when enforcement breaks", degraded)
	}
	if perIP > 1 {
		t.Fatalf("per-IP enforcer-failure criticals delivered %d times, want at most 1 systemic alert per window", perIP)
	}
}

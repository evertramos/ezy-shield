// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// The notifier drop counter must be exported whenever a notifier exists —
// not only with async AI enabled (adversarial review of #613).

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func TestNotifyDroppedGauge_RegisteredWithoutAI(t *testing.T) {
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(Config{
		Policy:     &config.Policy{Armed: false, BanThreshold: config.DefaultBanThreshold, ObserveThreshold: config.DefaultObserveThreshold, MaxBansPerMinute: config.DefaultMaxBansPerMinute, Strikes: config.DefaultStrikes},
		Store:      db,
		Notifier:   notify.New([]sdk.Notifier{&fakeNotifier{}}, 100, time.Hour, nil),
		SocketPath: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.metrics.reg.Snapshot(), "ezyshield_notifications_dropped_total") {
		t.Fatalf("dropped-notifications metric not registered without async AI")
	}
}

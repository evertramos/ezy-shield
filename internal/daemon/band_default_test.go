// SPDX-License-Identifier: AGPL-3.0-only

package daemon

// Regression tests for issue #443: an omitted ambiguous_band follows the
// operator's CONFIGURED ban_threshold instead of the compile-time default —
// with a raised threshold, scores between the static default's upper bound
// and the threshold are genuinely ambiguous but never consulted the AI.

import (
	"context"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
)

func newBandDaemon(t *testing.T, band [2]int, banThreshold int) *Daemon {
	t.Helper()
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	d, err := New(Config{
		Cfg: &config.Config{AI: &config.AICfg{AmbiguousBand: band}},
		Policy: &config.Policy{
			Armed:            false,
			BanThreshold:     banThreshold,
			ObserveThreshold: 10,
			MaxBansPerMinute: config.DefaultMaxBansPerMinute,
			Strikes:          config.DefaultStrikes,
		},
		Store:  db,
		MaxIPs: 10,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestNew_OmittedBandFollowsConfiguredThreshold(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		band         [2]int
		banThreshold int
		wantLo       int
		wantHi       int
	}{
		{
			name: "default threshold keeps the default band",
			band: config.DefaultAmbiguousBand, banThreshold: config.DefaultBanThreshold,
			wantLo: config.DefaultAmbiguousBand[0], wantHi: config.DefaultAmbiguousBand[1],
		},
		{
			name: "raised threshold extends the omitted band's upper bound",
			band: config.DefaultAmbiguousBand, banThreshold: 90,
			wantLo: config.DefaultAmbiguousBand[0], wantHi: 89,
		},
		{
			name: "lowered threshold shrinks the omitted band below it",
			band: config.DefaultAmbiguousBand, banThreshold: 50,
			wantLo: config.DefaultAmbiguousBand[0], wantHi: 49,
		},
		{
			name: "explicit band is honored as-is even with a raised threshold",
			band: [2]int{40, 60}, banThreshold: 90,
			wantLo: 40, wantHi: 60,
		},
		{
			name: "degenerate threshold leaves the default band untouched",
			band: config.DefaultAmbiguousBand, banThreshold: 20, // hi would be 19 <= lo 30
			wantLo: config.DefaultAmbiguousBand[0], wantHi: config.DefaultAmbiguousBand[1],
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newBandDaemon(t, tc.band, tc.banThreshold)
			if d.aiLo != tc.wantLo || d.aiHi != tc.wantHi {
				t.Fatalf("band = [%d, %d], want [%d, %d]", d.aiLo, d.aiHi, tc.wantLo, tc.wantHi)
			}
		})
	}
}

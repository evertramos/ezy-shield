// SPDX-License-Identifier: AGPL-3.0-only

package store_test

// Tests for the persistent per-IP hourly event counters (issue #134).

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
)

func TestEventCounts_UpsertSumPrune(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := openTestDB(t)

	ip := netip.MustParseAddr("192.0.2.77")
	other := netip.MustParseAddr("192.0.2.78")
	now := time.Now()
	bucket := store.HourBucket(now)
	oldBucket := store.HourBucket(now.Add(-30 * time.Hour))

	// Repeated upsert increments ONE row.
	for range 3 {
		if err := db.IncrEventCount(ctx, ip, "ssh_fail", bucket); err != nil {
			t.Fatalf("IncrEventCount: %v", err)
		}
	}
	if err := db.IncrEventCount(ctx, ip, "ssh_invalid_user", bucket); err != nil {
		t.Fatalf("IncrEventCount invalid_user: %v", err)
	}
	// Rows outside the window / for other IPs must not leak into the sum.
	if err := db.IncrEventCount(ctx, ip, "ssh_fail", oldBucket); err != nil {
		t.Fatalf("IncrEventCount old: %v", err)
	}
	if err := db.IncrEventCount(ctx, other, "ssh_fail", bucket); err != nil {
		t.Fatalf("IncrEventCount other: %v", err)
	}

	since := store.HourBucket(now.Add(-24 * time.Hour))
	sums, err := db.SumEventCounts(ctx, ip, []string{"ssh_fail", "ssh_invalid_user"}, since)
	if err != nil {
		t.Fatalf("SumEventCounts: %v", err)
	}
	if sums["ssh_fail"] != 3 || sums["ssh_invalid_user"] != 1 {
		t.Fatalf("sums = %v, want ssh_fail=3 ssh_invalid_user=1 (old bucket and other IP excluded)", sums)
	}

	// Kind filter: unrequested kinds never appear.
	sums, err = db.SumEventCounts(ctx, ip, []string{"ssh_invalid_user"}, since)
	if err != nil {
		t.Fatalf("SumEventCounts filtered: %v", err)
	}
	if len(sums) != 1 || sums["ssh_invalid_user"] != 1 {
		t.Fatalf("filtered sums = %v", sums)
	}

	// Prune removes only rows older than the cutoff.
	n, err := db.PruneEventCounts(ctx, since)
	if err != nil {
		t.Fatalf("PruneEventCounts: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1 (only the 30h-old bucket)", n)
	}
	sums, err = db.SumEventCounts(ctx, ip, []string{"ssh_fail"}, 0)
	if err != nil {
		t.Fatalf("SumEventCounts post-prune: %v", err)
	}
	if sums["ssh_fail"] != 3 {
		t.Fatalf("post-prune sum = %v, want in-window rows intact", sums)
	}
}

func TestHourBucket_FloorsToUTCHour(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 8, 25, 14, 59, 59, 0, time.UTC)
	want := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC).Unix()
	if got := store.HourBucket(at); got != want {
		t.Fatalf("HourBucket = %d, want %d", got, want)
	}
	// Same instant in another zone floors to the same UTC hour.
	loc := time.FixedZone("BRT", -3*3600)
	if got := store.HourBucket(at.In(loc)); got != want {
		t.Fatalf("HourBucket(zoned) = %d, want %d", got, want)
	}
}

func TestSumEventCounts_EmptyKinds(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	sums, err := db.SumEventCounts(context.Background(), netip.MustParseAddr("192.0.2.1"), nil, 0)
	if err != nil || len(sums) != 0 {
		t.Fatalf("empty kinds = (%v, %v), want empty map, nil error", sums, err)
	}
}

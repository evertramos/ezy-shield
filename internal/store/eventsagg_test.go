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

// TestConsumeEventCounts_Watermark (issue #636): a strike records what each
// long window had accumulated; reads subtract it; a watermark older than
// its window is ignored; pruning drops it with the counters.
func TestConsumeEventCounts_Watermark(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	ip := netip.MustParseAddr("203.0.113.55")
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= 5; i++ {
		if err := db.IncrEventCount(ctx, ip, "ssh_fail", store.HourBucket(now.Add(-time.Duration(i)*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	windows := map[time.Duration][]string{24 * time.Hour: {"ssh_fail"}, 7 * 24 * time.Hour: {"ssh_fail"}}
	if err := db.ConsumeEventCounts(ctx, ip, windows, now); err != nil {
		t.Fatalf("ConsumeEventCounts: %v", err)
	}
	got, err := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, now)
	if err != nil || got["ssh_fail"] != 5 {
		t.Fatalf("consumed(24h) = %v err=%v, want ssh_fail=5", got, err)
	}
	// A second strike replaces the watermark with the new totals.
	if err := db.IncrEventCount(ctx, ip, "ssh_fail", store.HourBucket(now)); err != nil {
		t.Fatal(err)
	}
	if err := db.ConsumeEventCounts(ctx, ip, windows, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, now); got["ssh_fail"] != 6 {
		t.Fatalf("consumed after second strike = %v, want 6", got)
	}
	// Older than its window: ignored.
	if got, _ := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, now.Add(25*time.Hour)); got["ssh_fail"] != 0 {
		t.Fatalf("stale watermark still read: %v", got)
	}
	// A zero snapshot clears the watermark instead of writing a zero row.
	if err := db.ConsumeEventCounts(ctx, ip, map[time.Duration][]string{24 * time.Hour: {"http_request"}}, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, now); len(got) != 1 || got["ssh_fail"] != 6 {
		t.Fatalf("zero snapshot wrote a row or clobbered the live one: %v", got)
	}
	// Pruned with the counters.
	if _, err := db.PruneEventCounts(ctx, store.HourBucket(now.Add(8*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ConsumedEventCounts(ctx, ip, 7*24*time.Hour, now); len(got) != 0 {
		t.Fatalf("watermark survived the prune: %v", got)
	}
}

// TestConsumeEventCounts_BucketAlignedExpiry (adversarial review of #636):
// the watermark must outlive the strike's own hourly bucket exactly —
// SumEventCounts keeps that bucket until HourBucket(now-window) passes it,
// so a second-precise cutoff opened a ≤1h hole where consumed evidence
// re-fired the ladder.
func TestConsumeEventCounts_BucketAlignedExpiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	ip := netip.MustParseAddr("203.0.113.56")
	strike := time.Date(2026, 9, 15, 12, 5, 0, 0, time.UTC) // 5 past the hour
	for range 5 {
		if err := db.IncrEventCount(ctx, ip, "ssh_fail", store.HourBucket(strike)); err != nil {
			t.Fatal(err)
		}
	}
	windows := map[time.Duration][]string{24 * time.Hour: {"ssh_fail"}}
	if err := db.ConsumeEventCounts(ctx, ip, windows, strike); err != nil {
		t.Fatal(err)
	}
	// Next day, 12:16: the 12:00 bucket is still summed, so the watermark
	// must still apply.
	at := strike.Add(24*time.Hour + 11*time.Minute)
	sums, err := db.SumEventCounts(ctx, ip, []string{"ssh_fail"}, store.HourBucket(at.Add(-24*time.Hour)))
	if err != nil || sums["ssh_fail"] != 5 {
		t.Fatalf("sum at +24h11m = %v err=%v, want the strike bucket (5)", sums, err)
	}
	if got, _ := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, at); got["ssh_fail"] != 5 {
		t.Fatalf("watermark expired before its bucket: consumed=%v", got)
	}
	// Once the bucket ages out of the sum, the watermark goes with it.
	at = strike.Add(25 * time.Hour)
	sums, _ = db.SumEventCounts(ctx, ip, []string{"ssh_fail"}, store.HourBucket(at.Add(-24*time.Hour)))
	got, _ := db.ConsumedEventCounts(ctx, ip, 24*time.Hour, at)
	if sums["ssh_fail"] != 0 || got["ssh_fail"] != 0 {
		t.Fatalf("at +25h: sum=%v consumed=%v, want both gone", sums, got)
	}
}

// TestEventCounts_IPv4MappedSpelling: parsers that hand over ::ffff:a.b.c.d
// and the decision engine (which unmaps) must hit the same counter and the
// same watermark row.
func TestEventCounts_IPv4MappedSpelling(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	plain := netip.MustParseAddr("203.0.113.57")
	mapped := netip.MustParseAddr("::ffff:203.0.113.57")
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	if err := db.IncrEventCount(ctx, mapped, "ssh_fail", store.HourBucket(now)); err != nil {
		t.Fatal(err)
	}
	sums, err := db.SumEventCounts(ctx, plain, []string{"ssh_fail"}, 0)
	if err != nil || sums["ssh_fail"] != 1 {
		t.Fatalf("mapped write not visible under the plain spelling: %v err=%v", sums, err)
	}
	windows := map[time.Duration][]string{24 * time.Hour: {"ssh_fail"}}
	if err := db.ConsumeEventCounts(ctx, plain, windows, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.ConsumedEventCounts(ctx, mapped, 24*time.Hour, now); got["ssh_fail"] != 1 {
		t.Fatalf("watermark not shared across spellings: %v", got)
	}
}

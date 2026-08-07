package ai

import (
	"net/netip"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func makeAgg(ip string, kinds map[string]int) sdk.Aggregate {
	addr, _ := netip.ParseAddr(ip)
	return sdk.Aggregate{
		IP:     addr,
		Window: 60 * time.Second,
		Count:  10,
		Kinds:  kinds,
	}
}

func makeVerdict(ip string, score int) sdk.Verdict {
	addr, _ := netip.ParseAddr(ip)
	return sdk.Verdict{IP: addr, Score: score, Source: "ai:anthropic"}
}

func TestCache_HitAndMiss(t *testing.T) {
	c := NewCache(5 * time.Minute)

	agg := makeAgg("1.1.1.1", map[string]int{"ssh_fail": 10})
	verdicts := []sdk.Verdict{makeVerdict("1.1.1.1", 80)}

	// Miss before Set.
	if got := c.Get(agg); got != nil {
		t.Errorf("expected cache miss, got %+v", got)
	}

	c.Set(agg, verdicts)

	// Hit after Set.
	got := c.Get(agg)
	if got == nil {
		t.Fatal("expected cache hit, got nil")
	}
	if len(got) != 1 || got[0].Score != 80 {
		t.Errorf("wrong cached value: %+v", got)
	}
}

// TestCache_SamePatternDifferentIP verifies that behavior-key ignores IP address.
func TestCache_SamePatternDifferentIP(t *testing.T) {
	c := NewCache(5 * time.Minute)

	kinds := map[string]int{"ssh_fail": 20}
	agg1 := makeAgg("1.1.1.1", kinds)
	agg2 := makeAgg("2.2.2.2", kinds) // different IP, same behavior

	verdicts := []sdk.Verdict{makeVerdict("1.1.1.1", 90)}
	c.Set(agg1, verdicts)

	got := c.Get(agg2)
	if got == nil {
		t.Fatal("same behavior pattern from different IP should be a cache hit")
	}
}

// TestCache_HitRewritesVerdictIP reproduces issue #311: the cache deliberately
// shares entries across IPs (behaviorKey excludes the IP), so a hit for IP B on
// an entry cached from IP A's traffic must return verdicts targeting B — never
// A. Replaying A's IP misdirects the decision engine (Action targets A, B
// evades the ban) and misattributes B's activity in the audit log.
func TestCache_HitRewritesVerdictIP(t *testing.T) {
	c := NewCache(5 * time.Minute)

	kinds := map[string]int{"ssh_fail": 20}
	aggA := makeAgg("192.0.2.10", kinds)
	aggB := makeAgg("198.51.100.99", kinds) // different IP, same behavior

	c.Set(aggA, []sdk.Verdict{makeVerdict("192.0.2.10", 90), makeVerdict("192.0.2.10", 75)})

	got := c.Get(aggB)
	if got == nil {
		t.Fatal("same behavior pattern from different IP should be a cache hit")
	}
	for i, v := range got {
		if v.IP != aggB.IP {
			t.Errorf("verdict[%d].IP = %s, want %s (cached verdict must be re-targeted to the requesting IP)", i, v.IP, aggB.IP)
		}
	}
}

// TestCache_HitReturnsCopy verifies a hit returns an independent copy: mutating
// the returned slice must not corrupt the stored entry for later consumers.
func TestCache_HitReturnsCopy(t *testing.T) {
	c := NewCache(5 * time.Minute)

	kinds := map[string]int{"ssh_fail": 20}
	aggA := makeAgg("192.0.2.10", kinds)
	aggB := makeAgg("198.51.100.99", kinds)

	c.Set(aggA, []sdk.Verdict{makeVerdict("192.0.2.10", 90)})

	first := c.Get(aggB)
	if first == nil {
		t.Fatal("expected cache hit")
	}
	first[0].Score = 1
	first[0].Reason = "mutated by consumer"

	second := c.Get(aggA)
	if second == nil {
		t.Fatal("expected cache hit")
	}
	if second[0].Score != 90 || second[0].Reason != "" {
		t.Errorf("stored entry was mutated through a returned slice: %+v", second[0])
	}
	if second[0].IP != aggA.IP {
		t.Errorf("verdict.IP = %s, want %s", second[0].IP, aggA.IP)
	}
}

// TestCache_DifferentPatternMiss verifies different kind counts produce different keys.
func TestCache_DifferentPatternMiss(t *testing.T) {
	c := NewCache(5 * time.Minute)

	agg1 := makeAgg("1.1.1.1", map[string]int{"ssh_fail": 10})
	agg2 := makeAgg("1.1.1.1", map[string]int{"ssh_fail": 99})

	c.Set(agg1, []sdk.Verdict{makeVerdict("1.1.1.1", 50)})
	if got := c.Get(agg2); got != nil {
		t.Errorf("different pattern should miss, got %+v", got)
	}
}

// TestCache_TTLExpiry verifies expired entries are evicted on Get.
func TestCache_TTLExpiry(t *testing.T) {
	c := NewCache(1 * time.Millisecond)

	agg := makeAgg("3.3.3.3", map[string]int{"scan": 5})
	c.Set(agg, []sdk.Verdict{makeVerdict("3.3.3.3", 70)})

	time.Sleep(5 * time.Millisecond)

	if got := c.Get(agg); got != nil {
		t.Errorf("expired entry should return nil, got %+v", got)
	}
	if c.Len() != 0 {
		t.Errorf("expired entry should be evicted, Len=%d", c.Len())
	}
}

// TestCache_ZeroTTLDisabled verifies a zero-TTL cache never hits.
func TestCache_ZeroTTLDisabled(t *testing.T) {
	c := NewCache(0)

	agg := makeAgg("4.4.4.4", map[string]int{"http_404": 100})
	c.Set(agg, []sdk.Verdict{makeVerdict("4.4.4.4", 55)})

	if got := c.Get(agg); got != nil {
		t.Errorf("zero-TTL cache should always miss, got %+v", got)
	}
}

// TestCache_Evict removes stale entries without touching live ones.
func TestCache_Evict(t *testing.T) {
	c := NewCache(100 * time.Millisecond)

	agg1 := makeAgg("1.1.1.1", map[string]int{"a": 1})
	agg2 := makeAgg("2.2.2.2", map[string]int{"b": 2})

	c.Set(agg1, []sdk.Verdict{makeVerdict("1.1.1.1", 10)})

	time.Sleep(150 * time.Millisecond)

	c.Set(agg2, []sdk.Verdict{makeVerdict("2.2.2.2", 20)}) // still live

	c.Evict()

	if c.Len() != 1 {
		t.Errorf("after Evict, want 1 entry, got %d", c.Len())
	}
	if got := c.Get(agg2); got == nil {
		t.Error("live entry should survive Evict")
	}
}

// ── Issue #402: allowlist-clamped verdicts must never be cached ──────────────

// TestCache_ClampedVerdictNotStored verifies that an allowlist-clamped
// (Score-0) verdict is not written to the cache: the entry is keyed by
// behavior signature, not IP, so caching a clamp would replay the zeroed
// score onto every non-allowlisted IP sharing the signature for a full
// cache TTL (issue #402, SECURITY-REVIEW §5).
func TestCache_ClampedVerdictNotStored(t *testing.T) {
	c := NewCache(5 * time.Minute)

	agg := makeAgg("192.0.2.10", map[string]int{"ssh_fail": 12})
	clamped := makeVerdict("192.0.2.10", 0)
	clamped.Reason = ReasonAllowlistClamped
	clamped.Source += AllowlistClampSourceSuffix

	c.Set(agg, []sdk.Verdict{clamped})

	if got := c.Get(agg); got != nil {
		t.Fatalf("clamped verdict was cached and replayed: %+v", got)
	}
	if c.Len() != 0 {
		t.Errorf("cache Len = %d, want 0 (no entry for all-clamped set)", c.Len())
	}
}

// TestCache_MixedClampedAndGenuine_StoresOnlyGenuine verifies that when a
// batch yields both clamped and genuine verdicts, only the genuine ones are
// stored.
func TestCache_MixedClampedAndGenuine_StoresOnlyGenuine(t *testing.T) {
	c := NewCache(5 * time.Minute)

	agg := makeAgg("192.0.2.11", map[string]int{"http_404": 40})
	clamped := makeVerdict("192.0.2.11", 0)
	clamped.Reason = ReasonAllowlistClamped
	clamped.Source += AllowlistClampSourceSuffix
	genuine := makeVerdict("192.0.2.11", 70)

	c.Set(agg, []sdk.Verdict{clamped, genuine})

	got := c.Get(agg)
	if len(got) != 1 {
		t.Fatalf("want exactly the genuine verdict cached, got %d: %+v", len(got), got)
	}
	if got[0].Score != 70 {
		t.Errorf("cached verdict score = %d, want 70", got[0].Score)
	}
}

// TestCache_GenuineScoreZeroStillCached verifies that a genuine benign
// verdict (Score 0 from the model, not from the allowlist clamp) is still
// cached — the clamp skip must not disable benign-result caching, which is
// what keeps AI cost proportional to pattern diversity.
func TestCache_GenuineScoreZeroStillCached(t *testing.T) {
	c := NewCache(5 * time.Minute)

	agg := makeAgg("192.0.2.12", map[string]int{"http_200": 3})
	benign := makeVerdict("192.0.2.12", 0)
	benign.Reason = "normal traffic"

	c.Set(agg, []sdk.Verdict{benign})

	if got := c.Get(agg); got == nil {
		t.Fatal("genuine Score-0 verdict should be cached, got miss")
	}
}

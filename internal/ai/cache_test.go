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

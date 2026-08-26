// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Cache is a TTL-based in-memory verdict cache keyed by IP behavior signature.
//
// The key is a hash of the aggregate's event kind counts and window duration —
// not the IP address — so identical traffic patterns from different IPs share
// cached verdicts. This avoids redundant API calls while keeping AI cost
// proportional to the diversity of attack patterns. Verdicts returned by Get
// are always re-targeted to the requesting aggregate's IP; the stored IP is
// never replayed (issue #311).
//
// It is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	verdicts  []sdk.Verdict
	expiresAt time.Time
}

// NewCache creates a Cache with the given entry TTL.
// A TTL of zero disables caching (all Gets return nil).
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// Get returns cached verdicts for agg's behavior signature, or nil on miss or expiry.
// Expired entries are deleted on access.
//
// Because entries are shared across IPs, every returned verdict is re-targeted
// to agg.IP: a hit for IP B on an entry cached from IP A's traffic must never
// replay A's address, or the decision engine would act on the wrong IP and the
// audit log would misattribute B's activity (issue #311). The returned slice is
// an independent copy; callers may mutate it freely.
func (c *Cache) Get(agg sdk.Aggregate) []sdk.Verdict {
	if c.ttl == 0 {
		return nil
	}
	key := behaviorKey(agg)

	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		return nil
	}
	out := make([]sdk.Verdict, len(e.verdicts))
	copy(out, e.verdicts)
	for i := range out {
		out[i].IP = agg.IP
	}
	return out
}

// Set stores verdicts for agg's behavior signature with the configured TTL.
// The slice is copied, so the entry is immune to later caller mutations.
//
// Allowlist-clamped verdicts are never stored (issue #402): the clamp is a
// property of one IP's allowlist membership, while the entry key is shared by
// every IP with the same traffic pattern — caching the clamp would hand every
// such IP a Score-0 replay (an AI-escalation evasion window of one cache TTL).
// A genuine model-issued Score 0 ("benign traffic") is still cached; only
// verdicts stamped by the provider clamp are skipped. If nothing survives the
// filter, no entry is created at all, so the next same-signature lookup is a
// MISS and consults the provider instead of hitting an empty entry.
func (c *Cache) Set(agg sdk.Aggregate, verdicts []sdk.Verdict) {
	if c.ttl == 0 {
		return
	}
	stored := make([]sdk.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		if IsAllowlistClamped(v) {
			continue
		}
		stored = append(stored, v)
	}
	if len(stored) == 0 {
		return
	}
	key := behaviorKey(agg)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = cacheEntry{
		verdicts:  stored,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Evict removes all expired entries. Call periodically to bound memory use.
func (c *Cache) Evict() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// Len returns the number of entries currently in the cache (including expired
// ones that haven't been evicted yet). Intended for metrics and tests.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// behaviorKey returns a SHA-256 hex digest of the aggregate's behavior:
// event kind counts and aggregation window. The IP address is excluded so
// identical attack patterns from different sources share the same cache entry.
func behaviorKey(agg sdk.Aggregate) string {
	type sig struct {
		Window string         `json:"w"`
		Kinds  map[string]int `json:"k"`
	}
	s := sig{Window: agg.Window.String(), Kinds: agg.Kinds}
	b, _ := json.Marshal(s) // map[string]int is always marshallable
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

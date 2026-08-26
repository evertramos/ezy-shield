// SPDX-License-Identifier: AGPL-3.0-only

// Package botverify implements forward-confirmed reverse DNS (FCrDNS)
// validation for well-known crawlers (issue #215).
//
// Naive User-Agent allowlisting is spoofable — attackers routinely claim to
// be Googlebot. The industry-standard check is FCrDNS: PTR lookup on the IP,
// verify the resolved name falls under the provider's published domains,
// then forward-resolve that name and require it to map back to the same IP.
// Only an IP that passes BOTH directions is treated as the bot it claims to
// be; everything else (PTR mismatch, forward mismatch, DNS timeout) fails
// closed to the normal ban path — a spoofer is banned like any attacker.
//
// DNS responses are untrusted input: lookups are bounded (timeout per
// operation, hard caps on names and addresses considered), results are never
// interpolated into queries or shell commands, and hostnames are length-
// capped before comparison. Verification runs only at decision time for
// candidate bans — never in the hot parse path — and results are cached with
// separate positive and negative TTLs.
package botverify

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Provider describes one verified-bot operator: how its User-Agent is
// claimed and which DNS suffixes its FCrDNS names must fall under.
type Provider struct {
	// Name identifies the provider in audits ("googlebot").
	Name string
	// UAContains are lowercase substrings; a request's User-Agent claiming
	// any of them makes the IP a verification candidate.
	UAContains []string
	// Domains are the DNS suffixes the PTR name must fall under
	// ("googlebot.com" matches "crawl-66-249-66-1.googlebot.com").
	Domains []string
}

// DefaultProviders returns the built-in provider table: the major crawlers
// whose operators document FCrDNS as the official verification mechanism.
func DefaultProviders() []Provider {
	return []Provider{
		{Name: "googlebot", UAContains: []string{"googlebot"}, Domains: []string{"googlebot.com", "google.com"}},
		{Name: "bingbot", UAContains: []string{"bingbot", "msnbot"}, Domains: []string{"search.msn.com"}},
		{Name: "applebot", UAContains: []string{"applebot"}, Domains: []string{"applebot.apple.com"}},
		{Name: "yandexbot", UAContains: []string{"yandexbot"}, Domains: []string{"yandex.com", "yandex.ru", "yandex.net"}},
		{Name: "baiduspider", UAContains: []string{"baiduspider"}, Domains: []string{"baidu.com", "baidu.jp"}},
		{Name: "duckduckbot", UAContains: []string{"duckduckbot"}, Domains: []string{"duckduckgo.com"}},
	}
}

// Merge overlays custom providers onto base: entries with a matching Name
// replace the base entry, new names append. Neither input is mutated.
func Merge(base, custom []Provider) []Provider {
	out := make([]Provider, len(base))
	copy(out, base)
	index := make(map[string]int, len(out))
	for i, p := range out {
		index[p.Name] = i
	}
	for _, p := range custom {
		if i, ok := index[p.Name]; ok {
			out[i] = p
			continue
		}
		index[p.Name] = len(out)
		out = append(out, p)
	}
	return out
}

// ClaimedProvider returns the first provider whose UA substring appears in
// ua (case-insensitive), or nil when the UA claims no known bot.
func ClaimedProvider(providers []Provider, ua string) *Provider {
	if ua == "" {
		return nil
	}
	low := strings.ToLower(ua)
	for i := range providers {
		for _, sub := range providers[i].UAContains {
			if sub != "" && strings.Contains(low, sub) {
				return &providers[i]
			}
		}
	}
	return nil
}

// Untrusted-DNS caps: how much of a hostile resolver's answer is even
// looked at.
const (
	maxPTRNames   = 3   // PTR names considered per IP
	maxFwdAddrs   = 16  // forward A/AAAA answers considered per name
	maxNameLength = 253 // RFC 1035 bound; longer answers are discarded
)

// lookupTimeout bounds each individual DNS operation.
const lookupTimeout = 2 * time.Second

// Cache TTLs. Positive results are stable (bot infrastructure rarely moves);
// negative results retry sooner so a transient DNS failure does not tar a
// genuine bot for hours.
const (
	positiveTTL = 6 * time.Hour
	negativeTTL = 15 * time.Minute
	maxCache    = 4096
)

// Resolver is the DNS dependency, satisfied by *net.Resolver and stubbed in
// tests.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type cacheEntry struct {
	verified bool
	until    time.Time
}

// Verifier performs cached FCrDNS validation.
type Verifier struct {
	resolver Resolver
	nowFn    func() time.Time

	mu    sync.Mutex
	cache map[netip.Addr]cacheEntry
}

// New creates a Verifier on resolver (pass net.DefaultResolver in
// production).
func New(resolver Resolver) *Verifier {
	return &Verifier{
		resolver: resolver,
		nowFn:    time.Now,
		cache:    make(map[netip.Addr]cacheEntry),
	}
}

// Verify reports whether ip forward-confirms as p. Timeouts and every DNS
// anomaly return false (fail closed to the normal ban path). Results are
// cached per IP.
func (v *Verifier) Verify(ctx context.Context, ip netip.Addr, p *Provider) bool {
	now := v.nowFn()
	v.mu.Lock()
	if e, ok := v.cache[ip]; ok && now.Before(e.until) {
		v.mu.Unlock()
		return e.verified
	}
	v.mu.Unlock()

	verified := v.fcrdns(ctx, ip, p)

	ttl := negativeTTL
	if verified {
		ttl = positiveTTL
	}
	v.mu.Lock()
	if len(v.cache) >= maxCache {
		for k, e := range v.cache {
			if !now.Before(e.until) {
				delete(v.cache, k)
			}
		}
	}
	if len(v.cache) < maxCache {
		v.cache[ip] = cacheEntry{verified: verified, until: now.Add(ttl)}
	}
	v.mu.Unlock()
	return verified
}

// fcrdns runs the two-direction check, uncached.
func (v *Verifier) fcrdns(ctx context.Context, ip netip.Addr, p *Provider) bool {
	ptrCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	names, err := v.resolver.LookupAddr(ptrCtx, ip.String())
	if err != nil || len(names) == 0 {
		return false
	}
	if len(names) > maxPTRNames {
		names = names[:maxPTRNames]
	}
	for _, name := range names {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		if host == "" || len(host) > maxNameLength || !domainMatches(host, p.Domains) {
			continue
		}
		if v.forwardConfirms(ctx, host, ip) {
			return true
		}
	}
	return false
}

// forwardConfirms resolves host and reports whether any answer equals ip.
func (v *Verifier) forwardConfirms(ctx context.Context, host string, ip netip.Addr) bool {
	fwdCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	addrs, err := v.resolver.LookupHost(fwdCtx, host)
	if err != nil {
		return false
	}
	if len(addrs) > maxFwdAddrs {
		addrs = addrs[:maxFwdAddrs]
	}
	for _, a := range addrs {
		got, err := netip.ParseAddr(a)
		if err != nil {
			continue // hostile or malformed answer — ignore
		}
		if got.Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

// domainMatches reports whether host equals a domain or is a subdomain of
// one (dot-anchored — "evilgooglebot.com" never matches "googlebot.com").
func domainMatches(host string, domains []string) bool {
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

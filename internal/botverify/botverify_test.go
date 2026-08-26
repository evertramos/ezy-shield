package botverify

// Tests for FCrDNS verification (issue #215) with a stub resolver: genuine
// bot, spoofed UA (PTR mismatch), forward mismatch, DNS timeout (fails
// closed), hostile answers (caps, dot-anchoring), and cache behavior.

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type stubResolver struct {
	ptr      map[string][]string
	fwd      map[string][]string
	ptrErr   error
	fwdErr   error
	ptrCalls atomic.Int32
}

func (s *stubResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	s.ptrCalls.Add(1)
	if s.ptrErr != nil {
		return nil, s.ptrErr
	}
	return s.ptr[addr], nil
}

func (s *stubResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if s.fwdErr != nil {
		return nil, s.fwdErr
	}
	return s.fwd[host], nil
}

func googlebot() *Provider {
	p := DefaultProviders()[0]
	return &p
}

func TestVerify_GenuineBot(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.10")
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {"crawl-192-0-2-10.googlebot.com."}},
		fwd: map[string][]string{"crawl-192-0-2-10.googlebot.com": {"192.0.2.10"}},
	}
	if !New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("genuine PTR+forward match must verify")
	}
}

func TestVerify_SpoofedUA_PTRMismatch(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.11")
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {"host-11.evil.example."}},
		fwd: map[string][]string{"host-11.evil.example": {"192.0.2.11"}},
	}
	if New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("PTR outside the provider domains must not verify")
	}
}

func TestVerify_DotAnchoredDomains(t *testing.T) {
	t.Parallel()
	// "evilgooglebot.com" must not satisfy "googlebot.com".
	ip := netip.MustParseAddr("192.0.2.12")
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {"crawler.evilgooglebot.com."}},
		fwd: map[string][]string{"crawler.evilgooglebot.com": {"192.0.2.12"}},
	}
	if New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("suffix match must be dot-anchored")
	}
}

func TestVerify_ForwardMismatch(t *testing.T) {
	t.Parallel()
	// PTR says googlebot, but the name resolves elsewhere — a hostile PTR
	// under the attacker's own reverse zone.
	ip := netip.MustParseAddr("192.0.2.13")
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {"real.googlebot.com."}},
		fwd: map[string][]string{"real.googlebot.com": {"198.51.100.99"}},
	}
	if New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("forward resolution must confirm the SAME ip")
	}
}

func TestVerify_DNSErrorFailsClosed(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.14")
	rs := &stubResolver{ptrErr: errors.New("i/o timeout")}
	if New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("DNS failure must fail closed (normal ban path)")
	}
}

func TestVerify_HostileAnswersIgnored(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.15")
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'a'
	}
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {string(long) + ".googlebot.com.", ""}},
		fwd: map[string][]string{},
	}
	if New(rs).Verify(context.Background(), ip, googlebot()) {
		t.Fatal("oversized/empty PTR answers must be discarded")
	}
	// Malformed forward answers are skipped, not fatal.
	ip2 := netip.MustParseAddr("192.0.2.16")
	rs2 := &stubResolver{
		ptr: map[string][]string{ip2.String(): {"c.googlebot.com."}},
		fwd: map[string][]string{"c.googlebot.com": {"not-an-ip", "192.0.2.16"}},
	}
	if !New(rs2).Verify(context.Background(), ip2, googlebot()) {
		t.Fatal("valid answer after a malformed one must still confirm")
	}
}

func TestVerify_CachePositiveAndNegative(t *testing.T) {
	t.Parallel()
	ip := netip.MustParseAddr("192.0.2.17")
	rs := &stubResolver{
		ptr: map[string][]string{ip.String(): {"c.googlebot.com."}},
		fwd: map[string][]string{"c.googlebot.com": {"192.0.2.17"}},
	}
	v := New(rs)
	now := time.Now()
	v.nowFn = func() time.Time { return now }

	for range 3 {
		if !v.Verify(context.Background(), ip, googlebot()) {
			t.Fatal("must verify")
		}
	}
	if got := rs.ptrCalls.Load(); got != 1 {
		t.Fatalf("PTR lookups = %d, want 1 (positive result cached)", got)
	}
	// Past the positive TTL the entry expires and DNS runs again.
	now = now.Add(positiveTTL + time.Minute)
	if !v.Verify(context.Background(), ip, googlebot()) {
		t.Fatal("must re-verify after TTL")
	}
	if got := rs.ptrCalls.Load(); got != 2 {
		t.Fatalf("PTR lookups = %d, want 2 after expiry", got)
	}

	// Negative caching: a failing IP is not re-looked-up within negativeTTL.
	bad := netip.MustParseAddr("192.0.2.18")
	before := rs.ptrCalls.Load()
	for range 3 {
		if v.Verify(context.Background(), bad, googlebot()) {
			t.Fatal("must not verify")
		}
	}
	if got := rs.ptrCalls.Load() - before; got != 1 {
		t.Fatalf("PTR lookups for negative = %d, want 1 (negative result cached)", got)
	}
	now = now.Add(negativeTTL + time.Minute)
	_ = v.Verify(context.Background(), bad, googlebot())
	if got := rs.ptrCalls.Load() - before; got != 2 {
		t.Fatalf("negative entry must expire after its shorter TTL, lookups = %d", got)
	}
}

func TestClaimedProvider(t *testing.T) {
	t.Parallel()
	providers := DefaultProviders()
	if p := ClaimedProvider(providers, "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"); p == nil || p.Name != "googlebot" {
		t.Fatalf("Googlebot UA not claimed: %v", p)
	}
	if p := ClaimedProvider(providers, "Mozilla/5.0 (compatible; bingbot/2.0)"); p == nil || p.Name != "bingbot" {
		t.Fatalf("bingbot UA not claimed: %v", p)
	}
	if p := ClaimedProvider(providers, "curl/8.0"); p != nil {
		t.Fatalf("plain UA claimed %v", p)
	}
	if p := ClaimedProvider(providers, ""); p != nil {
		t.Fatal("empty UA must claim nothing")
	}
}

func TestMerge_OverridesByName(t *testing.T) {
	t.Parallel()
	base := DefaultProviders()
	merged := Merge(base, []Provider{
		{Name: "googlebot", UAContains: []string{"googlebot"}, Domains: []string{"example.com"}},
		{Name: "mybot", UAContains: []string{"mybot"}, Domains: []string{"my.example"}},
	})
	if len(merged) != len(base)+1 {
		t.Fatalf("merged len = %d, want %d", len(merged), len(base)+1)
	}
	for _, p := range merged {
		if p.Name == "googlebot" && p.Domains[0] != "example.com" {
			t.Fatalf("override by name not applied: %v", p)
		}
	}
	// Base table untouched.
	if base[0].Domains[0] != "googlebot.com" {
		t.Fatalf("Merge mutated its input: %v", base[0])
	}
}

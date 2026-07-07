package cdndetect

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

// fakeResolver is a table-driven Resolver used by every test in this file.
// It never touches the network. Each domain maps to either a slice of
// addresses OR an error — matching net.Resolver's LookupNetIP contract.
type fakeResolver struct {
	answers map[string][]netip.Addr
	errs    map[string]error
	// calls records how many times LookupNetIP was called, so tests can
	// assert we didn't over-fetch.
	calls int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _ /*network*/, host string) ([]netip.Addr, error) {
	f.calls++
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	return f.answers[host], nil
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

// TestLoadProviders_EmbeddedFileParses is a smoke test that the shipped
// ranges.yaml decodes cleanly. Any hand-edit that breaks CIDR parsing will
// panic init() (see cdndetect.go) — this test catches it in CI without
// waiting for a full daemon start.
func TestLoadProviders_EmbeddedFileParses(t *testing.T) {
	t.Parallel()
	ps := Providers()
	if len(ps) == 0 {
		t.Fatal("Providers() returned nothing — embedded ranges.yaml is empty")
	}
	// Cloudflare MUST be populated in this cut. Stubs are allowed for the
	// rest, but "no cloudflare ranges" would silently break issue #43's
	// entire acceptance criterion.
	cf, ok := ProviderByID("cloudflare")
	if !ok {
		t.Fatal("cloudflare provider missing from embedded ranges")
	}
	if !cf.Populated() {
		t.Fatal("cloudflare provider has zero ranges — refresh from https://www.cloudflare.com/ips-v4")
	}
	// Sanity: Cloudflare should have both v4 and v6 ranges.
	var hasV4, hasV6 bool
	for _, p := range cf.Prefixes {
		if p.Addr().Is4() {
			hasV4 = true
		}
		if p.Addr().Is6() {
			hasV6 = true
		}
	}
	if !hasV4 || !hasV6 {
		t.Errorf("cloudflare ranges lack v4 or v6 coverage: v4=%v v6=%v", hasV4, hasV6)
	}
}

// TestLoadProviders_RejectsBadYAML covers the two failure modes that would
// slip in via a broken ranges.yaml PR: an invalid CIDR string and a duplicate
// provider id. Panics inside init() are inconvenient to test directly, so we
// exercise loadProviders on hand-rolled input instead.
func TestLoadProviders_RejectsBadYAML(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		raw     string
		wantErr string // substring
	}{
		{
			name: "invalid CIDR",
			raw: `providers:
  - id: bogus
    name: Bogus
    ranges:
      - 999.999.999.999/8
`,
			wantErr: "ranges[0]",
		},
		{
			name: "duplicate id",
			raw: `providers:
  - id: cf
    name: One
    ranges: [1.1.1.0/24]
  - id: cf
    name: Two
    ranges: [2.2.2.0/24]
`,
			wantErr: "duplicate",
		},
		{
			name: "missing name",
			raw: `providers:
  - id: nameless
    ranges: []
`,
			wantErr: "name is required",
		},
		{
			name:    "no providers",
			raw:     `providers: []`,
			wantErr: "no providers defined",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadProviders([]byte(tc.raw))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !contains(err.Error(), tc.wantErr) {
				t.Errorf("err=%v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// testProviders is a small, deterministic table used by MatchDomains tests
// so results don't depend on the real Cloudflare CIDR list. Two providers,
// non-overlapping.
func testProviders(t *testing.T) []Provider {
	t.Helper()
	raw := `providers:
  - id: cloudflare
    name: Cloudflare
    ranges:
      - 104.16.0.0/13
      - 2606:4700::/32
  - id: bunny
    name: Bunny.net
    ranges:
      - 45.10.244.0/22
`
	ps, err := loadProviders([]byte(raw))
	if err != nil {
		t.Fatalf("testProviders: %v", err)
	}
	return ps
}

func TestMatchDomains(t *testing.T) {
	t.Parallel()

	provs := testProviders(t)

	cases := []struct {
		name        string
		domain      string
		answer      []netip.Addr
		err         error
		wantMatched []string // provider IDs, in order of first match
	}{
		{
			name:        "cloudflare v4 hit",
			domain:      "site-cf.example.com",
			answer:      []netip.Addr{mustAddr(t, "104.21.13.183")},
			wantMatched: []string{"cloudflare"},
		},
		{
			name:        "cloudflare v6 hit",
			domain:      "site-cf-v6.example.com",
			answer:      []netip.Addr{mustAddr(t, "2606:4700:3036::abcd")},
			wantMatched: []string{"cloudflare"},
		},
		{
			name:        "non-CDN IP",
			domain:      "origin.example.com",
			answer:      []netip.Addr{mustAddr(t, "203.0.113.99")},
			wantMatched: nil,
		},
		{
			name:   "mixed A+AAAA one CF one origin",
			domain: "mixed.example.com",
			answer: []netip.Addr{
				mustAddr(t, "104.21.99.99"),
				mustAddr(t, "2001:db8::1"),
			},
			// Only the 104.21.x.x matches CF; the 2001:db8:: does not.
			wantMatched: []string{"cloudflare"},
		},
		{
			name:        "empty A record — no match, no error",
			domain:      "empty.example.com",
			answer:      nil,
			wantMatched: nil,
		},
		{
			name:        "lookup error — captured, not fatal",
			domain:      "broken.example.com",
			err:         errors.New("simulated NXDOMAIN"),
			wantMatched: nil,
		},
	}

	// Assemble one big fake resolver so all cases share it — verifies the
	// lookup count matches domain count (no over-fetch).
	fake := &fakeResolver{
		answers: make(map[string][]netip.Addr, len(cases)),
		errs:    make(map[string]error),
	}
	domains := make([]string, 0, len(cases))
	for _, tc := range cases {
		domains = append(domains, tc.domain)
		if tc.err != nil {
			fake.errs[tc.domain] = tc.err
			continue
		}
		fake.answers[tc.domain] = tc.answer
	}

	ctx := context.Background()
	results := MatchDomains(ctx, domains, Options{
		Resolver:      fake,
		Providers:     provs,
		LookupTimeout: 500 * time.Millisecond,
	})

	if len(results) != len(cases) {
		t.Fatalf("results len = %d, want %d", len(results), len(cases))
	}
	if fake.calls != len(cases) {
		t.Errorf("resolver called %d times, want %d (one per domain)", fake.calls, len(cases))
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := results[i]
			if r.Domain != tc.domain {
				t.Errorf("Domain = %q, want %q", r.Domain, tc.domain)
			}
			if tc.err != nil {
				if r.LookupError == nil {
					t.Errorf("expected LookupError, got nil")
				}
				if len(r.Matches) != 0 {
					t.Errorf("Matches non-empty despite lookup error: %+v", r.Matches)
				}
				return
			}
			var gotIDs []string
			for _, p := range r.CDNProviders() {
				gotIDs = append(gotIDs, p.ID)
			}
			if !reflect.DeepEqual(gotIDs, tc.wantMatched) {
				t.Errorf("providers=%v, want %v (matches=%+v)", gotIDs, tc.wantMatched, r.Matches)
			}
		})
	}
}

// TestMatchDomains_TrimsAndSkipsEmpty ensures the input sanitizer collapses
// whitespace-only entries so a botched split on VIRTUAL_HOST=" ,foo.com, "
// doesn't fire a garbage DNS lookup.
func TestMatchDomains_TrimsAndSkipsEmpty(t *testing.T) {
	t.Parallel()
	fake := &fakeResolver{
		answers: map[string][]netip.Addr{
			"foo.com": {mustAddr(t, "104.16.1.1")},
		},
	}
	results := MatchDomains(context.Background(),
		[]string{"", "  ", "foo.com"},
		Options{Resolver: fake, Providers: testProviders(t)})
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1 (whitespace-only inputs must be skipped)", len(results))
	}
	if fake.calls != 1 {
		t.Errorf("resolver called %d times, want 1", fake.calls)
	}
}

// TestMatchDomains_UnpopulatedProviderNeverMatches guards the stub-provider
// safety net: an entry with empty ranges must never contribute a false
// positive, even if a fake address collides with what a maintainer
// eventually types in.
func TestMatchDomains_UnpopulatedProviderNeverMatches(t *testing.T) {
	t.Parallel()
	raw := `providers:
  - id: cloudflare
    name: Cloudflare
    ranges: []
  - id: bunny
    name: Bunny.net
    ranges: []
`
	provs, err := loadProviders([]byte(raw))
	if err != nil {
		t.Fatalf("loadProviders: %v", err)
	}
	fake := &fakeResolver{
		answers: map[string][]netip.Addr{"x.com": {mustAddr(t, "1.2.3.4")}},
	}
	res := MatchDomains(context.Background(), []string{"x.com"},
		Options{Resolver: fake, Providers: provs})
	if len(res) != 1 {
		t.Fatalf("results len=%d", len(res))
	}
	if len(res[0].Matches) != 0 {
		t.Errorf("stub providers matched: %+v", res[0].Matches)
	}
}

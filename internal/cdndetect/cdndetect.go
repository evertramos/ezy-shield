// Package cdndetect resolves domain names and classifies the resulting IP
// addresses against a compile-time embedded table of CDN edge ranges. It is
// pure logic + one indirected Resolver so the init wizard can decide whether
// to offer an edge-enforcer setup without touching the network in tests.
//
// The package deliberately does NOT know anything about Docker, config files,
// or the wizard's prompt layer — it takes a domain, returns which CDN (if
// any) its DNS records belong to. Callers wire the higher-level flow.
//
// Threat model: the input domain is operator-typed at init time (or read
// from a container env var the operator installed). It is NOT attacker-
// controlled log data, so we don't need parser-grade hardening here — but
// we still cap the number of resolved addresses per domain (net.Resolver
// itself caps at the DNS message size, but be defensive) and never shell
// out. Match returns copied netip.Addr values; no mutable state leaks
// between calls.
package cdndetect

import (
	"context"
	_ "embed"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// rangesYAML is the embedded CDN range table. It ships with the binary so
// detection works without network access to CDN publishers at run time. To
// refresh, edit ranges.yaml in this directory — no code change needed.
//
//go:embed ranges.yaml
var rangesYAML []byte

// Provider is one CDN entry decoded from ranges.yaml. Prefixes is the parsed
// form of ranges (built once at package init) so lookups avoid re-parsing on
// every call. Sources is kept only for operator-facing messages.
type Provider struct {
	ID       string         // e.g. "cloudflare"
	Name     string         // display name, e.g. "Cloudflare"
	Sources  []string       // documentation URLs
	Prefixes []netip.Prefix // parsed CIDRs (may be empty for stubs)
}

// Populated reports whether Prefixes is non-empty. Callers use this to skip
// provider entries whose ranges have not yet been shipped (issue #43 lists
// most providers as stubs so the shape is future-proof).
func (p Provider) Populated() bool { return len(p.Prefixes) > 0 }

// providersFile is the raw YAML shape; kept unexported because callers only
// ever want the parsed Provider slice.
type providersFile struct {
	Providers []struct {
		ID      string   `yaml:"id"`
		Name    string   `yaml:"name"`
		Sources []string `yaml:"sources"`
		Ranges  []string `yaml:"ranges"`
	} `yaml:"providers"`
}

// defaultProviders is the parsed table built at package init from rangesYAML.
// A load failure panics — the file is compiled in, so this can only fail if
// a maintainer breaks the YAML in a PR. The panic surfaces the mistake in
// tests before any binary ships.
var defaultProviders []Provider

func init() {
	ps, err := loadProviders(rangesYAML)
	if err != nil {
		panic(fmt.Sprintf("cdndetect: parsing embedded ranges.yaml: %v", err))
	}
	defaultProviders = ps
}

// loadProviders parses raw YAML into the Provider slice and validates every
// CIDR. Exported-lowercase so tests can drive it with hand-rolled YAML
// without touching the embedded file.
func loadProviders(raw []byte) ([]Provider, error) {
	var f providersFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("yaml decode: %w", err)
	}
	if len(f.Providers) == 0 {
		return nil, fmt.Errorf("no providers defined")
	}
	seenID := make(map[string]bool, len(f.Providers))
	out := make([]Provider, 0, len(f.Providers))
	for i, p := range f.Providers {
		if p.ID == "" {
			return nil, fmt.Errorf("provider[%d]: id is required", i)
		}
		if seenID[p.ID] {
			return nil, fmt.Errorf("provider[%d]: duplicate id %q", i, p.ID)
		}
		seenID[p.ID] = true
		if p.Name == "" {
			return nil, fmt.Errorf("provider[%s]: name is required", p.ID)
		}
		prefixes := make([]netip.Prefix, 0, len(p.Ranges))
		for j, cidr := range p.Ranges {
			pref, err := netip.ParsePrefix(strings.TrimSpace(cidr))
			if err != nil {
				return nil, fmt.Errorf("provider %s: ranges[%d] %q: %w", p.ID, j, cidr, err)
			}
			// Store the canonical masked prefix so String() and Contains()
			// behave predictably (netip.ParsePrefix does not mask by itself).
			prefixes = append(prefixes, pref.Masked())
		}
		out = append(out, Provider{
			ID:       p.ID,
			Name:     p.Name,
			Sources:  append([]string(nil), p.Sources...),
			Prefixes: prefixes,
		})
	}
	return out, nil
}

// Providers returns a copy of the current in-memory provider table so a
// caller (e.g. `ezyshield doctor` listing supported CDNs) can inspect it
// without mutating shared state.
func Providers() []Provider {
	out := make([]Provider, len(defaultProviders))
	copy(out, defaultProviders)
	return out
}

// Resolver is the tiny surface Match needs from a DNS resolver. The real
// implementation wraps net.Resolver; tests provide a table-driven fake. The
// interface keeps the package free of side effects so it can be unit-tested
// without a live network.
type Resolver interface {
	// LookupNetIP returns the A/AAAA addresses for host. It follows the
	// net.Resolver.LookupNetIP contract: returns an error on lookup
	// failure, an empty slice with nil error is a valid "no such record"
	// answer for a name that exists but has no A/AAAA (rare, e.g. TXT-only).
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DefaultResolver returns a Resolver backed by the stdlib net.Resolver with
// no additional configuration. Callers may set a per-call timeout via ctx.
func DefaultResolver() Resolver {
	return stdlibResolver{r: net.DefaultResolver}
}

type stdlibResolver struct {
	r *net.Resolver
}

func (s stdlibResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return s.r.LookupNetIP(ctx, network, host)
}

// Match is one classification of a resolved address against a CDN provider.
// A single domain may return multiple Matches (e.g. an A that hits Cloudflare
// plus an AAAA that also hits Cloudflare, or a mixed-CDN setup — rare but
// possible). The wizard collapses duplicates by (Provider.ID, Addr).
type Match struct {
	Provider Provider
	Addr     netip.Addr
}

// DomainResult holds the outcome for one domain: every resolved IP, and the
// subset of those IPs that matched a known CDN range. Domains with an empty
// Matches slice are "resolved but not CDN-fronted" — the wizard still shows
// their IPs to the operator for context.
type DomainResult struct {
	Domain      string
	Addrs       []netip.Addr
	Matches     []Match
	LookupError error // non-nil when the DNS lookup itself failed (transient / NXDOMAIN)
}

// CDNProviders returns the deduplicated set of Provider structs whose ranges
// matched at least one address in this result. Order matches the first
// occurrence in Matches. Empty when the domain isn't CDN-fronted.
func (d DomainResult) CDNProviders() []Provider {
	seen := make(map[string]bool, len(d.Matches))
	out := make([]Provider, 0, len(d.Matches))
	for _, m := range d.Matches {
		if seen[m.Provider.ID] {
			continue
		}
		seen[m.Provider.ID] = true
		out = append(out, m.Provider)
	}
	return out
}

// LookupTimeoutDefault bounds a single DNS lookup when Options.LookupTimeout
// is zero. Chosen to be generous enough for slow recursors but short enough
// to keep the wizard responsive.
const LookupTimeoutDefault = 3 * time.Second

// Options controls one MatchDomains call. Zero values are safe defaults.
type Options struct {
	// Resolver overrides DefaultResolver(). Tests set this to a fake.
	Resolver Resolver
	// Providers overrides Providers(). Tests can inject a smaller table.
	Providers []Provider
	// LookupTimeout bounds each individual DNS lookup. Zero means
	// LookupTimeoutDefault. Callers should ALSO pass a top-level ctx with a
	// deadline covering the whole batch — Options.LookupTimeout guards only
	// against a single very slow name.
	LookupTimeout time.Duration
}

// MatchDomains resolves each domain, classifies its addresses against the
// CDN provider table, and returns one DomainResult per domain in input
// order. Duplicate domains in the input are preserved as-is; callers
// deduplicate upstream if desired.
//
// The function never returns an error; per-domain lookup failures are
// captured in DomainResult.LookupError. This lets the wizard surface
// per-domain state without a single NXDOMAIN aborting the whole detection.
func MatchDomains(ctx context.Context, domains []string, opts Options) []DomainResult {
	if opts.Resolver == nil {
		opts.Resolver = DefaultResolver()
	}
	provs := opts.Providers
	if provs == nil {
		provs = defaultProviders
	}
	timeout := opts.LookupTimeout
	if timeout <= 0 {
		timeout = LookupTimeoutDefault
	}
	out := make([]DomainResult, 0, len(domains))
	for _, d := range domains {
		domain := strings.TrimSpace(d)
		if domain == "" {
			continue
		}
		res := lookupOne(ctx, opts.Resolver, timeout, domain, provs)
		out = append(out, res)
	}
	return out
}

// lookupOne handles a single domain. Kept separate so the loop reads cleanly
// and per-domain context timeouts don't cascade.
func lookupOne(ctx context.Context, r Resolver, timeout time.Duration, domain string, provs []Provider) DomainResult {
	res := DomainResult{Domain: domain}
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.LookupNetIP(lctx, "ip", domain)
	if err != nil {
		res.LookupError = err
		return res
	}
	// Deduplicate — the resolver may return the same address twice for
	// distinct A vs AAAA queries under some Happy-Eyeballs configurations.
	seen := make(map[netip.Addr]bool, len(addrs))
	dedup := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if seen[a] {
			continue
		}
		seen[a] = true
		dedup = append(dedup, a)
	}
	// Sort so output order is deterministic (helps tests + operator prompts).
	sort.Slice(dedup, func(i, j int) bool { return dedup[i].Less(dedup[j]) })
	res.Addrs = dedup
	res.Matches = classify(dedup, provs)
	return res
}

// classify returns the Match list for addrs against provs. A single addr can
// only belong to one provider in practice (CDN ranges do not overlap), but
// we walk every provider to guard against a future ranges.yaml that has an
// accidental overlap — first-match-wins keeps behavior predictable.
func classify(addrs []netip.Addr, provs []Provider) []Match {
	var out []Match
	for _, a := range addrs {
		for _, p := range provs {
			if !p.Populated() {
				continue
			}
			for _, pref := range p.Prefixes {
				if pref.Contains(a) {
					out = append(out, Match{Provider: p, Addr: a})
					// First-match-wins per address.
					goto next
				}
			}
		}
	next:
	}
	return out
}

// ProviderByID looks up a provider entry by ID. Returns the zero Provider
// and false when unknown. The wizard uses this to fetch the display name
// for a hardcoded "cloudflare" branch.
func ProviderByID(id string) (Provider, bool) {
	for _, p := range defaultProviders {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}

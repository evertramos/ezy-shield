package config

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultBanThreshold is the default minimum score to trigger a strike.
const DefaultBanThreshold = 70

// DefaultObserveThreshold is the default minimum score to log/notify without banning.
const DefaultObserveThreshold = 40

// DefaultMaxBansPerMinute is the global ban-rate safety cap.
const DefaultMaxBansPerMinute = 30

// DefaultStrikes is the strike escalation table used when policy.yaml omits strikes.
// A TTL of zero means permanent ban.
var DefaultStrikes = []StrikeEntry{
	{TTL: Duration(5 * time.Minute)},
	{TTL: Duration(time.Hour)},
	{TTL: Duration(24 * time.Hour)},
	{TTL: Duration(168 * time.Hour)},
	{TTL: Duration(0)}, // permanent
}

// Policy holds enforcement policy loaded from policy.yaml.
type Policy struct {
	Armed            bool          `yaml:"armed"`
	BanThreshold     int           `yaml:"ban_threshold"`
	ObserveThreshold int           `yaml:"observe_threshold"`
	Strikes          []StrikeEntry `yaml:"strikes"`
	MaxBansPerMinute int           `yaml:"max_bans_per_minute"`
	Allowlist        []string      `yaml:"allowlist"`
	AdminCIDRs       []string      `yaml:"admin_cidrs"`
	// BlockCountries lists ISO 3166-1 alpha-2 country codes whose traffic receives
	// an immediate score boost (+GeoBlockScore) toward the ban threshold.
	// Requires GeoIP enrichment; silently skipped when enrichment is inactive.
	// Example: [CN, RU, KP]
	BlockCountries []string `yaml:"block_countries"`
	// BlockASNs lists autonomous system numbers to block (format "AS12345").
	// Same semantics as BlockCountries. Example: [AS16276, AS14061]
	BlockASNs []string `yaml:"block_asns"`
}

// GeoBlockScore is the score added to verdicts from blocked countries or ASNs.
// Set high enough to push any existing score above the default ban threshold (70).
const GeoBlockScore = 100

// StrikeEntry is one row in the strike escalation table.
type StrikeEntry struct {
	TTL Duration `yaml:"ttl"`
}

// Duration wraps time.Duration so gopkg.in/yaml.v3 can parse Go duration
// strings (e.g. "5m", "24h") and integer zero (0 = permanent ban).
type Duration time.Duration

// AsDuration returns the underlying time.Duration.
func (d Duration) AsDuration() time.Duration {
	return time.Duration(d)
}

// UnmarshalYAML parses Go duration strings ("5m", "1h") and integer 0.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	switch value.Tag {
	case "!!int":
		var n int64
		if err := value.Decode(&n); err != nil {
			return fmt.Errorf("line %d: invalid duration: %w", value.Line, err)
		}
		*d = Duration(n)
		return nil
	default:
		var s string
		if err := value.Decode(&s); err != nil {
			return fmt.Errorf("line %d: invalid duration: %w", value.Line, err)
		}
		dur, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("line %d: invalid duration %q: %w", value.Line, s, err)
		}
		*d = Duration(dur)
		return nil
	}
}

// LoadPolicy reads and strictly validates policy.yaml at path.
// Unknown keys are rejected; default values are applied where the policy omits them.
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path) //nolint:gosec // path is admin-controlled config location
	if err != nil {
		return nil, fmt.Errorf("opening policy %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only close; error irrelevant
	return LoadPolicyReader(f, path)
}

// LoadPolicyReader reads and strictly validates Policy from r.
// name is used only for error messages.
func LoadPolicyReader(r io.Reader, name string) (*Policy, error) {
	var p Policy
	if err := decodeStrict(r, name, &p); err != nil {
		return nil, err
	}
	p.applyDefaults()
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validating %s: %w", name, err)
	}
	return &p, nil
}

// applyDefaults fills in values that are safe to omit from policy.yaml.
// Note: ObserveThreshold is intentionally not defaulted here because 0 is a valid
// setting (notify for any score below ban_threshold), and Go's zero value would
// make it impossible to distinguish "not set" from "explicitly zero".
func (p *Policy) applyDefaults() {
	if len(p.Strikes) == 0 {
		p.Strikes = make([]StrikeEntry, len(DefaultStrikes))
		copy(p.Strikes, DefaultStrikes)
	}
	if p.BanThreshold == 0 {
		p.BanThreshold = DefaultBanThreshold
	}
	if p.MaxBansPerMinute == 0 {
		p.MaxBansPerMinute = DefaultMaxBansPerMinute
	}
}

// Validate checks policy constraints; called automatically by LoadPolicyReader.
func (p *Policy) Validate() error {
	if p.BanThreshold < 1 || p.BanThreshold > 100 {
		return fmt.Errorf("ban_threshold: %d is out of range [1, 100]", p.BanThreshold)
	}
	if p.ObserveThreshold < 0 || p.ObserveThreshold >= p.BanThreshold {
		return fmt.Errorf(
			"observe_threshold: %d must be in [0, ban_threshold) = [0, %d)",
			p.ObserveThreshold, p.BanThreshold)
	}
	if p.MaxBansPerMinute <= 0 {
		return fmt.Errorf("max_bans_per_minute: must be > 0, got %d", p.MaxBansPerMinute)
	}
	for i, entry := range p.Allowlist {
		if err := parseIPOrPrefix(entry); err != nil {
			return fmt.Errorf("allowlist[%d]: %w", i, err)
		}
	}
	for i, cidr := range p.AdminCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("admin_cidrs[%d]: invalid CIDR %q: %w", i, cidr, err)
		}
	}
	for i, c := range p.BlockCountries {
		if len(c) != 2 {
			return fmt.Errorf("block_countries[%d]: %q is not a valid ISO 3166-1 alpha-2 code", i, c)
		}
	}
	for i, a := range p.BlockASNs {
		if _, err := parseASN(a); err != nil {
			return fmt.Errorf("block_asns[%d]: %w", i, err)
		}
	}
	return nil
}

// parseASN parses an ASN string of the form "AS12345" and returns the numeric value.
func parseASN(s string) (uint32, error) {
	if len(s) < 3 || (s[0] != 'A' && s[0] != 'a') || (s[1] != 'S' && s[1] != 's') {
		return 0, fmt.Errorf("ASN %q must be in the form AS<number>", s)
	}
	var n uint64
	for _, c := range s[2:] {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("ASN %q must be in the form AS<number>", s)
		}
		n = n*10 + uint64(c-'0')
		if n > 4294967295 {
			return 0, fmt.Errorf("ASN %q number exceeds uint32 max", s)
		}
	}
	return uint32(n), nil //nolint:gosec // validated above
}

// parseIPOrPrefix accepts a bare IP address or a CIDR prefix.
func parseIPOrPrefix(s string) error {
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP address or CIDR %q", s)
}

package config

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultBanThreshold is the default minimum score to trigger a strike.
const DefaultBanThreshold = 70

// DefaultObserveThreshold is the default minimum score to log/notify without banning.
const DefaultObserveThreshold = 40

// DefaultMaxBansPerMinute is the global ban-rate safety cap.
const DefaultMaxBansPerMinute = 30

// DefaultBanIneffectiveGrace is the default (and minimum) grace period before
// traffic during a ban is considered anomalous. In-flight requests, CDN
// buffering, and log-write latency can cause legitimate hits after a ban.
const DefaultBanIneffectiveGrace = 90 * time.Second

// DefaultBanIneffectiveMinEvents is the default (and minimum) number of
// suppressed events after grace to trigger a ban_ineffective diagnostic.
const DefaultBanIneffectiveMinEvents = 3

// DefaultEscalationExemptWindow is how long after a ban's scheduled end a
// re-offense still counts as an escalation exempt from max_bans_per_minute.
// The exemption exists because re-banning an IP that was blocked until
// moments ago adds no new-lockout exposure; an IP whose last ban ended long
// ago is a fresh ban for rate-limit purposes and must count against the cap.
const DefaultEscalationExemptWindow = 24 * time.Hour

// MaxEscalationExemptWindow is the ceiling for escalation_exempt_window.
// A larger window weakens the max_bans_per_minute safety cap (Hard Rule §1),
// so policy may tighten the window but never widen it past this bound.
const MaxEscalationExemptWindow = 7 * 24 * time.Hour

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
//
// Armed is the only field that can change at runtime (the arm/disarm socket
// verbs, issue #228). Runtime readers MUST use IsArmed(); mutations go
// through SetArmed(). Direct access to the Armed field is safe only during
// load/validate, before the daemon's goroutines start.
type Policy struct {
	// armedMu guards Armed for runtime flips. It sits next to the field it
	// protects; Policy must never be copied by value after startup.
	armedMu sync.RWMutex `yaml:"-"`

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

	// BanIneffectiveGrace is the grace period after a ban before traffic is
	// considered anomalous (in-flight requests, CDN buffering, log latency).
	// Minimum 90s; defaults to 90s if omitted or below minimum.
	BanIneffectiveGrace Duration `yaml:"ban_ineffective_grace"`
	// BanIneffectiveMinEvents is the minimum number of suppressed events after
	// the grace period to trigger a ban_ineffective diagnostic.
	// Minimum 3; defaults to 3 if omitted or below minimum.
	BanIneffectiveMinEvents int `yaml:"ban_ineffective_min_events"`

	// EscalationExemptWindow bounds the escalation exemption from
	// max_bans_per_minute: a strike > 1 skips the cap only when the previous
	// ban ended within this window. Defaults to 24h if omitted or <= 0;
	// values above 7d are clamped down (widening weakens the safety cap).
	EscalationExemptWindow Duration `yaml:"escalation_exempt_window"`
}

// IsArmed reports whether enforcement is live. It is the required accessor
// for every runtime read of the armed state (the arm/disarm verbs flip it
// while the pipeline is running).
func (p *Policy) IsArmed() bool {
	p.armedMu.RLock()
	defer p.armedMu.RUnlock()
	return p.Armed
}

// SetArmed flips the armed state at runtime. Callers are responsible for
// persisting the change (RewriteArmed) and auditing it.
func (p *Policy) SetArmed(armed bool) {
	p.armedMu.Lock()
	defer p.armedMu.Unlock()
	p.Armed = armed
}

// armedLineRe matches the top-level `armed:` line of policy.yaml, capturing
// indentation and any trailing comment so a rewrite preserves both.
var armedLineRe = regexp.MustCompile(`(?m)^(armed[ \t]*:[ \t]*)(true|false)([ \t]*(?:#.*)?)$`)

// RewriteArmed surgically rewrites the `armed:` value in the policy file at
// path, preserving every other byte — comments, ordering, and formatting are
// operator property. It refuses (returning an error, changing nothing) when
// the file does not contain exactly one recognisable top-level armed line:
// guessing on an ambiguous file could flip the wrong thing in a security
// policy. The write is atomic (temp file + rename) and preserves the
// original file mode.
func RewriteArmed(path string, armed bool) error {
	data, err := os.ReadFile(path) //nolint:gosec // path is admin-controlled config location
	if err != nil {
		return fmt.Errorf("reading policy %s: %w", path, err)
	}
	matches := armedLineRe.FindAllIndex(data, -1)
	if len(matches) != 1 {
		return fmt.Errorf("policy %s: expected exactly one top-level 'armed:' line, found %d — edit the file manually", path, len(matches))
	}

	val := "false"
	if armed {
		val = "true"
	}
	updated := armedLineRe.ReplaceAll(data, []byte("${1}"+val+"${3}"))

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat policy %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, updated, info.Mode().Perm()); err != nil { //nolint:gosec // G703: path is the admin-controlled policy location (daemon config), not user input
		return fmt.Errorf("writing policy temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing policy %s: %w", path, err)
	}
	return nil
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

// MarshalYAML renders the duration in a form UnmarshalYAML accepts — the Go
// duration string ("5m0s"), or integer 0 for the permanent-ban marker — so a
// `config show` dump round-trips through LoadPolicyReader unchanged.
func (d Duration) MarshalYAML() (any, error) {
	if d == 0 {
		return 0, nil
	}
	return time.Duration(d).String(), nil
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
	// ban_ineffective thresholds: enforce minimums (per ADR-0009)
	if p.BanIneffectiveGrace.AsDuration() < DefaultBanIneffectiveGrace {
		p.BanIneffectiveGrace = Duration(DefaultBanIneffectiveGrace)
	}
	if p.BanIneffectiveMinEvents < DefaultBanIneffectiveMinEvents {
		p.BanIneffectiveMinEvents = DefaultBanIneffectiveMinEvents
	}
	// escalation_exempt_window: default when omitted, ceiling when widened —
	// tightening (any positive value below the ceiling) is always allowed.
	if p.EscalationExemptWindow.AsDuration() <= 0 {
		p.EscalationExemptWindow = Duration(DefaultEscalationExemptWindow)
	}
	if p.EscalationExemptWindow.AsDuration() > MaxEscalationExemptWindow {
		p.EscalationExemptWindow = Duration(MaxEscalationExemptWindow)
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

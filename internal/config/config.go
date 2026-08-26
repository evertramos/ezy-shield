// Package config provides YAML loading and strict validation for ezyshield
// configuration files. No secret values may appear in config files; use
// SecretRef for any credential field so the loader rejects inline values.
package config

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/nftnames"
)

// DefaultRulesDir is the drop-in overlay directory scanned for rule
// customizations (*.yaml, lexical order) when rules_dir is not set in
// config.yaml. See internal/rules.New for the layering semantics.
const DefaultRulesDir = "/etc/ezyshield/rules.d"

// Config holds the main runtime configuration loaded from config.yaml.
// No secrets appear here; credential fields use SecretRef.
type Config struct {
	DataDir    string `yaml:"data_dir"`
	SocketPath string `yaml:"socket_path"`
	// RulesPath is the DEPRECATED whole-file rule replacement: when set,
	// the file replaces the embedded base entirely and rules.d drop-ins
	// are ignored — the install stops receiving upstream rule tuning.
	// Prefer RulesDir drop-ins.
	RulesPath string `yaml:"rules_path"`
	// RulesDir overrides the rules.d drop-in directory (default
	// DefaultRulesDir). Drop-ins merge over the embedded base by rule
	// name and survive binary updates.
	RulesDir   string         `yaml:"rules_dir"`
	Log        LogConfig      `yaml:"log"`
	Collectors []CollectorCfg `yaml:"collectors"`
	Enforce    *EnforceCfg    `yaml:"enforce"`
	AI         *AICfg         `yaml:"ai"`
	Notify     *NotifyCfg     `yaml:"notify"`
	Enrich     *EnrichCfg     `yaml:"enrich"`
	Dashboard  *DashboardCfg  `yaml:"dashboard"`
}

// DashboardCfg configures the localhost-only web UI (see docs/dashboard.md).
// Both fields are optional; the dashboard command falls back to safe defaults
// (127.0.0.1:9090 and <data_dir>/dashboard.db).
type DashboardCfg struct {
	// Addr is the "host:port" the dashboard binds to. Must resolve to a
	// loopback address (127.0.0.1, ::1, or the literal "localhost").
	// Any other value is refused at startup — no 0.0.0.0 escape hatch.
	Addr string `yaml:"addr"`
	// AuthDBPath is the SQLite file storing the admin password hash.
	// Defaults to <data_dir>/dashboard.db when empty.
	AuthDBPath string `yaml:"auth_db_path"`
	// MetricsAuth controls whether GET /metrics requires the dashboard
	// session auth (issue #183). nil/true (default) = auth required;
	// false = unauthenticated scrape allowed — safe ONLY because the
	// listener is loopback-only, and still throttled.
	MetricsAuth *bool `yaml:"metrics_auth,omitempty"`
}

// EnrichCfg configures GeoIP/ASN enrichment via MaxMind MMDB databases.
// LicenseKey must be an "env:VARNAME" reference when auto_update is true;
// inline values are rejected at load time.
type EnrichCfg struct {
	// DBPath is the filesystem path to GeoLite2-Country.mmdb.
	DBPath string `yaml:"db_path"`
	// ASNPath is the filesystem path to GeoLite2-ASN.mmdb.
	ASNPath string `yaml:"asn_path"`
	// AutoUpdate enables weekly download of fresh MMDB files from MaxMind.
	// Requires license_key to be set.
	AutoUpdate bool `yaml:"auto_update"`
	// LicenseKey is the MaxMind account license key used for GeoLite2 downloads.
	// Must be an "env:VARNAME" reference; inline values are rejected.
	LicenseKey SecretRef `yaml:"license_key"`
}

// NotifyCfg configures notification channels.
// All credential fields use SecretRef; inline secrets are rejected at load time.
type NotifyCfg struct {
	// RateLimitPerMinute is the maximum number of notifications per channel per minute.
	// Defaults to 5 when omitted or zero.
	RateLimitPerMinute int `yaml:"rate_limit_per_minute"`
	// DedupWindowSec suppresses repeat notifications for the same IP+reason
	// within this window. Defaults to 600 seconds (10 minutes) when omitted or zero.
	DedupWindowSec int `yaml:"dedup_window_sec"`
	// NotifyOnlyWindowSec is the per-(IP, rule) suppression window for
	// notify_only events (issue #421): the first event notifies immediately,
	// repeats within the window fold into a single summary notification.
	// Omitted or 0 = 3600 (1 hour); negative = disabled (every event
	// notifies, pre-#421 behavior). Audit log rows are never suppressed.
	NotifyOnlyWindowSec int          `yaml:"notify_only_window_sec"`
	Telegram            *TelegramCfg `yaml:"telegram"`
	Email               *EmailCfg    `yaml:"email"`
	Slack               *SlackCfg    `yaml:"slack"`
	Discord             *DiscordCfg  `yaml:"discord"`
	Webhook             *WebhookCfg  `yaml:"webhook"`
}

// SlackCfg configures the Slack incoming webhook notification channel.
// WebhookURL must be an "env:VARNAME" reference; inline values are rejected.
type SlackCfg struct {
	WebhookURL SecretRef `yaml:"webhook_url"`
	// Channel overrides the default channel configured in the Slack app (e.g. "#security").
	// Leave empty to use the app default.
	Channel  string   `yaml:"channel"`
	Severity []string `yaml:"severity"`
}

// DiscordCfg configures the Discord webhook notification channel.
// WebhookURL must be an "env:VARNAME" reference; inline values are rejected.
type DiscordCfg struct {
	WebhookURL SecretRef `yaml:"webhook_url"`
	Severity   []string  `yaml:"severity"`
}

// WebhookCfg configures a generic HTTP webhook notification channel.
// URL must be an "env:VARNAME" reference; inline values are rejected.
// Headers values are passed verbatim on every request; use them for bearer tokens
// or API keys (values must come from environment variables, not inline config).
type WebhookCfg struct {
	URL      SecretRef         `yaml:"url"`
	Headers  map[string]string `yaml:"headers"`
	Severity []string          `yaml:"severity"`
}

// TelegramCfg configures the Telegram Bot notification channel.
// BotToken must be an "env:VARNAME" reference; inline values are rejected.
type TelegramCfg struct {
	BotToken SecretRef `yaml:"bot_token"`
	ChatIDs  []string  `yaml:"chat_ids"`
	// Severity lists which severity levels to forward ("info", "warn", "critical").
	// Empty means all severities.
	Severity []string `yaml:"severity"`
}

// EmailCfg configures the SMTP email notification channel.
// Password must be an "env:VARNAME" reference; inline values are rejected.
type EmailCfg struct {
	From     string    `yaml:"from"`
	To       []string  `yaml:"to"`
	Host     string    `yaml:"host"`
	Port     int       `yaml:"port"`
	Username string    `yaml:"username"`
	Password SecretRef `yaml:"password"`
	// TLS controls the connection mode: "starttls" (default, port 587),
	// "tls" (implicit TLS, port 465), or "none" (plaintext, not recommended).
	TLS string `yaml:"tls"`
	// Severity lists which severity levels to forward. Empty means all severities.
	Severity []string `yaml:"severity"`
}

// LogConfig holds structured-logging settings.
type LogConfig struct {
	Level string `yaml:"level"` // debug | info | warn | error
}

// CollectorCfg configures a single log collector.
type CollectorCfg struct {
	Kind      string `yaml:"kind"`      // "file" | "journald" | "docker"
	Path      string `yaml:"path"`      // required for kind: file
	Unit      string `yaml:"unit"`      // required for kind: journald
	Container string `yaml:"container"` // required for kind: docker (name, short ID, or full ID)
	// Parser, when set, forces parser selection by prefixing the source ID
	// (e.g. parser: nginx → source becomes "nginx:<path-or-container>").
	// Accepted values: "nginx", "ssh", "caddy", "traefik", "apache" (alias of nginx combined),
	// "apache-error" (Apache error log format).
	Parser string `yaml:"parser"`
}

// EnforceCfg configures local and edge enforcement backends.
type EnforceCfg struct {
	NFTables   *NFTablesCfg   `yaml:"nftables"`
	Cloudflare CloudflareCfgs `yaml:"cloudflare"`
}

// CloudflareCfgs is a list of Cloudflare account configurations. The YAML form
// accepts both the legacy single-object shape (one account) and the multi-object
// array shape (one entry per account); both decode to []CloudflareCfg.
type CloudflareCfgs []CloudflareCfg

// UnmarshalYAML lets `enforce.cloudflare` be either a single mapping or a
// sequence of mappings. The single-mapping form is kept for backward
// compatibility with existing single-account configs.
func (c *CloudflareCfgs) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		// An explicit `cloudflare: []` is operator error — if the key is present
		// the operator meant to configure something. Reject at parse so the
		// failure is reported as a YAML problem with a line number.
		if len(value.Content) == 0 {
			return fmt.Errorf("line %d: at least one entry is required when 'cloudflare' is set", value.Line)
		}
		var arr []CloudflareCfg
		if err := value.Decode(&arr); err != nil {
			return err
		}
		*c = arr
		return nil
	case yaml.MappingNode:
		var single CloudflareCfg
		if err := value.Decode(&single); err != nil {
			return err
		}
		*c = CloudflareCfgs{single}
		return nil
	default:
		return fmt.Errorf("line %d: 'cloudflare' must be a mapping or a sequence of mappings", value.Line)
	}
}

// NFTablesCfg holds nftables enforcer settings.
type NFTablesCfg struct {
	Socket string `yaml:"socket"` // unix socket path; default /run/ezyshield-enforcer/enforcer.sock
	Table  string `yaml:"table"`
	Set    string `yaml:"set"`
}

// DefaultCFListName is the Cloudflare Custom IP List EzyShield manages when
// list_name is unset. Single source of truth: the enforcer, doctor, test
// wizard, and init prompt all derive from here (issue #356 — the literal used
// to be re-declared at each site and could drift silently).
const DefaultCFListName = "ezyshield_blocked"

// CloudflareCfg holds Cloudflare edge enforcer settings.
// APIToken must be an "env:VARNAME" reference; inline values are rejected.
//
// Two enforcement modes are supported:
//   - "lists" (default): account-level Custom IP List. One API call propagates
//     to every zone that references the list. When zone_ids is set, WAF Custom
//     Rules are automatically managed in each zone. Free plan: 1 list, 10 000 items.
//     Requires account_id; zone_ids are optional (auto-management).
//   - "rulesets": per-zone WAF Custom Rule that contains an ip.src list. One
//     API call per zone; ~200 IP cap per rule (auto-split). Requires zone_ids;
//     account_id is ignored.
//
// Token scoping:
//   - lists mode (no zones): Account:Account Filter Lists:Edit on the chosen account.
//   - lists mode (with zones): Account:Account Filter Lists:Edit + Zone:Firewall Services:Edit on each zone.
//   - rulesets mode: Zone:Firewall:Edit on each listed zone (least-privilege).
type CloudflareCfg struct {
	// Name is a short operator-chosen label used to disambiguate accounts in
	// logs and error messages (e.g. "client_a", "main"). Optional when a single
	// account is configured; required and must be unique when multiple accounts
	// are configured. Must match [A-Za-z0-9_-]+ and be 1..32 characters.
	Name     string    `yaml:"name"`
	APIToken SecretRef `yaml:"api_token"`
	// Mode selects the enforcement backend. Empty defaults to "lists".
	Mode string `yaml:"mode"`
	// AccountID is the Cloudflare account ID; required when Mode=="lists".
	AccountID string `yaml:"account_id"`
	// ListName is the Custom IP List name used by Mode=="lists".
	// Defaults to DefaultCFListName; auto-created when missing.
	// Must match [A-Za-z0-9_]+ (Cloudflare constraint) and be 1..50 characters.
	ListName string `yaml:"list_name"`
	// Instance identifies THIS daemon among several EzyShield servers
	// sharing one Cloudflare account (the free plan allows a single list —
	// issue #486). Each daemon tags its list items "ezyshield:<instance>"
	// and reconciles/expires only its own subset, so servers never remove
	// each other's bans. Defaults to the hostname; set explicitly when
	// hostnames may collide or change. Must match [A-Za-z0-9._-]{1,32} and
	// stay stable across restarts (a changed value orphans this daemon's
	// previous items).
	Instance string `yaml:"instance,omitempty"`
	// AdoptLegacyItems lets exactly ONE instance take ownership of list
	// items written before per-instance tagging (bare "ezyshield" comment),
	// so they gain TTL expiry again and drain naturally. Enabling it on
	// more than one server sharing the account reintroduces the clobbering
	// this field exists to migrate away from — set it on a single server,
	// remove it once the legacy items are gone.
	AdoptLegacyItems bool `yaml:"adopt_legacy_items,omitempty"`
	// ZoneIDs is the list of zones to manage; required when Mode=="rulesets".
	ZoneIDs []string `yaml:"zone_ids"`
	// Action is the rule mode: "block" (default), "challenge", or "js_challenge".
	Action string `yaml:"action"`
	// Debounce is how long rapid Ban/Unban mutations are coalesced before one
	// batched API push. Omitted or 0 defaults to DefaultCFDebounce (15s).
	// Larger values mean fewer Cloudflare API calls at the cost of slower
	// edge propagation for new bans.
	Debounce Duration `yaml:"debounce,omitempty"`
	// ExpireFlushInterval is the cadence at which item removals (expired bans
	// and unbans) are batched into a single API call in "lists" mode, instead
	// of riding every push. Omitted or 0 defaults to
	// DefaultCFExpireFlushInterval (3m). The trade-off is fail-closed: an
	// expired IP can stay blocked at the edge for up to this long.
	ExpireFlushInterval Duration `yaml:"expire_flush_interval,omitempty"`
}

// ProviderCfg describes one provider entry in a failover chain.
// Per-entry fields override the parent AICfg values when non-zero.
// APIKey must be an "env:VARNAME" reference; inline values are rejected.
type ProviderCfg struct {
	Name             string    `yaml:"name"`
	Priority         int       `yaml:"priority"`
	Model            string    `yaml:"model"`
	APIKey           SecretRef `yaml:"api_key"`
	Endpoint         string    `yaml:"endpoint"`
	TokenBudgetDaily int       `yaml:"token_budget_daily"`
}

// AICfg holds AI provider settings.
// Use the single-provider form (provider: name, api_key: env:VAR) or the
// multi-provider form (providers: [{name:, priority:, ...}]).
// When both are present, providers takes precedence.
// APIKey must be an "env:VARNAME" reference; inline values are rejected at load time.
type AICfg struct {
	Provider string    `yaml:"provider"`
	Model    string    `yaml:"model"`
	APIKey   SecretRef `yaml:"api_key"`
	// Endpoint is the base URL for the AI provider; used by ollama (default http://localhost:11434).
	Endpoint         string        `yaml:"endpoint"`
	AmbiguousBand    [2]int        `yaml:"ambiguous_band"`
	TokenBudgetDaily int           `yaml:"token_budget_daily"`
	CacheTTL         Duration      `yaml:"cache_ttl"`
	Providers        []ProviderCfg `yaml:"providers"`
}

// LoadConfig reads and strictly validates the config.yaml at path.
// Unknown YAML keys are rejected and error messages include line numbers.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // path is the admin-controlled config location
	if err != nil {
		return nil, fmt.Errorf("opening config %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only close; error irrelevant
	return LoadConfigReader(f, path)
}

// LoadConfigReader reads and strictly validates Config from r.
// name is used only for error messages.
func LoadConfigReader(r io.Reader, name string) (*Config, error) {
	var cfg Config
	if err := decodeStrict(r, name, &cfg); err != nil {
		return nil, err
	}
	// Default the AI band before validation: [0, 0] (omitted — or explicit
	// zeros, indistinguishable in YAML) becomes DefaultAmbiguousBand, the
	// same zeros-are-defaulted convention the policy loader uses. Any other
	// degenerate band is an explicit operator mistake and is rejected by
	// validateAI (issue #324).
	if cfg.AI != nil && cfg.AI.AmbiguousBand == [2]int{0, 0} {
		cfg.AI.AmbiguousBand = DefaultAmbiguousBand
	}
	// Default the Cloudflare mutation cadences before validation, following the
	// same zeros-are-defaulted convention as the AI band: omitted and explicit
	// zero are indistinguishable in YAML, and both mean "use the default"
	// (issue #445). Defaulting here (not in the enforcer) makes the effective
	// values visible in `ezyshield config show`.
	if cfg.Enforce != nil {
		for i := range cfg.Enforce.Cloudflare {
			if cfg.Enforce.Cloudflare[i].Debounce == 0 {
				cfg.Enforce.Cloudflare[i].Debounce = Duration(DefaultCFDebounce)
			}
			if cfg.Enforce.Cloudflare[i].ExpireFlushInterval == 0 {
				cfg.Enforce.Cloudflare[i].ExpireFlushInterval = Duration(DefaultCFExpireFlushInterval)
			}
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating %s: %w", name, err)
	}
	// Default the rules.d overlay dir here (not in the daemon) so directly
	// constructed Configs in tests opt in explicitly, while every loaded
	// production config gets the overlay. The legacy exclusive rules_path,
	// when set, disables the overlay entirely inside rules.New.
	if cfg.RulesDir == "" {
		cfg.RulesDir = DefaultRulesDir
	}
	return &cfg, nil
}

// DefaultAmbiguousBand is applied when ai is configured but ambiguous_band is
// omitted. It matches the value `ezyshield init` writes: scores in
// [30, DefaultBanThreshold-1] consult the AI. Without a valid band the daemon
// silently never calls the configured provider (issue #324).
//
// The upper bound deliberately stops just below DefaultBanThreshold: a score
// at or above the ban threshold has already decided "ban" on its own (the
// decision engine takes the max score), so consulting the AI for it is pure
// token spend (issue #419) — see AIBandOverlapWarning.
var DefaultAmbiguousBand = [2]int{30, DefaultBanThreshold - 1}

// DefaultCFDebounce is the Cloudflare mutation-coalescing window applied when
// enforce.cloudflare.debounce is omitted (issue #445). Rapid Ban/Unban calls
// within this window collapse into one batched API push.
const DefaultCFDebounce = 15 * time.Second

// DefaultCFExpireFlushInterval is the cadence for batched Cloudflare list-item
// removals (expired bans/unbans) applied when
// enforce.cloudflare.expire_flush_interval is omitted (issue #445). Removals
// are deferred to this ticker in "lists" mode so item-by-item expire deletes
// stop hammering the Lists API rate limit.
const DefaultCFExpireFlushInterval = 3 * time.Minute

// AIBandOverlapWarning returns a human-readable advisory when the configured
// AI ambiguous band overlaps the policy ban threshold, or "" when there is
// nothing to warn about (AI disabled, no provider, or no overlap).
//
// The overlap is a warning, not a validation error (backward compatibility —
// the previously shipped default band [30, 75] overlapped the default
// threshold 70): the daemon skips consults for scores >= ban_threshold either
// way (issue #419), so an overlapping band only misleads the operator about
// which scores actually reach the AI. Band and threshold live in different
// files (config.yaml vs policy.yaml), so this cross-check runs where both are
// loaded (daemon start, `ezyshield validate`) rather than in either loader.
func AIBandOverlapWarning(cfg *Config, pol *Policy) string {
	if cfg == nil || pol == nil || cfg.AI == nil {
		return ""
	}
	if cfg.AI.Provider == "" && len(cfg.AI.Providers) == 0 {
		return ""
	}
	lo, hi := cfg.AI.AmbiguousBand[0], cfg.AI.AmbiguousBand[1]
	if hi < pol.BanThreshold {
		return ""
	}
	return fmt.Sprintf(
		"ai.ambiguous_band [%d, %d] overlaps policy ban_threshold (%d): scores >= %d already decide a ban on rules alone and the daemon skips their AI consult, so the overlap only wastes intent — lower the band's upper bound to at most %d",
		lo, hi, pol.BanThreshold, pol.BanThreshold, pol.BanThreshold-1)
}

var validLogLevels = map[string]bool{
	"debug": true, "info": true, "warn": true, "error": true,
}

// Validate checks field constraints; it is called automatically by LoadConfigReader.
func (c *Config) Validate() error {
	// First: fail closed on credentials pasted into non-secret fields, so no
	// later validator (or `config show`) ever sees — let alone echoes — a key
	// that landed in the wrong field (issue #172).
	if err := scanForMisplacedSecrets(c); err != nil {
		return err
	}
	if c.Log.Level != "" && !validLogLevels[c.Log.Level] {
		return fmt.Errorf("log.level: %q is not one of debug|info|warn|error", c.Log.Level)
	}
	for i, col := range c.Collectors {
		if err := validateCollector(col, i); err != nil {
			return err
		}
	}
	if c.Enforce != nil && c.Enforce.NFTables != nil {
		if err := validateNFTables(*c.Enforce.NFTables); err != nil {
			return fmt.Errorf("enforce.nftables: %w", err)
		}
	}
	if c.Enforce != nil && len(c.Enforce.Cloudflare) > 0 {
		if err := validateCloudflareList(c.Enforce.Cloudflare); err != nil {
			return fmt.Errorf("enforce.cloudflare: %w", err)
		}
	}
	if c.Notify != nil {
		if err := validateNotify(c.Notify); err != nil {
			return fmt.Errorf("notify: %w", err)
		}
	}
	if c.AI != nil {
		if err := validateAI(c.AI); err != nil {
			return fmt.Errorf("ai: %w", err)
		}
	}
	if c.Enrich != nil {
		if err := validateEnrich(c.Enrich); err != nil {
			return fmt.Errorf("enrich: %w", err)
		}
	}
	if c.Dashboard != nil && c.Dashboard.Addr != "" {
		if err := validateLoopbackAddr(c.Dashboard.Addr); err != nil {
			return fmt.Errorf("dashboard: %w", err)
		}
	}
	return nil
}

// validateLoopbackAddr mirrors the dashboard's own startup check
// (internal/dashboard checkLoopback, Hard Rule 2: dashboard = 127.0.0.1 only)
// so `config validate` rejects a non-loopback addr instead of blessing a
// config the dashboard will refuse at boot (issue #324). AuthDBPath needs no
// static check — empty means the documented <data_dir>/dashboard.db default.
func validateLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("addr %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("addr %q: host must be a loopback IP or \"localhost\"", addr)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("addr %q: refusing non-loopback bind; dashboard is localhost-only", addr)
	}
	return nil
}

func validateEnrich(e *EnrichCfg) error {
	if e.AutoUpdate && !e.LicenseKey.IsSet() {
		return fmt.Errorf("'license_key' is required when auto_update is true")
	}
	return nil
}

var validProviderNames = map[string]bool{
	"anthropic": true,
	"openai":    true,
	"ollama":    true,
}

func validateAI(ai *AICfg) error {
	// Single-provider form: the same name set as the failover array. Was
	// previously unvalidated, which let a pasted API key load and leak via
	// `config show` (issue #172).
	if ai.Provider != "" && !validProviderNames[ai.Provider] {
		return fmt.Errorf("unknown provider %s (must be anthropic|openai|ollama)",
			enumValueForError(ai.Provider))
	}
	for i, p := range ai.Providers {
		if p.Name == "" {
			return fmt.Errorf("ai.providers[%d]: 'name' is required", i)
		}
		if !validProviderNames[p.Name] {
			return fmt.Errorf("ai.providers[%d]: unknown provider %s (must be anthropic|openai|ollama)",
				i, enumValueForError(p.Name))
		}
		if p.Priority < 0 {
			return fmt.Errorf("ai.providers[%d]: priority must be >= 0", i)
		}
	}
	// With a provider configured, the band decides whether AI ever runs: the
	// daemon consults AI only for scores inside [low, high] and treats
	// low >= high as "disabled". An omitted or reversed band therefore
	// silently turns the configured provider off (issue #324) — fail closed
	// here instead.
	if ai.Provider != "" || len(ai.Providers) > 0 {
		lo, hi := ai.AmbiguousBand[0], ai.AmbiguousBand[1]
		if lo < 0 || hi > 100 || lo >= hi {
			return fmt.Errorf("ambiguous_band: want [low, high] with 0 <= low < high <= 100, got [%d, %d] — scores in this band consult the AI; an empty or reversed band silently disables the configured provider", lo, hi)
		}
	}
	return nil
}

var validParserNames = map[string]bool{
	"nginx":        true,
	"ssh":          true,
	"apache":       true,
	"apache-error": true,
	"traefik":      true,
	"caddy":        true,
}

// ValidParserNames returns the set of collector parser names accepted by config
// validation, sorted for stable output. Exposed so the daemon's parser-routing
// coverage test can assert every accepted name is actually handled by a
// registered parser (issue #308): a name that validates but has no parser
// silently drops every line from that log source.
func ValidParserNames() []string {
	names := make([]string, 0, len(validParserNames))
	for name := range validParserNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func validateCollector(col CollectorCfg, idx int) error {
	switch col.Kind {
	case "file":
		if col.Path == "" {
			return fmt.Errorf("collectors[%d]: kind 'file' requires 'path'", idx)
		}
	case "journald":
		if col.Unit == "" {
			return fmt.Errorf("collectors[%d]: kind 'journald' requires 'unit'", idx)
		}
	case "docker":
		if col.Container == "" {
			return fmt.Errorf("collectors[%d]: kind 'docker' requires 'container'", idx)
		}
	case "":
		return fmt.Errorf("collectors[%d]: 'kind' is required", idx)
	default:
		return fmt.Errorf("collectors[%d]: invalid kind %q (must be file|journald|docker)", idx, col.Kind)
	}
	if col.Parser != "" && !validParserNames[col.Parser] {
		return fmt.Errorf("collectors[%d]: invalid parser %q (must be nginx|ssh|apache|apache-error|traefik|caddy)", idx, col.Parser)
	}
	return nil
}

var validCFActions = map[string]bool{
	"block": true, "challenge": true, "js_challenge": true,
}

var validCFModes = map[string]bool{
	"lists": true, "rulesets": true,
}

// cfListNameMaxLen mirrors the Cloudflare Custom IP List name constraint.
// Names are restricted to [A-Za-z0-9_]+ and length 1..50.
const cfListNameMaxLen = 50

// cfInstanceNameMaxLen caps the operator-facing CloudflareCfg.Name field.
const cfInstanceNameMaxLen = 32

// validateCloudflareList enforces multi-account rules on top of per-entry
// validation: when more than one account is configured, every entry must carry
// a non-empty unique Name so logs and errors can identify which account a given
// API failure came from.
func validateCloudflareList(list CloudflareCfgs) error {
	if len(list) == 0 {
		return fmt.Errorf("at least one entry is required when 'cloudflare' is set")
	}
	requireNames := len(list) > 1
	seen := make(map[string]int, len(list))
	for i, cf := range list {
		if err := validateCloudflare(cf); err != nil {
			return fmt.Errorf("[%d]: %w", i, err)
		}
		if cf.Name != "" {
			if err := validateCFInstanceName(cf.Name); err != nil {
				return fmt.Errorf("[%d]: 'name': %w", i, err)
			}
			if prev, dup := seen[cf.Name]; dup {
				return fmt.Errorf("[%d]: duplicate 'name' %q (also used by [%d])", i, cf.Name, prev)
			}
			seen[cf.Name] = i
		} else if requireNames {
			return fmt.Errorf("[%d]: 'name' is required when more than one cloudflare account is configured", i)
		}
	}
	return nil
}

// validateCFInstanceName restricts the operator-chosen account label so it can
// appear safely in logs and the enforcer's Name() output without escaping.
func validateCFInstanceName(name string) error {
	if len(name) == 0 || len(name) > cfInstanceNameMaxLen {
		return fmt.Errorf("length must be 1..%d, got %d", cfInstanceNameMaxLen, len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_', r == '-':
		default:
			return fmt.Errorf("must match [A-Za-z0-9_-]+")
		}
	}
	return nil
}

func validateCloudflare(cf CloudflareCfg) error {
	if !cf.APIToken.IsSet() {
		return fmt.Errorf("'api_token' is required")
	}
	if cf.Debounce < 0 {
		return fmt.Errorf("'debounce' must be positive, got %s", time.Duration(cf.Debounce))
	}
	if cf.ExpireFlushInterval < 0 {
		return fmt.Errorf("'expire_flush_interval' must be positive, got %s", time.Duration(cf.ExpireFlushInterval))
	}
	mode := cf.Mode
	if mode == "" {
		mode = "lists"
	}
	if !validCFModes[mode] {
		return fmt.Errorf("'mode' must be lists|rulesets, got %q", cf.Mode)
	}
	switch mode {
	case "lists":
		if cf.AccountID == "" {
			return fmt.Errorf("'account_id' is required when mode is 'lists'")
		}
		if cf.ListName != "" {
			if err := validateCFListName(cf.ListName); err != nil {
				return fmt.Errorf("'list_name': %w", err)
			}
		}
		if cf.Instance != "" {
			if err := validateCFInstance(cf.Instance); err != nil {
				return fmt.Errorf("'instance': %w", err)
			}
		}
		// zone_ids are optional in lists mode; when set, WAF rules are auto-managed per zone
		for i, z := range cf.ZoneIDs {
			if z == "" {
				return fmt.Errorf("zone_ids[%d]: must not be empty", i)
			}
		}
	case "rulesets":
		if len(cf.ZoneIDs) == 0 {
			return fmt.Errorf("at least one 'zone_ids' entry is required when mode is 'rulesets'")
		}
		for i, z := range cf.ZoneIDs {
			if z == "" {
				return fmt.Errorf("zone_ids[%d]: must not be empty", i)
			}
		}
	}
	if cf.Action != "" && !validCFActions[cf.Action] {
		return fmt.Errorf("'action' must be block|challenge|js_challenge, got %q", cf.Action)
	}
	return nil
}

// validateCFInstance rejects per-daemon instance identifiers that would
// produce an unusable list-item tag (issue #486): the value becomes part of
// every item's comment and must be short and shell/log-safe.
func validateCFInstance(instance string) error {
	if len(instance) == 0 || len(instance) > 32 {
		return fmt.Errorf("length must be 1..32, got %d", len(instance))
	}
	for _, r := range instance {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("must match [A-Za-z0-9._-]+, got %q", instance)
		}
	}
	return nil
}

// validateCFListName rejects names that Cloudflare would reject so the operator
// learns the failure at load time rather than the first API call.
func validateCFListName(name string) error {
	if len(name) == 0 || len(name) > cfListNameMaxLen {
		return fmt.Errorf("length must be 1..%d, got %d", cfListNameMaxLen, len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_':
		default:
			return fmt.Errorf("must match [A-Za-z0-9_]+")
		}
	}
	return nil
}

// validateNFTables format-checks the optional table/set names (issue #268).
// Empty values are valid — the enforcer defaults to "inet ezyshield" /
// "blocked". Non-empty values must pass the strict identifier rules in
// internal/nftnames; the privileged helper re-validates independently.
func validateNFTables(n NFTablesCfg) error {
	if _, err := nftnames.Resolve(n.Table, n.Set); err != nil {
		return err
	}
	return nil
}

var validSeverities = map[string]bool{
	"info": true, "warn": true, "critical": true,
}

var validTLSModes = map[string]bool{
	"starttls": true, "tls": true, "none": true,
}

func validateNotify(n *NotifyCfg) error {
	if n.RateLimitPerMinute < 0 {
		return fmt.Errorf("rate_limit_per_minute must be ≥ 0")
	}
	if n.DedupWindowSec < 0 {
		return fmt.Errorf("dedup_window_sec must be ≥ 0")
	}
	if t := n.Telegram; t != nil {
		// The daemon unconditionally resolves the token at startup, so an
		// unset ref must fail here, not at boot (issue #324).
		if !t.BotToken.IsSet() {
			return fmt.Errorf("telegram: 'bot_token' is required")
		}
		if len(t.ChatIDs) == 0 {
			return fmt.Errorf("telegram: at least one chat_id is required")
		}
		for i, s := range t.Severity {
			if !validSeverities[s] {
				return fmt.Errorf("telegram.severity[%d]: %q is not one of info|warn|critical", i, s)
			}
		}
	}
	if e := n.Email; e != nil {
		if e.From == "" {
			return fmt.Errorf("email: 'from' is required")
		}
		if len(e.To) == 0 {
			return fmt.Errorf("email: at least one 'to' address is required")
		}
		if e.Host == "" {
			return fmt.Errorf("email: 'host' is required")
		}
		if e.Port <= 0 || e.Port > 65535 {
			return fmt.Errorf("email: 'port' must be in [1, 65535], got %d", e.Port)
		}
		if e.TLS != "" && !validTLSModes[e.TLS] {
			return fmt.Errorf("email: tls %q is not one of starttls|tls|none", e.TLS)
		}
		// Same startup contract as the telegram token (issue #324).
		if !e.Password.IsSet() {
			return fmt.Errorf("email: 'password' is required")
		}
		for i, s := range e.Severity {
			if !validSeverities[s] {
				return fmt.Errorf("email.severity[%d]: %q is not one of info|warn|critical", i, s)
			}
		}
	}
	if sl := n.Slack; sl != nil {
		if !sl.WebhookURL.IsSet() {
			return fmt.Errorf("slack: 'webhook_url' is required")
		}
		for i, s := range sl.Severity {
			if !validSeverities[s] {
				return fmt.Errorf("slack.severity[%d]: %q is not one of info|warn|critical", i, s)
			}
		}
	}
	if di := n.Discord; di != nil {
		if !di.WebhookURL.IsSet() {
			return fmt.Errorf("discord: 'webhook_url' is required")
		}
		for i, s := range di.Severity {
			if !validSeverities[s] {
				return fmt.Errorf("discord.severity[%d]: %q is not one of info|warn|critical", i, s)
			}
		}
	}
	if wh := n.Webhook; wh != nil {
		if !wh.URL.IsSet() {
			return fmt.Errorf("webhook: 'url' is required")
		}
		for i, s := range wh.Severity {
			if !validSeverities[s] {
				return fmt.Errorf("webhook.severity[%d]: %q is not one of info|warn|critical", i, s)
			}
		}
	}
	return nil
}

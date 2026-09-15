// SPDX-License-Identifier: AGPL-3.0-only

// Package config provides YAML loading and strict validation for ezyshield
// configuration files. No secret values may appear in config files; use
// SecretRef for any credential field so the loader rejects inline values.
package config

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/internal/nftnames"
	"github.com/evertramos/ezy-shield/internal/siem"
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
	// SIEM lists outbound event-forwarding sinks (issue #203).
	SIEM []SIEMSinkCfg `yaml:"siem"`
	// VerifiedBots enables FCrDNS protection for well-known crawlers
	// (issue #215). Absent/disabled = no DNS lookups ever happen.
	VerifiedBots *VerifiedBotsCfg `yaml:"verified_bots"`
	// Retention configures data-retention pruning (issue #184). Absent =
	// never prune anything. See internal/config/retention.go.
	Retention *RetentionCfg `yaml:"retention"`
	// Docker selects the Docker Engine API endpoint every docker consumer
	// uses (log collectors, exec watcher, evidence extraction). Absent =
	// the default unix socket, i.e. the historical behaviour.
	Docker *DockerCfg `yaml:"docker"`
	// DockerExec enables the docker exec activity watcher (issue #220) —
	// observational post-exploitation signal; never a ban source.
	DockerExec *DockerExecCfg `yaml:"docker_exec"`
	// WebshellWatch enables the webshell-drop tripwire (issue #221) —
	// observational filesystem watch over web roots; never a ban source.
	WebshellWatch *WebshellWatchCfg `yaml:"webshell_watch"`
	// Feeds lists IP reputation feeds to download and parse (issue #194).
	// Download/parse only for now — enforcement is the follow-up (#195).
	Feeds []FeedCfg `yaml:"feeds"`
	// Plugins gates the tier-1 plugin system (issue #207). Absent or
	// enabled:false = no plugin executable is ever spawned; even enabled,
	// only names in Allow may run.
	Plugins *PluginsCfg `yaml:"plugins"`
	// SelfCheck configures the periodic hardening self-check (issue #563).
	// Absent = enabled with defaults; set enabled: false to opt out.
	SelfCheck *SelfCheckCfg `yaml:"self_check"`
}

// SelfCheckCfg controls the daemon's periodic hardening self-check (issue
// #563): the read-only systemd unit checks from `doctor` (AF_NETLINK for
// the enforcer, RuntimeDirectory for both units) plus the functional
// netlink probe, run on a timer with a CRITICAL notification when the
// state degrades and an INFO one when it recovers. Steady state is silent.
//
// ON BY DEFAULT — the point is not depending on the operator remembering
// to run doctor. To disable it entirely (minimal installs, hosts where
// periodic `systemctl show` calls are undesirable):
//
//	self_check:
//	  enabled: false
type SelfCheckCfg struct {
	// Enabled defaults to true when the section is absent or the field is
	// omitted (pointer distinguishes "omitted" from an explicit false).
	Enabled *bool `yaml:"enabled"`
	// Interval between runs. Default 6h; floor 10m (a hot systemctl loop
	// helps nobody).
	Interval Duration `yaml:"interval,omitempty"`
}

// SelfCheckEnabled resolves the tri-state: absent section or omitted field
// mean enabled.
func (c *Config) SelfCheckEnabled() bool {
	if c.SelfCheck == nil || c.SelfCheck.Enabled == nil {
		return true
	}
	return *c.SelfCheck.Enabled
}

// PluginsCfg configures tier-1 plugin discovery (issue #207). Executing
// operator-provided binaries is opt-in TWICE: Enabled must be true AND the
// plugin's manifest name must be listed in Allow — dropping a file into
// plugins.d is never enough to execute code.
type PluginsCfg struct {
	Enabled bool `yaml:"enabled"`
	// Dir overrides /etc/ezyshield/plugins.d.
	Dir string `yaml:"dir"`
	// Allow is the explicit by-name allowlist. Required when enabled.
	Allow []string `yaml:"allow"`
}

// SIEMSinkCfg describes one SIEM forwarding destination (issue #203).
// Outbound only — no listener is ever created. Delivery is asynchronous
// with a bounded queue; a slow or dead SIEM can never back-pressure the
// decision pipeline.
type SIEMSinkCfg struct {
	// Name identifies the sink in logs/doctor. Required; unique;
	// [A-Za-z0-9_-]{1,32}.
	Name string `yaml:"name"`
	// Address is scheme://target: udp://host:port, tcp://host:port,
	// tls://host:port, uds:///path, file:///path.
	Address string `yaml:"address"`
	// Format is "json" (default), "cef", or "rfc5424".
	Format string `yaml:"format"`
	// Events filters which audit ops are forwarded (empty = all). See the
	// SIEM guide for the documented kinds.
	Events []string `yaml:"events"`
	// CAFile optionally pins the CA bundle for tls:// (PEM path).
	CAFile string `yaml:"ca_file,omitempty"`
	// QueueSize bounds the in-memory queue (default 1024, max 65536).
	QueueSize int `yaml:"queue_size,omitempty"`
	// AllowInsecureTransport must be set to true to use plaintext tcp://
	// or udp:// — audit events can carry credentials-adjacent data (IPs,
	// rule reasons quoting log lines), and plaintext transports expose
	// them in transit. doctor warns loudly when this is set.
	AllowInsecureTransport bool `yaml:"allow_insecure_transport,omitempty"`
}

// FeedCfg describes one IP reputation feed (issue #194). The feed body is
// remote, attacker-adjacent input; internal/feeds enforces the runtime caps
// (10MiB response, 4KiB lines, reserved-range dropping) — this section only
// carries the operator's choices, validated strictly at load.
type FeedCfg struct {
	// Name identifies the feed in logs and provenance. Required; unique;
	// [A-Za-z0-9_-]{1,32}.
	Name string `yaml:"name"`
	// URL is the feed source. https:// only — http is rejected.
	URL string `yaml:"url"`
	// Format is "plain" (one IP per line), "cidr" (IP or prefix per line,
	// ';'/'#' comments), or "abuseipdb" (plain list export).
	Format string `yaml:"format"`
	// RefreshInterval is how often the feed is re-fetched. Required;
	// minimum 1h (politeness floor).
	RefreshInterval Duration `yaml:"refresh_interval"`
	// MaxEntries caps parsed entries per feed. 0 = 100k default; values
	// above the 500k hard cap are rejected.
	MaxEntries int `yaml:"max_entries"`
	// Timeout bounds one fetch (default 30s).
	Timeout Duration `yaml:"timeout,omitempty"`
	// Action decides what the daemon does with the feed's entries (#195):
	// "observe" (default) stores them in memory as a reputation flag that
	// boosts rule scores when the IP also appears in local events — no
	// firewall write; "block" additionally drops the entries at the edge
	// of the ezyshield nftables table via the dedicated blocked_feeds set.
	// Feed entries NEVER create strikes and never appear as bans.
	Action string `yaml:"action"`
	// TTL is the nft per-element timeout for action:block entries. 0 =
	// twice the refresh interval, so entries survive one missed refresh
	// but drain on their own when a feed dies.
	TTL Duration `yaml:"ttl,omitempty"`
}

// DockerCfg selects how EzyShield reaches the Docker Engine API. One
// endpoint serves every docker consumer — the log collectors, the exec
// watcher and on-demand evidence extraction — because a host runs one
// engine.
//
// The choice is a privilege decision, not a connectivity detail:
//
//   - unix:///var/run/docker.sock (the default) is the engine itself.
//     Reaching it means the service user is in the 'docker' group, which is
//     root-equivalent on the host.
//   - tcp://127.0.0.1:2375 is meant for a filtering, read-only proxy in
//     front of the engine, which exposes container logs and events while
//     refusing container creation, exec and mounts. That is the scoped
//     alternative to the group.
//
// EzyShield never opens a listener for this: it is only ever the client
// (Hard Rule 2). TLS to a remote engine is out of scope.
type DockerCfg struct {
	// Host is the endpoint: unix:///absolute/path or tcp://host:port.
	// Empty means the default unix socket.
	Host string `yaml:"host"`
	// AllowRemote accepts a tcp:// host that is not a loopback literal.
	// Off by default: an Engine endpoint reachable from off-host is
	// root-equivalent to everyone who can reach it unless it is a
	// filtering proxy, and the traffic is unauthenticated plaintext.
	AllowRemote bool `yaml:"allow_remote"`
}

// DockerHost returns the configured Engine endpoint in docker.host syntax,
// falling back to the default unix socket. Safe on a nil receiver so
// call sites can stay unconditional.
func (c *Config) DockerHost() string {
	if c == nil || c.Docker == nil || c.Docker.Host == "" {
		return collector.DefaultDockerHost
	}
	return c.Docker.Host
}

// DockerExecCfg configures the docker exec activity watcher (issue #220).
// Opt-in: absent or enabled=false means the events API is never touched.
type DockerExecCfg struct {
	Enabled bool `yaml:"enabled"`
	// Ignore lists container-name or image patterns to skip (glob syntax
	// per path.Match; a pattern without glob metacharacters matches as a
	// substring) — legitimate cron/health tooling.
	Ignore []string `yaml:"ignore"`
}

// WebshellWatchCfg configures the webshell-drop tripwire (issue #221).
// Opt-in: absent or enabled=false means no filesystem is ever swept.
type WebshellWatchCfg struct {
	Enabled bool `yaml:"enabled"`
	// Roots are the web-root directories to sweep (required when enabled).
	Roots []string `yaml:"roots"`
	// Extensions overrides the default executable web extensions
	// (.php, .phtml, .php5, .php7, .phar). Leading dot required.
	Extensions []string `yaml:"extensions"`
	// Ignore lists path patterns to skip (path.Match globs or substrings)
	// — cache/upload dirs that legitimately churn.
	Ignore []string `yaml:"ignore"`
	// IntervalSec overrides the 10s sweep cadence (floor 5s).
	IntervalSec int `yaml:"interval_sec"`
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
	// Users provisions per-user RBAC access (issue #204): each entry is a
	// name, a role (viewer|operator|admin), and a per-user token as an
	// env: reference — inline token literals are rejected like every other
	// secret. Empty keeps the legacy single-credential model, whose
	// password admin remains an implicit admin either way.
	Users []DashboardUserCfg `yaml:"users,omitempty"`
}

// DashboardUserCfg is one provisioned dashboard user (issue #204).
type DashboardUserCfg struct {
	// Name identifies the user in sessions and audit records. Required;
	// unique; [A-Za-z0-9_-]{1,32}.
	Name string `yaml:"name"`
	// Role is viewer (read-only), operator (+ ban/unban), or admin
	// (+ allowlist mutations, arm/disarm, policy edit).
	Role string `yaml:"role"`
	// Token is the user's login token — env-reference only. Generate with
	// e.g. `openssl rand -hex 32`; doctor warns when the resolved value
	// is shorter than 32 bytes.
	Token SecretRef `yaml:"token"`
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
	Bunny      *BunnyCfg      `yaml:"bunny"`
	AWSWAF     *AWSWAFCfg     `yaml:"aws_waf"`
}

// AWSWAFCfg holds AWS WAFv2 edge enforcer settings (issue #201, per
// ADR-0012). Presence of the section enables the enforcer. Credentials are
// deliberately ABSENT from this struct: they come from the standard AWS
// chain (env vars, ~/.aws/credentials, IMDSv2) and must never appear in
// EzyShield config files — the strict loader rejects any credential-shaped
// key here as an unknown field, and validation double-checks for pasted
// key material in the values.
type AWSWAFCfg struct {
	// Name is a short operator-chosen label used to disambiguate this
	// enforcer in logs (surfaces as "awswaf[<name>]"). Optional.
	Name string `yaml:"name"`
	// Scope is "regional" (ALB/API Gateway; requires Region) or
	// "cloudfront" (global; the API pins region us-east-1).
	Scope string `yaml:"scope"`
	// Region is the AWS region for scope "regional" (e.g. eu-west-1).
	Region string `yaml:"region"`
	// IPSetV4/IPSetV6 designate the IPSets EzyShield maintains. At least
	// one is required; EzyShield only ever mutates the sets named here and
	// never touches WebACLs.
	IPSetV4 *AWSIPSetRefCfg `yaml:"ipset_v4"`
	IPSetV6 *AWSIPSetRefCfg `yaml:"ipset_v6"`
}

// AWSIPSetRefCfg identifies one WAFv2 IPSet by its Name and Id (both shown
// in the AWS console and present in the set's ARN).
type AWSIPSetRefCfg struct {
	Name string `yaml:"name"`
	ID   string `yaml:"id"`
}

// BunnyCfg holds bunny.net edge enforcer settings (issue #198). Presence of
// the section enables the enforcer, matching the cloudflare convention.
// APIKey must be an "env:VARNAME" reference; inline values are rejected at
// load time like every other secret.
//
// The enforcer manages each configured pull zone's BlockedIps list via the
// bunny.net pull-zone API. That list is flat (no per-entry tagging), so
// EzyShield takes ownership of the whole list on the configured zones —
// entries added by hand in the bunny panel are removed on reconcile.
type BunnyCfg struct {
	// Name is a short operator-chosen label used to disambiguate this
	// enforcer in logs (surfaces as "bunny[<name>]"). Optional. Must match
	// [A-Za-z0-9_-]+ and be 1..32 characters when set.
	Name string `yaml:"name"`
	// APIKey is the bunny.net account API key — env-reference only.
	APIKey SecretRef `yaml:"api_key"`
	// PullZones are the numeric pull zone IDs the blocklist applies to.
	// At least one is required.
	PullZones []int64 `yaml:"pull_zones"`
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
	// Async enables the second-layer analysis worker (issue #222):
	// grey-zone episodes are queued and analyzed in the background —
	// the pipeline never blocks on a provider; a dead provider degrades
	// to rules-only detection.
	Async bool `yaml:"async"`
	// AsyncQueueSize bounds the grey-zone queue (default 256, max 65536).
	// On overflow the OLDEST episode is dropped and counted.
	AsyncQueueSize int `yaml:"async_queue_size"`
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
	if c.Enforce != nil && c.Enforce.Bunny != nil {
		if err := validateBunny(c.Enforce.Bunny); err != nil {
			return fmt.Errorf("enforce.bunny: %w", err)
		}
	}
	if c.Enforce != nil && c.Enforce.AWSWAF != nil {
		if err := validateAWSWAF(c.Enforce.AWSWAF); err != nil {
			return fmt.Errorf("enforce.aws_waf: %w", err)
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
	if c.Dashboard != nil && len(c.Dashboard.Users) > 0 {
		if err := validateDashboardUsers(c.Dashboard.Users); err != nil {
			return fmt.Errorf("dashboard.users: %w", err)
		}
	}
	if c.Plugins != nil {
		if err := validatePlugins(c.Plugins); err != nil {
			return fmt.Errorf("plugins: %w", err)
		}
	}
	if c.SelfCheck != nil {
		if iv := time.Duration(c.SelfCheck.Interval); iv != 0 && iv < 10*time.Minute {
			return fmt.Errorf("self_check: interval %s is below the 10m floor (0/omitted = default 6h)", iv)
		}
	}
	if len(c.SIEM) > 0 {
		if err := validateSIEM(c.SIEM); err != nil {
			return fmt.Errorf("siem: %w", err)
		}
	}
	if c.VerifiedBots != nil {
		if err := validateVerifiedBots(c.VerifiedBots); err != nil {
			return fmt.Errorf("verified_bots: %w", err)
		}
	}
	if c.Retention != nil {
		if err := validateRetention(c.Retention); err != nil {
			return fmt.Errorf("retention: %w", err)
		}
	}
	if c.Docker != nil {
		if err := validateDocker(c.Docker); err != nil {
			return fmt.Errorf("docker: %w", err)
		}
	}
	if c.DockerExec != nil {
		for i, pat := range c.DockerExec.Ignore {
			if _, err := path.Match(pat, "probe"); err != nil {
				return fmt.Errorf("docker_exec.ignore[%d]: invalid pattern %q: %w", i, pat, err)
			}
		}
	}
	if c.WebshellWatch != nil {
		if err := validateWebshellWatch(c.WebshellWatch); err != nil {
			return fmt.Errorf("webshell_watch: %w", err)
		}
	}
	if len(c.Feeds) > 0 {
		if err := validateFeeds(c.Feeds); err != nil {
			return fmt.Errorf("feeds: %w", err)
		}
	}
	return nil
}

// validateDocker checks the Engine endpoint. Only unix:// and tcp:// are
// accepted, and a tcp:// endpoint must be a loopback IP literal unless the
// operator explicitly accepted the risk with allow_remote — an Engine
// endpoint reachable off-host is root-equivalent to whoever reaches it
// unless a filtering proxy stands in front, and nothing in this
// configuration can prove that one does.
func validateDocker(d *DockerCfg) error {
	if d.Host == "" {
		if d.AllowRemote {
			return fmt.Errorf("'allow_remote' is set but no 'host' is configured; it only applies to a tcp:// endpoint")
		}
		return nil
	}
	ep, err := collector.ParseDockerHost(d.Host)
	if err != nil {
		return fmt.Errorf("'host': %w", err)
	}
	if ep.IsUnix() && d.AllowRemote {
		return fmt.Errorf("'allow_remote' is set but 'host' is a unix socket; it only applies to a tcp:// endpoint")
	}
	if ep.IsTCP() && !ep.IsLoopback() && !d.AllowRemote {
		return fmt.Errorf("'host': %s is not a loopback address — reaching a Docker Engine endpoint over the network "+
			"is root-equivalent unless a filtering read-only proxy stands in front of it, and the traffic is "+
			"unauthenticated plaintext; publish the proxy on 127.0.0.1 instead, or set docker.allow_remote: true "+
			"to accept the risk", ep.String())
	}
	return nil
}

var validSIEMFormats = map[string]bool{"": true, "json": true, "cef": true, "rfc5424": true}

// validateSIEM checks the forwarding sinks (issue #203). Plaintext tcp/udp
// is rejected unless the operator explicitly opts in — audit events cross
// the wire and can quote hostile-but-sensitive log content.
func validateSIEM(list []SIEMSinkCfg) error {
	seen := make(map[string]int, len(list))
	for i, s := range list {
		if s.Name == "" {
			return fmt.Errorf("[%d]: 'name' is required", i)
		}
		if err := validateCFInstanceName(s.Name); err != nil {
			return fmt.Errorf("[%d]: 'name': %w", i, err)
		}
		if prev, dup := seen[s.Name]; dup {
			return fmt.Errorf("[%d]: duplicate 'name' %q (also used by [%d])", i, s.Name, prev)
		}
		seen[s.Name] = i
		scheme, _, err := siem.ParseAddress(s.Address)
		if err != nil {
			return fmt.Errorf("[%d] %s: 'address': %w", i, s.Name, err)
		}
		if (scheme == "tcp" || scheme == "udp") && !s.AllowInsecureTransport {
			return fmt.Errorf("[%d] %s: plaintext %s:// sends audit events unencrypted — use tls://, or set allow_insecure_transport: true if the network is trusted", i, s.Name, scheme)
		}
		if !validSIEMFormats[s.Format] {
			return fmt.Errorf("[%d] %s: 'format' must be json|cef|rfc5424, got %q", i, s.Name, s.Format)
		}
		if s.CAFile != "" && scheme != "tls" {
			return fmt.Errorf("[%d] %s: 'ca_file' only applies to tls:// addresses", i, s.Name)
		}
		if s.QueueSize < 0 || s.QueueSize > 65536 {
			return fmt.Errorf("[%d] %s: 'queue_size' must be 0..65536, got %d", i, s.Name, s.QueueSize)
		}
		for j, ev := range s.Events {
			if strings.TrimSpace(ev) == "" {
				return fmt.Errorf("[%d] %s: events[%d] must not be empty", i, s.Name, j)
			}
		}
	}
	return nil
}

// Feed validation constants mirror internal/feeds (kept literal here so the
// config package stays dependency-light; the feeds package re-checks its own
// caps at runtime).
const (
	feedHardMaxEntries    = 500_000
	feedMinRefreshSeconds = 3600
)

var validFeedFormats = map[string]bool{"plain": true, "cidr": true, "abuseipdb": true}

// validateFeeds checks the reputation-feed list (issue #194): https-only
// URLs, known formats, a 1h refresh floor, sane entry caps, unique names.
func validateFeeds(list []FeedCfg) error {
	seen := make(map[string]int, len(list))
	for i, f := range list {
		if f.Name == "" {
			return fmt.Errorf("[%d]: 'name' is required", i)
		}
		if err := validateCFInstanceName(f.Name); err != nil {
			return fmt.Errorf("[%d]: 'name': %w", i, err)
		}
		if prev, dup := seen[f.Name]; dup {
			return fmt.Errorf("[%d]: duplicate 'name' %q (also used by [%d])", i, f.Name, prev)
		}
		seen[f.Name] = i
		u, err := url.Parse(f.URL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("[%d] %s: 'url' is not a valid URL", i, f.Name)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("[%d] %s: 'url' must be https:// — a reputation feed fetched over http can be tampered in transit", i, f.Name)
		}
		if !validFeedFormats[f.Format] {
			return fmt.Errorf("[%d] %s: 'format' must be plain|cidr|abuseipdb, got %q", i, f.Name, f.Format)
		}
		ri := f.RefreshInterval.AsDuration()
		if ri <= 0 {
			return fmt.Errorf("[%d] %s: 'refresh_interval' is required (minimum 1h)", i, f.Name)
		}
		if ri < feedMinRefreshSeconds*time.Second {
			return fmt.Errorf("[%d] %s: 'refresh_interval' %s is below the 1h politeness floor", i, f.Name, ri)
		}
		if f.MaxEntries < 0 {
			return fmt.Errorf("[%d] %s: 'max_entries' must not be negative", i, f.Name)
		}
		if f.MaxEntries > feedHardMaxEntries {
			return fmt.Errorf("[%d] %s: 'max_entries' %d exceeds the %d hard cap", i, f.Name, f.MaxEntries, feedHardMaxEntries)
		}
		if f.Timeout.AsDuration() < 0 {
			return fmt.Errorf("[%d] %s: 'timeout' must not be negative", i, f.Name)
		}
		if f.Action != "" && f.Action != "observe" && f.Action != "block" {
			return fmt.Errorf("[%d] %s: 'action' must be observe|block, got %q", i, f.Name, f.Action)
		}
		if f.TTL.AsDuration() < 0 {
			return fmt.Errorf("[%d] %s: 'ttl' must not be negative", i, f.Name)
		}
	}
	return nil
}

func validateWebshellWatch(w *WebshellWatchCfg) error {
	if w.Enabled && len(w.Roots) == 0 {
		return fmt.Errorf("'roots' is required when enabled (the web directories to sweep)")
	}
	for i, r := range w.Roots {
		if !filepath.IsAbs(r) {
			return fmt.Errorf("roots[%d]: %q must be an absolute path", i, r)
		}
	}
	for i, e := range w.Extensions {
		if !strings.HasPrefix(e, ".") || len(e) < 2 {
			return fmt.Errorf("extensions[%d]: %q must start with a dot (e.g. \".php\")", i, e)
		}
	}
	for i, pat := range w.Ignore {
		if _, err := path.Match(pat, "probe"); err != nil {
			return fmt.Errorf("ignore[%d]: invalid pattern %q: %w", i, pat, err)
		}
	}
	if w.IntervalSec != 0 && w.IntervalSec < 5 {
		return fmt.Errorf("interval_sec: %d is below the 5s floor (a hot sweep loop over web roots)", w.IntervalSec)
	}
	return nil
}

// validDashboardRoles is the RBAC role enum (issue #204).
var validDashboardRoles = map[string]bool{"viewer": true, "operator": true, "admin": true}

// validateDashboardUsers checks the RBAC user list (issue #204): unique
// valid names, the role enum, and a token that MUST be an env: reference —
// the SecretRef loader already rejects inline literals with a redacted
// error, so here only presence is checked. Token entropy on the RESOLVED
// value is a doctor warning (config validation never resolves secrets).
func validateDashboardUsers(users []DashboardUserCfg) error {
	seen := make(map[string]int, len(users))
	for i, u := range users {
		if u.Name == "" {
			return fmt.Errorf("[%d]: 'name' is required", i)
		}
		if err := validateCFInstanceName(u.Name); err != nil {
			return fmt.Errorf("[%d]: 'name': %w", i, err)
		}
		if prev, dup := seen[u.Name]; dup {
			return fmt.Errorf("[%d]: duplicate name %q (also at [%d])", i, u.Name, prev)
		}
		seen[u.Name] = i
		if !validDashboardRoles[u.Role] {
			return fmt.Errorf("[%d] (%s): 'role' must be viewer, operator, or admin, got %q", i, u.Name, u.Role)
		}
		if !u.Token.IsSet() {
			return fmt.Errorf("[%d] (%s): 'token' is required (env:VARNAME reference)", i, u.Name)
		}
	}
	return nil
}

// validatePlugins checks the tier-1 plugin gate (issue #207): an enabled
// plugin system MUST carry an explicit allowlist, and allow entries follow
// the plugin-name grammar (lowercase, no path characters — names, never
// paths).
func validatePlugins(p *PluginsCfg) error {
	if p.Enabled && len(p.Allow) == 0 {
		return fmt.Errorf("'allow' must list at least one plugin name when enabled (explicit allowlist — no plugin runs implicitly)")
	}
	seen := make(map[string]int, len(p.Allow))
	for i, name := range p.Allow {
		if !pluginAllowNameRE.MatchString(name) {
			return fmt.Errorf("allow[%d]: %q is not a valid plugin name (want %s)", i, name, pluginAllowNameRE)
		}
		if prev, dup := seen[name]; dup {
			return fmt.Errorf("allow[%d]: duplicate name %q (also at [%d])", i, name, prev)
		}
		seen[name] = i
	}
	return nil
}

var pluginAllowNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

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
	if ai.AsyncQueueSize < 0 || ai.AsyncQueueSize > 65536 {
		return fmt.Errorf("async_queue_size: must be in [0, 65536] (0 = default 256), got %d", ai.AsyncQueueSize)
	}
	if ai.Async && ai.Provider == "" && len(ai.Providers) == 0 {
		return fmt.Errorf("async: true requires a configured provider")
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
	"postfix":      true,
	"dovecot":      true,
	"vaultwarden":  true,
	"nextcloud":    true,
	"keycloak":     true,
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

// validateBunny checks the bunny.net edge enforcer section (issue #198):
// the API key must be configured (env-reference only — the SecretRef loader
// already rejects inline literals with a redacted error) and at least one
// positive pull zone ID is required.
func validateBunny(b *BunnyCfg) error {
	if !b.APIKey.IsSet() {
		return fmt.Errorf("'api_key' is required")
	}
	if len(b.PullZones) == 0 {
		return fmt.Errorf("at least one 'pull_zones' entry is required")
	}
	seen := make(map[int64]int, len(b.PullZones))
	for i, z := range b.PullZones {
		if z <= 0 {
			return fmt.Errorf("pull_zones[%d]: must be a positive pull zone ID, got %d", i, z)
		}
		if prev, dup := seen[z]; dup {
			return fmt.Errorf("pull_zones[%d]: duplicate zone %d (also at [%d])", i, z, prev)
		}
		seen[z] = i
	}
	if b.Name != "" {
		if err := validateCFInstanceName(b.Name); err != nil {
			return fmt.Errorf("'name': %w", err)
		}
	}
	return nil
}

// validateAWSWAF checks the AWS WAF edge enforcer section (issue #201, per
// ADR-0012): scope regional|cloudfront (regional requires a region), at
// least one fully-identified IPSet, and — because AWS credentials must
// NEVER live in EzyShield config files — a fail-closed refusal of anything
// that looks like pasted AWS key material in the values.
func validateAWSWAF(a *AWSWAFCfg) error {
	switch strings.ToLower(a.Scope) {
	case "regional":
		if a.Region == "" {
			return fmt.Errorf("scope 'regional' requires 'region' (e.g. eu-west-1)")
		}
	case "cloudfront":
		// The WAFv2 API pins CLOUDFRONT calls to us-east-1; a region here
		// would be ignored, which is operator confusion — reject it.
		if a.Region != "" && a.Region != "us-east-1" {
			return fmt.Errorf("scope 'cloudfront' pins region us-east-1; drop 'region' (got %q)", a.Region)
		}
	case "":
		return fmt.Errorf("'scope' is required: regional or cloudfront")
	default:
		return fmt.Errorf("'scope' must be regional or cloudfront, got %q", a.Scope)
	}
	if a.IPSetV4 == nil && a.IPSetV6 == nil {
		return fmt.Errorf("at least one of 'ipset_v4'/'ipset_v6' is required")
	}
	for label, ref := range map[string]*AWSIPSetRefCfg{"ipset_v4": a.IPSetV4, "ipset_v6": a.IPSetV6} {
		if ref == nil {
			continue
		}
		if ref.Name == "" || ref.ID == "" {
			return fmt.Errorf("%s: both 'name' and 'id' are required", label)
		}
	}
	if a.Name != "" {
		if err := validateCFInstanceName(a.Name); err != nil {
			return fmt.Errorf("'name': %w", err)
		}
	}
	// No pasted-credential check needed here: the loader's generic
	// credential scan already rejects AKIA/ASIA-shaped material in ANY
	// config field, and this struct deliberately has no credential fields
	// at all (ADR-0012: the standard AWS chain only).
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

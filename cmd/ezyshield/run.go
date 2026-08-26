package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/enrich"
	"github.com/evertramos/ezy-shield/internal/feeds"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/internal/webshell"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// sourceID builds the RawLine source for a file collector when the parser field
// overrides automatic parser routing (e.g. parser: nginx → "nginx:<path>").
func sourceID(parserName, path string) string {
	if parserName == "" {
		return ""
	}
	return parserName + ":" + path
}

// defaultParsers returns the parser set the daemon routes collector lines
// through. Every parser name accepted by config validation (see
// internal/config validParserNames) must be handled by exactly one parser
// here; otherwise a collector with that parser silently drops every line
// (issue #308). The parser-coverage test in run_parsers_test.go enforces this.
func defaultParsers(logger *slog.Logger) []sdk.Parser {
	return []sdk.Parser{
		parser.NewSSHParser(logger),
		parser.NewNginxParser(logger, parser.NginxConfig{}),
		parser.NewApacheErrorParser(logger),
		parser.NewCaddyParser(logger, parser.CaddyConfig{}),
		parser.NewTraefikParser(logger, parser.TraefikConfig{}),
		parser.NewPostfixParser(logger),
		parser.NewDovecotParser(logger),
		parser.NewVaultwardenParser(logger),
		parser.NewNextcloudParser(logger),
		parser.NewKeycloakParser(logger),
	}
}

func newRunCmd() *cobra.Command {
	var (
		configPath string
		policyPath string
		dbPath     string
		socketPath string
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the EzyShield daemon (long-running)",
		Long: `Start EzyShield in daemon mode.

The daemon tails configured log sources, detects malicious IPs, and enforces
bans locally via nftables (when armed=true in policy.yaml). A unix socket at
/run/ezyshield/ezyshield.sock provides the control API used by the ban/unban/
list/allow sub-commands.

Shutdown signals:
  SIGTERM  graceful — drains in-flight events (≤30 s) before exiting
  SIGINT   immediate — stops without draining`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDaemon(configPath, policyPath, dbPath, socketPath)
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "/etc/ezyshield/config.yaml",
		"path to config.yaml")
	cmd.Flags().StringVar(&policyPath, "policy", "/etc/ezyshield/policy.yaml",
		"path to policy.yaml")
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/ezyshield/ezyshield.db",
		"path to SQLite database")
	cmd.Flags().StringVar(&socketPath, "socket", daemon.DefaultSocketPath,
		"path to control socket")

	return cmd
}

func runDaemon(configPath, policyPath, dbPath, socketPath string) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("run: load config: %w", err)
	}

	policy, err := config.LoadPolicy(policyPath)
	if err != nil {
		return fmt.Errorf("run: load policy: %w", err)
	}

	ctx := context.Background()

	// Ensure the database directory exists.
	if err := os.MkdirAll(dirOf(dbPath), 0o750); err != nil {
		return fmt.Errorf("run: create db dir: %w", err)
	}

	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("run: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	// Configure structured logging level from config.
	logLevel := slog.LevelInfo
	switch cfg.Log.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// Advisory cross-file check (issue #419): an ambiguous_band reaching into
	// the ban_threshold misleads the operator — the daemon skips those
	// consults regardless (see maybeConsultAI). Warn once at startup.
	if msg := config.AIBandOverlapWarning(cfg, policy); msg != "" {
		slog.Warn("run: " + msg)
	}

	parsers := defaultParsers(logger)

	collectors := buildCollectors(cfg, logger)

	var (
		enf sdk.Enforcer
		// nftEnf keeps the concrete nftables enforcer for the reputation-
		// feed sets (issue #195): feed entries travel their own SyncFeeds
		// path, never the Ban/Sync fan-out the gate wraps below.
		nftEnf *enforce.NftablesEnforcer
	)
	if cfg.Enforce != nil && cfg.Enforce.NFTables != nil {
		sockPath := cfg.Enforce.NFTables.Socket
		if sockPath == "" {
			sockPath = enforce.DefaultSocketPath
		}
		if _, err := os.Stat(sockPath); err != nil {
			slog.Warn("enforcer socket not present at startup; bans will be stored but not applied until helper starts",
				"socket", sockPath, "err", err)
		}
		allowlist := parseAllowlist(policy)
		// Table/set come from config (issue #268): empty means the enforcer
		// defaults; non-default names are validated at config load and the
		// helper is capability-probed before first use.
		nftEnf = enforce.New(sockPath, allowlist,
			enforce.WithNames(cfg.Enforce.NFTables.Table, cfg.Enforce.NFTables.Set))
		enf = nftEnf
	}

	var edgeEnforcers []sdk.Enforcer
	if cfg.Enforce != nil && len(cfg.Enforce.Cloudflare) > 0 {
		for i := range cfg.Enforce.Cloudflare {
			cf := cfg.Enforce.Cloudflare[i]
			cfEnf, cfErr := enforce.NewCloudflareEnforcer(ctx, &cf, parseAllowlist(policy))
			if cfErr != nil {
				// Per-account isolation: one bad token/account_id doesn't disable
				// the rest. cfg.Name is operator-set and validated by config.
				slog.Warn("run: cloudflare enforcer unavailable; continuing without it",
					"cloudflare_name", cf.Name, "err", cfErr)
				continue
			}
			edgeEnforcers = append(edgeEnforcers, cfEnf)
		}
	}
	if cfg.Enforce != nil && cfg.Enforce.Bunny != nil {
		bunnyEnf, bErr := enforce.NewBunnyEnforcer(&enforce.BunnyConfig{
			AccessKey:   cfg.Enforce.Bunny.APIKey,
			PullZoneIDs: cfg.Enforce.Bunny.PullZones,
			Name:        cfg.Enforce.Bunny.Name,
		}, parseAllowlist(policy))
		if bErr != nil {
			// Same isolation as cloudflare: a missing key disables only bunny.
			slog.Warn("run: bunny enforcer unavailable; continuing without it",
				"bunny_name", cfg.Enforce.Bunny.Name, "err", bErr)
		} else {
			edgeEnforcers = append(edgeEnforcers, bunnyEnf)
		}
	}
	if len(edgeEnforcers) > 0 {
		all := make([]sdk.Enforcer, 0, len(edgeEnforcers)+1)
		if enf != nil {
			all = append(all, enf)
		}
		all = append(all, edgeEnforcers...)
		if len(all) == 1 {
			enf = all[0]
		} else {
			enf = enforce.NewMulti(all...)
		}
	}

	if enf != nil {
		// Authoritative allowlist/anti-lockout gate ahead of the enforcer
		// fan-out (issue #230). Enforcer-internal checks remain belt-and-braces;
		// this choke point is what guarantees the invariant for every enforcer,
		// including future ones that forget their own guard.
		enf = enforce.NewGate(enf, parseAllowlist(policy), decision.ProcSSHPeers)
	}

	var disp *notify.Dispatcher
	if cfg.Notify != nil {
		notifiers, sevs, err := buildNotifiers(cfg.Notify, logger)
		if err != nil {
			return fmt.Errorf("run: build notifiers: %w", err)
		}
		if len(notifiers) > 0 {
			dedupSec := cfg.Notify.DedupWindowSec
			if dedupSec <= 0 {
				dedupSec = notify.DefaultDedupWindowSec
			}
			disp = notify.New(notifiers, cfg.Notify.RateLimitPerMinute,
				time.Duration(dedupSec)*time.Second, sevs)
		}
	}

	var (
		aiProvider sdk.AIProvider
		aiBudget   *ai.Budget
		aiCache    *ai.Cache
	)
	if cfg.AI != nil {
		allowlist := parseAllowlist(policy)
		maxTTL := time.Duration(0)
		if len(policy.Strikes) > 0 {
			maxTTL = policy.Strikes[len(policy.Strikes)-1].TTL.AsDuration()
		}
		cacheTTL := cfg.AI.CacheTTL.AsDuration()
		if cacheTTL == 0 {
			cacheTTL = 15 * time.Minute
		}

		if len(cfg.AI.Providers) > 0 {
			// Multi-provider failover chain: build each provider in priority order.
			chain, chainErr := buildAIChain(cfg.AI, allowlist, maxTTL, db)
			if chainErr != nil {
				slog.Warn("run: AI chain unavailable; continuing without AI", "err", chainErr)
			} else {
				aiProvider = chain
				// Chain-level budget with daily=0 (unlimited); per-provider budgets
				// are managed inside the chain. This keeps the daemon's budget
				// pre-check non-blocking while the chain enforces per-provider limits.
				aiBudget = ai.NewBudget("chain", 0, db)
				aiCache = ai.NewCache(cacheTTL)
			}
		} else if cfg.AI.APIKey.IsSet() || cfg.AI.Provider == "ollama" {
			// Single-provider path (backward compatible).
			var (
				prov    sdk.AIProvider
				provErr error
			)
			switch cfg.AI.Provider {
			case "openai":
				prov, provErr = ai.NewOpenAIProvider(cfg.AI, allowlist, maxTTL, nil)
			case "ollama":
				prov, provErr = ai.NewOllamaProvider(cfg.AI, allowlist, maxTTL, nil)
			default:
				prov, provErr = ai.NewAnthropicProvider(cfg.AI, allowlist, maxTTL, nil)
			}
			if provErr != nil {
				slog.Warn("run: AI provider unavailable; continuing without AI", "err", provErr)
			} else {
				aiProvider = prov
				aiBudget = ai.NewBudget(prov.Name(), cfg.AI.TokenBudgetDaily, db)
				aiCache = ai.NewCache(cacheTTL)
			}
		}
	}

	var enricher *enrich.Enricher
	if cfg.Enrich != nil {
		dbPath := cfg.Enrich.DBPath
		asnPath := cfg.Enrich.ASNPath
		enricher = enrich.New(dbPath, asnPath)
		if cfg.Enrich.AutoUpdate {
			licenseKey, keyErr := cfg.Enrich.LicenseKey.Resolve()
			if keyErr != nil {
				slog.Warn("run: enrich license key unavailable; auto-update disabled", "err", keyErr)
			} else {
				updater := enrich.NewUpdater(enricher, licenseKey, dbPath, asnPath)
				go updater.Run(ctx)
			}
		}
	}

	// Docker exec activity watcher (issue #220): opt-in, observational only.
	// Wired here (not inside the daemon) so the daemon package never imports
	// the linux-only collector package.
	var execActivity func(ctx context.Context, report func(daemon.ExecActivityReport))
	if cfg.DockerExec != nil && cfg.DockerExec.Enabled {
		watcher := &collector.DockerExecWatcher{Ignore: cfg.DockerExec.Ignore, Logger: logger}
		execActivity = func(ctx context.Context, report func(daemon.ExecActivityReport)) {
			err := watcher.Run(ctx, func(ev collector.ExecEvent) {
				report(daemon.ExecActivityReport{
					Container: ev.Container,
					Image:     ev.Image,
					Command:   ev.Command,
					User:      ev.User,
				})
			})
			if err != nil && ctx.Err() == nil {
				slog.Error("run: docker exec watcher stopped", "err", err)
			}
		}
	}

	dcfg := daemon.Config{
		Cfg:              cfg,
		Policy:           policy,
		Store:            db,
		Parsers:          parsers,
		Collectors:       collectors,
		Enforcer:         enf,
		Notifier:         disp,
		AIProvider:       aiProvider,
		AIBudget:         aiBudget,
		AICache:          aiCache,
		Enricher:         enricher,
		SocketPath:       socketPath,
		Version:          version,
		PolicyPath:       policyPath,
		ExecActivity:     execActivity,
		WebshellActivity: buildWebshellActivity(cfg),
		FeedUpdates:      buildFeedUpdates(cfg),
	}
	if nftEnf != nil {
		dcfg.FeedSyncer = nftEnf
	}
	d, err := daemon.New(dcfg)
	if err != nil {
		return fmt.Errorf("run: create daemon: %w", err)
	}

	return d.Run(ctx)
}

// buildFeedUpdates wires the reputation-feed refresh loop (issues #194/#195)
// into the daemon via injection — the daemon package never imports
// internal/feeds. Returns nil (feature off) when no feeds are configured.
func buildFeedUpdates(cfg *config.Config) func(context.Context, func(daemon.FeedUpdate)) {
	if len(cfg.Feeds) == 0 {
		return nil
	}
	fcfgs := make([]feeds.FeedConfig, 0, len(cfg.Feeds))
	meta := make(map[string]config.FeedCfg, len(cfg.Feeds))
	for _, f := range cfg.Feeds {
		fcfgs = append(fcfgs, feeds.FeedConfig{
			Name:            f.Name,
			URL:             f.URL,
			Format:          f.Format,
			RefreshInterval: f.RefreshInterval.AsDuration(),
			MaxEntries:      f.MaxEntries,
			Timeout:         f.Timeout.AsDuration(),
		})
		meta[f.Name] = f
	}
	return func(ctx context.Context, report func(daemon.FeedUpdate)) {
		fetcher := feeds.New(nil, slog.Default())
		slog.Info("run: reputation feeds active", "feeds", len(fcfgs))
		fetcher.Run(ctx, fcfgs, func(res *feeds.Result) {
			m := meta[res.Name]
			action := m.Action
			if action == "" {
				action = "observe"
			}
			ttl := m.TTL.AsDuration()
			if ttl <= 0 {
				// Twice the refresh interval: survives one missed refresh,
				// drains on its own when the feed dies.
				ttl = 2 * m.RefreshInterval.AsDuration()
			}
			report(daemon.FeedUpdate{
				Name:     res.Name,
				Action:   action,
				TTL:      ttl,
				Prefixes: res.Prefixes,
			})
		})
	}
}

// buildWebshellActivity wires the opt-in webshell-drop tripwire (issue
// #221) into the daemon via injection — the daemon package never imports
// internal/webshell. Returns nil (feature off) unless enabled in config.
func buildWebshellActivity(cfg *config.Config) func(context.Context, func(daemon.WebshellReport)) {
	wcfg := cfg.WebshellWatch
	if wcfg == nil || !wcfg.Enabled {
		return nil
	}
	return func(ctx context.Context, report func(daemon.WebshellReport)) {
		w, err := webshell.New(webshell.Config{
			Roots:      wcfg.Roots,
			Extensions: wcfg.Extensions,
			Ignore:     wcfg.Ignore,
			Interval:   time.Duration(wcfg.IntervalSec) * time.Second,
		})
		if err != nil {
			slog.Error("run: webshell watcher disabled", "err", err)
			return
		}
		slog.Info("run: webshell tripwire active", "roots", wcfg.Roots)
		_ = w.Run(ctx, func(ev webshell.Event) {
			report(daemon.WebshellReport{
				Path:       ev.Path,
				Op:         ev.Op,
				Owner:      ev.Owner,
				Size:       ev.Size,
				Suspicious: ev.Suspicious,
				Markers:    ev.Markers,
				Count:      ev.Count,
			})
		})
	}
}

// buildCollectors creates sdk.Collector instances from the config slice.
// An empty result is legal (config validate treats it as a warning since
// issue #339) but must be LOUD: an armed daemon with zero collectors
// ingests nothing and protects nothing, while status/systemd look healthy
// (issue #386; status additionally reports collectors_state NONE, #456).
func buildCollectors(cfg *config.Config, logger *slog.Logger) []sdk.Collector {
	if len(cfg.Collectors) == 0 {
		logger.Warn("run: no collectors configured — no log source is being monitored, nothing will ever be detected; " +
			"add collectors to config.yaml (see '" + progName + " doctor')")
	}
	var cols []sdk.Collector
	for _, c := range cfg.Collectors {
		switch c.Kind {
		case "file":
			cols = append(cols, &collector.FileTailCollector{
				Path:           c.Path,
				Logger:         logger,
				SourceOverride: sourceID(c.Parser, c.Path),
			})
		case "journald":
			cols = append(cols, &collector.JournaldCollector{
				Unit:   c.Unit,
				Logger: logger,
			})
		case "docker":
			cols = append(cols, &collector.DockerCollector{
				Container: c.Container,
				Parser:    c.Parser,
				Logger:    logger,
			})
		}
	}
	return cols
}

// buildNotifiers builds sdk.Notifier instances from the notify config.
// Credentials are resolved from environment variables via SecretRef.
// The returned severity map keys on Notifier.Name(); a nil or absent entry means all severities.
func buildNotifiers(cfg *config.NotifyCfg, logger *slog.Logger) ([]sdk.Notifier, map[string][]string, error) {
	_ = logger
	var notifiers []sdk.Notifier
	severities := make(map[string][]string)

	if t := cfg.Telegram; t != nil {
		token, err := t.BotToken.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("telegram: %w", err)
		}
		notifiers = append(notifiers, notify.NewTelegram(token, t.ChatIDs))
		if len(t.Severity) > 0 {
			severities["telegram"] = t.Severity
		}
	}

	if e := cfg.Email; e != nil {
		password, err := e.Password.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("email: %w", err)
		}
		notifiers = append(notifiers, notify.NewEmail(e.From, e.To, e.Host, e.Port, e.Username, password, e.TLS))
		if len(e.Severity) > 0 {
			severities["email"] = e.Severity
		}
	}

	if sl := cfg.Slack; sl != nil {
		url, err := sl.WebhookURL.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("slack: %w", err)
		}
		notifiers = append(notifiers, notify.NewSlack(url, sl.Channel))
		if len(sl.Severity) > 0 {
			severities["slack"] = sl.Severity
		}
	}

	if di := cfg.Discord; di != nil {
		url, err := di.WebhookURL.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("discord: %w", err)
		}
		notifiers = append(notifiers, notify.NewDiscord(url))
		if len(di.Severity) > 0 {
			severities["discord"] = di.Severity
		}
	}

	if wh := cfg.Webhook; wh != nil {
		url, err := wh.URL.Resolve()
		if err != nil {
			return nil, nil, fmt.Errorf("webhook: %w", err)
		}
		headers, err := resolveWebhookHeaders(wh.Headers)
		if err != nil {
			return nil, nil, err
		}
		notifiers = append(notifiers, notify.NewWebhook(url, headers))
		if len(wh.Severity) > 0 {
			severities["webhook"] = wh.Severity
		}
	}

	return notifiers, severities, nil
}

// resolveWebhookHeaders resolves "env:VARNAME" references in webhook header
// values (written by `config notifier webhook`) so the secret lives in .env,
// never in config.yaml. Values without the env: prefix pass through verbatim
// for backward compatibility with hand-written configs. Errors carry only
// the header NAME — never the value (SECURITY-REVIEW §4); the SecretRef
// resolver already redacts malformed references.
func resolveWebhookHeaders(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return in, nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if !strings.HasPrefix(v, "env:") {
			out[k] = v
			continue
		}
		resolved, err := config.SecretRef(v).Resolve()
		if err != nil {
			return nil, fmt.Errorf("webhook: header %q: %w", k, err)
		}
		out[k] = resolved
	}
	return out, nil
}

// dirOf returns the directory part of path.
func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}

// buildAIChain constructs a ChainProvider from cfg.AI.Providers sorted by
// priority ascending (1 = highest). Each entry gets its own per-provider budget.
// Entries that fail to construct are logged and skipped; if no entries succeed
// an error is returned.
func buildAIChain(
	cfg *config.AICfg,
	allowlist []netip.Prefix,
	maxTTL time.Duration,
	store ai.BudgetStore,
) (*ai.ChainProvider, error) {
	// Sort by priority (ascending); stable so equal-priority order is config order.
	sorted := make([]config.ProviderCfg, len(cfg.Providers))
	copy(sorted, cfg.Providers)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Priority < sorted[j-1].Priority; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	var entries []ai.ChainEntry
	for idx, pcfg := range sorted {
		merged := mergeProviderCfg(cfg, pcfg)
		var (
			prov    sdk.AIProvider
			provErr error
		)
		switch pcfg.Name {
		case "openai":
			prov, provErr = ai.NewOpenAIProvider(merged, allowlist, maxTTL, nil)
		case "ollama":
			prov, provErr = ai.NewOllamaProvider(merged, allowlist, maxTTL, nil)
		default:
			prov, provErr = ai.NewAnthropicProvider(merged, allowlist, maxTTL, nil)
		}
		if provErr != nil {
			slog.Warn("run: AI chain: provider init failed, skipping",
				"provider", pcfg.Name, "err", provErr)
			continue
		}
		daily := pcfg.TokenBudgetDaily
		if daily == 0 {
			daily = cfg.TokenBudgetDaily
		}
		entries = append(entries, ai.ChainEntry{
			Provider: prov,
			Budget:   ai.NewBudget(fmt.Sprintf("%s-%d", pcfg.Name, idx), daily, store),
		})
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("ai chain: no providers could be initialised")
	}
	return ai.NewChainProvider(entries), nil
}

// mergeProviderCfg copies the global AICfg and applies per-provider overrides.
func mergeProviderCfg(base *config.AICfg, p config.ProviderCfg) *config.AICfg {
	merged := *base
	merged.Provider = p.Name
	if p.Model != "" {
		merged.Model = p.Model
	}
	if p.APIKey.IsSet() {
		merged.APIKey = p.APIKey
	}
	if p.Endpoint != "" {
		merged.Endpoint = p.Endpoint
	}
	return &merged
}

// parseAllowlist builds a []netip.Prefix from policy allowlist + admin_cidrs.
// Entries are canonicalized (issue #365): bare IPs are unmapped and mapped
// CIDRs become their plain-IPv4 form via decision.NormalizePrefix — the same
// rules the decision layer applies to its own copy since #314/#364 — so a
// mapped-form policy entry protects its range at the enforce layer too. An
// entry NormalizePrefix rejects (mapped broader than /96) is kept as parsed:
// dropping it would remove protection, and the decision layer already fails
// loud on those.
func parseAllowlist(policy *config.Policy) []netip.Prefix {
	var prefixes []netip.Prefix
	appendPrefix := func(p netip.Prefix) {
		if norm, err := decision.NormalizePrefix(p); err == nil {
			p = norm
		}
		prefixes = append(prefixes, p)
	}
	for _, s := range policy.Allowlist {
		if p, err := netip.ParsePrefix(s); err == nil {
			appendPrefix(p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, s := range policy.AdminCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			appendPrefix(p)
		}
	}
	return prefixes
}

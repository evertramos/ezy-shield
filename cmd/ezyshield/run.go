package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/collector"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/daemon"
	"github.com/evertramos/ezy-shield/internal/enforce"
	"github.com/evertramos/ezy-shield/internal/enrich"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/store"
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

	parsers := []sdk.Parser{
		parser.NewSSHParser(logger),
		parser.NewNginxParser(logger, parser.NginxConfig{}),
		parser.NewCaddyParser(logger, parser.CaddyConfig{}),
		parser.NewTraefikParser(logger, parser.TraefikConfig{}),
	}

	collectors := buildCollectors(cfg, logger)

	var enf sdk.Enforcer
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
		enf = enforce.New(sockPath, allowlist)
	}

	if cfg.Enforce != nil && len(cfg.Enforce.Cloudflare) > 0 {
		cfEnforcers := make([]sdk.Enforcer, 0, len(cfg.Enforce.Cloudflare))
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
			cfEnforcers = append(cfEnforcers, cfEnf)
		}
		all := make([]sdk.Enforcer, 0, len(cfEnforcers)+1)
		if enf != nil {
			all = append(all, enf)
		}
		all = append(all, cfEnforcers...)
		switch len(all) {
		case 0:
			// nothing wired up
		case 1:
			enf = all[0]
		default:
			enf = enforce.NewMulti(all...)
		}
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

	d, err := daemon.New(daemon.Config{
		Cfg:        cfg,
		Policy:     policy,
		Store:      db,
		Parsers:    parsers,
		Collectors: collectors,
		Enforcer:   enf,
		Notifier:   disp,
		AIProvider: aiProvider,
		AIBudget:   aiBudget,
		AICache:    aiCache,
		Enricher:   enricher,
		SocketPath: socketPath,
		Version:    version,
	})
	if err != nil {
		return fmt.Errorf("run: create daemon: %w", err)
	}

	return d.Run(ctx)
}

// buildCollectors creates sdk.Collector instances from the config slice.
func buildCollectors(cfg *config.Config, logger *slog.Logger) []sdk.Collector {
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
		notifiers = append(notifiers, notify.NewWebhook(url, wh.Headers))
		if len(wh.Severity) > 0 {
			severities["webhook"] = wh.Severity
		}
	}

	return notifiers, severities, nil
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
func parseAllowlist(policy *config.Policy) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, s := range policy.Allowlist {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, s := range policy.AdminCIDRs {
		if p, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}

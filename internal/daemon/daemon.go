package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/evertramos/ezy-shield/internal/aggregate"
	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/enrich"
	"github.com/evertramos/ezy-shield/internal/notify"
	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// DefaultSocketPath is where the control socket is created.
	DefaultSocketPath = "/run/ezyshield/ezyshield.sock"
	// DefaultMaxIPs is the default LRU cap for the per-IP aggregator.
	DefaultMaxIPs = 10_000
	// drainTimeout is how long SIGTERM waits for in-flight events to clear.
	drainTimeout = 30 * time.Second
	// flushInterval is how often stale aggregator buckets are evicted.
	flushInterval = 10 * time.Minute
	// rawLinesBuf is the size of the inter-stage channel between collectors and
	// the pipeline, providing back-pressure without blocking individual collectors.
	rawLinesBuf = 4096
)

// daemonStore is the persistence interface required by the daemon.
// *store.DB satisfies this interface.
type daemonStore interface {
	decision.Store
	ActiveBans(ctx context.Context) ([]sdk.Action, error)
	ExpireBans(ctx context.Context, now time.Time) (int, error)
	Unban(ctx context.Context, ip netip.Addr) error
	UnbanPrefix(ctx context.Context, prefix netip.Prefix) (int, error)
	AuditOp(ctx context.Context, op string, prefix netip.Prefix, ttl time.Duration, reason string) error
	// Arm/disarm support (issue #228): persisted runtime state + system audits.
	SetState(ctx context.Context, key, value string) error
	GetState(ctx context.Context, key string) (string, bool, error)
	DeleteState(ctx context.Context, key string) error
	AuditSystem(ctx context.Context, op, reason string) error
	RecordManualBan(ctx context.Context, ip netip.Addr, ttl time.Duration, reason string) error
	AddAllow(ctx context.Context, prefix netip.Prefix, expiresAt *time.Time, reason string) error
	RemoveAllow(ctx context.Context, prefix netip.Prefix) (int, error)
	ListAllow(ctx context.Context) ([]store.AllowEntry, error)
	ExpireAllows(ctx context.Context, now time.Time) (int, error)
	ListAuditLog(ctx context.Context, limit int) ([]store.AuditEntry, error)
	// Read-only queries backing the "report" verb (issue #54).
	GetOffender(ctx context.Context, ip netip.Addr) (*store.OffenderRecord, error)
	ActiveBanForIP(ctx context.Context, ip netip.Addr) (*store.BanRecord, error)
	StrikesForIP(ctx context.Context, ip netip.Addr, limit int) ([]store.StrikeRecord, error)
	AuditLogForIP(ctx context.Context, ip netip.Addr, limit int) ([]store.AuditEntry, error)
	ListOffenders(ctx context.Context, permanentOnly bool, limit int) ([]store.OffenderSummary, error)
}

// geoLookup is the minimal interface consumed from *enrich.Enricher.
// Using an interface here keeps the concrete type out of the daemon's
// hot path and allows mock injection in tests.
type geoLookup interface {
	Lookup(addr netip.Addr) sdk.Enrichment
}

// Config carries all pre-built components the daemon wires together.
// All fields except Policy and Store are optional (nil = feature disabled).
type Config struct {
	Cfg        *config.Config
	Policy     *config.Policy
	Store      daemonStore
	Parsers    []sdk.Parser
	Collectors []sdk.Collector
	Enforcer   sdk.Enforcer       // nil = no local enforcement
	Notifier   *notify.Dispatcher // nil = no notifications
	AIProvider sdk.AIProvider     // nil = no AI analysis
	AIBudget   *ai.Budget         // nil = no budget tracking
	AICache    *ai.Cache          // nil = no verdict caching
	Enricher   *enrich.Enricher   // nil = no GeoIP/ASN enrichment
	SocketPath string             // defaults to DefaultSocketPath
	Version    string
	MaxIPs     int // LRU cap; 0 = DefaultMaxIPs
	// PolicyPath is the policy.yaml location; the arm/disarm verbs persist
	// armed-state changes there (issue #228). Empty = runtime-only flips
	// (tests).
	PolicyPath string
	// ArmWindowTick overrides the auto-revert poll interval (tests only;
	// 0 = default 15s).
	ArmWindowTick time.Duration
}

// enricherFrom converts a *enrich.Enricher into the geoLookup interface, or
// returns nil when enricher is nil. This avoids a non-nil interface holding
// a nil pointer (which would cause a nil dereference in Lookup calls).
func enricherFrom(e *enrich.Enricher) geoLookup {
	if e == nil {
		return nil
	}
	return e
}

// Daemon wires collectors → parsers → aggregator → rules → decision →
// enforcer + notifier.  It also serves the unix-socket control API.
type Daemon struct {
	cfg    *config.Config
	policy *config.Policy
	store  daemonStore

	agg     *aggregate.Aggregator
	ruleEng *rules.Engine
	decEng  *decision.Engine

	parsers    []sdk.Parser
	collectors []sdk.Collector
	enforcer   sdk.Enforcer
	notifier   *notify.Dispatcher
	enricher   geoLookup // nil = enrichment disabled; set via enricherFrom()

	// AI optional components; all three must be non-nil to enable AI analysis.
	aiProvider     sdk.AIProvider
	aiBudget       *ai.Budget
	aiCache        *ai.Cache
	aiLo, aiHi     int         // ambiguous band: lo <= score <= hi triggers AI
	aiBudgetWarned atomic.Bool // guards the single "budget exceeded" WARN

	socketPath string
	// policyPath is where arm/disarm persist the armed flag ("" = skip).
	policyPath string
	// armWindowTick is the auto-revert poll interval (0 = default 15s).
	armWindowTick time.Duration
	// ineffDedup deduplicates ban_ineffective notifications systemically
	// (ADR-0009 §4, issue #146).
	ineffDedup ineffDedup
	// enfHealth tracks enforcer Ban/Sync health for the honest
	// enforcement-state reporting (issue #174).
	enfHealth enfHealth
	startTime time.Time
	version   string

	// evidenceJournalctl and evidenceDockerSocket override the journalctl
	// binary and Docker engine socket used by on-demand evidence extraction
	// (issue #126). Empty means the defaults ("journalctl" from PATH,
	// /var/run/docker.sock). Only set by tests.
	evidenceJournalctl   string
	evidenceDockerSocket string

	// staticAllowlist holds the parsed policy.Allowlist + policy.AdminCIDRs.
	// It is derived once at construction from d.policy and never mutated,
	// so no lock is needed. Kept semantically separate from runtimeAllowlist
	// so `ezyshield list --allow` / `ezyshield unallow` continue to reflect
	// only store-owned (runtime) entries — static prefixes are only
	// materialised at enforcer-sync time (see syncEnforcerAllowlist).
	staticAllowlist []netip.Prefix

	// events fans live pipeline/CLI events out to "subscribe" socket clients
	// (the `watch` command). Best-effort broadcast: slow subscribers drop
	// events rather than back-pressuring the pipeline.
	events *eventBus

	mu               sync.RWMutex
	runtimeAllowlist []netip.Prefix // dynamically added by the 'allow' socket command

	// actionsSink, when non-nil, receives every Action the pipeline produces.
	// Used in tests to observe pipeline output without a running enforcer.
	actionsSink chan<- sdk.Action
}

// New constructs a Daemon from a Config, building the rule engine and decision
// engine internally.  Store and Policy must be non-nil.
func New(dcfg Config) (*Daemon, error) {
	if dcfg.Policy == nil {
		return nil, fmt.Errorf("daemon: Policy must not be nil")
	}
	if dcfg.Store == nil {
		return nil, fmt.Errorf("daemon: Store must not be nil")
	}

	// RulesDir is defaulted by config.LoadConfigReader; a nil/hand-built
	// Cfg (tests) gets no overlay dir, which means embed-only — identical
	// to the pre-#136 behavior.
	rulesPath, rulesDir := "", ""
	if dcfg.Cfg != nil {
		rulesPath = dcfg.Cfg.RulesPath
		rulesDir = dcfg.Cfg.RulesDir
	}
	ruleEng, err := rules.New(rulesPath, rulesDir)
	if err != nil {
		return nil, fmt.Errorf("daemon: rule engine: %w", err)
	}

	windows := ruleEng.Windows()
	if len(windows) == 0 {
		windows = []time.Duration{time.Minute, 10 * time.Minute}
	}

	maxIPs := dcfg.MaxIPs
	if maxIPs <= 0 {
		maxIPs = DefaultMaxIPs
	}

	agg := aggregate.New(windows, 0).WithMaxIPs(maxIPs)

	decEng, err := decision.New(dcfg.Policy, dcfg.Store)
	if err != nil {
		return nil, fmt.Errorf("daemon: decision engine: %w", err)
	}

	socketPath := dcfg.SocketPath
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	d := &Daemon{
		cfg:             dcfg.Cfg,
		policy:          dcfg.Policy,
		store:           dcfg.Store,
		agg:             agg,
		ruleEng:         ruleEng,
		decEng:          decEng,
		parsers:         dcfg.Parsers,
		collectors:      dcfg.Collectors,
		enforcer:        dcfg.Enforcer,
		notifier:        dcfg.Notifier,
		aiProvider:      dcfg.AIProvider,
		aiBudget:        dcfg.AIBudget,
		aiCache:         dcfg.AICache,
		enricher:        enricherFrom(dcfg.Enricher),
		staticAllowlist: staticAllowlistFromPolicy(dcfg.Policy),
		events:          newEventBus(),
		socketPath:      socketPath,
		version:         dcfg.Version,
		startTime:       time.Now(),
		policyPath:      dcfg.PolicyPath,
		armWindowTick:   dcfg.ArmWindowTick,
	}

	// Enforcement-anomaly delivery (ADR-0009 §4, issue #146): the engine
	// detects, the daemon delivers. Injected before any goroutine starts.
	decEng.SetDiagnostics(d)

	if dcfg.Cfg != nil && dcfg.Cfg.AI != nil {
		d.aiLo = dcfg.Cfg.AI.AmbiguousBand[0]
		d.aiHi = dcfg.Cfg.AI.AmbiguousBand[1]
	}

	return d, nil
}

// SetActionsSink sets a channel that receives every pipeline Action.
// Intended for tests only.  Must be called before Run.
func (d *Daemon) SetActionsSink(ch chan<- sdk.Action) { d.actionsSink = ch }

// AddCollector appends a collector to the daemon's list.
// Must be called before Run.
func (d *Daemon) AddCollector(c sdk.Collector) { d.collectors = append(d.collectors, c) }

// Run starts the daemon.  It blocks until the context is cancelled or a signal
// is received:
//   - SIGTERM: graceful — stops collectors, drains in-flight events (≤30 s), then exits.
//   - SIGINT:  immediate — cancels everything and returns.
//
// Returns nil on clean shutdown.
func (d *Daemon) Run(parentCtx context.Context) error {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	slog.InfoContext(ctx, "daemon: starting",
		"version", d.version,
		"armed", d.policy.IsArmed(),
		"socket", d.socketPath,
	)

	// Sync enforcer at startup so active bans in the store are re-applied.
	if err := d.syncEnforcer(ctx); err != nil {
		slog.WarnContext(ctx, "daemon: startup enforcer sync failed", "err", err)
	}

	// Restore the runtime allowlist from the store (entries added by `ezyshield
	// allow` survive daemon restarts and expire automatically).
	if err := d.reloadAllowlist(ctx); err != nil {
		slog.WarnContext(ctx, "daemon: startup allowlist reload failed", "err", err)
	}

	// Push the reloaded allowlist to the enforcer's @allowed set so the
	// raw/prerouting drop rules honour allowlist-supremacy across restarts
	// (issue #23). Only enforcers that manage local firewall state care.
	if err := d.syncEnforcerAllowlist(ctx); err != nil {
		slog.WarnContext(ctx, "daemon: startup enforcer allowlist sync failed", "err", err)
	}

	rawLines := make(chan sdk.RawLine, rawLinesBuf)

	// collCtx controls collectors only; cancelled on SIGTERM to start draining.
	collCtx, cancelColls := context.WithCancel(ctx)
	defer cancelColls()

	var collWg sync.WaitGroup
	for _, col := range d.collectors {
		collWg.Add(1)
		go func(c sdk.Collector) {
			defer collWg.Done()
			d.runCollector(collCtx, c, rawLines)
		}(col)
	}

	// Close the rawLines channel once all collectors exit so the pipeline drains.
	collsDone := make(chan struct{})
	go func() {
		collWg.Wait()
		close(collsDone)
		close(rawLines)
	}()

	// Pipeline goroutine reads rawLines until the channel is closed.
	pipelineDone := make(chan struct{})
	go func() {
		defer close(pipelineDone)
		d.runPipeline(ctx, rawLines)
	}()

	// Aggregator flush goroutine — keeps memory bounded by removing idle IPs.
	go d.runFlush(ctx)

	// Socket server goroutine. Probe first so a manual `ezyshield watch`
	// doesn't unlink and replace a live daemon's control socket (issue #14).
	if d.socketPath != "" {
		if err := ProbeSocket(ctx, d.socketPath); err != nil {
			return fmt.Errorf("daemon: control socket unavailable: %w", err)
		}
		go d.serveSocket(ctx)
	}

	// Expire bans periodically.
	go d.runExpireBans(ctx)

	// Expire temporal allowlist entries periodically.
	go d.runExpireAllows(ctx)

	// Settle an arm window whose deadline passed while the daemon was down,
	// then keep watching it (issue #228).
	d.checkArmWindow(ctx, time.Now())
	go d.runArmWindow(ctx)

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		switch sig {
		case syscall.SIGTERM:
			slog.InfoContext(ctx, "daemon: SIGTERM — draining in-flight events")
			cancelColls() // stop collectors → rawLines will close → pipeline drains
			select {
			case <-pipelineDone:
				slog.InfoContext(ctx, "daemon: pipeline drained")
			case <-time.After(drainTimeout):
				slog.WarnContext(ctx, "daemon: drain timeout, forcing shutdown")
			}
		case syscall.SIGINT:
			slog.InfoContext(ctx, "daemon: SIGINT — immediate shutdown")
		}

	case <-parentCtx.Done():
		// Caller cancelled: drain briefly.
		cancelColls()
		select {
		case <-pipelineDone:
		case <-time.After(5 * time.Second):
		}
	}

	cancel()
	slog.InfoContext(ctx, "daemon: stopped")
	return nil
}

// runCollector wraps a single collector run with panic recovery and re-notifies
// on unexpected crash (watchdog role for per-collector goroutines).
func (d *Daemon) runCollector(ctx context.Context, c sdk.Collector, out chan<- sdk.RawLine) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.ErrorContext(ctx, "daemon: collector panic recovered",
				"panic", r, "stack", string(stack))
			d.notifyPanic(ctx, fmt.Sprintf("collector panic: %v", r))
		}
	}()
	if err := c.Run(ctx, out); err != nil && ctx.Err() == nil {
		slog.ErrorContext(ctx, "daemon: collector error", "err", err)
	}
}

// runPipeline reads raw lines, parses them into Events, feeds the aggregator,
// evaluates rules, and dispatches Actions.  It exits when rawLines is closed.
func (d *Daemon) runPipeline(ctx context.Context, rawLines <-chan sdk.RawLine) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.ErrorContext(ctx, "daemon: pipeline panic recovered",
				"panic", r, "stack", string(stack))
			d.notifyPanic(ctx, fmt.Sprintf("pipeline panic: %v", r))
		}
	}()

	for raw := range rawLines {
		if ctx.Err() != nil {
			return
		}
		d.processRaw(ctx, raw)
	}
}

// processRaw parses a single RawLine and runs the full pipeline for each Event.
func (d *Daemon) processRaw(ctx context.Context, raw sdk.RawLine) {
	events, err := d.parse(raw)
	if err != nil {
		slog.DebugContext(ctx, "daemon: parse error", "source", raw.Source, "err", err)
		return
	}

	for _, ev := range events {
		d.agg.Add(ev)

		verdicts := d.evaluateRules(ctx, ev.SourceIP)
		if len(verdicts) == 0 {
			continue
		}

		verdicts = d.maybeConsultAI(ctx, ev.SourceIP, verdicts)
		verdicts = d.maybeInjectGeoVerdict(ctx, ev.SourceIP, verdicts)

		// Live "detection" events for `watch` subscribers. Published before the
		// allowlist check on purpose: a detection happened either way, and the
		// resulting action (or lack of one) is a separate event.
		d.publishDetections(verdicts)

		// Runtime allowlist (added via 'allow' command) is checked before decision.
		if d.isRuntimeAllowlisted(ev.SourceIP) {
			slog.DebugContext(ctx, "daemon: runtime-allowlisted — skipping", "ip", ev.SourceIP)
			continue
		}

		action, err := d.decEng.Decide(ctx, verdicts)
		if err != nil {
			if err == decision.ErrRateLimited {
				slog.WarnContext(ctx, "daemon: ban rate limit exceeded; pausing 1 s")
				d.notifyCritical(ctx, "ban rate limit exceeded")
				time.Sleep(time.Second)
			} else {
				slog.ErrorContext(ctx, "daemon: decide error", "ip", ev.SourceIP, "err", err)
			}
			continue
		}

		d.dispatch(ctx, action)
	}
}

// maybeConsultAI checks if the highest-scoring verdict falls in the configured
// ambiguous band; if so it calls the AI provider (with budget and cache checks)
// and appends AI verdicts to the slice.  Returns verdicts unchanged when AI is
// disabled, the band is unconfigured, or the score is outside the band.
func (d *Daemon) maybeConsultAI(ctx context.Context, ip netip.Addr, verdicts []sdk.Verdict) []sdk.Verdict {
	if d.aiProvider == nil || d.aiBudget == nil || d.aiCache == nil {
		return verdicts
	}
	if d.aiLo >= d.aiHi {
		return verdicts
	}

	highScore := 0
	for _, v := range verdicts {
		if v.Score > highScore {
			highScore = v.Score
		}
	}
	if highScore < d.aiLo || highScore > d.aiHi {
		return verdicts
	}

	// Budget check — skip and warn once if daily limit is exhausted.
	exceeded, err := d.aiBudget.Exceeded(ctx)
	if err != nil {
		slog.WarnContext(ctx, "daemon: ai budget check failed", "err", err)
		return verdicts
	}
	if exceeded {
		if d.aiBudgetWarned.CompareAndSwap(false, true) {
			slog.WarnContext(ctx, "daemon: AI daily token budget exceeded; switching to rules-only")
		}
		return verdicts
	}

	// Collect aggregates for all windows; populate enrichment when available.
	now := time.Now()
	windows := d.agg.Windows()
	aggs := make([]sdk.Aggregate, 0, len(windows))
	for _, w := range windows {
		a := d.agg.Aggregate(ip, w, now)
		if d.enricher != nil {
			a.Enrich = d.enricher.Lookup(ip)
		}
		aggs = append(aggs, a)
	}

	// Cache check — keyed on first (shortest) window aggregate behavior signature.
	if len(aggs) > 0 {
		if cached := d.aiCache.Get(aggs[0]); cached != nil {
			slog.DebugContext(ctx, "daemon: ai cache hit", "ip", ip)
			return append(verdicts, cached...)
		}
	}

	// Fetch current budget for prompt style hint.
	budget, err := d.aiBudget.Current(ctx)
	if err != nil {
		slog.WarnContext(ctx, "daemon: ai budget query failed", "err", err)
		return verdicts
	}

	aiVerdicts, usage, err := d.aiProvider.Analyze(ctx, aggs, budget)
	if err != nil {
		slog.WarnContext(ctx, "daemon: ai analyze failed", "ip", ip, "err", err)
		return verdicts
	}

	slog.InfoContext(ctx, "daemon: ai analyzed",
		"ip", ip,
		"input_tokens", usage.InputTokens,
		"output_tokens", usage.OutputTokens,
		"cost_usd", usage.CostUSD,
	)

	if budgetExceeded, err := d.aiBudget.Consume(ctx, usage); err != nil {
		slog.WarnContext(ctx, "daemon: ai budget consume failed", "err", err)
	} else if budgetExceeded {
		slog.WarnContext(ctx, "daemon: AI daily token budget now exhausted")
		d.aiBudgetWarned.Store(true)
	}

	if len(aggs) > 0 && len(aiVerdicts) > 0 {
		d.aiCache.Set(aggs[0], aiVerdicts)
	}

	return append(verdicts, aiVerdicts...)
}

// maybeInjectGeoVerdict appends a synthetic "geo_block" verdict when the IP's
// country or ASN matches the policy block lists.  Returns verdicts unchanged
// when enrichment is disabled or the IP is not in any block list.
// The injected verdict carries GeoBlockScore so it pushes the combined score
// above the ban threshold even on first contact (no strikes needed).
func (d *Daemon) maybeInjectGeoVerdict(ctx context.Context, ip netip.Addr, verdicts []sdk.Verdict) []sdk.Verdict {
	if d.enricher == nil {
		return verdicts
	}
	if len(d.policy.BlockCountries) == 0 && len(d.policy.BlockASNs) == 0 {
		return verdicts
	}

	enr := d.enricher.Lookup(ip)

	// Country check.
	if enr.Country != "" {
		for _, c := range d.policy.BlockCountries {
			if strings.EqualFold(c, enr.Country) {
				slog.InfoContext(ctx, "daemon: geo_block country match",
					"ip", ip, "country", enr.Country)
				return append(verdicts, sdk.Verdict{
					IP:       ip,
					Score:    config.GeoBlockScore,
					Category: "geo_block",
					Source:   "policy:block_countries",
					Reason:   "blocked country: " + enr.Country,
				})
			}
		}
	}

	// ASN check (policy stores "AS12345", enrichment stores uint32).
	if enr.ASN != 0 {
		asnStr := fmt.Sprintf("AS%d", enr.ASN)
		for _, a := range d.policy.BlockASNs {
			if strings.EqualFold(a, asnStr) {
				slog.InfoContext(ctx, "daemon: geo_block ASN match",
					"ip", ip, "asn", asnStr, "org", enr.ASNOrg)
				return append(verdicts, sdk.Verdict{
					IP:       ip,
					Score:    config.GeoBlockScore,
					Category: "geo_block",
					Source:   "policy:block_asns",
					Reason:   fmt.Sprintf("blocked ASN: %s (%s)", asnStr, enr.ASNOrg),
				})
			}
		}
	}

	return verdicts
}

// parse returns Events from raw using the first matching parser.
func (d *Daemon) parse(raw sdk.RawLine) ([]sdk.Event, error) {
	for _, p := range d.parsers {
		if p.Matches(raw.Source) {
			return p.Parse(raw)
		}
	}
	return nil, nil // no matching parser → silently ignore
}

// evaluateRules aggregates all windows for ip and collects triggered verdicts.
// When an enricher is configured, each aggregate's Enrich field is populated
// before being passed to the rule engine.
func (d *Daemon) evaluateRules(ctx context.Context, ip netip.Addr) []sdk.Verdict {
	now := time.Now()
	var verdicts []sdk.Verdict
	for _, w := range d.agg.Windows() {
		agg := d.agg.Aggregate(ip, w, now)
		if d.enricher != nil {
			agg.Enrich = d.enricher.Lookup(ip)
		}
		verdicts = append(verdicts, d.ruleEng.Evaluate(ctx, agg)...)
	}
	return verdicts
}

// dispatch executes a decided Action: calls enforcer, notifier, and the test sink.
func (d *Daemon) dispatch(ctx context.Context, action sdk.Action) {
	slog.InfoContext(ctx, "daemon: action",
		"op", action.Op, "ip", action.IP,
		"strike", action.Strike, "ttl", action.TTL,
		"reason", action.Reason,
	)

	if d.actionsSink != nil {
		select {
		case d.actionsSink <- action:
		default:
		}
	}

	d.publishActionEvent(action.Op, action.IP.String(), action.Strike,
		action.TTL, action.Reason, "pipeline")

	if action.Op == "ban" && d.enforcer != nil {
		t := sdk.Target{IP: action.IP, TTL: action.TTL}
		err := d.enforcer.Ban(ctx, t)
		if err != nil {
			slog.ErrorContext(ctx, "daemon: enforcer ban failed", "ip", action.IP, "err", err)
			d.notifyCritical(ctx, fmt.Sprintf("enforcer ban failed for %s: %v", action.IP, err))
		}
		// Enforcement-state health (issue #174): a failed ban flips the
		// daemon to DEGRADED so status/doctor stop claiming protection.
		d.recordEnforceResult(ctx, "ban", err)
	}

	if d.notifier != nil && (action.Op == "ban" || action.Op == "dry_ban" || action.Op == "notify_only") {
		msg := sdk.Notification{
			Severity: severityFor(action.Op),
			Title:    fmt.Sprintf("[%s] %s — strike %d", action.Op, action.IP, action.Strike),
			Body:     action.Reason,
			Action:   &action,
		}
		if err := d.notifier.Send(ctx, msg); err != nil {
			slog.ErrorContext(ctx, "daemon: notifier error", "err", err)
		}
	}
}

// isRuntimeAllowlisted checks if ip is in the daemon's in-memory allowlist.
func (d *Daemon) isRuntimeAllowlisted(ip netip.Addr) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, p := range d.runtimeAllowlist {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// runtimeAllowlistOverlap reports whether prefix overlaps any entry of the
// in-memory runtime allowlist (operator 'allow' entries), returning the
// first overlapping entry. Overlap in either direction counts: a manual ban
// of a range that CONTAINS an allowlisted prefix would lock those hosts out
// just as surely as banning them directly (issue #211).
func (d *Daemon) runtimeAllowlistOverlap(prefix netip.Prefix) (bool, netip.Prefix) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	for _, p := range d.runtimeAllowlist {
		if p.Overlaps(prefix) {
			return true, p
		}
	}
	return false, netip.Prefix{}
}

// reloadAllowlist rebuilds the in-memory runtime allowlist from the store.
// Called at startup and after expiry sweeps so the in-memory view never lags
// behind the persisted state.
func (d *Daemon) reloadAllowlist(ctx context.Context) error {
	entries, err := d.store.ListAllow(ctx)
	if err != nil {
		return fmt.Errorf("list allows: %w", err)
	}
	prefixes := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		prefixes = append(prefixes, e.Prefix)
	}
	d.mu.Lock()
	d.runtimeAllowlist = prefixes
	d.mu.Unlock()
	return nil
}

// syncEnforcer loads active bans from the store and calls Enforcer.Sync.
// Simulated dry-run bans (Op=="dry_ban", ADR-0009 §5) are NEVER handed to
// the enforcer: they exist only to mirror suppression/escalation while
// armed=false, and must not materialise as real firewall rules — not even
// after the operator flips armed=true and the daemon restarts.
func (d *Daemon) syncEnforcer(ctx context.Context) error {
	if d.enforcer == nil {
		return nil
	}
	bans, err := d.store.ActiveBans(ctx)
	if err != nil {
		return fmt.Errorf("load active bans: %w", err)
	}
	targets := make([]sdk.Target, 0, len(bans))
	for _, b := range bans {
		if b.Op != "ban" {
			continue
		}
		targets = append(targets, sdk.Target{IP: b.IP, TTL: b.TTL})
	}
	err = d.enforcer.Sync(ctx, targets)
	// Enforcement-state health (issue #174): reconcile is the periodic
	// signal that flips DEGRADED→ACTIVE on recovery (and ACTIVE→DEGRADED if
	// the firewall backend went away between bans).
	d.recordEnforceResult(ctx, "sync", err)
	return err
}

// allowlistSyncer is the optional side of sdk.Enforcer that mirrors the
// daemon's allowlist to a local firewall — currently only satisfied by the
// nftables enforcer. Kept out of sdk.Enforcer proper because edge enforcers
// (Cloudflare) don't have a matching concept.
type allowlistSyncer interface {
	Allow(ctx context.Context, prefix netip.Prefix) error
	Unallow(ctx context.Context, prefix netip.Prefix) error
	SyncAllowlist(ctx context.Context, want []netip.Prefix) error
}

// syncEnforcerAllowlist pushes the union of the policy allowlist
// (policy.Allowlist + policy.AdminCIDRs, held in staticAllowlist) and the
// runtime allowlist (store-owned entries) to the enforcer's @allowed set.
// Called at startup (after reloadAllowlist) and after each expiry sweep.
// No-op when the enforcer doesn't implement the allowlistSyncer interface
// (e.g. Cloudflare edge enforcer alone).
//
// Materialising the union only here (not in runtimeAllowlist) keeps the
// runtime slice semantically store-owned: `ezyshield list --allow` shows
// only the entries an operator added at runtime, and audit trails aren't
// polluted with static policy prefixes. Issue #37.
func (d *Daemon) syncEnforcerAllowlist(ctx context.Context) error {
	syncer, ok := d.enforcer.(allowlistSyncer)
	if !ok {
		return nil
	}
	d.mu.RLock()
	runtime := make([]netip.Prefix, len(d.runtimeAllowlist))
	copy(runtime, d.runtimeAllowlist)
	d.mu.RUnlock()
	want := unionPrefixes(d.staticAllowlist, runtime)
	return syncer.SyncAllowlist(ctx, want)
}

// staticAllowlistFromPolicy parses policy.Allowlist + policy.AdminCIDRs into
// []netip.Prefix. Entries are already validated at policy-load time (see
// internal/config/policy.go Validate), so any parse failure here is treated
// as "skip" — logging is deferred to the caller since we have no context.
// Bare IPs in policy.Allowlist are widened to a host prefix (/32 or /128) so
// nftables can accept them in the "interval" set flag.
//
// A nil policy returns nil (defensive; New rejects nil policy, but tests may
// construct a Daemon differently in the future).
func staticAllowlistFromPolicy(p *config.Policy) []netip.Prefix {
	if p == nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(p.Allowlist)+len(p.AdminCIDRs))
	for _, s := range p.Allowlist {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, pfx)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, s := range p.AdminCIDRs {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			prefixes = append(prefixes, pfx)
		}
	}
	return prefixes
}

// unionPrefixes returns the deduplicated union of two prefix slices, preserving
// the order of first occurrence (static entries first, then runtime).
// netip.Prefix is comparable, so a map[netip.Prefix]struct{} is safe as a set.
// Duplicates can arise legitimately when an operator runs `ezyshield allow
// 203.0.113.42/32` for a prefix already listed in policy.admin_cidrs; the sync
// must push each nft element exactly once (SyncAllowlist iterates a map, but
// belt-and-suspenders: deduplicate before crossing the process boundary).
func unionPrefixes(a, b []netip.Prefix) []netip.Prefix {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(a)+len(b))
	out := make([]netip.Prefix, 0, len(a)+len(b))
	for _, p := range a {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range b {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// runFlush periodically removes stale aggregator buckets to bound memory.
func (d *Daemon) runFlush(ctx context.Context) {
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			d.agg.Flush(ctx, now.Add(-d.agg.Windows()[len(d.agg.Windows())-1]))
		}
	}
}

// runExpireAllows periodically removes elapsed allowlist entries from the store
// and rebuilds the in-memory runtime allowlist so expired ranges stop bypassing
// the decision pipeline within at most one tick.
func (d *Daemon) runExpireAllows(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n, err := d.store.ExpireAllows(ctx, now)
			if err != nil {
				slog.ErrorContext(ctx, "daemon: expire allows error", "err", err)
				continue
			}
			if n > 0 {
				slog.InfoContext(ctx, "daemon: expired allows", "count", n)
				if err := d.reloadAllowlist(ctx); err != nil {
					slog.ErrorContext(ctx, "daemon: post-expire allow reload failed", "err", err)
				}
				// Keep the enforcer's @allowed set in sync so expired
				// entries no longer accept at the raw hook (issue #23).
				if err := d.syncEnforcerAllowlist(ctx); err != nil {
					slog.ErrorContext(ctx, "daemon: post-expire enforcer allowlist sync failed", "err", err)
				}
			}
		}
	}
}

// runExpireBans periodically removes elapsed bans from the store.
func (d *Daemon) runExpireBans(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n, err := d.store.ExpireBans(ctx, now)
			if err != nil {
				slog.ErrorContext(ctx, "daemon: expire bans error", "err", err)
				continue
			}
			if n > 0 {
				slog.InfoContext(ctx, "daemon: expired bans", "count", n)
				// Reconcile enforcer after expiry.
				if err := d.syncEnforcer(ctx); err != nil {
					slog.ErrorContext(ctx, "daemon: post-expire sync failed", "err", err)
				}
			}
		}
	}
}

// notifyPanic sends a critical notification about a recovered panic.
func (d *Daemon) notifyPanic(ctx context.Context, msg string) {
	if d.notifier == nil {
		return
	}
	_ = d.notifier.Send(ctx, sdk.Notification{
		Severity: "critical",
		Title:    "daemon panic recovered",
		Body:     msg,
	})
}

// notifyCritical sends a critical system notification.
func (d *Daemon) notifyCritical(ctx context.Context, msg string) {
	if d.notifier == nil {
		return
	}
	_ = d.notifier.Send(ctx, sdk.Notification{
		Severity: "critical",
		Title:    msg,
		Body:     msg,
	})
}

func severityFor(op string) string {
	switch op {
	case "ban":
		return "warn"
	case "dry_ban":
		return "info"
	case "notify_only":
		return "info"
	default:
		return "info"
	}
}

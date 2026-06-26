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
	startTime  time.Time
	version    string

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

	rulesPath := ""
	if dcfg.Cfg != nil {
		rulesPath = dcfg.Cfg.RulesPath
	}
	ruleEng, err := rules.New(rulesPath)
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
		cfg:        dcfg.Cfg,
		policy:     dcfg.Policy,
		store:      dcfg.Store,
		agg:        agg,
		ruleEng:    ruleEng,
		decEng:     decEng,
		parsers:    dcfg.Parsers,
		collectors: dcfg.Collectors,
		enforcer:   dcfg.Enforcer,
		notifier:   dcfg.Notifier,
		aiProvider: dcfg.AIProvider,
		aiBudget:   dcfg.AIBudget,
		aiCache:    dcfg.AICache,
		enricher:   enricherFrom(dcfg.Enricher),
		socketPath: socketPath,
		version:    dcfg.Version,
		startTime:  time.Now(),
	}

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
		"armed", d.policy.Armed,
		"socket", d.socketPath,
	)

	// Sync enforcer at startup so active bans in the store are re-applied.
	if err := d.syncEnforcer(ctx); err != nil {
		slog.WarnContext(ctx, "daemon: startup enforcer sync failed", "err", err)
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

	// Socket server goroutine.
	if d.socketPath != "" {
		go d.serveSocket(ctx)
	}

	// Expire bans periodically.
	go d.runExpireBans(ctx)

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

	if action.Op == "ban" && d.enforcer != nil {
		t := sdk.Target{IP: action.IP, TTL: action.TTL}
		if err := d.enforcer.Ban(ctx, t); err != nil {
			slog.ErrorContext(ctx, "daemon: enforcer ban failed", "ip", action.IP, "err", err)
			d.notifyCritical(ctx, fmt.Sprintf("enforcer ban failed for %s: %v", action.IP, err))
		}
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

// syncEnforcer loads active bans from the store and calls Enforcer.Sync.
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
		targets = append(targets, sdk.Target{IP: b.IP, TTL: b.TTL})
	}
	return d.enforcer.Sync(ctx, targets)
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

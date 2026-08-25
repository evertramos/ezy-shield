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

	// Collector supervision defaults (issue #305). A collector goroutine that
	// returns a runtime error is restarted with capped exponential backoff so a
	// transient fault (logrotate reopen delay, journald restart, a briefly
	// missing file) can't silently disable detection on that source until the
	// next daemon restart. Context cancellation is treated as a clean shutdown
	// and is never restarted.
	defaultCollectorBackoffBase = 1 * time.Second
	// defaultCollectorBackoffMax caps the restart delay so a permanently broken
	// collector settles into a slow retry instead of hot-looping.
	defaultCollectorBackoffMax = 30 * time.Second
	// defaultCollectorStableRuntime is how long a single Run must survive before
	// its next failure is treated as a fresh incident (backoff + failure counter
	// reset). Without this a collector that runs healthily for hours then hits
	// one error would inherit stale escalated backoff.
	defaultCollectorStableRuntime = 60 * time.Second
	// defaultCollectorFailureAlert is the number of consecutive failures after
	// which a critical notification fires, so a permanently broken source
	// surfaces to the operator instead of retrying silently forever.
	defaultCollectorFailureAlert = 5
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
	// EnfProbeTick overrides the enforcement health-probe interval (tests
	// only; 0 = default 5m). See runEnforceProbe (issue #174).
	EnfProbeTick time.Duration
	// ExpireTick overrides the ban/allow expiry poll interval (tests only;
	// 0 = default 1m). See runExpireBans / runExpireAllows (issue #327).
	ExpireTick time.Duration
	// SSHRecheckTick / SSHRecheckDelay override the deferred anti-lockout
	// re-evaluation poll interval and refusal→re-check delay (tests only;
	// 0 = defaults). See sshrecheck.go (issue #420).
	SSHRecheckTick  time.Duration
	SSHRecheckDelay time.Duration
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
	aiProvider sdk.AIProvider
	aiBudget   *ai.Budget
	aiCache    *ai.Cache
	aiLo, aiHi int // ambiguous band: lo <= score <= hi triggers AI

	socketPath string
	// policyPath is where arm/disarm persist the armed flag ("" = skip).
	policyPath string
	// armWindowTick is the auto-revert poll interval (0 = default 15s).
	armWindowTick time.Duration
	// enfProbeTick is the enforcement health-probe interval (0 = default 5m).
	enfProbeTick time.Duration
	// expireTick is the ban/allow expiry poll interval (0 = default 1m).
	expireTick time.Duration
	// sshRecheckTick / sshRecheckDelay tune the deferred anti-lockout
	// re-evaluation (0 = defaults; see sshrecheck.go, issue #420).
	sshRecheckTick  time.Duration
	sshRecheckDelay time.Duration
	// sshRecheck holds the per-IP deferred re-checks armed after SSH-peer
	// anti-lockout refusals that suppressed a would-be ban (issue #420).
	sshRecheck sshRecheckQueue
	// ineffDedup deduplicates ban_ineffective notifications systemically
	// (ADR-0009 §4, issue #146).
	ineffDedup ineffDedup
	// enfHealth tracks enforcer Ban/Sync health for the honest
	// enforcement-state reporting (issue #174).
	enfHealth enfHealth
	// collHealth tracks per-collector runtime health for the honest
	// observation-state reporting in status (issue #456; see collhealth.go).
	// Fed by the runCollector supervisor (issue #305).
	collHealth collHealth
	startTime  time.Time
	version    string

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

	// Collector supervision tunables (issue #305). Zero means "use the package
	// default"; only tests set these to keep restart timing fast.
	collBackoffBase   time.Duration
	collBackoffMax    time.Duration
	collStableRuntime time.Duration
	collFailureAlert  int
}

// collectorBackoffBase / collectorBackoffMax / collectorStableRuntime /
// collectorFailureAlert return the effective supervision tunables, falling back
// to the package defaults when unset (issue #305).
func (d *Daemon) collectorBackoffBase() time.Duration {
	if d.collBackoffBase > 0 {
		return d.collBackoffBase
	}
	return defaultCollectorBackoffBase
}

func (d *Daemon) collectorBackoffMax() time.Duration {
	if d.collBackoffMax > 0 {
		return d.collBackoffMax
	}
	return defaultCollectorBackoffMax
}

func (d *Daemon) collectorStableRuntime() time.Duration {
	if d.collStableRuntime > 0 {
		return d.collStableRuntime
	}
	return defaultCollectorStableRuntime
}

func (d *Daemon) collectorFailureAlert() int {
	if d.collFailureAlert > 0 {
		return d.collFailureAlert
	}
	return defaultCollectorFailureAlert
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
		enfProbeTick:    dcfg.EnfProbeTick,
		expireTick:      dcfg.ExpireTick,
		sshRecheckTick:  dcfg.SSHRecheckTick,
		sshRecheckDelay: dcfg.SSHRecheckDelay,
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

	// Keep the enforcement state fresh on quiet hosts (issue #174).
	go d.runEnforceProbe(ctx)

	// Re-evaluate IPs whose would-be ban was refused because of an
	// ESTABLISHED SSH connection, once that connection is gone (issue #420).
	go d.runSSHRecheck(ctx)

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

// runCollector supervises a single collector for the life of collCtx (issue
// #305). A collector whose Run returns a runtime error — or panics — is
// restarted with capped exponential backoff so a transient fault (a briefly
// missing log file, a logrotate reopen that overruns filetail's short internal
// retry, a journald restart killing journalctl) cannot silently disable
// detection on that source until the daemon itself is restarted. It
// distinguishes two exits that must NOT restart: context cancellation (clean
// shutdown / SIGTERM drain) and a nil return (the source finished on its own,
// e.g. a bounded file), both of which end supervision. Backoff and the
// consecutive-failure counter reset once a Run has survived collectorStableRuntime,
// so a long-healthy collector that later fails is treated as a fresh incident
// rather than inheriting stale escalated backoff.
func (d *Daemon) runCollector(ctx context.Context, c sdk.Collector, out chan<- sdk.RawLine) {
	name := collectorName(c)
	backoff := d.collectorBackoffBase()
	consecutiveFailures := 0

	for {
		// Never start (or restart) after a shutdown signal.
		if ctx.Err() != nil {
			return
		}

		start := time.Now()
		err := d.runCollectorOnce(ctx, c, out)
		ran := time.Since(start)

		// Clean shutdown: context cancelled. Do not restart.
		if ctx.Err() != nil {
			return
		}

		// A run that survived long enough is considered healthy; its next
		// failure starts a fresh backoff/alert cycle (and clears any
		// degraded state it had in the status report, issue #456).
		if ran >= d.collectorStableRuntime() {
			backoff = d.collectorBackoffBase()
			consecutiveFailures = 0
			d.recordCollectorHealthy(ctx, name)
		}

		// A nil return without cancellation means the source completed on its
		// own (nothing left to tail). Restarting would hot-loop, so stop.
		if err == nil {
			slog.InfoContext(ctx, "daemon: collector exited cleanly", "collector", name)
			return
		}

		consecutiveFailures++
		d.recordCollectorFailure(ctx, name, consecutiveFailures, err)
		slog.WarnContext(ctx, "daemon: collector error; restarting after backoff",
			"collector", name,
			"err", err,
			"backoff", backoff,
			"consecutive_failures", consecutiveFailures,
		)

		// Surface a permanently broken source instead of retrying silently.
		if consecutiveFailures == d.collectorFailureAlert() {
			d.notifyCritical(ctx, fmt.Sprintf(
				"collector %q failed %d times in a row; detection on this source may be degraded",
				name, consecutiveFailures))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, d.collectorBackoffMax())
	}
}

// runCollectorOnce runs a collector exactly once, converting a panic into an
// error so the supervisor (runCollector) can restart it rather than letting the
// panic unwind and kill the supervising goroutine.
func (d *Daemon) runCollectorOnce(ctx context.Context, c sdk.Collector, out chan<- sdk.RawLine) (err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := debug.Stack()
			slog.ErrorContext(ctx, "daemon: collector panic recovered",
				"collector", collectorName(c), "panic", r, "stack", string(stack))
			d.notifyPanic(ctx, fmt.Sprintf("collector panic: %v", r))
			err = fmt.Errorf("collector panic: %v", r)
		}
	}()
	return c.Run(ctx, out)
}

// collectorName derives a stable, human-readable identity for logs and alerts.
// Collectors may implement the optional Name() string method (the concrete
// filetail/journald/docker collectors do); otherwise the Go type name is used.
// It never returns attacker-controlled content beyond an operator-configured
// path/unit/container name.
func collectorName(c sdk.Collector) string {
	if n, ok := c.(interface{ Name() string }); ok {
		if s := n.Name(); s != "" {
			return s
		}
	}
	return fmt.Sprintf("%T", c)
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

		// An SSH-peer anti-lockout refusal that suppressed a would-be ban is
		// re-examined after the connection closes — a fast-reconnect burst
		// otherwise ends with in-window evidence nobody ever looks at again
		// (issue #420).
		d.maybeScheduleSSHRecheck(ctx, action, verdicts)
	}
}

// bindVerdictsToIP enforces the AI-boundary target invariant at the daemon
// chokepoint (issue #402, Hard Rule 1, SECURITY-REVIEW §5): every AI verdict
// leaving maybeConsultAI must target the IP whose aggregates were analyzed.
// A verdict naming any other address — a model-chosen victim smuggled in via
// prompt injection, a hallucination, or a stale cache entry — is dropped, and
// survivors are rewritten to the canonical requested address so the decision
// engine's single-IP invariant holds.
//
// Providers already bound verdicts to their batch (boundToBatch, issue #312)
// and the cache re-targets replayed entries (issue #311); this daemon-side
// pass deliberately repeats the check once, centrally, so a future provider or
// cache path that forgets its local bound cannot reintroduce the class
// (defense in depth — do not remove the provider-level bounds in its name).
//
// Matching is representation-insensitive via Unmap (IPv4-mapped IPv6 forms
// compare equal to their IPv4 address, cf. #314) but otherwise exact: netip
// address equality includes the zone, so a zone mismatch in either direction
// fails closed (dropped, never "close enough"-rebound).
func bindVerdictsToIP(ctx context.Context, verdicts []sdk.Verdict, ip netip.Addr) []sdk.Verdict {
	if len(verdicts) == 0 {
		return verdicts
	}
	want := ip.Unmap()
	out := make([]sdk.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		if v.IP.Unmap() != want {
			slog.WarnContext(ctx, "daemon: dropping AI verdict for off-request IP",
				"verdict_ip", v.IP, "requested_ip", ip, "score", v.Score, "source", v.Source)
			continue
		}
		v.IP = ip
		out = append(out, v)
	}
	return out
}

// maybeConsultAI checks if the highest-scoring verdict falls in the configured
// ambiguous band; if so it calls the AI provider (with budget and cache checks)
// and appends AI verdicts to the slice.  Returns verdicts unchanged when AI is
// disabled, the band is unconfigured, or the score is outside the band.
//
// All returned AI verdicts — fresh or cached — pass through bindVerdictsToIP,
// and fresh verdicts are bound before the cache Set so a poisoned target can
// neither act now nor be replayed later.
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

	// ── Decided-outcome gates (issue #419) ──────────────────────────────────
	// The decision engine takes the MAX score across verdicts (Decide), so a
	// consult can only matter while the rules alone are still below the ban
	// threshold. Once a rule has already decided "ban", an AI verdict is
	// structurally unable to change the outcome — a lower AI score never
	// reduces a rule ban. Skip the consult; the distinct log lines below let
	// audits count the savings (61% of audited spend fell in these gates).
	if highScore >= d.policy.BanThreshold {
		slog.DebugContext(ctx, "daemon: ai consult skipped — rule score already decisive",
			"ip", ip, "score", highScore, "ban_threshold", d.policy.BanThreshold)
		return verdicts
	}

	// Likewise, an actively banned IP is a decided outcome: the engine's
	// active-ban guard suppresses new strikes for the ban's duration, so a
	// consult could only re-analyze traffic leaking past enforcement. Mirror
	// the guard's one asymmetry (ADR-0009 §5): an ARMED engine ignores
	// simulated (dry-run) bans — nothing is enforced for those, so the
	// consult can still convert the episode into a real ban and proceeds.
	// On a store error, fall through and consult (pre-#419 behavior): a
	// wasted call is safer than silently muting the AI leg on a DB hiccup.
	if _, _, dryBan, banned, err := d.store.GetBanInfo(ctx, ip.Unmap()); err != nil {
		slog.WarnContext(ctx, "daemon: ai ban-state check failed; consulting anyway",
			"ip", ip, "err", err)
	} else if banned && (!dryBan || !d.policy.IsArmed()) {
		slog.DebugContext(ctx, "daemon: ai consult skipped — IP already banned",
			"ip", ip, "score", highScore, "dry_run", dryBan)
		return verdicts
	}

	// Budget check — skip and warn once if daily limit is exhausted.
	exceeded, err := d.aiBudget.Exceeded(ctx)
	if err != nil {
		slog.WarnContext(ctx, "daemon: ai budget check failed", "err", err)
		return verdicts
	}
	if exceeded {
		// Once per UTC day (Budget owns the rollover, issue #359) — the old
		// process-lifetime bool meant day-two breaches were never logged.
		if d.aiBudget.NoteExceededToday() {
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
	// Cache.Get already re-targets replayed verdicts to the requesting IP
	// (issue #311); the bind below re-asserts that invariant at the chokepoint.
	if len(aggs) > 0 {
		if cached := d.aiCache.Get(aggs[0]); cached != nil {
			slog.DebugContext(ctx, "daemon: ai cache hit", "ip", ip)
			return append(verdicts, bindVerdictsToIP(ctx, cached, ip)...)
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
	}

	// Bind BEFORE the cache Set: an off-request verdict must neither reach the
	// decision engine now nor be stored for signature replay later (#402).
	aiVerdicts = bindVerdictsToIP(ctx, aiVerdicts, ip)

	// Cache.Set skips allowlist-clamped verdicts internally (issue #402), so a
	// clamp for this IP is never replayed onto same-signature traffic from
	// non-allowlisted sources.
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
// daemon's allowlist to a local firewall — implemented by the nftables
// enforcer and forwarded through the enforce.Gate / enforce.MultiEnforcer
// wrappers run.go always applies (enforce.AllowlistSyncer is the exported
// mirror of this interface; compile-time guards in internal/enforce keep the
// wrappers forwarding — issue #317). Kept out of sdk.Enforcer proper because
// edge enforcers (Cloudflare) don't have a matching concept.
type allowlistSyncer interface {
	Allow(ctx context.Context, prefix netip.Prefix) error
	Unallow(ctx context.Context, prefix netip.Prefix) error
	SyncAllowlist(ctx context.Context, want []netip.Prefix) error
}

// syncEnforcerAllowlist pushes the union of the policy allowlist
// (policy.Allowlist + policy.AdminCIDRs, held in staticAllowlist) and the
// runtime allowlist (store-owned entries) to the enforcer's @allowed set.
// Called at startup (after reloadAllowlist), after each expiry sweep, and
// after an operator unallow (handleUnallow, issue #404).
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
// IPv4-mapped spellings ("::ffff:192.0.2.0/120", copied from dual-stack logs)
// are canonicalized to plain v4 (issue #405, allowlist side of #365): fed to
// Gate.SyncAllowlist verbatim they would land in the nftables @allowed v6 set
// as dead entries that never match IPv4 packets. Mapped prefixes broader than
// /96 have no IPv4 equivalent and are kept as parsed — dropping an allowlist
// entry would remove protection. Mirrors cmd/ezyshield parseAllowlist (#400).
//
// A nil policy returns nil (defensive; New rejects nil policy, but tests may
// construct a Daemon differently in the future).
func staticAllowlistFromPolicy(p *config.Policy) []netip.Prefix {
	if p == nil {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(p.Allowlist)+len(p.AdminCIDRs))
	appendPrefix := func(pfx netip.Prefix) {
		if norm, err := decision.NormalizePrefix(pfx); err == nil {
			pfx = norm
		}
		prefixes = append(prefixes, pfx)
	}
	for _, s := range p.Allowlist {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			appendPrefix(pfx)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	for _, s := range p.AdminCIDRs {
		if pfx, err := netip.ParsePrefix(s); err == nil {
			appendPrefix(pfx)
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
	t := time.NewTicker(d.expireTickVal())
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

// expireTickVal returns the configured expiry poll interval (tests) or the
// 1-minute default (issue #327 gave this loop the same injection point the
// arm-window and enforcement-probe loops already had, so it is testable).
func (d *Daemon) expireTickVal() time.Duration {
	if d.expireTick > 0 {
		return d.expireTick
	}
	return time.Minute
}

// runExpireBans periodically removes elapsed bans from the store.
func (d *Daemon) runExpireBans(ctx context.Context) {
	t := time.NewTicker(d.expireTickVal())
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

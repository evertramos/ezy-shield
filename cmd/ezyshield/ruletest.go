// SPDX-License-Identifier: AGPL-3.0-only

package main

// `ezyshield rule test` (issue #224): dry-evaluate one rule against the
// event history the daemon already stores, BEFORE enabling it. Strictly
// read-only — no strikes, no bans, no audit mutations; the store is only
// SELECTed and the daemon is never contacted.
//
// The critical output is the false-positive early warning: how many of the
// would-be detections land on allowlisted/admin addresses. A rule that
// "fires" mostly on the operator's own ranges needs tuning, not enabling.
//
// Honest limitation (documented in --help and in every run): evaluation
// uses the stored hourly aggregates (events_agg), so granularity is bounded
// by the 1-hour buckets and by retention; only kinds referenced by
// long-window (>1h) rules are persisted at all, and field-level matchers
// cannot be applied (the aggregates keep counts, never field values).

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/internal/store"
)

// ruleTestIPCap bounds the sampled per-IP listing (text and JSON).
const ruleTestIPCap = 10

// ruleTestLimitation is the honest-limitation line printed on every run.
const ruleTestLimitation = "evaluation uses stored hourly aggregates: granularity is bounded by 1-hour buckets and by retention, " +
	"and only kinds referenced by long-window (>1h) rules in the running rule set are persisted"

func newRuleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "Work with detection rules",
	}
	cmd.AddCommand(newRuleTestCmd())
	return cmd
}

func newRuleTestCmd() *cobra.Command {
	var (
		since      string
		dbPath     string
		configPath = defaultConfigDir + "/config.yaml"
		policyPath = defaultConfigDir + "/policy.yaml"
	)

	cmd := &cobra.Command{
		Use:   "test <name|file>",
		Short: "Dry-evaluate a rule against stored event history (no side effects)",
		Long: `Evaluate one rule against the event history the daemon already stores,
without enabling it and without any side effects: no strikes, no bans, no
audit mutations. The daemon does not need to be running.

The argument is either the name of a loaded rule (embedded base, rules.d
drop-in, or legacy rules_path override — resolved through config.yaml) or a
path to a standalone rules YAML file. The rule is validated with the same
fail-closed validation as the daemon's loader; an invalid rule is a clear
error and a non-zero exit.

Output: how many times the rule would have fired, unique IPs (sampled),
per-day distribution, and — critically — how many of those IPs are covered
by the allowlist/admin CIDRs or the runtime allowlist (the false-positive
early warning: a rule firing on your own ranges needs tuning, not enabling).

Honest limitation: ` + ruleTestLimitation + `.
Field-level matchers (field/value/contains) cannot be applied to stored
aggregates; such rules are reported as a kind-level UPPER BOUND, loudly.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, err := parseSinceDuration(since)
			if err != nil {
				return fmt.Errorf("invalid --since %q: %w", since, err)
			}
			return runRuleTest(cmd, args[0], dur, dbPath, configPath, policyPath,
				cmd.Flags().Changed("config"), cmd.Flags().Changed("policy"))
		},
	}

	cmd.Flags().StringVar(&since, "since", "24h",
		"history window to evaluate (Go duration; 'd' suffix allowed, e.g. 7d)")
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/ezyshield/ezyshield.db",
		"path to SQLite database")
	cmd.Flags().StringVar(&configPath, "config", configPath,
		"path to config.yaml (for rules.d / rules_path resolution)")
	cmd.Flags().StringVar(&policyPath, "policy", policyPath,
		"path to policy.yaml (for the allowlist false-positive check)")

	return cmd
}

// parseSinceDuration parses a Go duration, additionally accepting a "d"
// (day) suffix — "7d" reads better than "168h" for history ranges.
func parseSinceDuration(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseFloat(n, 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("expected a positive number of days before 'd'")
		}
		return time.Duration(days * float64(24*time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return d, nil
}

// ruleTestIP is one sampled IP in the result.
type ruleTestIP struct {
	IP          string `json:"ip"`
	Detections  int    `json:"detections"`
	Events      int    `json:"events"`
	Allowlisted bool   `json:"allowlisted"`
	AllowSource string `json:"allow_source,omitempty"` // "policy" | "runtime"
}

// ruleTestResult is the per-rule JSON envelope.
type ruleTestResult struct {
	Rule struct {
		Name          string   `json:"name"`
		Kinds         []string `json:"kinds"`
		WindowSeconds int64    `json:"window_seconds"`
		Threshold     int      `json:"threshold"`
		Score         int      `json:"score"`
		Category      string   `json:"category"`
		FieldLevel    bool     `json:"field_level"`
	} `json:"rule"`
	Since           string         `json:"since"`
	Detections      int            `json:"detections"`
	UniqueIPs       int            `json:"unique_ips"`
	AllowlistedHits int            `json:"allowlisted_hits"`
	IPs             []ruleTestIP   `json:"ips"`
	IPsTruncated    bool           `json:"ips_truncated"`
	PerDay          map[string]int `json:"per_day"`
	UpperBound      bool           `json:"upper_bound"`
	Warnings        []string       `json:"warnings"`
	Limitation      string         `json:"limitation"`
}

// ipSimulation is the per-IP outcome of the sliding-window dry run.
type ipSimulation struct {
	ip         string
	events     int
	detections []int64 // bucket starts (epoch seconds) where the rule would fire
}

// simulateRule slides the rule window over the stored hourly buckets and
// counts rising-edge threshold crossings per IP: consecutive saturated hours
// are one incident, and a new detection is only counted after the windowed
// sum has dropped back below the threshold. rows must be ordered by
// (ip, bucket_start), as EventCountsByHour returns them.
func simulateRule(rows []store.HourCount, window time.Duration, threshold int) []ipSimulation {
	var out []ipSimulation
	winSec := int64(window / time.Second)

	flush := func(ip string, buckets []store.HourCount) {
		sim := ipSimulation{ip: ip}
		sum := 0
		i := 0
		fired := false
		for j := range buckets {
			sim.events += buckets[j].Count
			// Evict buckets that fell out of the window ending at this hour.
			for i < j && buckets[i].BucketStart <= buckets[j].BucketStart-winSec {
				sum -= buckets[i].Count
				i++
			}
			// Between event hours the sum only decays; if it dropped below
			// the threshold before this bucket, a new crossing is a new
			// detection.
			if sum < threshold {
				fired = false
			}
			sum += buckets[j].Count
			if sum >= threshold && !fired {
				sim.detections = append(sim.detections, buckets[j].BucketStart)
				fired = true
			}
		}
		out = append(out, sim)
	}

	start := 0
	for i := 1; i <= len(rows); i++ {
		if i == len(rows) || rows[i].IP != rows[i-1].IP {
			flush(rows[i-1].IP, rows[start:i])
			start = i
		}
	}
	return out
}

// allowChecker answers "is this IP protected?" from the two allowlist
// layers a running daemon would consult: the static policy allowlist
// (allowlist + admin_cidrs) and the runtime allowlist stored in the DB.
type allowChecker struct {
	policy  []netip.Prefix
	runtime []netip.Prefix
}

func (a allowChecker) check(ip netip.Addr) (bool, string) {
	for _, p := range a.policy {
		if p.Contains(ip) {
			return true, "policy"
		}
	}
	for _, p := range a.runtime {
		if p.Contains(ip) {
			return true, "runtime"
		}
	}
	return false, ""
}

func runRuleTest(cmd *cobra.Command, arg string, since time.Duration,
	dbPath, configPath, policyPath string, configSet, policySet bool) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	now := time.Now()

	// 1. Resolve the rule(s): a standalone file path, or a loaded-rule name.
	var (
		infos    []rules.RuleInfo
		warnings []string
	)
	if fi, err := os.Stat(arg); err == nil && !fi.IsDir() {
		infos, err = rules.LoadStandaloneFile(arg)
		if err != nil {
			return err
		}
	}

	// The engine is loaded either to resolve a rule name or (best-effort,
	// for standalone files) to know which kinds the running rule set
	// persists — the coverage warning below.
	var persisted map[string]bool
	eng, engErr := loadEngineForTest(configPath, configSet)
	if eng != nil {
		persisted = map[string]bool{}
		for _, kinds := range eng.KindsForLongWindows() {
			for _, k := range kinds {
				persisted[k] = true
			}
		}
	}
	if infos == nil {
		if engErr != nil {
			return fmt.Errorf("rule test: load rule set: %w", engErr)
		}
		info, ok := eng.Rule(arg)
		if !ok {
			return fmt.Errorf("rule test: no rule named %q and no such file; loaded rules: %s",
				arg, strings.Join(eng.RuleNames(), ", "))
		}
		infos = []rules.RuleInfo{info}
	} else if engErr != nil {
		warnings = append(warnings,
			fmt.Sprintf("could not load the running rule set (%v): cannot check which kinds are persisted", engErr))
	}

	// 2. The store must already exist — this command never creates state.
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("rule test: no database at %s (is this the right --db path?): %w", dbPath, err)
	}
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("rule test: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	// 3. Allowlist layers for the false-positive check.
	checker, allowWarn, err := loadAllowlists(ctx, db, policyPath, policySet, now)
	if err != nil {
		return err
	}
	warnings = append(warnings, allowWarn...)

	// 4. Evaluate each rule and render.
	results := make([]ruleTestResult, 0, len(infos))
	for _, info := range infos {
		res, err := evaluateRuleAgainstStore(ctx, db, info, since, now, persisted, checker)
		if err != nil {
			return err
		}
		res.Warnings = append(append([]string{}, warnings...), res.Warnings...)
		results = append(results, res)
	}

	if jsonOutput {
		return writeJSON(out, map[string]any{"results": results})
	}
	for i, res := range results {
		if i > 0 {
			fmt.Fprintln(out) //nolint:errcheck
		}
		renderRuleTest(cmd, res)
	}
	return nil
}

// loadEngineForTest loads the same rule layers the daemon would: config.yaml
// (when present) supplies rules_path / rules_dir; a missing default config
// falls back to the embedded base + default rules.d. An explicitly-set
// --config that cannot be read is an error surfaced to the caller.
func loadEngineForTest(configPath string, configSet bool) (*rules.Engine, error) {
	overridePath := ""
	rulesDir := config.DefaultRulesDir
	if _, err := os.Stat(configPath); err == nil {
		cfg, err := config.LoadConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", configPath, err)
		}
		overridePath = cfg.RulesPath
		rulesDir = cfg.RulesDir
	} else if configSet {
		return nil, fmt.Errorf("config %s: %w", configPath, err)
	}
	return rules.New(overridePath, rulesDir)
}

// loadAllowlists builds the false-positive checker from policy.yaml (static
// allowlist + admin CIDRs, same parsing as the decision engine) and the
// runtime allowlist rows in the store (expired entries skipped).
func loadAllowlists(ctx context.Context, db *store.DB, policyPath string, policySet bool, now time.Time) (allowChecker, []string, error) {
	var checker allowChecker
	var warnings []string

	if _, err := os.Stat(policyPath); err == nil {
		pol, err := config.LoadPolicy(policyPath)
		if err != nil {
			return checker, nil, fmt.Errorf("rule test: load %s: %w", policyPath, err)
		}
		checker.policy, err = decision.StaticAllowlist(pol)
		if err != nil {
			return checker, nil, fmt.Errorf("rule test: %w", err)
		}
	} else if policySet {
		return checker, nil, fmt.Errorf("rule test: policy %s: %w", policyPath, err)
	} else {
		warnings = append(warnings,
			fmt.Sprintf("no policy at %s: the allowlisted-hit check only covers the runtime allowlist", policyPath))
	}

	entries, err := db.ListAllow(ctx)
	if err != nil {
		return checker, nil, fmt.Errorf("rule test: list runtime allowlist: %w", err)
	}
	for _, e := range entries {
		if !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now) {
			continue
		}
		checker.runtime = append(checker.runtime, e.Prefix)
	}
	return checker, warnings, nil
}

// evaluateRuleAgainstStore runs one rule's dry evaluation.
func evaluateRuleAgainstStore(ctx context.Context, db *store.DB, info rules.RuleInfo,
	since time.Duration, now time.Time, persisted map[string]bool, checker allowChecker) (ruleTestResult, error) {

	var res ruleTestResult
	res.Rule.Name = info.Name
	res.Rule.Kinds = info.Kinds
	res.Rule.WindowSeconds = int64(info.Window / time.Second)
	res.Rule.Threshold = info.Threshold
	res.Rule.Score = info.Score
	res.Rule.Category = info.Category
	res.Rule.FieldLevel = info.FieldLevel()
	res.Since = now.Add(-since).UTC().Format(time.RFC3339)
	res.PerDay = map[string]int{}
	res.Limitation = ruleTestLimitation

	if info.FieldLevel() {
		res.UpperBound = true
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"rule matches on field %q, but stored aggregates keep counts only: results are a kind-level UPPER BOUND, not what the rule would actually fire", info.Field))
	}
	if info.Window <= rules.LongWindowCutoff {
		res.Warnings = append(res.Warnings,
			"window <= 1h is served by the in-memory aggregator at runtime; stored history may be empty or partial for these kinds")
	}
	if persisted != nil {
		var missing []string
		for _, k := range info.Kinds {
			if !persisted[k] {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"kind(s) %s are not persisted by the currently loaded rule set — stored history for them is likely empty",
				strings.Join(missing, ", ")))
		}
	}
	if since < info.Window {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"--since range (%s) is shorter than the rule window (%s); a real window never fits in the evaluated range", since, info.Window))
	}

	rows, err := db.EventCountsByHour(ctx, info.Kinds, store.HourBucket(now.Add(-since)))
	if err != nil {
		return res, fmt.Errorf("rule test: %w", err)
	}
	sims := simulateRule(rows, info.Window, info.Threshold)

	for _, sim := range sims {
		if len(sim.detections) == 0 {
			continue
		}
		res.Detections += len(sim.detections)
		res.UniqueIPs++
		entry := ruleTestIP{IP: sim.ip, Detections: len(sim.detections), Events: sim.events}
		if addr, err := netip.ParseAddr(sim.ip); err == nil {
			entry.Allowlisted, entry.AllowSource = checker.check(addr.Unmap())
		}
		if entry.Allowlisted {
			res.AllowlistedHits++
		}
		res.IPs = append(res.IPs, entry)
		for _, b := range sim.detections {
			day := time.Unix(b, 0).UTC().Format("2006-01-02")
			res.PerDay[day]++
		}
	}

	// Sample: most-firing IPs first, allowlisted ones never dropped (they
	// are the warning this command exists for).
	sort.SliceStable(res.IPs, func(i, j int) bool {
		if res.IPs[i].Allowlisted != res.IPs[j].Allowlisted {
			return res.IPs[i].Allowlisted
		}
		return res.IPs[i].Detections > res.IPs[j].Detections
	})
	if len(res.IPs) > ruleTestIPCap {
		res.IPs = res.IPs[:ruleTestIPCap]
		res.IPsTruncated = true
	}
	return res, nil
}

// renderRuleTest prints the human-readable report for one rule.
func renderRuleTest(cmd *cobra.Command, res ruleTestResult) {
	out := cmd.OutOrStdout()
	st := newStyler(out)

	name := sanitizeField(res.Rule.Name, reportFieldMax)
	window := time.Duration(res.Rule.WindowSeconds) * time.Second
	fmt.Fprintln(out, st.header("Rule test: "+name))                                          //nolint:errcheck
	fmt.Fprintf(out, "  kinds: %s | window: %s | threshold: %d | score: %d | category: %s\n", //nolint:errcheck
		sanitizeField(strings.Join(res.Rule.Kinds, ", "), reportReasonMax),
		window, res.Rule.Threshold, res.Rule.Score,
		sanitizeField(res.Rule.Category, reportFieldMax))
	fmt.Fprintf(out, "  evaluating stored aggregates since %s\n\n", res.Since) //nolint:errcheck

	suffix := ""
	if res.UpperBound {
		suffix = "  (kind-level UPPER BOUND — see warnings)"
	}
	fmt.Fprintf(out, "  Would have fired : %d time(s)%s\n", res.Detections, suffix) //nolint:errcheck
	fmt.Fprintf(out, "  Unique IPs       : %d\n", res.UniqueIPs)                    //nolint:errcheck
	if res.AllowlistedHits > 0 {
		fmt.Fprintln(out, st.fail(fmt.Sprintf( //nolint:errcheck
			"Allowlisted hits : %d — this rule would fire on protected addresses; tune it before enabling", res.AllowlistedHits)))
	} else {
		fmt.Fprintf(out, "  Allowlisted hits : 0\n") //nolint:errcheck
	}

	if len(res.IPs) > 0 {
		fmt.Fprintf(out, "\n  IPs (top %d by detections):\n", ruleTestIPCap) //nolint:errcheck
		for _, ip := range res.IPs {
			mark := ""
			if ip.Allowlisted {
				mark = "  [ALLOWLISTED: " + ip.AllowSource + "]"
			}
			fmt.Fprintf(out, "    %-40s %3d detection(s), %4d event(s)%s\n", ip.IP, ip.Detections, ip.Events, mark) //nolint:errcheck
		}
		if res.IPsTruncated {
			fmt.Fprintln(out, st.dim("    … more IPs omitted (use --json for the full sampled set)")) //nolint:errcheck
		}
	}

	if len(res.PerDay) > 0 {
		days := make([]string, 0, len(res.PerDay))
		for d := range res.PerDay {
			days = append(days, d)
		}
		sort.Strings(days)
		fmt.Fprintln(out, "\n  Per-day distribution (UTC):") //nolint:errcheck
		for _, d := range days {
			fmt.Fprintf(out, "    %s  %d\n", d, res.PerDay[d]) //nolint:errcheck
		}
	}

	for _, w := range res.Warnings {
		fmt.Fprintln(out, st.warn(sanitizeField(w, reportReasonMax*2))) //nolint:errcheck
	}
	fmt.Fprintln(out, st.dim("  Limitation: "+res.Limitation+".")) //nolint:errcheck
}

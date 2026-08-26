// SPDX-License-Identifier: AGPL-3.0-only

package main

// `ezyshield report --since` (issue #229): the incident digest — "what
// happened on this server since yesterday?" as one readable document.
//
// The base digest is fully offline and deterministic: it aggregates data
// already in the store (strikes + persisted verdicts, audit ops, hourly
// event counters, offenders, active bans) with zero AI dependency and zero
// side effects. The optional --narrative section calls the configured AI
// provider with the SAME aggregated/redacted digest JSON — never raw log
// lines — and any failure degrades to the plain digest with a note.
//
// Security (§1 SECURITY-REVIEW): categories, rule names, and reasons are
// copied from hostile log-derived verdicts. Every such field goes through
// sanitizeField for terminal output and mdCell inside markdown tables.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/evertramos/ezy-shield/internal/ai"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
)

// digestSchemaVersion versions the --json envelope.
const digestSchemaVersion = 1

// digestTopOffenders bounds the top-offender table.
const digestTopOffenders = 10

// digestKV is one name→count line in the digest.
type digestKV struct {
	Name      string `json:"name"`
	Count     int    `json:"count"`
	UniqueIPs int    `json:"unique_ips,omitempty"`
}

// digestOffender is one row of the top-offender table.
type digestOffender struct {
	IP           string `json:"ip"`
	Strikes      int    `json:"strikes"`
	MaxStrike    int    `json:"max_strike"`
	TotalStrikes int    `json:"total_strikes"`
	New          bool   `json:"new"`
}

// digestData is the deterministic digest (and the exact JSON handed to the
// AI narrative — aggregated and redacted by construction: it holds counts,
// categories, rule names, and IPs; never raw log lines).
type digestData struct {
	SchemaVersion int    `json:"schema_version"`
	Since         string `json:"since"`
	WindowSeconds int64  `json:"window_seconds"`
	GeneratedAt   string `json:"generated_at"`

	Totals struct {
		Events     int `json:"events"`
		EventIPs   int `json:"event_ips"`
		Strikes    int `json:"strikes"`
		StrikeIPs  int `json:"strike_ips"`
		Bans       int `json:"bans"`
		DryBans    int `json:"dry_bans"`
		Unbans     int `json:"unbans"`
		NotifyOnly int `json:"notify_only"`
	} `json:"totals"`

	EventsByKind []digestKV       `json:"events_by_kind"`
	Categories   []digestKV       `json:"categories"`
	Rules        []digestKV       `json:"rules"`
	TopOffenders []digestOffender `json:"top_offenders"`

	NewOffenders    int `json:"new_offenders"`
	RepeatOffenders int `json:"repeat_offenders"`

	ActiveBans    int `json:"active_bans"`
	PermanentBans int `json:"permanent_bans"`
	DryRunBans    int `json:"dry_run_bans"`

	Patterns  []string `json:"patterns"`
	Truncated bool     `json:"truncated"`

	Narrative     string `json:"narrative,omitempty"`
	NarrativeNote string `json:"narrative_note,omitempty"`
}

// buildDigest aggregates the window from the store. Pure reads; the only
// nondeterminism is the clock, which the caller injects for golden tests.
func buildDigest(ctx context.Context, db *store.DB, since time.Duration, now time.Time) (*digestData, error) {
	d := &digestData{SchemaVersion: digestSchemaVersion}
	from := now.Add(-since)
	d.Since = from.UTC().Format(time.RFC3339)
	d.WindowSeconds = int64(since / time.Second)
	d.GeneratedAt = now.UTC().Format(time.RFC3339)

	strikes, total, err := db.StrikesSince(ctx, from, 0)
	if err != nil {
		return nil, err
	}
	d.Totals.Strikes = total
	d.Truncated = total > len(strikes)

	// Per-IP, per-category, and per-rule aggregation from the persisted
	// verdicts (rule verdicts carry "rule/<name>: …" reasons).
	type ipAgg struct {
		strikes   int
		maxStrike int
	}
	perIP := map[string]*ipAgg{}
	catCount := map[string]int{}
	catIPs := map[string]map[string]bool{}
	ruleCount := map[string]int{}
	ruleIPs := map[string]map[string]bool{}
	for _, s := range strikes {
		a := perIP[s.IP]
		if a == nil {
			a = &ipAgg{}
			perIP[s.IP] = a
		}
		a.strikes++
		if s.StrikeNum > a.maxStrike {
			a.maxStrike = s.StrikeNum
		}
		for _, v := range s.Verdicts {
			if v.Category != "" {
				catCount[v.Category]++
				if catIPs[v.Category] == nil {
					catIPs[v.Category] = map[string]bool{}
				}
				catIPs[v.Category][s.IP] = true
			}
			if name, ok := ruleNameFromReason(v.Reason); ok {
				ruleCount[name]++
				if ruleIPs[name] == nil {
					ruleIPs[name] = map[string]bool{}
				}
				ruleIPs[name][s.IP] = true
			}
		}
	}
	d.Totals.StrikeIPs = len(perIP)
	d.Categories = sortedKV(catCount, catIPs)
	d.Rules = sortedKV(ruleCount, ruleIPs)

	// Audit ops → enforcement activity totals.
	ops, err := db.AuditOpCountsSince(ctx, from)
	if err != nil {
		return nil, err
	}
	d.Totals.Bans = ops["ban"]
	d.Totals.DryBans = ops["dry_ban"]
	d.Totals.Unbans = ops["unban"] + ops["expired"]
	d.Totals.NotifyOnly = ops["notify_only"]

	// Hourly event counters (only long-window kinds are persisted — the
	// digest says so in its footer).
	kinds, eventIPs, err := db.EventKindTotalsSince(ctx, store.HourBucket(from))
	if err != nil {
		return nil, err
	}
	d.EventsByKind = sortedKV(kinds, nil)
	for _, kv := range d.EventsByKind {
		d.Totals.Events += kv.Count
	}
	d.Totals.EventIPs = eventIPs

	// New vs repeat offenders, from offenders.first_seen.
	ips := make([]string, 0, len(perIP))
	for ip := range perIP {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	meta, err := db.OffenderMetaFor(ctx, ips)
	if err != nil {
		return nil, err
	}
	fromKey := from.UTC().Format(time.RFC3339)
	newIPs := map[string]bool{}
	for ip, m := range meta {
		if m.FirstSeen >= fromKey {
			newIPs[ip] = true
		}
	}
	d.NewOffenders = len(newIPs)
	d.RepeatOffenders = len(perIP) - len(newIPs)

	// Top offenders: most strikes first, ties by max strike then IP.
	for ip, a := range perIP {
		d.TopOffenders = append(d.TopOffenders, digestOffender{
			IP:           ip,
			Strikes:      a.strikes,
			MaxStrike:    a.maxStrike,
			TotalStrikes: meta[ip].TotalStrikes,
			New:          newIPs[ip],
		})
	}
	sort.Slice(d.TopOffenders, func(i, j int) bool {
		a, b := d.TopOffenders[i], d.TopOffenders[j]
		if a.Strikes != b.Strikes {
			return a.Strikes > b.Strikes
		}
		if a.MaxStrike != b.MaxStrike {
			return a.MaxStrike > b.MaxStrike
		}
		return a.IP < b.IP
	})
	if len(d.TopOffenders) > digestTopOffenders {
		d.TopOffenders = d.TopOffenders[:digestTopOffenders]
	}

	// Enforcement snapshot.
	d.ActiveBans, d.PermanentBans, d.DryRunBans, err = db.ActiveBanSummary(ctx)
	if err != nil {
		return nil, err
	}

	d.Patterns = digestPatterns(d)
	return d, nil
}

// ruleNameFromReason extracts "<name>" from the rule-verdict reason format
// "rule/<name>: …". Non-rule verdicts (AI, geo) return false.
func ruleNameFromReason(reason string) (string, bool) {
	rest, ok := strings.CutPrefix(reason, "rule/")
	if !ok {
		return "", false
	}
	name, _, ok := strings.Cut(rest, ":")
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

// sortedKV renders a count map as a deterministic slice: count descending,
// then name ascending.
func sortedKV(counts map[string]int, ips map[string]map[string]bool) []digestKV {
	out := make([]digestKV, 0, len(counts))
	for name, n := range counts {
		kv := digestKV{Name: name, Count: n}
		if ips != nil {
			kv.UniqueIPs = len(ips[name])
		}
		out = append(out, kv)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// digestPatterns derives the deterministic "notable patterns" bullets.
func digestPatterns(d *digestData) []string {
	var out []string
	for _, c := range d.Categories {
		if c.UniqueIPs >= 3 {
			out = append(out, fmt.Sprintf(
				"coordinated %s activity: %d distinct IPs struck in the window", c.Name, c.UniqueIPs))
		}
	}
	for _, o := range d.TopOffenders {
		if o.MaxStrike >= 3 {
			out = append(out, fmt.Sprintf(
				"escalation: %s reached strike %d (total strikes on record: %d)", o.IP, o.MaxStrike, o.TotalStrikes))
		}
	}
	if d.Totals.DryBans > 0 && d.Totals.Bans == 0 {
		out = append(out, fmt.Sprintf(
			"dry-run mode: %d ban(s) were simulated but not enforced in this window", d.Totals.DryBans))
	}
	if d.NewOffenders > 0 && d.NewOffenders >= d.RepeatOffenders && d.Totals.StrikeIPs >= 3 {
		out = append(out, fmt.Sprintf(
			"fresh wave: %d of %d striking IPs were first seen inside the window", d.NewOffenders, d.Totals.StrikeIPs))
	}
	return out
}

// ── Rendering ────────────────────────────────────────────────────────────────

// renderDigestMarkdown renders the stable documented section structure:
// header, Totals, Events by kind, Strikes by category, Strikes by rule,
// Top offenders, New vs repeat, Enforcement, Notable patterns, and the
// optional AI narrative — always in this order, sections omitted only when
// empty (Totals and Enforcement always render).
func renderDigestMarkdown(d *digestData) string {
	var b strings.Builder
	window := (time.Duration(d.WindowSeconds) * time.Second).String()
	fmt.Fprintf(&b, "# EzyShield digest — last %s\n\n", window)
	fmt.Fprintf(&b, "_Window since %s · generated %s_\n\n", d.Since, d.GeneratedAt)

	b.WriteString("## Totals\n\n")
	b.WriteString("| Metric | Count |\n|---|---|\n")
	fmt.Fprintf(&b, "| Events (persisted counters) | %d |\n", d.Totals.Events)
	fmt.Fprintf(&b, "| IPs with events | %d |\n", d.Totals.EventIPs)
	fmt.Fprintf(&b, "| Strikes | %d |\n", d.Totals.Strikes)
	fmt.Fprintf(&b, "| IPs struck | %d |\n", d.Totals.StrikeIPs)
	fmt.Fprintf(&b, "| Bans | %d |\n", d.Totals.Bans)
	fmt.Fprintf(&b, "| Dry-run bans | %d |\n", d.Totals.DryBans)
	fmt.Fprintf(&b, "| Unbans/expiries | %d |\n", d.Totals.Unbans)
	fmt.Fprintf(&b, "| Notify-only | %d |\n", d.Totals.NotifyOnly)
	b.WriteString("\n")

	if len(d.EventsByKind) > 0 {
		b.WriteString("## Events by kind\n\n| Kind | Events |\n|---|---|\n")
		for _, kv := range d.EventsByKind {
			fmt.Fprintf(&b, "| %s | %d |\n", mdCell(kv.Name, reportFieldMax), kv.Count)
		}
		b.WriteString("\n")
	}

	if len(d.Categories) > 0 {
		b.WriteString("## Strikes by category\n\n| Category | Verdicts | Unique IPs |\n|---|---|---|\n")
		for _, kv := range d.Categories {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", mdCell(kv.Name, reportFieldMax), kv.Count, kv.UniqueIPs)
		}
		b.WriteString("\n")
	}

	if len(d.Rules) > 0 {
		b.WriteString("## Strikes by rule\n\n| Rule | Verdicts | Unique IPs |\n|---|---|---|\n")
		for _, kv := range d.Rules {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", mdCell(kv.Name, reportFieldMax), kv.Count, kv.UniqueIPs)
		}
		b.WriteString("\n")
	}

	if len(d.TopOffenders) > 0 {
		b.WriteString("## Top offenders\n\n| IP | Strikes (window) | Max strike | Total strikes | New |\n|---|---|---|---|---|\n")
		for _, o := range d.TopOffenders {
			newMark := "repeat"
			if o.New {
				newMark = "new"
			}
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %s |\n", mdCell(o.IP, reportFieldMax), o.Strikes, o.MaxStrike, o.TotalStrikes, newMark)
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "New offenders: %d · repeat offenders: %d\n\n", d.NewOffenders, d.RepeatOffenders)
	}

	b.WriteString("## Enforcement\n\n")
	fmt.Fprintf(&b, "- Active bans: %d (%d permanent, %d dry-run)\n\n", d.ActiveBans, d.PermanentBans, d.DryRunBans)

	if len(d.Patterns) > 0 {
		b.WriteString("## Notable patterns\n\n")
		for _, p := range d.Patterns {
			fmt.Fprintf(&b, "- %s\n", mdCell(p, reportReasonMax))
		}
		b.WriteString("\n")
	}

	if d.Narrative != "" {
		b.WriteString("## AI narrative\n\n")
		b.WriteString("_Generated by the configured AI provider from the aggregated digest data above (advisory only)._\n\n")
		for _, line := range strings.Split(d.Narrative, "\n") {
			fmt.Fprintf(&b, "%s\n", mdCell(line, reportLineMax))
		}
		b.WriteString("\n")
	} else if d.NarrativeNote != "" {
		fmt.Fprintf(&b, "_%s_\n\n", mdCell(d.NarrativeNote, reportReasonMax))
	}

	if d.Truncated {
		b.WriteString("_Note: breakdowns are based on the most recent strikes (detail capped); totals are exact._\n\n")
	}
	b.WriteString("_Event totals come from the persisted hourly counters, which only track kinds referenced by long-window rules._\n")
	return b.String()
}

// renderDigestText renders the terminal view of the same sections.
func renderDigestText(cmd *cobra.Command, d *digestData) {
	w := cmd.OutOrStdout()
	st := newStyler(w)
	window := (time.Duration(d.WindowSeconds) * time.Second).String()

	fmt.Fprintln(w, st.header("EzyShield digest — last "+window))                  //nolint:errcheck
	fmt.Fprintf(w, "  window since %s · generated %s\n\n", d.Since, d.GeneratedAt) //nolint:errcheck

	fmt.Fprintf(w, "  Events (persisted counters): %d from %d IPs\n", d.Totals.Events, d.Totals.EventIPs) //nolint:errcheck
	fmt.Fprintf(w, "  Strikes: %d on %d IPs (new: %d, repeat: %d)\n",                                     //nolint:errcheck
		d.Totals.Strikes, d.Totals.StrikeIPs, d.NewOffenders, d.RepeatOffenders)
	fmt.Fprintf(w, "  Actions: %d bans, %d dry-run bans, %d unbans/expiries, %d notify-only\n", //nolint:errcheck
		d.Totals.Bans, d.Totals.DryBans, d.Totals.Unbans, d.Totals.NotifyOnly)
	fmt.Fprintf(w, "  Active bans now: %d (%d permanent, %d dry-run)\n", d.ActiveBans, d.PermanentBans, d.DryRunBans) //nolint:errcheck

	if len(d.Categories) > 0 {
		fmt.Fprintln(w, "\n  Strikes by category:") //nolint:errcheck
		for _, kv := range d.Categories {
			fmt.Fprintf(w, "    %-24s %5d verdicts, %4d IPs\n", sanitizeField(kv.Name, reportFieldMax), kv.Count, kv.UniqueIPs) //nolint:errcheck
		}
	}
	if len(d.Rules) > 0 {
		fmt.Fprintln(w, "\n  Strikes by rule:") //nolint:errcheck
		for _, kv := range d.Rules {
			fmt.Fprintf(w, "    %-32s %5d verdicts, %4d IPs\n", sanitizeField(kv.Name, reportFieldMax), kv.Count, kv.UniqueIPs) //nolint:errcheck
		}
	}
	if len(d.TopOffenders) > 0 {
		fmt.Fprintln(w, "\n  Top offenders (window):") //nolint:errcheck
		for _, o := range d.TopOffenders {
			mark := "repeat"
			if o.New {
				mark = "new"
			}
			fmt.Fprintf(w, "    %-40s %3d strike(s), max strike %d, total %d [%s]\n", //nolint:errcheck
				o.IP, o.Strikes, o.MaxStrike, o.TotalStrikes, mark)
		}
	}
	if len(d.Patterns) > 0 {
		fmt.Fprintln(w, "\n  Notable patterns:") //nolint:errcheck
		for _, p := range d.Patterns {
			fmt.Fprintln(w, st.warn(sanitizeField(p, reportReasonMax))) //nolint:errcheck
		}
	}
	if d.Narrative != "" {
		fmt.Fprintln(w, "\n  AI narrative (advisory, generated from the aggregated digest):") //nolint:errcheck
		for _, line := range strings.Split(d.Narrative, "\n") {
			fmt.Fprintf(w, "    %s\n", sanitizeField(line, reportLineMax)) //nolint:errcheck
		}
	} else if d.NarrativeNote != "" {
		fmt.Fprintln(w, st.warn(sanitizeField(d.NarrativeNote, reportReasonMax))) //nolint:errcheck
	}
	if d.Truncated {
		fmt.Fprintln(w, st.dim("  Note: breakdowns are based on the most recent strikes (detail capped); totals are exact.")) //nolint:errcheck
	}
	fmt.Fprintln(w, st.dim("  Event totals come from the persisted hourly counters (long-window kinds only).")) //nolint:errcheck
}

// ── Command path ─────────────────────────────────────────────────────────────

// runReportDigest is the `report --since` entry point. Read-only: the store
// is opened only if it already exists, and nothing is written except the
// AI-usage accounting row when --narrative actually calls a provider.
func runReportDigest(cmd *cobra.Command, sinceStr, dbPath, configPath, output string, narrative, configSet bool) error {
	ctx := cmd.Context()
	since, err := parseSinceDuration(sinceStr)
	if err != nil {
		return fmt.Errorf("invalid --since %q: %w", sinceStr, err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("report: no database at %s (is this the right --db path?): %w", dbPath, err)
	}
	db, err := store.Open(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("report: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	d, err := buildDigest(ctx, db, since, time.Now())
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	if narrative {
		addDigestNarrative(ctx, db, d, configPath, configSet)
	}

	switch {
	case jsonOutput:
		return writeJSON(cmd.OutOrStdout(), d)
	case output == "md":
		_, err := fmt.Fprint(cmd.OutOrStdout(), renderDigestMarkdown(d))
		return err
	default:
		renderDigestText(cmd, d)
		return nil
	}
}

// addDigestNarrative fills d.Narrative from the configured AI provider, or
// d.NarrativeNote explaining why not. Failures NEVER fail the digest —
// the AC requires degradation to the plain document.
func addDigestNarrative(ctx context.Context, db *store.DB, d *digestData, configPath string, configSet bool) {
	cfg, err := loadAIConfig(configPath, configSet)
	if err != nil {
		d.NarrativeNote = "AI narrative skipped: " + err.Error()
		return
	}
	if cfg == nil {
		d.NarrativeNote = "AI narrative skipped: no AI provider configured"
		return
	}

	// Daily token budget gate — same accounting table the daemon uses.
	if cfg.TokenBudgetDaily > 0 {
		used, err := db.TodayUsage(ctx, cfg.Provider)
		if err == nil && used.InputTokens+used.OutputTokens >= cfg.TokenBudgetDaily {
			d.NarrativeNote = "AI narrative skipped: daily token budget exhausted"
			return
		}
	}

	// The narrative input is the digest itself — aggregated, redacted, no
	// raw log lines by construction.
	payload, err := json.Marshal(d)
	if err != nil {
		d.NarrativeNote = "AI narrative skipped: " + err.Error()
		return
	}
	text, usage, err := ai.Narrate(ctx, cfg, payload)
	if err != nil {
		d.NarrativeNote = "AI narrative unavailable (" + sanitizeField(err.Error(), reportReasonMax) + "); showing the plain digest"
		return
	}
	if err := db.RecordUsage(ctx, cfg.Provider, usage, ""); err != nil {
		// Accounting failure must not eat the narrative; note it instead.
		d.NarrativeNote = "note: AI usage accounting failed: " + sanitizeField(err.Error(), reportReasonMax)
	}
	d.Narrative = text
}

// loadAIConfig returns the AI section of config.yaml, nil when the file or
// section is absent (and the path was not explicitly set).
func loadAIConfig(configPath string, configSet bool) (*config.AICfg, error) {
	if _, err := os.Stat(configPath); err != nil {
		if configSet {
			return nil, fmt.Errorf("config %s: %w", configPath, err)
		}
		return nil, nil
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return cfg.AI, nil
}

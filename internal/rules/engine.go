// SPDX-License-Identifier: AGPL-3.0-only

// Package rules provides the always-available rule-based verdict engine.
// All evaluation logic is pure (no I/O after construction).
package rules

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/configs"
	"github.com/evertramos/ezy-shield/pkg/sdk"
	"gopkg.in/yaml.v3"
)

// duration is a yaml-deserializable time.Duration.
type duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler for duration.
func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	dur, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	*d = duration(dur)
	return nil
}

// spec describes a single detection rule loaded from YAML.
// Field and Value/Contains/ContainsAny are optional; omitting Field matches all events of
// the listed kinds. Value, Contains, and ContainsAny are mutually exclusive.
type spec struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Kinds       []string `yaml:"kinds"`
	Field       string   `yaml:"field,omitempty"`
	Value       string   `yaml:"value,omitempty"`
	Contains    string   `yaml:"contains,omitempty"`
	ContainsAny []string `yaml:"contains_any,omitempty"`
	Window      duration `yaml:"window"`
	Threshold   int      `yaml:"threshold"`
	Score       int      `yaml:"score"`
	Category    string   `yaml:"category"`
}

type rulesFile struct {
	Rules []spec `yaml:"rules"`
}

// Engine evaluates sdk.Aggregate values against loaded rules and emits
// sdk.Verdicts. All Evaluate calls are pure (no I/O).
type Engine struct {
	rules []spec
}

// New creates an Engine from up to three layers (issue #136):
//
//  1. Legacy exclusive replacement: if overridePath is non-empty the rules
//     are loaded exclusively from that file — the embedded base AND any
//     rules.d drop-ins are DISABLED, matching the pre-#136 contract. This
//     path is deprecated: it freezes the install out of upstream rule
//     tuning, and a loud WARN says so at startup.
//  2. Embedded base: configs/rules.yaml compiled into the binary. Always
//     loaded (when overridePath is empty), so base tuning rides every
//     binary update.
//  3. Drop-in overlay: every *.yaml / *.yml file in rulesDir (lexical
//     order), merged by rule `name` — an overlay entry replaces a
//     same-named earlier entry (base or prior drop-in) and new names are
//     appended. Overriding an existing rule logs a WARN: silently
//     downgrading a shipped protective rule is the real risk of this
//     feature. A missing rulesDir is fine (no overlay); an unreadable or
//     invalid drop-in fails closed — the caller should refuse to start.
//
// On any parse or validation error the embedded defaults are NOT used as a
// fallback — the caller should refuse to start. Validation always runs on
// the final merged set.
//
// Note the safety boundary (SECURITY-REVIEW §2): rules — from any layer —
// only ever SUGGEST verdicts. The allowlist and anti-lockout clamps live
// downstream in the decision engine and run on every target regardless of
// which layer produced the verdict. The rule schema carries no
// allowlist/unban field and must never gain one.
func New(overridePath, rulesDir string) (*Engine, error) {
	if overridePath != "" {
		slog.Warn("rules: rules_path is set — the embedded base and rules.d drop-ins are disabled; "+
			"this install receives no upstream rule updates until it migrates to rules.d",
			"rules_path", overridePath)
		var rf rulesFile
		f, err := os.Open(overridePath) //nolint:gosec // path comes from operator config, not attacker input
		if err != nil {
			return nil, fmt.Errorf("rules: open %q: %w", overridePath, err)
		}
		defer f.Close() //nolint:errcheck
		if err := decodeRules(f, &rf); err != nil {
			return nil, err
		}
		if err := validateRules(rf.Rules, nil); err != nil {
			return nil, err
		}
		return &Engine{rules: rf.Rules}, nil
	}

	var base rulesFile
	data, err := configs.FS.ReadFile("rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("rules: read embedded rules.yaml: %w", err)
	}
	if err := decodeRules(strings.NewReader(string(data)), &base); err != nil {
		return nil, err
	}

	merged, origin, err := applyDropins(base.Rules, rulesDir)
	if err != nil {
		return nil, err
	}

	if err := validateRules(merged, origin); err != nil {
		return nil, err
	}
	return &Engine{rules: merged}, nil
}

// applyDropins overlays every *.yaml / *.yml drop-in from dir onto base,
// merged by rule name in lexical file order. A missing dir returns base
// unchanged; any other read/parse error fails closed. The returned origin
// map records which drop-in file contributed each rule name ("" = embedded
// base) so validation failures on the merged set can name the file the
// operator must fix.
func applyDropins(base []spec, dir string) ([]spec, map[string]string, error) {
	if dir == "" {
		return base, nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, nil, nil
		}
		return nil, nil, fmt.Errorf("rules: read drop-in dir %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	// origin tracks which layer currently owns each rule name, for the
	// shadowing WARN ("" = embedded base).
	origin := make(map[string]string, len(base))
	index := make(map[string]int, len(base))
	for i, r := range base {
		origin[r.Name] = ""
		index[r.Name] = i
	}

	merged := base
	for _, name := range files {
		path := filepath.Join(dir, name)
		f, err := os.Open(path) //nolint:gosec // path is operator-owned config dir content, not attacker input
		if err != nil {
			return nil, nil, fmt.Errorf("rules: open drop-in %q: %w", path, err)
		}
		var rf rulesFile
		decErr := decodeRules(f, &rf)
		_ = f.Close()
		if decErr != nil {
			return nil, nil, fmt.Errorf("rules: drop-in %q: %w", path, decErr)
		}
		for _, r := range rf.Rules {
			if i, ok := index[r.Name]; ok {
				prev := merged[i]
				from := origin[r.Name]
				if from == "" {
					from = "embedded base"
				}
				slog.Warn("rules: drop-in overrides an existing rule",
					"rule", r.Name,
					"file", path,
					"overrides", from,
					"old_threshold", prev.Threshold, "new_threshold", r.Threshold,
					"old_score", prev.Score, "new_score", r.Score)
				merged[i] = r
			} else {
				merged = append(merged, r)
				index[r.Name] = len(merged) - 1
			}
			origin[r.Name] = path
		}
	}
	return merged, origin, nil
}

// LongWindowCutoff splits rule windows between the two evaluation paths
// (issue #134): windows <= cutoff are served by the in-memory sliding-window
// aggregator (which retains events, enabling field-level rules); windows
// above it are served by persistent per-IP hourly counters in the store
// (aggregate integers only — hence the kind-level-only validation below).
const LongWindowCutoff = time.Hour

// LongCounterKindPrefix marks the synthetic counter kinds of long-window
// field-level rules (issue #585). A rule such as "wp-login attempts per
// day" cannot be served by the plain per-kind counters (they keep no
// field values), so the daemon counts the rule's OWN matcher on the hot
// path under a kind derived from the rule name, and the long-window
// evaluation reads that counter back. The prefix cannot collide with a
// parser kind (parsers never emit a colon).
const LongCounterKindPrefix = "rule:"

// LongCounterKind returns the persisted counter kind of the named
// long-window field-level rule.
func LongCounterKind(rule string) string { return LongCounterKindPrefix + rule }

// IsLongCounterKind reports whether kind is a rule-derived counter kind
// rather than a parser event kind.
func IsLongCounterKind(kind string) bool { return strings.HasPrefix(kind, LongCounterKindPrefix) }

// isLongField reports whether r is a long-window rule with a field-level
// matcher — the shape served by its own counter (issue #585).
func isLongField(r spec) bool {
	return time.Duration(r.Window) > LongWindowCutoff && r.Field != ""
}

// KindsForLongWindows returns, for each distinct rule window strictly
// greater than LongWindowCutoff, the union of counter kinds its rules read:
// the parser kinds of kind-level rules, and the rule-derived counter kind
// (LongCounterKind) of field-level rules — never a field rule's parser
// kinds, so high-volume HTTP traffic is not counted wholesale on its
// account. The daemon uses this to know which counters to write and which
// extra windows to evaluate from them. Read-only; Evaluate itself is
// untouched by the long-window path (design constraint of #134).
func (e *Engine) KindsForLongWindows() map[time.Duration][]string {
	out := map[time.Duration][]string{}
	for _, r := range e.rules {
		w := time.Duration(r.Window)
		if w <= LongWindowCutoff {
			continue
		}
		seen := make(map[string]bool, len(out[w]))
		for _, k := range out[w] {
			seen[k] = true
		}
		kinds := r.Kinds
		if r.Field != "" {
			kinds = []string{LongCounterKind(r.Name)}
		}
		for _, k := range kinds {
			if !seen[k] {
				out[w] = append(out[w], k)
				seen[k] = true
			}
		}
	}
	return out
}

// LongFieldEventKinds returns the parser event kinds referenced by
// long-window field-level rules — the hot-path prefilter: only an event of
// one of these kinds can ever need LongCounterKinds (issue #585).
func (e *Engine) LongFieldEventKinds() map[string]bool {
	out := map[string]bool{}
	for _, r := range e.rules {
		if !isLongField(r) {
			continue
		}
		for _, k := range r.Kinds {
			out[k] = true
		}
	}
	return out
}

// LongCounterKinds returns the rule-derived counter kinds ev increments:
// one per long-window field-level rule whose kinds include ev.Kind and
// whose matcher ev satisfies (the identical predicate countMatches and
// evidenceLines apply). Pure; a few substring checks per event, no I/O.
func (e *Engine) LongCounterKinds(ev sdk.Event) []string { return e.counterKinds(ev, true) }

// MemoryCounterKinds is LongCounterKinds for the field-level rules served
// by the in-memory aggregator (window ≤ LongWindowCutoff). The aggregator
// runs it as its Classifier (issue #622): the count of a field-level rule
// then survives the sample cap, because evicted matching events are still
// counted under LongCounterKind(rule) and countMatches reads that key.
func (e *Engine) MemoryCounterKinds(ev sdk.Event) []string { return e.counterKinds(ev, false) }

func (e *Engine) counterKinds(ev sdk.Event, long bool) []string {
	var out []string
	for _, r := range e.rules {
		if r.Field == "" || isLongField(r) != long {
			continue
		}
		hit := false
		for _, k := range r.Kinds {
			if k == ev.Kind {
				hit = true
				break
			}
		}
		if hit && fieldMatches(r, ev) {
			out = append(out, LongCounterKind(r.Name))
		}
	}
	return out
}

// Windows returns the unique window durations referenced by the loaded rules.
// The aggregator should produce an sdk.Aggregate for each of these windows so
// that Evaluate can match every rule.
func (e *Engine) Windows() []time.Duration {
	seen := make(map[time.Duration]struct{}, len(e.rules))
	out := make([]time.Duration, 0, len(e.rules))
	for _, r := range e.rules {
		w := time.Duration(r.Window)
		if _, ok := seen[w]; !ok {
			seen[w] = struct{}{}
			out = append(out, w)
		}
	}
	return out
}

// Evaluate applies all rules whose Window matches agg.Window to agg, returning
// every triggered verdict. An empty (non-nil) slice is returned when no rules
// fire. Context cancellation stops evaluation early.
func (e *Engine) Evaluate(ctx context.Context, agg sdk.Aggregate) []sdk.Verdict {
	verdicts := make([]sdk.Verdict, 0)
	for _, r := range e.rules {
		if ctx.Err() != nil {
			break
		}
		if time.Duration(r.Window) != agg.Window {
			continue
		}
		if v, ok := applyRule(r, agg); ok {
			verdicts = append(verdicts, v)
		}
	}
	return verdicts
}

// applyRule evaluates a single rule against agg.
// Returns the verdict and true if the rule's threshold is met.
func applyRule(r spec, agg sdk.Aggregate) (sdk.Verdict, bool) {
	count := countMatches(r, agg)
	if count < r.Threshold {
		return sdk.Verdict{}, false
	}
	return sdk.Verdict{
		IP:         agg.IP,
		Score:      r.Score,
		Category:   r.Category,
		Confidence: 1.0,
		Reason:     fmt.Sprintf("rule/%s: %d events in %s (threshold %d)", r.Name, count, time.Duration(r.Window), r.Threshold),
		Source:     "rules",
		SuggestTTL: 0, // policy decides
		Evidence:   evidenceLines(r, agg),
	}, true
}

// evidenceLines collects up to sdk.EvidenceMaxLines raw log lines from the
// sample events that MATCH the firing rule — the capture-at-detection
// evidence of ADR-0011 (issue #127). The matching predicate mirrors
// countMatches exactly, so the attached lines are (a subset of) the very
// events that were counted. Events without Raw (synthetic, long-window
// counter aggregates, pre-#127 tests) contribute nothing. Runs only when a
// rule fires, never per event.
func evidenceLines(r spec, agg sdk.Aggregate) []string {
	kindSet := make(map[string]struct{}, len(r.Kinds))
	for _, k := range r.Kinds {
		kindSet[k] = struct{}{}
	}
	var out []string
	for _, ev := range agg.Sample {
		if len(out) >= sdk.EvidenceMaxLines {
			break
		}
		if _, ok := kindSet[ev.Kind]; !ok || len(ev.Raw) == 0 {
			continue
		}
		if r.Field != "" && !fieldMatches(r, ev) {
			continue
		}
		out = append(out, string(ev.Raw))
	}
	return out
}

// fieldMatches reports whether ev satisfies the rule's field-level matcher.
// Factored from countMatches' scan so evidenceLines applies the identical
// predicate.
func fieldMatches(r spec, ev sdk.Event) bool {
	val, exists := ev.Fields[r.Field]
	if !exists {
		return false
	}
	switch {
	case r.Value != "":
		return val == r.Value
	case r.Contains != "":
		return strings.Contains(val, r.Contains)
	case len(r.ContainsAny) > 0:
		for _, sub := range r.ContainsAny {
			if strings.Contains(val, sub) {
				return true
			}
		}
	}
	return false
}

// countMatches returns the number of events in agg that satisfy the rule.
//
// For kind-only rules (no Field), Kinds counts are used directly — they are
// exact even when Sample is capped.
//
// For field-level rules, the rule's own counter kind (LongCounterKind) is
// used when the aggregate carries it — the persisted counter of a
// long-window rule (issue #585) or, for an in-memory window, the count the
// aggregator kept through its Classifier (issue #622), which stays exact
// after the sample cap evicted the matching events. Otherwise Sample is
// scanned; it holds the NEWEST events of the window (issue #622), so a
// saturated sample is a lower bound over the most recent traffic and a
// busy client's current attack is never hidden behind its older requests.
func countMatches(r spec, agg sdk.Aggregate) int {
	kindSet := make(map[string]struct{}, len(r.Kinds))
	for _, k := range r.Kinds {
		kindSet[k] = struct{}{}
	}

	if r.Field == "" {
		// Kind-level rule: use exact counts from the Kinds map.
		total := 0
		for kind, n := range agg.Kinds {
			if _, ok := kindSet[kind]; ok {
				total += n
			}
		}
		return total
	}

	// Field-level rule served by its own counter: the persisted counter of
	// a long-window rule (issue #585 — the aggregate the daemon builds from
	// the store carries the count and no Sample) or the in-memory count
	// kept by the aggregator's Classifier (issue #622). An aggregate
	// without the key (no classifier: unit tests, the benchmark) falls
	// through to the scan below — same predicate, same result while the
	// sample is not saturated.
	if n, ok := agg.Kinds[LongCounterKind(r.Name)]; ok {
		return n
	}

	// Field-level rule: scan Sample for matching field values. The
	// predicate is shared with evidenceLines (ADR-0011) so captured
	// evidence is always a subset of the counted events.
	total := 0
	for _, ev := range agg.Sample {
		if _, ok := kindSet[ev.Kind]; !ok {
			continue
		}
		if fieldMatches(r, ev) {
			total++
		}
	}
	return total
}

func decodeRules(r io.Reader, out *rulesFile) error {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		// An empty or comments-only file decodes to io.EOF — that is a
		// legitimate drop-in (e.g. a fully-commented tuning template),
		// not an error.
		if errors.Is(err, io.EOF) {
			return nil
		}
		return fmt.Errorf("rules: decode YAML: %w", err)
	}
	return nil
}

// validateRules checks the final rule set. origin, when non-nil, maps a rule
// name to the drop-in file that contributed it ("" = embedded base) — a
// failure on a drop-in-owned rule then names the file the operator must fix.
func validateRules(rules []spec, origin map[string]string) error {
	for i, r := range rules {
		if err := validateRule(i, r); err != nil {
			if from := origin[r.Name]; from != "" {
				return fmt.Errorf("drop-in %q: %w", from, err)
			}
			return err
		}
	}
	return nil
}

func validateRule(i int, r spec) error {
	if r.Name == "" {
		return fmt.Errorf("rules[%d]: name is required", i)
	}
	if len(r.Kinds) == 0 {
		return fmt.Errorf("rule %q: kinds must be non-empty", r.Name)
	}
	if r.Threshold <= 0 {
		return fmt.Errorf("rule %q: threshold must be > 0, got %d", r.Name, r.Threshold)
	}
	if r.Score < 0 || r.Score > 100 {
		return fmt.Errorf("rule %q: score must be 0–100, got %d", r.Name, r.Score)
	}
	if time.Duration(r.Window) <= 0 {
		return fmt.Errorf("rule %q: window must be > 0", r.Name)
	}
	if (r.Value != "" && r.Contains != "") || (r.Value != "" && len(r.ContainsAny) > 0) || (r.Contains != "" && len(r.ContainsAny) > 0) {
		return fmt.Errorf("rule %q: value, contains, and contains_any are mutually exclusive", r.Name)
	}
	// field and the matchers only work as a pair (issue #316): countMatches
	// consults value/contains/contains_any only when field is set, and a
	// field with no matcher can never increment. Either half alone is a
	// silent footgun — over-matching every event of the listed kinds, or a
	// protective rule that never fires — so both fail closed at load time,
	// like every other validation error here.
	hasMatcher := r.Value != "" || r.Contains != "" || len(r.ContainsAny) > 0
	if hasMatcher && r.Field == "" {
		return fmt.Errorf("rule %q: value/contains/contains_any require 'field' (without it the matcher is ignored and every event of the listed kinds counts)", r.Name)
	}
	if r.Field != "" && !hasMatcher {
		return fmt.Errorf("rule %q: 'field' requires one of value, contains, or contains_any (without a matcher the rule can never fire)", r.Name)
	}
	if r.Category == "" {
		return fmt.Errorf("rule %q: category is required", r.Name)
	}
	// Long-window rules (issue #134) are evaluated from persistent per-IP
	// hourly counters. Kind-level rules read the parser-kind counters;
	// field-level rules read a counter of their own matcher, written on
	// the hot path under LongCounterKind (issue #585) — so both shapes are
	// valid above the cutoff. A rule name that would collide with the
	// counter namespace is rejected here rather than silently aliasing.
	if IsLongCounterKind(r.Name) {
		return fmt.Errorf("rule %q: names may not start with %q (reserved for long-window counter kinds)", r.Name, LongCounterKindPrefix)
	}
	return nil
}

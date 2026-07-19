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
		if err := validateRules(rf.Rules); err != nil {
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

	merged, err := applyDropins(base.Rules, rulesDir)
	if err != nil {
		return nil, err
	}

	if err := validateRules(merged); err != nil {
		return nil, err
	}
	return &Engine{rules: merged}, nil
}

// applyDropins overlays every *.yaml / *.yml drop-in from dir onto base,
// merged by rule name in lexical file order. A missing dir returns base
// unchanged; any other read/parse error fails closed.
func applyDropins(base []spec, dir string) ([]spec, error) {
	if dir == "" {
		return base, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return base, nil
		}
		return nil, fmt.Errorf("rules: read drop-in dir %q: %w", dir, err)
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
			return nil, fmt.Errorf("rules: open drop-in %q: %w", path, err)
		}
		var rf rulesFile
		decErr := decodeRules(f, &rf)
		_ = f.Close()
		if decErr != nil {
			return nil, fmt.Errorf("rules: drop-in %q: %w", path, decErr)
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
	return merged, nil
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
	}, true
}

// countMatches returns the number of events in agg that satisfy the rule.
//
// For kind-only rules (no Field), Kinds counts are used directly — they are
// exact even when Sample is capped.
//
// For field-level rules, Sample is scanned. The default sample cap (4096) is
// large enough for all built-in rule thresholds. If the sample is saturated the
// count is a lower bound: the rule still triggers correctly as long as the true
// count exceeds the threshold.
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

	// Field-level rule: scan Sample for matching field values.
	total := 0
	for _, ev := range agg.Sample {
		if _, ok := kindSet[ev.Kind]; !ok {
			continue
		}
		val, exists := ev.Fields[r.Field]
		if !exists {
			continue
		}
		if r.Value != "" && val == r.Value {
			total++
		} else if r.Contains != "" && strings.Contains(val, r.Contains) {
			total++
		} else if len(r.ContainsAny) > 0 {
			// ContainsAny: OR logic — match if any substring is found
			for _, sub := range r.ContainsAny {
				if strings.Contains(val, sub) {
					total++
					break
				}
			}
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

func validateRules(rules []spec) error {
	for i, r := range rules {
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
		if r.Category == "" {
			return fmt.Errorf("rule %q: category is required", r.Name)
		}
	}
	return nil
}

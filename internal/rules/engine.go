// Package rules provides the always-available rule-based verdict engine.
// All evaluation logic is pure (no I/O after construction).
package rules

import (
	"context"
	"fmt"
	"io"
	"os"
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

// New creates an Engine.
//
// If overridePath is non-empty the rules are loaded exclusively from that file,
// replacing the embedded defaults. On a parse or validation error the embedded
// defaults are NOT used as a fallback — the caller should refuse to start.
//
// If overridePath is empty the embedded configs/rules.yaml is used.
func New(overridePath string) (*Engine, error) {
	var rf rulesFile
	if overridePath != "" {
		f, err := os.Open(overridePath) //nolint:gosec // path comes from operator config, not attacker input
		if err != nil {
			return nil, fmt.Errorf("rules: open %q: %w", overridePath, err)
		}
		defer f.Close() //nolint:errcheck
		if err := decodeRules(f, &rf); err != nil {
			return nil, err
		}
	} else {
		data, err := configs.FS.ReadFile("rules.yaml")
		if err != nil {
			return nil, fmt.Errorf("rules: read embedded rules.yaml: %w", err)
		}
		if err := decodeRules(strings.NewReader(string(data)), &rf); err != nil {
			return nil, err
		}
	}
	if err := validateRules(rf.Rules); err != nil {
		return nil, err
	}
	return &Engine{rules: rf.Rules}, nil
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

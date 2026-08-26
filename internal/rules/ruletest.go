// SPDX-License-Identifier: AGPL-3.0-only

package rules

// Read-only rule introspection for `ezyshield rule test` (issue #224).
// Nothing here mutates the engine or evaluates events — it only exposes a
// validated, exported view of loaded rules so the CLI can dry-run one rule
// against stored aggregates without reaching into unexported internals.

import (
	"fmt"
	"os"
	"sort"
	"time"
)

// RuleInfo is the exported read-only view of a single loaded rule. It
// mirrors spec field-for-field; the CLI must never be able to feed a rule
// back into evaluation through this type (dry testing is pure read).
type RuleInfo struct {
	Name        string
	Description string
	Kinds       []string
	Field       string
	Value       string
	Contains    string
	ContainsAny []string
	Window      time.Duration
	Threshold   int
	Score       int
	Category    string
}

// FieldLevel reports whether the rule carries a field-level matcher. Stored
// aggregates keep kind counts only, so field-level rules can only be
// dry-tested as a kind-level UPPER BOUND (the caller must say so loudly).
func (r RuleInfo) FieldLevel() bool {
	return r.Field != ""
}

func infoFromSpec(s spec) RuleInfo {
	return RuleInfo{
		Name:        s.Name,
		Description: s.Description,
		Kinds:       append([]string(nil), s.Kinds...),
		Field:       s.Field,
		Value:       s.Value,
		Contains:    s.Contains,
		ContainsAny: append([]string(nil), s.ContainsAny...),
		Window:      time.Duration(s.Window),
		Threshold:   s.Threshold,
		Score:       s.Score,
		Category:    s.Category,
	}
}

// Rule returns the loaded rule with the given name (from whichever layer
// won the merge: embedded base, drop-in, or legacy override file).
func (e *Engine) Rule(name string) (RuleInfo, bool) {
	for _, r := range e.rules {
		if r.Name == name {
			return infoFromSpec(r), true
		}
	}
	return RuleInfo{}, false
}

// RuleNames returns the names of all loaded rules, sorted, so a
// name-not-found error can list what IS available.
func (e *Engine) RuleNames() []string {
	out := make([]string, 0, len(e.rules))
	for _, r := range e.rules {
		out = append(out, r.Name)
	}
	sort.Strings(out)
	return out
}

// LoadStandaloneFile decodes and validates one rules YAML file exactly like
// the loader does (strict fields, same fail-closed validation), without
// merging any other layer. Invalid content is an error — never a partial
// result — so `rule test` refuses the same files the daemon would refuse.
func LoadStandaloneFile(path string) ([]RuleInfo, error) {
	f, err := os.Open(path) //nolint:gosec // path is an operator-typed CLI argument, not attacker input
	if err != nil {
		return nil, fmt.Errorf("rules: open %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck
	var rf rulesFile
	if err := decodeRules(f, &rf); err != nil {
		return nil, fmt.Errorf("rules: file %q: %w", path, err)
	}
	if len(rf.Rules) == 0 {
		return nil, fmt.Errorf("rules: file %q contains no rules", path)
	}
	if err := validateRules(rf.Rules, nil); err != nil {
		return nil, fmt.Errorf("rules: file %q: %w", path, err)
	}
	out := make([]RuleInfo, 0, len(rf.Rules))
	for _, s := range rf.Rules {
		out = append(out, infoFromSpec(s))
	}
	return out, nil
}

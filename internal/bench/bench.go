// Package bench runs the full detection pipeline (parse → aggregate →
// rules → decision, dry-run) over a labeled corpus of attack and legitimate
// traffic (issue #216), turning "it detects brute force" into published,
// regression-guarded numbers: detection rate, false positives, and
// time-to-first-strike.
//
// Determinism: every scenario runs on a VIRTUAL clock (a fixed epoch plus
// the scenario's per-line interval); parsers' own timestamps are overridden
// with the virtual time before aggregation, so runs are stable across
// machines and wall-clock time. The AI layer is never involved (rules-only,
// per the issue's scope), and nothing is enforced — the policy is dry-run
// and no enforcer is wired.
package bench

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/evertramos/ezy-shield/internal/aggregate"
	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/decision"
	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/internal/rules"
	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// Scenario is one labeled corpus entry (a YAML file under the corpus dir).
type Scenario struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Label is "attack" (the attacker IPs must be caught) or "legit"
	// (ANY ban-band action is a false positive).
	Label string `yaml:"label"`
	// Source is the collector source ID that selects the parser
	// ("journald:sshd", "file:/var/log/nginx/access.log").
	Source string `yaml:"source"`
	// AttackerIPs are the IPs expected to be caught (attack scenarios).
	AttackerIPs []string `yaml:"attacker_ips"`
	// IntervalMS is the virtual spacing between lines (default 1000).
	IntervalMS int      `yaml:"interval_ms"`
	Lines      []string `yaml:"lines"`
}

// ScenarioResult is the per-scenario outcome.
type ScenarioResult struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	// Detected: an attack scenario produced a ban-band decision for an
	// attacker IP.
	Detected bool `json:"detected"`
	// Rules are the rule names that fired (from verdict reasons), sorted.
	Rules []string `json:"rules,omitempty"`
	// TimeToFirstStrikeSec is the virtual seconds from scenario start to
	// the first ban-band decision; -1 when none.
	TimeToFirstStrikeSec float64 `json:"time_to_first_strike_sec"`
	// FalsePositive: a legit scenario produced ANY ban-band decision.
	FalsePositive bool `json:"false_positive"`
}

// Report is the machine-readable benchmark output.
type Report struct {
	Scenarios      []ScenarioResult `json:"scenarios"`
	Attacks        int              `json:"attacks"`
	Detected       int              `json:"detected"`
	DetectionRate  float64          `json:"detection_rate"`
	LegitScenarios int              `json:"legit_scenarios"`
	FalsePositives int              `json:"false_positives"`
}

// benchEpoch is the fixed virtual start time (never wall clock).
var benchEpoch = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// RunCorpus loads every *.yaml under dir and runs each scenario through a
// fresh pipeline.
func RunCorpus(dir string) (*Report, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("bench: read corpus dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("bench: no scenarios in %s", dir)
	}

	rep := &Report{}
	for _, name := range names {
		sc, err := loadScenario(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		res, err := runScenario(sc)
		if err != nil {
			return nil, fmt.Errorf("bench: scenario %s: %w", sc.Name, err)
		}
		rep.Scenarios = append(rep.Scenarios, *res)
		switch sc.Label {
		case "attack":
			rep.Attacks++
			if res.Detected {
				rep.Detected++
			}
		case "legit":
			rep.LegitScenarios++
			if res.FalsePositive {
				rep.FalsePositives++
			}
		}
	}
	if rep.Attacks > 0 {
		rep.DetectionRate = float64(rep.Detected) / float64(rep.Attacks)
	}
	return rep, nil
}

func loadScenario(path string) (*Scenario, error) {
	data, err := os.ReadFile(path) //nolint:gosec // repo-owned fixture path
	if err != nil {
		return nil, fmt.Errorf("bench: read %s: %w", path, err)
	}
	sc := &Scenario{}
	if err := yaml.Unmarshal(data, sc); err != nil {
		return nil, fmt.Errorf("bench: parse %s: %w", path, err)
	}
	if sc.Name == "" || (sc.Label != "attack" && sc.Label != "legit") || sc.Source == "" || len(sc.Lines) == 0 {
		return nil, fmt.Errorf("bench: %s: name, label (attack|legit), source, and lines are required", path)
	}
	if sc.Label == "attack" && len(sc.AttackerIPs) == 0 {
		return nil, fmt.Errorf("bench: %s: attack scenarios need attacker_ips", path)
	}
	if sc.IntervalMS <= 0 {
		sc.IntervalMS = 1000
	}
	return sc, nil
}

// runScenario replays one scenario on a fresh pipeline with a virtual clock.
func runScenario(sc *Scenario) (*ScenarioResult, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	parsers := []sdk.Parser{
		parser.NewSSHParser(logger),
		parser.NewNginxParser(logger, parser.NginxConfig{}),
	}

	ruleEng, err := rules.New("", "")
	if err != nil {
		return nil, err
	}
	agg := aggregate.New(ruleEng.Windows(), 0)

	ctx := context.Background()
	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	pol := &config.Policy{
		Armed:            false, // dry-run: decisions are recorded, never enforced
		BanThreshold:     config.DefaultBanThreshold,
		ObserveThreshold: config.DefaultObserveThreshold,
		MaxBansPerMinute: config.DefaultMaxBansPerMinute,
		Strikes:          config.DefaultStrikes,
	}
	dec, err := decision.New(pol, db)
	if err != nil {
		return nil, err
	}
	dec.SetSSHPeerProbe(func() []netip.Addr { return nil }) // no host state in a benchmark

	attackers := map[netip.Addr]bool{}
	for _, s := range sc.AttackerIPs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("attacker_ips: %w", err)
		}
		attackers[a] = true
	}

	res := &ScenarioResult{Name: sc.Name, Label: sc.Label, TimeToFirstStrikeSec: -1}
	ruleSet := map[string]bool{}
	clock := benchEpoch
	interval := time.Duration(sc.IntervalMS) * time.Millisecond

	for _, line := range sc.Lines {
		raw := sdk.RawLine{Source: sc.Source, Line: []byte(line), At: clock}
		var events []sdk.Event
		for _, p := range parsers {
			if p.Matches(sc.Source) {
				events, _ = p.Parse(raw)
				break
			}
		}
		for _, ev := range events {
			ev.Time = clock // virtual clock beats any parsed timestamp — determinism
			agg.Add(ev)

			var verdicts []sdk.Verdict
			for _, w := range agg.Windows() {
				verdicts = append(verdicts, ruleEng.Evaluate(ctx, agg.Aggregate(ev.SourceIP, w, clock))...)
			}
			if len(verdicts) == 0 {
				continue
			}
			for _, v := range verdicts {
				if name, ok := strings.CutPrefix(v.Reason, "rule/"); ok {
					if i := strings.IndexByte(name, ':'); i > 0 {
						ruleSet[name[:i]] = true
					}
				}
			}
			act, err := dec.Decide(ctx, verdicts)
			if err != nil {
				continue // rate limit etc. — a benchmark never aborts on it
			}
			if act.Op == "ban" || act.Op == "dry_ban" {
				if sc.Label == "legit" {
					res.FalsePositive = true
				}
				if attackers[act.IP] && !res.Detected {
					res.Detected = true
					res.TimeToFirstStrikeSec = clock.Sub(benchEpoch).Seconds()
				}
			}
		}
		clock = clock.Add(interval)
	}

	for r := range ruleSet {
		res.Rules = append(res.Rules, r)
	}
	sort.Strings(res.Rules)
	return res, nil
}

// Summary renders the human-readable table.
func Summary(rep *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "detection rate: %d/%d (%.0f%%)   false positives: %d/%d legit scenarios\n\n",
		rep.Detected, rep.Attacks, rep.DetectionRate*100, rep.FalsePositives, rep.LegitScenarios)
	for _, s := range rep.Scenarios {
		mark := "ok"
		switch {
		case s.Label == "attack" && !s.Detected:
			mark = "MISSED"
		case s.FalsePositive:
			mark = "FALSE POSITIVE"
		}
		ttfs := "—"
		if s.TimeToFirstStrikeSec >= 0 {
			ttfs = fmt.Sprintf("%.1fs", s.TimeToFirstStrikeSec)
		}
		fmt.Fprintf(&b, "  %-28s %-6s %-14s ttfs=%-8s rules=%s\n",
			s.Name, s.Label, mark, ttfs, strings.Join(s.Rules, ","))
	}
	return b.String()
}

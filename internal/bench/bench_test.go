// SPDX-License-Identifier: AGPL-3.0-only

//go:build bench

package bench

// Regression gate for the detection benchmark (issue #216). Run with:
//
//	go test -tags bench ./internal/bench/ -v        (or: make bench)
//
// The committed baseline (fixtures/bench/baseline.json) is the contract:
// a rules/parser change that loses a detection or gains a false positive
// fails here, and updating the baseline is an explicit, reviewable diff.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type baseline struct {
	DetectionRate  float64         `json:"detection_rate"`
	FalsePositives int             `json:"false_positives"`
	Detected       map[string]bool `json:"detected"`
}

func TestBenchCorpus_AgainstBaseline(t *testing.T) {
	corpus := filepath.Join("..", "..", "fixtures", "bench", "corpus")
	rep, err := RunCorpus(corpus)
	if err != nil {
		t.Fatalf("RunCorpus: %v", err)
	}

	// Human summary + machine-readable report, always printed.
	t.Logf("\n%s", Summary(rep))
	if raw, err := json.MarshalIndent(rep, "", "  "); err == nil {
		if out := os.Getenv("BENCH_JSON_OUT"); out != "" {
			// G703: out is the invoking developer's/CI's own path choice.
			if werr := os.WriteFile(filepath.Clean(out), raw, 0o600); werr != nil { //nolint:gosec
				t.Logf("write %s: %v", out, werr)
			}
		} else {
			t.Logf("report JSON:\n%s", raw)
		}
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "bench", "baseline.json"))
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var base baseline
	if err := json.Unmarshal(data, &base); err != nil {
		t.Fatalf("parse baseline: %v", err)
	}

	// Regression thresholds: detections may only be gained, never lost;
	// false positives may only shrink, never grow.
	if rep.DetectionRate < base.DetectionRate {
		t.Errorf("detection rate regressed: %.2f < baseline %.2f", rep.DetectionRate, base.DetectionRate)
	}
	if rep.FalsePositives > base.FalsePositives {
		t.Errorf("false positives regressed: %d > baseline %d", rep.FalsePositives, base.FalsePositives)
	}
	got := map[string]ScenarioResult{}
	for _, s := range rep.Scenarios {
		got[s.Name] = s
	}
	for name, wasDetected := range base.Detected {
		s, ok := got[name]
		if !ok {
			t.Errorf("baseline scenario %q missing from the corpus (removing scenarios needs an explicit baseline update)", name)
			continue
		}
		if wasDetected && !s.Detected {
			t.Errorf("scenario %q was detected at baseline time and is now MISSED", name)
		}
		if s.FalsePositive {
			t.Errorf("scenario %q produced a false positive", name)
		}
	}
	// New scenarios must enter the baseline explicitly.
	for _, s := range rep.Scenarios {
		if _, ok := base.Detected[s.Name]; !ok {
			t.Errorf("scenario %q is not in baseline.json — add it (explicit, reviewable diff)", s.Name)
		}
	}
}

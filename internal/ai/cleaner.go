// SPDX-License-Identifier: AGPL-3.0-only

package ai

// Log Cleaner (issue #222): the token-frugality gate in front of the
// async analysis layer. Everything that cannot change an AI verdict is
// dropped BEFORE a provider is involved: static-asset noise, empty
// aggregates. The reduction is measured so the frugality claim is a
// number, not a slogan.
//
// Redaction posture: providers only ever see Count/Kinds/Enrich/Behavior
// (buildPayload) — raw Sample lines never reach a payload. The cleaner's
// job is therefore volume reduction plus building the Behavior summary
// through the one sanitizing boundary (behavior.go).

import (
	"path"
	"strings"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// staticAssetExts is request noise no verdict ever hinges on.
var staticAssetExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".mp4": true, ".webm": true, ".avif": true,
}

// CleanStats reports what the cleaner removed.
type CleanStats struct {
	// EventsBefore/EventsAfter count sampled events across the batch.
	EventsBefore int
	EventsAfter  int
	// AggregatesDropped counts aggregates removed entirely (nothing left).
	AggregatesDropped int
}

// ReductionRatio returns the fraction of sampled volume removed, in
// [0, 1]. Zero events in = zero reduction.
func (s CleanStats) ReductionRatio() float64 {
	if s.EventsBefore == 0 {
		return 0
	}
	return float64(s.EventsBefore-s.EventsAfter) / float64(s.EventsBefore)
}

// CleanAggregates filters the batch for AI analysis: static-asset sample
// events are dropped, the Behavior summary is (re)built from what
// remains, and aggregates left with no events at all are removed. The
// input is not mutated.
func CleanAggregates(batch []sdk.Aggregate) ([]sdk.Aggregate, CleanStats) {
	var stats CleanStats
	out := make([]sdk.Aggregate, 0, len(batch))
	for _, agg := range batch {
		stats.EventsBefore += len(agg.Sample)

		kept := make([]sdk.Event, 0, len(agg.Sample))
		for _, ev := range agg.Sample {
			if isStaticAssetEvent(ev) {
				continue
			}
			kept = append(kept, ev)
		}
		stats.EventsAfter += len(kept)

		if agg.Count == 0 && len(kept) == 0 {
			stats.AggregatesDropped++
			continue
		}
		cleaned := agg
		cleaned.Sample = kept
		cleaned.Behavior = SummarizeBehavior(cleaned)
		out = append(out, cleaned)
	}
	return out, stats
}

// isStaticAssetEvent reports whether the event is a static-asset request.
func isStaticAssetEvent(ev sdk.Event) bool {
	p := ev.Fields["path"]
	if p == "" {
		return false
	}
	ext := strings.ToLower(path.Ext(stripQuery(p)))
	return staticAssetExts[ext]
}

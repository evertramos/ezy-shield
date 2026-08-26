// SPDX-License-Identifier: AGPL-3.0-only

package ai

// Behavioral aggregate enrichment (issue #222): condense an aggregate's
// sampled events into the compact distributions the async analysis layer
// needs — paths, methods, status classes, user agents. Shared
// infrastructure with the evidence-capture pipeline (#127): both read the
// same Sample events; this file is the ONE place sample fields become
// AI-visible data.
//
// Security (§1/§5): sample field values are hostile log content. Nothing
// raw crosses this boundary — every string is control-stripped and
// length-capped, lists are top-N by frequency, and querystrings are cut
// from paths (they are where secrets/PII land in URLs).

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/evertramos/ezy-shield/pkg/sdk"
)

const (
	// behaviorTopN bounds each top list.
	behaviorTopN = 5
	// behaviorValueCap bounds one path/UA string.
	behaviorValueCap = 96
)

// SummarizeBehavior builds the compact behavioral summary from agg.Sample.
// Returns nil when the sample carries none of the HTTP fields — non-HTTP
// aggregates (SSH, mail) stay summary-free rather than empty-object noise.
func SummarizeBehavior(agg sdk.Aggregate) *sdk.BehaviorSummary {
	paths := map[string]int{}
	methods := map[string]int{}
	statuses := map[string]int{}
	uas := map[string]int{}

	for _, ev := range agg.Sample {
		if p := ev.Fields["path"]; p != "" {
			paths[cleanBehaviorValue(stripQuery(p))]++
		}
		if m := ev.Fields["method"]; m != "" {
			methods[cleanBehaviorValue(m)]++
		}
		if s := ev.Fields["status"]; s != "" {
			statuses[statusClass(s)]++
		}
		if ua := ev.Fields["ua"]; ua != "" {
			uas[cleanBehaviorValue(ua)]++
		}
	}
	if len(paths) == 0 && len(methods) == 0 && len(statuses) == 0 && len(uas) == 0 {
		return nil
	}
	return &sdk.BehaviorSummary{
		TopPaths:      topN(paths, behaviorTopN),
		Methods:       methods,
		StatusClasses: statuses,
		TopUserAgents: topN(uas, behaviorTopN),
	}
}

// stripQuery cuts everything from '?' on — querystrings are where tokens,
// session ids and PII land in URLs, and the path family is the signal.
func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

// statusClass folds a status code into its class ("404" → "4xx"); values
// that don't look like status codes fold into "other".
func statusClass(s string) string {
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' {
		return string(s[0]) + "xx"
	}
	return "other"
}

// cleanBehaviorValue strips control/non-printable runes and caps length —
// hostile log fields must not smuggle prompt text or escapes into payloads.
func cleanBehaviorValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= behaviorValueCap {
			break
		}
	}
	return b.String()
}

// topN renders the N most frequent entries as "value (xCount)", ties
// broken lexically for determinism.
func topN(counts map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(counts))
	for k, v := range counts {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if len(all) > n {
		all = all[:n]
	}
	out := make([]string, len(all))
	for i, e := range all {
		out[i] = fmt.Sprintf("%s (x%d)", e.k, e.v)
	}
	return out
}

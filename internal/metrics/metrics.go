// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics implements process-lifetime counters/gauges and Prometheus
// text exposition (issue #183) with zero dependencies — the text format is a
// few lines of writer code, which is exactly why no client library is worth
// its transitive weight in a security daemon.
//
// Label cardinality is bounded BY CONSTRUCTION: a labeled metric declares its
// single label name at registration from a fixed allowlist (parser,
// collector, enforcer, provider, level, op, version), label values are
// pattern-checked and capped per metric, and there is no API to attach
// arbitrary key/value pairs. IPs, usernames, and paths can never become
// label values without failing the pattern or the tests that pin the
// allowlist.
package metrics

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// AllowedLabels is the closed set of label names a metric may declare.
// The cardinality lint test pins every registered metric to this set.
var AllowedLabels = map[string]bool{
	"parser": true, "collector": true, "enforcer": true,
	"provider": true, "level": true, "op": true, "version": true,
}

const (
	// maxLabelValues caps distinct values per labeled metric — far above
	// any enumerable set (parsers, collectors, ...), far below abuse.
	maxLabelValues = 64
	// maxLabelValueLen caps one label value's length.
	maxLabelValueLen = 64
)

// labelValueRe rejects anything that is not a short, printable token.
// Dots/colons/slashes allowed so type-derived names ("*parser.SSHParser")
// and versions ("v0.1.0-rc1") fit; quotes/backslashes/newlines never do.
var labelValueRe = regexp.MustCompile(`^[A-Za-z0-9_.:*/-]{1,64}$`)

// Counter is a monotonically increasing uint64.
type Counter struct{ v atomic.Uint64 }

// Inc adds 1.
func (c *Counter) Inc() { c.v.Add(1) }

// Add adds n (negative n is ignored — counters only go up).
func (c *Counter) Add(n int64) {
	if n > 0 {
		c.v.Add(uint64(n))
	}
}

// Value returns the current count.
func (c *Counter) Value() uint64 { return c.v.Load() }

// Gauge is a settable int64.
type Gauge struct{ v atomic.Int64 }

// Set replaces the value.
func (g *Gauge) Set(n int64) { g.v.Store(n) }

// Value returns the current value.
func (g *Gauge) Value() int64 { return g.v.Load() }

// metric is one registered family.
type metric struct {
	name  string
	help  string
	typ   string // counter | gauge
	label string // "" = unlabeled

	// Unlabeled storage.
	counter *Counter
	gauge   *Gauge
	// gaugeFn, when set, is evaluated at exposition time (e.g. active
	// bans sourced from the store).
	gaugeFn func() int64
	// constPair, when set, is a pre-rendered `name="value"` label pair
	// attached to the (gauge) sample — build_info's version label.
	constPair string

	mu       sync.Mutex
	byLabel  map[string]*Counter
	overflow atomic.Uint64 // increments attempted past maxLabelValues
}

// Registry holds registered metrics and renders the exposition.
type Registry struct {
	mu      sync.Mutex
	metrics []*metric
	byName  map[string]*metric
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]*metric{}}
}

// Default is the process-wide registry the pipeline instruments.
var Default = NewRegistry()

func (r *Registry) register(m *metric) *metric {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.byName[m.name]; ok {
		return existing
	}
	r.metrics = append(r.metrics, m)
	r.byName[m.name] = m
	return m
}

// Counter registers (or returns) an unlabeled counter.
func (r *Registry) Counter(name, help string) *Counter {
	m := r.register(&metric{name: name, help: help, typ: "counter", counter: &Counter{}})
	return m.counter
}

// Gauge registers (or returns) an unlabeled gauge.
func (r *Registry) Gauge(name, help string) *Gauge {
	m := r.register(&metric{name: name, help: help, typ: "gauge", gauge: &Gauge{}})
	return m.gauge
}

// GaugeFunc registers a gauge whose value is computed at exposition time.
func (r *Registry) GaugeFunc(name, help string, fn func() int64) {
	r.register(&metric{name: name, help: help, typ: "gauge", gaugeFn: fn})
}

// LabeledCounter is a counter family with exactly one label.
type LabeledCounter struct{ m *metric }

// LabeledCounter registers (or returns) a counter family with one label
// name, which MUST be in AllowedLabels — anything else panics at
// registration (a programming error, caught by the lint test long before
// production).
func (r *Registry) LabeledCounter(name, help, label string) *LabeledCounter {
	if !AllowedLabels[label] {
		panic(fmt.Sprintf("metrics: label %q is not in the bounded-cardinality allowlist", label))
	}
	m := r.register(&metric{
		name: name, help: help, typ: "counter", label: label,
		byLabel: map[string]*Counter{},
	})
	return &LabeledCounter{m: m}
}

// With returns the counter for one label value. Values failing the token
// pattern are folded into "invalid"; values past the per-metric cap fold
// into "other" — the scrape stays bounded no matter what the caller passes.
func (c *LabeledCounter) With(value string) *Counter {
	if !labelValueRe.MatchString(value) {
		value = "invalid"
	}
	c.m.mu.Lock()
	defer c.m.mu.Unlock()
	if ctr, ok := c.m.byLabel[value]; ok {
		return ctr
	}
	if len(c.m.byLabel) >= maxLabelValues {
		c.m.overflow.Add(1)
		if ctr, ok := c.m.byLabel["other"]; ok {
			return ctr
		}
		value = "other"
	}
	ctr := &Counter{}
	c.m.byLabel[value] = ctr
	return ctr
}

// WriteExposition renders the Prometheus text format (version 0.0.4):
// HELP/TYPE lines followed by samples, families in registration order,
// label values sorted for stable output.
func (r *Registry) WriteExposition(w io.Writer) error {
	r.mu.Lock()
	metrics := append([]*metric(nil), r.metrics...)
	r.mu.Unlock()

	for _, m := range metrics {
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n",
			m.name, escapeHelp(m.help), m.name, m.typ); err != nil {
			return err
		}
		switch {
		case m.gaugeFn != nil:
			sample := m.name
			if m.constPair != "" {
				sample += "{" + m.constPair + "}"
			}
			if _, err := fmt.Fprintf(w, "%s %d\n", sample, m.gaugeFn()); err != nil {
				return err
			}
		case m.gauge != nil:
			if _, err := fmt.Fprintf(w, "%s %d\n", m.name, m.gauge.Value()); err != nil {
				return err
			}
		case m.label != "":
			m.mu.Lock()
			keys := make([]string, 0, len(m.byLabel))
			for k := range m.byLabel {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			type kv struct {
				k string
				v uint64
			}
			rows := make([]kv, 0, len(keys))
			for _, k := range keys {
				rows = append(rows, kv{k: k, v: m.byLabel[k].Value()})
			}
			m.mu.Unlock()
			for _, row := range rows {
				if _, err := fmt.Fprintf(w, "%s{%s=%q} %d\n", m.name, m.label, row.k, row.v); err != nil {
					return err
				}
			}
		case m.counter != nil:
			if _, err := fmt.Fprintf(w, "%s %d\n", m.name, m.counter.Value()); err != nil {
				return err
			}
		}
	}
	return nil
}

// BuildInfo registers the ezyshield_build_info{version="..."} 1 gauge.
func (r *Registry) BuildInfo(version string) {
	if !labelValueRe.MatchString(version) {
		version = "invalid"
	}
	r.register(&metric{
		name:      "ezyshield_build_info",
		help:      "Build information; the value is always 1.",
		typ:       "gauge",
		constPair: fmt.Sprintf("version=%q", version),
		gaugeFn:   func() int64 { return 1 },
	})
}

// Snapshot returns the exposition as a string.
func (r *Registry) Snapshot() string {
	var b strings.Builder
	_ = r.WriteExposition(&b)
	return b.String()
}

// LabelNames returns each registered labeled metric's label name, for the
// cardinality lint test.
func (r *Registry) LabelNames() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	for _, m := range r.metrics {
		if m.label != "" {
			out[m.name] = m.label
		}
	}
	return out
}

// escapeHelp keeps HELP lines single-line per the exposition format.
func escapeHelp(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

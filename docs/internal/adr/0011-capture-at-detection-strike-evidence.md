# ADR-0011: Capture-at-detection strike evidence

Date: 2026-08-25
Status: Accepted
Issue: #127 (follow-up to #54)

## Context

`report --evidence` (issue #54) extracts log excerpts **on demand**: it shows
what currently mentions the IP in the logs, not what actually triggered each
strike. Logs rotate and containers restart — by the time an operator writes
an abuse@ complaint, the original attack lines may be gone. The forensically
correct evidence is the exact lines that produced the verdict, captured at
detection time.

This ADR decides the contract changes, storage shape, bounds, and retention
for carrying triggering lines through the pipeline.

## Decision

### Contract changes (architecture §3–§4)

1. **`sdk.Event` gains `Raw []byte`** — an optional, bounded copy of the
   originating log line. The daemon attaches it in `processRaw` right after
   parsing (a copy, truncated to `EvidenceRawCap = 512` bytes), so **all
   source kinds are covered uniformly** (file, journald, docker): capture
   happens in-pipeline, downstream of every collector. Parsers stay
   untouched and never see or interpret `Raw`.

2. **`sdk.Verdict` gains `Evidence []string`** — up to
   `EvidenceMaxLines = 5` raw lines collected by the rule engine **when a
   rule fires**, from the sample events that actually matched that rule
   (same kind/field matching as the threshold count). AI and geo verdicts
   carry no evidence. Long-window (>1h) rules evaluate from persistent
   counters (issue #134) which retain no events, so their verdicts carry no
   evidence either — the short-window verdict for the same burst usually
   does.

3. **`sdk.Action` is unchanged.** Verdicts already ride
   `Action.Verdicts` into `store.RecordStrike`.

### Storage: no schema change

`RecordStrike` already serializes `Action.Verdicts` as JSON into the
existing `strikes.verdicts` column. `Verdict.Evidence` therefore persists
with **zero migration**: the column is the natural home for
verdict-attached data, and `StrikesForIP` deserializes it back without new
code. A dedicated evidence table was considered and rejected — it would
duplicate the verdict↔strike association the JSON column already encodes,
and every consumer (report verb, dashboard) already reads that column.

### Bounds

- Per event: `Raw` capped at **512 bytes** (a full nginx access line is
  ~200–400 bytes; SSH auth lines ~150). The cap is applied at attach time,
  before the event enters the aggregator.
- Per verdict: at most **5 evidence lines** (~2.5 KB worst case).
- Per strike: bounded by verdicts count (small: rules + optional AI/geo).
- Memory: `Raw` rides the aggregator's existing sample buffers, whose
  event count is already capped (sample cap per bucket, LRU cap on IPs).
  The addition is at most 512 bytes/event on buffers that already hold
  parsed `Fields` of comparable size — same order of magnitude, no new
  unbounded dimension.

### Retention

Evidence lives inside `strikes.verdicts`, so it follows the strikes
retention policy (issue #184, `retention.strikes`, default 730d, pruned in
batches). No separate blob lifecycle. History rows are never edited: a
strike's evidence is immutable once recorded.

### Hostile bytes

Raw lines are attacker-controlled. As everywhere else in EzyShield
(reasons, categories), **sanitization happens at render time, never at
storage time**: the CLI strips control characters/ANSI and caps line length
before printing (same helpers as the on-demand evidence path); the markdown
renderer already neutralizes fences. Nothing anywhere interpolates stored
evidence into SQL, shell, or nft input.

### Surfacing

`report --evidence` now shows both, clearly labeled:

- **Captured evidence per strike** (authoritative — what fired the rule),
  rendered from `strikes.verdicts`; always present when strikes carry it,
  and included in the JSON/markdown wire form as
  `strikes[].verdicts[].evidence`.
- **On-demand excerpts** (recent activity — the existing late grep),
  unchanged.

## Consequences

- Abuse reports can cite the exact triggering lines even after log
  rotation; the wire schema gains one optional array field
  (backwards-compatible: absent for pre-existing strikes).
- Aggregator memory grows by the bounded `Raw` payload; the 512-byte cap
  keeps it within the existing sample-buffer order of magnitude.
- The rule engine's fire path does a bounded extra scan (≤ sample size,
  only when a rule actually fires — not per event).

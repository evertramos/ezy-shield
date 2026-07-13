# ADR-0008: Versioned AbuseReport schema in pkg/sdk

**Status:** Accepted
**Date:** 2026-07-13

## Context

Issue #54 asks for a per-IP abuse report (country, strikes, attack type,
block timestamps, actions, strike history) consumable both by humans
(markdown for provider abuse@ desks) and by machines (`--json`). pkg/sdk is
the only public API surface; everything else lives under `internal/`. If the
JSON shape were an ad-hoc internal struct, every external consumer (scripts,
future integrations) would depend on an unversioned, unstable contract.

## Decision

The report payload is a dedicated `AbuseReport` type in `pkg/sdk` carrying an
explicit `schema_version` field (currently 1). Rules:

- Changes are additive only: new fields must be `omitempty`; existing field
  names and semantics never change within a version. Breaking changes bump
  `AbuseReportSchemaVersion`.
- All timestamps are RFC 3339 UTC strings (matching the store's storage
  format and the existing `events` verb), not `time.Time`, so the wire format
  is explicit and locale-free.
- The type is transport-agnostic: today it is served by the daemon's
  read-only `report` socket verb and printed by `ezyshield report --json`;
  any future exporter reuses the same schema.
- Raw log lines are not part of the schema's persisted sources — evidence,
  when added, is extracted on demand from the original log files and included
  as an additive field.

## Consequences

- External consumers can pin `schema_version == 1` and rely on the shape
- Wire types duplicate a few fields of `sdk.Verdict` (`AbuseReportVerdict`)
  instead of reusing it — deliberate, so internal refactors of `Verdict`
  (netip/duration representations) cannot silently break the public JSON
- Report content (reasons, categories) may embed hostile log content;
  terminal renderers must sanitize — the schema documents this obligation

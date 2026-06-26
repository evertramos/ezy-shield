# ADR-0002: Cloudflare edge enforcement — IP Access Rules → Rulesets → Lists

**Status:** Superseded (default changed to Lists)  
**Date:** 2026-06-20 (updated 2026-06-24)

## Context

We need to block IPs at the Cloudflare edge. The legacy approach — one IP Access Rule per ban — creates many API calls and hits rate/plan limits quickly. We need atomic bulk updates that work within free-plan constraints.

## Decision (Phase 2 — original)

We used the Rulesets API with a single WAF Custom Rule (`ip.src in {...}`) instead of individual IP Access Rules.

## Decision (Phase 2.1 — current default)

We now default to **Custom IP Lists** (`mode: lists`). A single account-level list holds all blocked IPs; WAF Custom Rules in each zone reference that list. The Rulesets mode remains available as `mode: rulesets`.

### Why Lists over Rulesets

| | Rulesets | Lists (new default) |
|---|---|---|
| API calls per ban | 1 per zone | **1 total** (account-level) |
| IP capacity | ~200 (expression size limit) | **10,000** |
| Multi-zone propagation | manual per zone | automatic |
| Free plan | ✅ | ✅ (1 list, 10k items) |

## Consequences

- One API call adds/removes IPs for all zones at once
- 10k IP limit covers most use cases without rotation
- User must create the WAF rule referencing the list once per zone (or `ezyshield init` will do it in the future)
- Rulesets mode kept for users who need per-zone control or can't use account-level tokens
- Config: `enforce.cloudflare.mode: lists` (default) or `enforce.cloudflare.mode: rulesets`

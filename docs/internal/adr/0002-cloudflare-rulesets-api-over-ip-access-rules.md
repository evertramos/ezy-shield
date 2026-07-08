# ADR-0002: Cloudflare edge enforcement — IP Access Rules → Rulesets → Lists

**Status:** Implemented (auto WAF rule creation for Lists mode)  
**Date:** 2026-06-20 (updated 2026-07-08)

## Context

We need to block IPs at the Cloudflare edge. The legacy approach — one IP Access Rule per ban — creates many API calls and hits rate/plan limits quickly. We need atomic bulk updates that work within free-plan constraints.

## Decision (Phase 2 — original)

We used the Rulesets API with a single WAF Custom Rule (`ip.src in {...}`) instead of individual IP Access Rules.

## Decision (Phase 2.1 — current default)

We default to **Custom IP Lists** (`mode: lists`). A single account-level list holds all blocked IPs; WAF Custom Rules in each zone reference that list. The Rulesets mode remains available as `mode: rulesets`.

### Phase 2.2 — WAF rule auto-creation (implemented)

When `zone_ids` is configured in lists mode, ezyshield now **automatically manages WAF Custom Rules per zone**, eliminating the manual step. The list is still managed at account level (1 API call per ban), but each zone's WAF rule is created/updated on first Sync.

### Why Lists over Rulesets

| | Rulesets | Lists (current) |
|---|---|---|
| API calls per ban | 1 per zone | **1 total** (account-level) |
| IP capacity | ~200 (expression size limit) | **10,000** |
| Multi-zone propagation | manual per zone | **automatic** |
| WAF rules | manual per zone | **auto-managed** per zone |
| Free plan | ✅ | ✅ (1 list, 10k items) |

## Consequences

- One API call adds/removes IPs for all zones at once
- 10k IP limit covers most use cases without rotation
- WAF rules are auto-created and managed per zone when `zone_ids` is set
- Rulesets mode kept for users who need per-zone control or can't use account-level tokens
- Config: `enforce.cloudflare.mode: lists` (default) or `enforce.cloudflare.mode: rulesets`; optional `zone_ids` for auto-WAF-rule creation
- Token scoping: Account:Account Filter Lists:Edit + Zone:Firewall Services:Edit (for auto-rule creation)

# ADR-0001: nftables over iptables

**Status:** Accepted  
**Date:** 2026-06-20

## Context

We need a local firewall backend to enforce IP bans. iptables is deprecated — it's been a wrapper over nftables since 2021, and RHEL 9 removed it entirely. We need native set support for managing thousands of banned IPs efficiently.

## Decision

We chose nftables as EzyShield's local firewall backend.

## Consequences

- Native sets with per-element timeout give us auto-expiry without cron jobs
- O(1) hash lookup scales to thousands of IPs; atomic transactions prevent partial-apply bugs
- A single `inet` table handles both IPv4 and IPv6, simplifying our ruleset

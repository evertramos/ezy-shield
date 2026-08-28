---
title: Verified Bots
description: Protecting legitimate crawlers with forward-confirmed reverse DNS
order: 11
---

# Verified-Bot Protection

Anti-lockout protects *you*; nothing yet protected legitimate crawlers from an over-eager rule. Banning Googlebot is one of the most damaging false positives a site owner can suffer — search visibility quietly degrades while every dashboard stays green. This feature spares well-known bots from bans, safely.

## Why User-Agent alone is never trusted

Anyone can send `User-Agent: Googlebot/2.1` — attackers routinely do, precisely because naive setups allowlist it. A UA claim on its own is worthless.

The industry-standard check (documented by Google, Microsoft, and Apple as *the* verification mechanism) is **forward-confirmed reverse DNS** (FCrDNS):

1. **PTR lookup** on the connecting IP → e.g. `crawl-66-249-66-1.googlebot.com`.
2. **Domain check**: the name must fall under the provider's published domains (`googlebot.com`, `google.com`) — dot-anchored, so `evilgooglebot.com` never matches.
3. **Forward confirmation**: resolve that name back and require it to map to the **same IP**.

Only an IP passing both directions is treated as the bot it claims to be. A spoofer fails step 2 or 3 and proceeds down the normal ban path — claiming to be Googlebot changes nothing for it.

## Enabling

```yaml
# /etc/ezyshield/config.yaml
verified_bots:
  enabled: true
```

Covered by default: **Googlebot, Bingbot (msnbot), Applebot, YandexBot, Baiduspider, DuckDuckBot.**

## How it fits the decision pipeline

- The check runs **only at decision time for ban candidates** — never in the hot parse path. No bot claim in the IP's observed traffic → no DNS at all.
- Ordering: allowlist and anti-lockout still run first and always win. The bot guard can only convert a would-be ban into an audited `record` (`verified-bot spared: googlebot` in the audit log) — it can never cause or escalate a ban.
- DNS is bounded: 2s timeout per lookup, capped answer counts, responses treated as untrusted input. Results are cached (6h positive, 15min negative), so a busy crawler costs one lookup pair every few hours.
- **Fails closed**: a DNS timeout or any anomaly means the claim is simply ignored — the normal ban path proceeds. An unreachable resolver can never turn into a ban exemption.

## Adding your own provider

Uptime monitors and other legitimate probes can be added if their operator publishes stable rDNS:

```yaml
verified_bots:
  enabled: true
  providers:
    - name: mymonitor
      ua_contains: [MyMonitor]          # case-insensitive substrings
      domains: [monitor.example.com]    # PTR must fall under this suffix
```

Entries are merged with the built-ins by `name` — reusing a built-in name replaces that entry. Only add providers whose rDNS you can rely on; a provider whose PTR records don't confirm gains nothing (and loses nothing — its traffic is just judged like everyone else's).

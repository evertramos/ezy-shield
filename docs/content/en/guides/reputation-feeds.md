---
title: Reputation Feeds
description: Use public IP blocklists as an extra signal or block source
order: 13
---

# Reputation Feeds

## What they are

Public IP reputation feeds (Spamhaus DROP, FireHOL, AbuseIPDB exports) list
addresses observed attacking *other people's* servers. EzyShield can pull
them in as an extra signal — or drop them outright at the firewall — while
keeping them strictly separated from everything your own server observed.

```yaml
# /etc/ezyshield/config.yaml
feeds:
  - name: spamhaus-drop
    url: https://www.spamhaus.org/drop/drop.txt
    format: cidr
    refresh_interval: 12h
    action: observe            # or: block
```

Formats: `plain` (one IP per line), `cidr` (IP or prefix per line, `;`/`#`
comments — Spamhaus DROP and FireHOL), `abuseipdb` (plain list export).
Respect each feed's usage policy — the annotated example in
`configs/config.yaml` carries per-feed notes (Spamhaus asks for at most two
fetches a day; AbuseIPDB exports require an account).

## observe vs block

- **`action: observe`** (default): entries live only in the daemon's
  memory as a *reputation flag*. When an IP from a feed **also** trips
  your local rules, its score gets a +15 boost and the verdict reason
  carries `[reputation:<feed>]`. A feed alone never creates a verdict,
  a strike, or a ban — someone else's report is corroboration, not proof.
- **`action: block`**: entries are additionally dropped at the edge of
  the ezyshield nftables table, in a **dedicated set**.

## Set separation — feeds are not bans

Feed entries never touch the strike ladder, never appear in
`ezyshield list`, and never write rows to the ban store. They live in
their own nftables sets (`blocked_feeds` / `blocked_feeds6`), reconciled
wholesale on every refresh with a per-element timeout (default 2× the
refresh interval — a dead feed drains on its own instead of blocking
forever). Your strike history stays purely behavioral: what *your* server
observed, with evidence.

Each refresh writes one audit-log summary row (`feed_refresh`: entries,
skipped-by-guardrails, removed) — never one row per IP.

## Why feeds can never bypass the allowlist

A feed is remote data that somebody else controls — treat it as
potentially poisoned. EzyShield defends in layers:

1. **At parse time** (per fetch): only strict IP/CIDR parsing; private,
   loopback, link-local and reserved ranges are always dropped; 10MiB /
   4KiB / entry-count caps; https-only including redirects; a failed or
   garbage refresh keeps the last known-good set.
2. **Before any apply**: every entry is filtered against your allowlist
   and admin CIDRs, your live SSH peers, and shared CDN ranges — in both
   overlap directions, so a broad prefix covering your admin host is
   dropped just like the host itself.
3. **In the firewall**: the allowlist accept rules sit *before* the feed
   drop rules in every chain.
4. `armed: false` (dry-run) writes nothing to the firewall.

## Operating

```bash
ezyshield feeds status        # per feed: last/next refresh, entries, skipped
ezyshield feeds refresh       # re-fetch every feed now
ezyshield feeds refresh spamhaus-drop
```

A non-zero "skipped" count means the guardrails filtered entries — on a
reputable feed that is unusual and worth a look (it is also logged as a
possible-poisoning warning).

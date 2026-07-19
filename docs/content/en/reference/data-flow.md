---
title: Data Flow Reference
description: Every outbound connection — when, where, what is sent, and how to run fully local
order: 5
---

# Data Flow Reference

Trusting a root-capable security daemon means knowing exactly what it sends,
where, and when. This page lists **every outbound connection EzyShield can
make**, what each payload contains, and the exact configuration for running
with **zero outbound traffic**.

Two facts frame everything below:

- **The core pipeline is fully local.** Collectors, parsers, the rule engine,
  the decision engine, nftables enforcement, the SQLite store, and the audit
  trail all run offline. No feature requires an account, an enrollment, or a
  connection to any EzyShield-operated service — none exists.
- **There is no telemetry.** No usage analytics, no crash reporting, no
  update pings from the daemon. Every connection listed here is either
  something **you configured** or a command **you ran**.

Each claim on this page is verifiable in the source; the last section maps
every connection to the file that implements it.

## Daemon runtime connections (all opt-in)

These only happen while the daemon runs, and only if you enabled the feature.

| Connection | Destination | Trigger | What is sent | How to disable |
|---|---|---|---|---|
| AI verdicts (Anthropic) | `api.anthropic.com` (fixed) | An aggregate scores in the ambiguous band — obvious cases never leave the rule engine | Per-IP summary only: attacker IP, time window, event counts by kind, and GeoIP/ASN metadata if configured. **Raw log lines are excluded by design** — no usernames, paths, or user agents. API key travels in the `x-api-key` header only | Omit the `ai:` section |
| AI verdicts (OpenAI) | `api.openai.com` (fixed) | Same as above | Same payload shape; key in the `Authorization` header | Omit the `ai:` section |
| AI verdicts (Ollama) | `http://localhost:11434` by default — leaves the machine only if you point `endpoint` at a remote host | Same as above | Same payload shape; no API key | Omit the `ai:` section |
| Cloudflare edge enforcement | `api.cloudflare.com` | A real ban/unban while **armed**, plus periodic reconcile (`Sync`). In dry-run (`armed: false`) no enforcer call is made at all | The banned IP address and a fixed `ezyshield` comment tag. **No domains, no rule names, no log content.** Account ID in the URL, token in the header | Don't configure the `cloudflare` enforcer |
| GeoIP/ASN database updates | `download.maxmind.com` | Only when a MaxMind license key is configured: at startup if a database file is missing, then weekly | The license key and the edition name (`GeoLite2-Country` / `GeoLite2-ASN`) as request parameters — nothing about your server or traffic. **Lookups themselves are local** (`.mmdb` files on disk) | Don't configure a license key (skip `ezyshield config enrich maxmind`) |
| Notifications — Telegram | `api.telegram.org` | A notifiable event (ban, critical error), per your `notify:` config, after dedup/rate limiting | Structured alert fields: severity, title, a short summary, and the triggering action (operation, IP, reason, TTL). Length-capped and escaped; **no raw log lines** | Omit the notifier |
| Notifications — Slack / Discord / webhook | The webhook URL **you** configure | Same | Same fields as JSON | Omit the notifier |
| Notifications — e-mail | The SMTP server **you** configure | Same | Same fields as a MIME message | Omit the notifier |

Every outbound request uses HTTPS with certificate verification (Ollama and
SMTP go where you point them), carries a timeout, and honors shutdown
cancellation. A failed AI call falls back to the rule engine; a failed
notification or database update is logged and retried later — the detection
pipeline never blocks on the network.

## Command-time connections (only while you run them)

These happen interactively, never from the daemon:

- **`ezyshield update`** — contacts `api.github.com` and downloads from
  `github.com` (plain GET requests; release checksums are verified before
  install). The daemon **never checks for updates on its own**. Air-gapped
  hosts can point `EZYSHIELD_UPDATE_URL` at an internal mirror — or simply
  never run the command and update via your own package mirror.
- **`ezyshield init`** — asks `https://ifconfig.me` for your server's public
  IP (to suggest allowlist entries); may install `nftables` through your
  system package manager if missing; and, only if you choose Cloudflare,
  verifies the token and sets up the list/WAF rule against
  `api.cloudflare.com`.
- **`ezyshield config enforcer cloudflare` / `ezyshield test enforce
  cloudflare`** — token verification and connectivity checks against
  `api.cloudflare.com`.

## What never leaves the machine

- **Raw log lines.** They are parsed locally and stored locally. The one
  place they travel at all is into your own terminal or report file: evidence
  extraction (`ezyshield report`) reads journald via a local `journalctl`
  invocation and Docker logs via the local Engine socket
  (`/var/run/docker.sock`). Sending an abuse report anywhere is a manual
  action you take with the generated file.
- **Your identity and your users'.** Hostnames, site domains, usernames,
  request paths, and user agents appear in **no** outbound payload. The AI
  providers receive counters; Cloudflare receives attacker IPs.
- **Secrets.** Each credential is sent only to its own service, as that
  service's auth mechanism. Secrets never appear in payload bodies, logs, or
  error messages — CI gates enforce this
  (`internal/ai/secret_leak_test.go`, `internal/config/secret_leak_test.go`).
- **The store.** The SQLite database, strike history, and append-only audit
  trail are local files. Nothing syncs them anywhere.
- **Telemetry.** There is none — no analytics, no phone-home, no
  crash reporting, no version pings.

Note the honest fine print: any outbound request implies a DNS lookup of
that destination through your system resolver, and the attacker IPs you ban
are visible to Cloudflare if you enable edge enforcement — that is the
feature working as described.

## Local-only surfaces

For completeness, the interfaces that exist but never accept or make network
connections beyond the host:

- **Control plane** — a unix socket (`0660`), no TCP listener.
- **Dashboard** — binds `127.0.0.1` only and serves embedded assets; no CDN
  scripts or fonts are fetched by its pages.
- **Collectors** — file tails, `journalctl` (local process), and the Docker
  Engine unix socket.
- **CDN range data and detection rules** — embedded in the binary at build
  time, not fetched at runtime.

## Running fully local (zero outbound)

The configuration below produces a daemon that makes **no network connection
whatsoever** beyond delivering packets to its own firewall:

- **AI**: omit the `ai:` section entirely — or run
  [Ollama](https://ollama.com) on the same host (`endpoint:
  http://localhost:11434`) for AI verdicts without leaving the machine.
- **Enforcement**: configure only the `nftables` enforcer (skip
  `cloudflare`). All blocking happens in the local firewall.
- **Enrichment**: don't configure a MaxMind license key. Decisions work
  without GeoIP; you lose country/ASN context in reports and AI payloads.
- **Notifications**: omit `notify:` (or point e-mail at a local relay and
  accept that hop).
- **Updates**: install from the signed packages via your own mirror and never
  run `ezyshield update`, or set `EZYSHIELD_UPDATE_URL` to an internal
  mirror.

What you give up, honestly: edge blocking (attackers reach your firewall
before being dropped — they are still dropped), AI second opinions (the
deterministic rule engine is the primary detector and keeps working
unchanged), GeoIP/ASN context, push notifications, and one-command updates.
Detection quality, the strike ladder, anti-lockout, and the audit trail are
unaffected.

## Verify it yourself

Every connection above maps to one implementation file:

| Connection | Source |
|---|---|
| Anthropic | `internal/ai/anthropic.go` (payload sanitization documented at the `aggregatePayload` type) |
| OpenAI | `internal/ai/openai.go` |
| Ollama | `internal/ai/ollama.go` |
| Cloudflare enforcer | `internal/enforce/cloudflare.go`, `internal/enforce/cloudflare_lists.go` |
| MaxMind updater | `internal/enrich/updater.go` |
| Telegram / Slack / Discord / webhook / e-mail | `internal/notify/` |
| `ezyshield update` | `internal/update/client.go`, `cmd/ezyshield/update.go` |
| `init` public-IP lookup | `cmd/ezyshield/init.go` |
| Cloudflare wizard/test calls | `cmd/ezyshield/init_cdn.go`, `cmd/ezyshield/testenforce.go` |
| Local evidence extraction | `internal/daemon/evidence_ondemand.go` |

A quick audit that the list is complete:

```bash
grep -rn "https://" --include="*.go" internal/ cmd/ | grep -v _test
```

If a future release adds an outbound connection, this page must change in the
same pull request — treat any drift as a bug and report it.

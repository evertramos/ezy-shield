# Production testing status

What has actually been exercised on the live dogfood fleet versus what is
only unit/integration-tested and still needs a real production run. The
fleet: **kylian** and **ant** (x86_64), **unaids** (x86_64), **oci1**
(aarch64 / ARM) — all on `v0.2.1-rc.x`.

Legend: ✅ validated on live servers · 🔶 partial / in progress · ⬜ not yet
exercised in production (unit/integration-tested only).

## Detection & decision

| Area | Status | Notes |
|------|:------:|-------|
| SSH brute-force detection → ban | ✅ | Firing on real attackers on all hosts. |
| Low-and-slow SSH daily/weekly tiers | ✅ | Paced attackers caught by the persistent counters. |
| HTTP scanner / wp-probe detection → ban | ✅ | Seen on the reverse-proxied hosts. |
| Strike ladder escalation | ✅ | 5m → 1h → 24h → 7d → permanent observed. |
| Consumed-evidence watermark (#636) | ✅ | Re-strikes cite only NEW events under persistent attack. |
| Anti-lockout: active SSH peer immunity | ✅ | Refusals logged, then the deferred re-check bans. |
| Verified-bot sparing | ⬜ | No confirmed live spare yet. |
| AI second-layer (ambiguous band) | 🔶 | Runs where an AI key is configured; not systematically verified. |
| GeoIP / MaxMind enrichment | ⬜ | Not exercised in production. |

## Enforcement

| Area | Status | Notes |
|------|:------:|-------|
| Local nftables enforcement | ✅ | `store == kernel` exact on all four hosts. |
| ARM (aarch64) parity | ✅ | oci1 detects and enforces identically to x86. |
| Per-IP aggregator memory bound (#622) | ✅ | Memory plateaus below the old peak, x86 and ARM. |
| Cloudflare Lists edge enforcement | ✅ | kylian (~2.5k items); push/retry + stale-mirror rebuild seen. |
| Bunny edge enforcer | ⬜ | Code + unit tests only. |
| AWS WAF edge enforcer | ⬜ | Code + unit tests only. |
| Proxy/CDN-fronted HTTP bans | 🔶 | Local ban is ineffective behind a CDN (documented, #659) — edge enforcement required. |

## Notifiers

| Channel | Status | Notes |
|---------|:------:|-------|
| Telegram | 🔶 | Token resolves from `.env` (#665) and the host is stamped (#668); end-to-end delivery being confirmed. |
| Email | ⬜ | Not exercised in production. |
| Slack | ⬜ | Not exercised in production. |
| Discord | ⬜ | Not exercised in production. |
| Webhook | ⬜ | Not exercised in production. |
| Hostname on every alert (#668) | 🔶 | Confirming the source host shows for a multi-server fleet on one chat. |

## Diagnostics & CLI

| Area | Status | Notes |
|------|:------:|-------|
| `doctor` health checks | ✅ | Run across the fleet. |
| `ban_ineffective` diagnostic | ✅ | In-grace (benign) and post-grace (real leak) both observed. |
| `doctor` in-grace no longer false-FAILs (#657) | 🔶 | In the rc; confirm on the fleet. |
| Config wizard (`config notifier`) | ✅ | Works after the cloudflare-omitempty fix (#663). |
| `test`/`validate` resolve `.env` secrets (#665) | 🔶 | In the rc; confirm on the fleet. |
| `man ezyshield` top-level page (#653) | 🔶 | In the rc; confirm the packaged man page. |
| apt install / upgrade flow | ✅ | Including the ARM host. |

## Integrations & platform

| Area | Status | Notes |
|------|:------:|-------|
| Docker log collection (containers) | ✅ | Reverse-proxy access logs drive HTTP detection. |
| SIEM forwarding | ⬜ | Not exercised in production. |
| Reputation feeds | ⬜ | Not exercised in production. |
| Dashboard (localhost) + remote access | ⬜ | Not exercised in production. |
| Tier-1 plugins | ⬜ | Not exercised in production. |
| Mail-server parsers (postfix/dovecot) | ⬜ | Not exercised in production. |
| App tripwires (Nextcloud / Vaultwarden / Keycloak) | ⬜ | Not exercised in production. |
| Webshell tripwire | ⬜ | Not exercised in production. |
| Migrate from fail2ban | ⬜ | Not exercised in production. |

## Notes
- "Validated on live servers" means observed working against real traffic on
  the dogfood fleet, not merely covered by unit or e2e tests.
- Keep this current as channels and integrations are exercised in production.

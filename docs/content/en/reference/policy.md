---
title: Policy Reference
description: Complete policy.yaml field reference
order: 3
---

# Policy Reference

Complete reference for `/etc/ezyshield/policy.yaml` — decision thresholds, strike escalation, safety limits, and enforcement mode. Every field below exists in the current release; the file is strictly validated (unknown keys are rejected).

## Full example (all fields, defaults shown)

```yaml
# Dry-run by default: nothing is blocked until you set armed: true.
armed: false

# Score thresholds (rule engine + AI produce a score 0-100)
ban_threshold:     70   # score >= this triggers a strike
observe_threshold: 40   # score in [observe, ban) -> log/notify only

# Strike escalation: ban TTL per cumulative strike count.
# TTL of 0 means permanent ban.
strikes:
  - ttl: 5m     # strike 1
  - ttl: 1h     # strike 2
  - ttl: 24h    # strike 3
  - ttl: 168h   # strike 4 (7 days)
  - ttl: 0      # strike 5 — permanent

# Global safety cap: maximum ban actions per minute.
max_bans_per_minute: 30

# Escalations (strike > 1) skip the cap only when the previous ban ended
# within this window. Default 24h; values above 168h are clamped down.
escalation_exempt_window: 24h

# ban_ineffective diagnostic: fires when a banned IP keeps producing log
# events (enforcement anomaly — e.g. a CDN in front of the server).
# Both values are floors: policy may raise them, never lower them.
ban_ineffective_grace: 90s
ban_ineffective_min_events: 3

# IPs/CIDRs that can NEVER be banned. Allowlist wins over everything.
allowlist: []

# Admin CIDRs merged into the runtime allowlist at startup and before each ban.
admin_cidrs: []

# Geo blocking (optional; requires GeoIP enrichment — silently skipped
# without it). Matching traffic gets a large score boost, not an instant ban.
block_countries: []   # ISO 3166-1 alpha-2, e.g. [CN, RU]
block_asns: []        # e.g. [AS16276, AS14061]
```

Every value above is the loader default, with one exception: `observe_threshold`
has **no** default — `applyDefaults` leaves it untouched, so omitting it yields
`0` (notify on any score below `ban_threshold`). The `40` shown here mirrors the
shipped `configs/policy.yaml` as a sensible starting point; see the
[Thresholds](#thresholds) table below.

## armed

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `armed` | bool | `false` | `true` = enforce bans; `false` = dry-run: the full pipeline runs and records `dry_ban` decisions, but no enforcer is called, so nothing is actually blocked |

Dry-run is the default on purpose — run it until `ezyshield doctor` is clean and the decisions in the log look right.

Dry-run still **records** (ADR-0009 §5): each `dry_ban` writes the strike, a
simulated ban row (`dry_run=1`) in `bans_active`, and an audit entry through the
same `RecordStrike` path as a real ban, and it suppresses follow-up events from
that IP just like a real ban. Only the enforcer call is skipped. Because strikes
are cumulative and persist, an IP that re-offends after you set `armed: true`
can start higher on the ladder than a fresh offender — the dry-run history
counts.

## Thresholds

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ban_threshold` | int (1–100) | 70 | Score at or above this triggers a strike/ban |
| `observe_threshold` | int (0–ban_threshold) | 0 | Score in `[observe_threshold, ban_threshold)` produces a notification but no strike; below it, the event is only recorded |

Scores come from the rule engine (see `configs/rules.yaml`) and, for ambiguous cases, the optional AI provider — whose verdict is advisory and always clamped by this policy.

## strikes

Escalation table indexed by the IP's cumulative strike count; the count past the end of the table clamps to the last entry.

| Field | Type | Description |
|-------|------|-------------|
| `strikes[].ttl` | duration or `0` | Ban duration for that strike. `0` = permanent |

Default ladder: `5m → 1h → 24h → 168h → permanent`.

Semantics (one episode = one strike): while a ban is active, new events from that IP never add strikes — they are suppressed and counted. The ladder advances only when the IP re-offends **after** a ban expires. Runaway escalation from a single burst is structurally impossible.

## Rate limiting

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_bans_per_minute` | int (>0) | 30 | Global cap on ban actions per minute. Exceeding it returns an error instead of silently dropping the limit — a poisoned feed or parser bug cannot ban the internet |
| `escalation_exempt_window` | duration | `24h` (max `168h`) | An escalation (strike > 1) skips the cap only when the previous ban **ended within this window** — re-blocking an IP that was blocked moments ago adds no lockout risk. Anything older counts against the cap like a fresh ban. Values above 7d are clamped down |

## ban_ineffective diagnostic

In a healthy armed setup, a banned IP cannot produce new log lines — packets die at the firewall. Log events mentioning a banned IP therefore signal an enforcement anomaly (CDN in front of the server, conntrack not flushed, v4/v6 mismatch). EzyShield emits a structured `ban_ineffective` WARN, once per ban, with ladder context.

| Field | Type | Floor/Default | Description |
|-------|------|---------------|-------------|
| `ban_ineffective_grace` | duration | 90s | Events within this window after a ban are counted but never trigger the diagnostic (in-flight requests, proxy buffering, log latency) |
| `ban_ineffective_min_events` | int | 3 | Suppressed events after the grace period needed to fire the WARN |

Both are floors: policy may raise them, never lower them. The diagnostic never escalates a ban — the remedy it points to is edge enforcement or real-IP parsing, not harsher sentencing.

## allowlist & admin_cidrs

| Field | Type | Description |
|-------|------|-------------|
| `allowlist` | list of IP/CIDR | Never banned, checked **first**, unbypassable — wins over rules, AI, and geo blocking |
| `admin_cidrs` | list of CIDR | Merged into the runtime allowlist at startup and re-checked before every ban (anti-lockout) |

The active SSH peer is additionally re-derived before every ban and can never be banned.

```yaml
allowlist:
  - 192.0.2.0/24          # your office
  - 198.51.100.7          # a specific host
admin_cidrs:
  - 10.0.0.0/8
```

Because an allowlisted range can **never** be banned, keep entries as narrow
as the traffic you actually need to exempt — a broad private range silently
removes enforcement from everything inside it, permanently.

### Docker hosts

When `ezyshield init` detects Docker, it allowlists only the bridge network
subnets that actually exist on the host (enumerated via the Docker API/CLI),
never a blanket RFC1918 range. If enumeration fails, it falls back to
Docker's own default bridge subnet (`172.17.0.0/16`) alone — still never the
entire `172.16.0.0/12`. Hosts without Docker get no docker-related allowlist
entry at all.

The generated `policy.yaml` includes a commented-out example for adding a
broader internal range (VPN, office LAN, a multi-host docker overlay)
deliberately:

```yaml
# To allow a broader internal range (VPN, office LAN, a multi-host docker
# overlay) deliberately, uncomment and edit the line below.
# Trade-off: an allowlisted range can NEVER be banned (allowlist always wins
# over rules, AI, and geo blocking) — the broader the range, the more of your
# network permanently loses enforcement coverage.
# 'ezyshield doctor' warns if any private allowlist entry is /16 or broader.
#   - 10.0.0.0/8
```

`ezyshield doctor` warns (not fails) when the allowlist contains a private
(RFC1918/ULA) range at `/16` or broader, whatever put it there.

> **Upgrading from an older EzyShield?** `init` never rewrites an existing
> `policy.yaml`, so a config generated before this fix keeps its
> `172.16.0.0/12` entry unchanged. Review the `allowlist` section of your
> `policy.yaml` and narrow that entry to your real docker bridge subnet(s)
> (`docker network ls` / `docker network inspect`) — `ezyshield doctor` flags
> the old entry as a WARN to remind you.

## Geo blocking

| Field | Type | Description |
|-------|------|-------------|
| `block_countries` | list of ISO alpha-2 codes | Traffic from these countries gets a +100 score boost |
| `block_asns` | list of `AS<number>` | Same semantics per autonomous system |

Requires GeoIP enrichment to be active; silently skipped otherwise. The boost pushes traffic over `ban_threshold` — allowlist still wins, and a country/ASN match alone never bypasses the strike ladder.

## Validation

```bash
sudo ezyshield config validate   # strict schema + constraint check
sudo ezyshield doctor            # full environment check
```

Unknown keys fail validation, and genuinely out-of-range values are rejected
with the exact reason — e.g. `ban_threshold: 150` (must be in `[1, 100]`),
`observe_threshold` ≥ `ban_threshold`, or a negative `max_bans_per_minute`.

One subtlety: an **explicit `0`** for `ban_threshold` or `max_bans_per_minute`
is **not** rejected. Defaults are applied *before* the range check, so a `0`
(indistinguishable from an omitted field) is replaced by the default — `70` and
`30` respectively — and then passes. `observe_threshold` is the exception: it
has no default, so `0` stays `0`.

## anti_lockout (ADR-0013)

By default, any IP with an **ESTABLISHED** TCP connection to the sshd
port is immune to bans — the guarantee that you can never lock yourself
out. The kernel, however, cannot tell a *logged-in session* from a
*connection parked before authentication* (sshd's `Timeout before
authentication`), so an attacker holding sockets open borrows the same
immunity (the #559 incident).

```yaml
anti_lockout:
  require_authenticated: true   # default: false
```

With `require_authenticated: true`, immunity additionally requires an
**active systemd-logind session** for that IP — which covers both your
interactive shells and non-interactive automation (`ssh host 'cmd'`,
agents), since logind registers PAM sessions with or without a TTY. A
connection that never authenticates becomes bannable after a **10s
grace window** (covers the just-logged-in race).

Safety properties (the reason this is opt-in and safe to try):

- **Fail-open** — if `loginctl` is missing, errors, or times out, or a
  session's `RemoteHost` is a hostname (`UseDNS yes`), narrowing is
  disabled entirely and behavior reverts to ESTABLISHED-only. No logind
  failure can enable a ban today's code would refuse.
- `allowlist` / `admin_cidrs` are checked **before** any of this and
  remain your durable protection — put your fixed IPs there.
- Known limitation: an **idle** `ControlPersist` master (no open
  channel) has no logind session and loses immunity while idle; active
  work always has a channel. `ezyshield doctor` reports the effective
  mode and whether logind answers.

## SSH probe / aggressive tier

The SSH parser recognises far more line variants than it bans on. Every SSH
event carries one of four kinds:

| Kind | What it is | Counted by default rules? |
|------|------------|---------------------------|
| `ssh_invalid_user` | auth attempt against an invalid / unknown / not-allowed user | **yes** |
| `ssh_fail` | auth attempt against a valid / known user | **yes** |
| `ssh_probe` | connection/protocol anomaly or a corroborating termination/PAM echo (scanners, bare `Connection closed by <ip>`, `banner exchange` errors, `kex` resets, `pam_unix ... authentication failure`) | **no** |
| `ssh_accept` | successful login | never (telemetry only) |

Recognising a line never bans anyone — only a rule that *counts* its kind does.
The built-in `ssh_bruteforce` rules count only the two real-attempt kinds, so the
default posture has a near-zero false-positive rate.

To also ban scanners and malformed-handshake sources, enable the opt-in
aggressive rule shipped (commented) in `configs/rules.yaml`:

```yaml
rules:
  - name: ssh_probe_aggressive
    description: "SSH scanners / malformed connections"
    kinds: [ssh_probe]
    window: 60s
    threshold: 10
    score: 60
    category: scanner
```

> **Higher false-positive risk.** `ssh_probe` fires on bare connection churn,
> which a legitimate client behind CGNAT or a flaky network can also produce.
> Keep it off unless you understand your traffic, and always pair it with a
> correct `allowlist`. The specific line that matched is available in each
> event's `subtype` field for tuning.

`ssh_accept` is recorded for reporting but is **not** used to suppress strikes:
on a shared IP a successful login is not proof that other attempts from that IP
are benign. Operator anti-lockout belongs to the `allowlist` / a management
plane, not to "this IP logged in once".

---
title: Policy Reference
description: Complete policy.yaml field reference
order: 3
---

# Policy Reference

Complete reference for `/etc/ezyshield/policy.yaml`. Controls decision thresholds, strike escalation, and enforcement mode.

## Top level

```yaml
armed: false                  # Enable enforcement (default: dry-run)

thresholds:
  ssh_bruteforce: 70
  web_scanner: 60
  # ... more rule thresholds

strikes:
  - ttl: 5m
    ban_duration: 5m
  - ttl: 1h
    ban_duration: 1h
  - ttl: 24h
    ban_duration: 24h
  - ttl: 7d
    ban_duration: 7d
  - ttl: forever
    ban_duration: permanent

allowlist:
  cidrs: []
  asns: []

rate_limit:
  max_bans_per_minute: 30
```

## armed

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `armed` | bool | `false` | `true` = enforce bans; `false` = dry-run only |

## thresholds

Confidence scores (0–100) below which an attack is ignored.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ssh_bruteforce` | int | 70 | SSH login attempts |
| `web_scanner` | int | 60 | Port scanners, bot crawlers |
| `web_bruteforce` | int | 75 | WordPress/Drupal login attempts |
| `wordpress_xmlrpc` | int | 80 | WordPress XML-RPC abuse |

If AI is enabled and a decision is ambiguous (40–70), the AI provider is consulted.

## strikes

Escalation table: IPs accumulate strikes with TTLs.

```yaml
strikes:
  - ttl: 5m
    ban_duration: 5m
  - ttl: 1h
    ban_duration: 1h
  - ttl: 24h
    ban_duration: 24h
  - ttl: 7d
    ban_duration: 7d
  - ttl: forever
    ban_duration: permanent
```

- Strike #1 → 5 min ban (TTL 5 min: if no new hits, forget the strike)
- Strike #2 (within 1 hour of strike #1) → 1 hour ban
- Strike #3 (within 24 hours) → 24 hour ban
- Strike #4 (within 7 days) → 7 day ban
- Strike #5 (permanent TTL) → permanent ban

TTL = how long to remember a strike before forgetting it.
BAN_DURATION = how long to enforce the ban.

## allowlist

IPs/CIDRs/ASNs that are never banned, even if they match attack patterns.

```yaml
allowlist:
  cidrs:
    - 192.0.2.0/24          # Your office
    - 198.51.100.100/32     # A specific vendor
  asns:
    - 12345                 # ISP ASN
```

Allowlist is checked FIRST, before any rule engine decision. No way to bypass it.

## rate_limit

Safety cap to prevent runaway bans.

```yaml
rate_limit:
  max_bans_per_minute: 30
```

If the rule engine tries to ban more than 30 IPs in one minute, the excess bans are queued for the next minute. This prevents a misconfigured rule from banning the entire internet.

## Minimal example

```yaml
armed: false

thresholds:
  ssh_bruteforce: 70
  web_scanner: 60

strikes:
  - ttl: 5m
    ban_duration: 5m
  - ttl: 1h
    ban_duration: 1h
  - ttl: 24h
    ban_duration: 24h
  - ttl: 7d
    ban_duration: 7d
  - ttl: forever
    ban_duration: permanent

allowlist:
  cidrs:
    - 10.0.0.0/8            # Internal network

rate_limit:
  max_bans_per_minute: 30
```

## Validation

Validate your policy after editing:

```bash
sudo ezyshield doctor
```

## Common customizations

**Aggressive blocking (lower thresholds):**

```yaml
thresholds:
  ssh_bruteforce: 50
  web_scanner: 40
```

**Longer bans for repeat offenders:**

```yaml
strikes:
  - ttl: 1h
    ban_duration: 1h
  - ttl: 7d
    ban_duration: 7d
  - ttl: 30d
    ban_duration: 30d
  - ttl: forever
    ban_duration: permanent
```

**Whitelist a subnet (e.g., a CDN):**

```yaml
allowlist:
  cidrs:
    - 203.0.113.0/24
```

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

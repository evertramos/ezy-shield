---
title: Your First Run
description: Walk through your first watch session, understanding dry-run output, and arming EzyShield
order: 3
---

# Your First Run

After installation, you've configured EzyShield with at least one log source. Now let's run it for the first time and understand what it's doing.

## Step 1: Start in dry-run (default)

By default, EzyShield runs in **dry-run mode** — it analyzes logs and makes decisions, but never blocks anything. This is intentional: observe first, arm second.

Dry-run mirrors armed semantics exactly: a `dry_ban` records its strike and a
**simulated ban** with the same TTL a real ban would get, and further events
from that IP are suppressed until the simulated TTL expires — so the escalation
you observe (strike 1 → 2 → 3 …) is exactly what production would apply.
Nothing is ever enforced: simulated bans never reach the firewall, and
`ezyshield status` reports them separately from active bans.

```bash
sudo ezyshield run
```

The daemon logs structured JSON lines to stderr. A dry-run decision looks
like:

```json
{"time":"2026-07-08T10:15:30Z","level":"INFO","msg":"decision: dry_ban (armed=false)","ip":"203.0.113.42","would_strike":1,"would_ttl":300000000000}
```

Notice the `dry_ban` verdict — it would have blocked that IP, but in dry-run mode it only logs. `would_ttl` is in nanoseconds (slog's default duration encoding); `300000000000` is 5 minutes.

## Step 2: Read the dry-run output

Each verdict line tells you:
- **The attack**: ssh brute-force, WordPress login scraping, etc.
- **The attacker's IP**: 203.0.113.42
- **Strike count and score**: how many times this IP has attacked, and the confidence level
- **The action**: `dry_ban` (what would happen if armed), or `allow` (allowlist matched)
- Re-hits during a simulated ban show as `already_banned` — one episode, one strike, exactly like armed mode

Run for 24 hours in dry-run and monitor:
- False positives: legitimate IPs being scored high
- Coverage: which attack patterns are detected
- Noise: how many events per minute

## Step 3: Check audit trail

See what would have been blocked:

```bash
ezyshield report | head -30
```

Without an IP argument, `report` lists every recorded offender in a summary
table (`IP`, `FIRST SEEN`, `LAST SEEN`, `STRIKES`, `BANNED`, `COUNTRY`, `ASN`)
— nothing is actually blocked. For the full per-IP decision history (strikes,
scores, evidence), pass an IP:

```bash
ezyshield report 203.0.113.42
```

## Step 4: Arm it

Once you're confident, arm with the dedicated command — no config editing,
no restart:

```bash
sudo ezyshield arm
```

`arm` runs a mandatory pre-flight before flipping anything: enforcer
health, `admin_cidrs`/allowlist coverage, a "would I ban myself?" check for
your own SSH client IP, and a summary of recent dry-run activity. Failing
checks refuse the transition (`--force` overrides everything except the
self-ban check — that one is never bypassable).

The safest way to arm for the first time is with an auto-revert window:

```bash
sudo ezyshield arm --for 1h
```

For the next hour EzyShield enforces for real. If everything looks good,
make it permanent:

```bash
sudo ezyshield arm --keep
```

If you do nothing — or you locked yourself out and can't do anything —
the daemon reverts to dry-run by itself when the window expires and sends
a notification. The revert runs inside the daemon, so it fires even if
your SSH session is gone.

Both transitions are persisted to `policy.yaml` and recorded in the audit
log; `sudo ezyshield disarm` returns to dry-run at any moment.

Once armed, EzyShield blocks in real-time: bans go to nftables (local),
Cloudflare (edge), and notifications are sent.

## Step 5: Monitor active bans

```bash
ezyshield list           # active bans
ezyshield list --allow   # allowlist entries
ezyshield status
```

See what's banned, your allowlist, and the daemon's health.

## Troubleshooting

**Q: My legitimate traffic is being blocked**

A: Add it to the allowlist in `policy.yaml`:

```yaml
allowlist:
  - 198.51.100.0/24    # your office
  - 192.0.2.100        # a specific user
```

Apply the change with a restart:

```bash
sudo systemctl restart ezyshield
```

**Q: No events being detected**

A: Check that log sources are configured and that logs are actually being written:

```bash
sudo ezyshield doctor
tail -f /var/log/auth.log      # For SSH
tail -f /var/log/nginx/access.log  # For Nginx
```

**Q: I want to ban/unban manually**

A:

```bash
sudo ezyshield ban 203.0.113.42 --ttl 0  # ttl=0 = permanent (no expiry)
sudo ezyshield unban 203.0.113.42        # Unban
sudo ezyshield allow 198.51.100.0/24     # Allowlist a CIDR
```

## Next steps

- Read the [Config Reference](../reference/config.md) to tune thresholds
- Explore [Guides](../guides/cloudflare.md) for Cloudflare + nftables integration
- Check [Security](../security/overview.md) to understand the guarantees

---
title: Your First Run
description: Walk through your first watch session, understanding dry-run output, and arming EzyShield
order: 3
---

# Your First Run

After installation, you've configured EzyShield with at least one log source. Now let's run it for the first time and understand what it's doing.

## Step 1: Start in dry-run (default)

By default, EzyShield runs in **dry-run mode** — it analyzes logs and makes decisions, but never blocks anything. This is intentional: observe first, arm second.

```bash
sudo ezyshield watch
```

You'll see output like:

```
2026-07-08T10:15:23Z INFO starting pipeline
2026-07-08T10:15:24Z INFO collector[journald]: started
2026-07-08T10:15:24Z INFO collector[file]: tailing /var/log/nginx/access.log
2026-07-08T10:15:30Z WARN decision: ssh brute-force attempt from 203.0.113.42 (3 strikes, score 95)
  verdict: dry_ban (would ban for 5 minutes)
```

Notice the `dry_ban` verdict — it would have blocked that IP, but in dry-run mode it only logs.

## Step 2: Read the dry-run output

Each verdict line tells you:
- **The attack**: ssh brute-force, WordPress login scraping, etc.
- **The attacker's IP**: 203.0.113.42
- **Strike count and score**: how many times this IP has attacked, and the confidence level
- **The action**: `dry_ban` (what would happen if armed), or `allow` (allowlist matched)

Run for 24 hours in dry-run and monitor:
- False positives: legitimate IPs being scored high
- Coverage: which attack patterns are detected
- Noise: how many events per minute

## Step 3: Check audit trail

Query the audit log to see what would have been blocked:

```bash
ezyshield list --audit | head -20
```

This shows the full decision history without actually blocking.

## Step 4: Arm it

Once you're confident, edit `policy.yaml`:

```yaml
armed: true
```

Then reload the daemon:

```bash
sudo systemctl restart ezyshield
```

EzyShield now blocks in real-time: bans go to nftables (local), Cloudflare (edge), and notifications are sent.

## Step 5: Monitor active bans

```bash
ezyshield list --bans
ezyshield list --allowlist
ezyshield status
```

See what's banned, your allowlist, and the daemon's health.

## Troubleshooting

**Q: My legitimate traffic is being blocked**

A: Add it to the allowlist in `policy.yaml`:

```yaml
allowlist:
  cidrs:
    - 198.51.100.0/24    # Your office
    - 192.0.2.100/32     # Specific user
```

Reload:

```bash
sudo systemctl reload ezyshield
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
sudo ezyshield ban 203.0.113.42         # Ban permanently
sudo ezyshield unban 203.0.113.42       # Unban
sudo ezyshield allow 198.51.100.0/24    # Allowlist a CIDR
```

## Next steps

- Read the [Config Reference](../reference/config.md) to tune thresholds
- Explore [Guides](../guides/cloudflare.md) for Cloudflare + nftables integration
- Check [Security](../security/overview.md) to understand the guarantees

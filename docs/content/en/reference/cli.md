---
title: CLI Reference
description: All commands and flags
order: 4
---

# CLI Reference

Complete command reference for the `ezyshield` CLI.

## ezyshield init

Interactive setup wizard. Configures log sources, enforcement backends, AI providers, and notifications.

```bash
sudo ezyshield init
```

Creates `/etc/ezyshield/config.yaml` and `/etc/ezyshield/policy.yaml` with secure permissions (0600).

## ezyshield watch

Start the daemon in the foreground. Reads logs, makes decisions, enforces bans.

```bash
sudo ezyshield watch
```

Runs in dry-run mode by default (`armed: false` in policy.yaml).

## ezyshield status

Show daemon status: uptime, active bans, recent decisions.

```bash
ezyshield status

# JSON output
ezyshield status --json
```

Output:
- Daemon uptime
- Total IPs currently banned
- Total IPs allowlisted
- Decisions in last hour

## ezyshield list

Query the audit log and state.

```bash
# All audit entries (default: last 100)
ezyshield list --audit

# Active bans only
ezyshield list --bans

# Allowlisted IPs/CIDRs/ASNs
ezyshield list --allowlist

# JSON output
ezyshield list --audit --json

# Limit results
ezyshield list --audit --limit 50
```

Columns:
- Timestamp
- Action (ban/unban/allow)
- IP or CIDR
- Rule (ssh_bruteforce, web_scanner, etc.)
- Score
- Decision (dry_ban, ban, allow)

## ezyshield ban

Manually ban an IP or CIDR.

```bash
# Ban for default strike duration (5 min, 1h, 24h, 7d, permanent)
sudo ezyshield ban 203.0.113.42

# Ban permanently (shorthand)
sudo ezyshield ban --permanent 203.0.113.42

# Ban a subnet
sudo ezyshield ban 203.0.113.0/24
```

Manual bans bypass the allowlist — even allowlisted IPs can be manually banned.

## ezyshield unban

Remove an active ban.

```bash
sudo ezyshield unban 203.0.113.42

# Unban a subnet
sudo ezyshield unban 203.0.113.0/24
```

Does not delete audit history.

## ezyshield allow

Add an IP/CIDR/ASN to the allowlist.

```bash
# Add IP
sudo ezyshield allow 192.0.2.100

# Add CIDR
sudo ezyshield allow 192.0.2.0/24

# Add ASN (blocks all IPs from this ISP)
sudo ezyshield allow --asn 12345
```

Allowlist is checked first. No rule can ban an allowlisted IP.

## ezyshield doctor

Validate config, permissions, and log sources.

```bash
sudo ezyshield doctor
```

Checks:
- Config file syntax and permissions
- Log sources are readable
- Firewall setup (nftables table/set exist)
- AI provider connectivity (if configured)
- Notification channels (Telegram, Slack, etc.)

## ezyshield scan

Discover listening services on this host.

```bash
sudo ezyshield scan

# JSON output
sudo ezyshield scan --json
```

Lists all listening ports, protocols, and services. Used to identify what to log.

## ezyshield version

Show version info.

```bash
ezyshield version

# JSON output
ezyshield version --json
```

## ezyshield test-notify

Test notification channels without waiting for a real event.

```bash
sudo ezyshield test-notify telegram

# Test all channels
sudo ezyshield test-notify all
```

Sends a test message to each configured channel.

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (not all commands) |
| `--config` | Path to config.yaml (default: `/etc/ezyshield/config.yaml`) |
| `--policy` | Path to policy.yaml (default: `/etc/ezyshield/policy.yaml`) |
| `-h, --help` | Show help text |

## Examples

**Monitor daemon activity:**

```bash
watch ezyshield status
```

**Export audit log to JSON for analysis:**

```bash
ezyshield list --audit --json > audit.json
```

**Check if an IP is currently banned:**

```bash
ezyshield list --bans --json | jq '.[] | select(.ip == "203.0.113.42")'
```

**Permanently ban a botnet subnet:**

```bash
sudo ezyshield ban --permanent 203.0.113.0/24
```

**Add your office to allowlist:**

```bash
sudo ezyshield allow 192.0.2.0/24
```

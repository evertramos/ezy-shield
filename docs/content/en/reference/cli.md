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

## ezyshield config

Inspect and validate configuration.

### ezyshield config show

Render the effective configuration — after parsing, strict validation, and defaults — as YAML, or JSON with `--json`. Secret values never appear in the output: credential fields hold `env:VARNAME` references by design, and webhook header values (which may carry raw tokens) are shown as `<redacted>`.

```bash
ezyshield config show

# JSON output
ezyshield config show --json

# Non-default file locations
ezyshield config show --config ./config.yaml --policy ./policy.yaml
```

Exit codes: `0` rendered, `1` configuration invalid, `2` file not found / unreadable.

### ezyshield config validate

Validate `config.yaml` and `policy.yaml` without starting the daemon: strict YAML parsing, field constraints, strike-table monotonicity, allowlist CIDRs, and warnings for unreadable log paths or unset env vars.

```bash
ezyshield config validate

# Non-default file locations
ezyshield config validate --config ./config.yaml --policy ./policy.yaml
```

The top-level `ezyshield validate` is kept as an alias and behaves identically.

Exit codes: `0` valid (may have warnings), `1` errors found, `2` file not found / unreadable.

### ezyshield config enforcer <name>

Interactive wizard to add or reconfigure one enforcer on an existing installation — the same prompts and dry token validation the init wizard runs, without regenerating anything else.

```bash
sudo ezyshield config enforcer cloudflare
```

- The write is atomic (temp file + rename); the previous file is kept as `config.yaml.bak` and the merged configuration is re-validated before anything touches disk. Comments are not carried over — recover them from the `.bak` if needed.
- Secret tokens go to the `.env` file next to `config.yaml` (mode 0600), never into `config.yaml` itself (`api_token: env:CLOUDFLARE_API_TOKEN`).
- On success the command prints the changed keys and next steps (`config validate`, restart the daemon). If the wizard aborts, nothing is written.

Available names: `cloudflare`. The `notifier`, `ai`, and `collector` kinds follow the same pattern and are being added component by component.

Exit codes: `0` saved, `1` wizard aborted or write failed, `2` config.yaml not found (run `init` first).

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

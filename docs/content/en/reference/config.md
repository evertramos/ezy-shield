---
title: Config Reference
description: Complete config.yaml field reference
order: 2
---

# Config Reference

Complete reference for `/etc/ezyshield/config.yaml`. All paths are required unless marked optional.

## Top level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `data_dir` | string | Yes | SQLite database path (e.g., `/var/lib/ezyshield`) |
| `collectors` | list | Yes | Log sources to tail |
| `enforce` | object | Yes | Firewall enforcement backends |
| `notify` | object | No | Notification channels |
| `ai` | object | No | AI provider config (for ambiguous traffic) |

## collectors

Array of log sources. At least one required.

```yaml
collectors:
  - kind: journald
    unit: sshd
  - kind: file
    path: /var/log/nginx/access.log
```

### journald collector

| Field | Type | Description |
|-------|------|-------------|
| `kind` | "journald" | - |
| `unit` | string | systemd unit name (e.g., `sshd`, `docker`) |

### file collector

| Field | Type | Description |
|-------|------|-------------|
| `kind` | "file" | - |
| `path` | string | Absolute path to log file |

## enforce

At least one backend required.

```yaml
enforce:
  nftables:
    table: inet ezyshield
    set: blocked
  cloudflare:
    api_token: env:EZYSHIELD_CF_TOKEN
    zone_ids: [abc123, def456]
    action: block  # block | challenge | js_challenge
```

### nftables

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `table` | string | Yes | Table name (e.g., `inet ezyshield`) |
| `set` | string | Yes | Set name for blocked IPs (e.g., `blocked`) |

### cloudflare

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `api_token` | string | Yes | Token as `env:VAR_NAME` (never inline) |
| `zone_ids` | list | Yes | Cloudflare Zone IDs to update |
| `action` | string | Yes | `block` \| `challenge` \| `js_challenge` |

## notify (optional)

Send alerts when IPs are banned.

```yaml
notify:
  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_BOT_TOKEN
    chat_ids: ["-1001234567890"]
  email:
    smtp_host: smtp.example.com
    smtp_port: 587
    from: ezyshield@example.com
    to: [admin@example.com]
    password: env:EZYSHIELD_SMTP_PASSWORD
  slack:
    webhook_url: env:EZYSHIELD_SLACK_WEBHOOK
  discord:
    webhook_url: env:EZYSHIELD_DISCORD_WEBHOOK
  webhook:
    url: https://example.com/webhooks/ezyshield
    headers:
      Authorization: "Bearer env:EZYSHIELD_WEBHOOK_TOKEN"
```

All secret fields use `env:VAR_NAME` syntax — never hardcode credentials.

## ai (optional)

Enable AI scoring for ambiguous events.

```yaml
ai:
  provider: anthropic
  model: claude-3-5-sonnet-20241022
  api_key: env:ANTHROPIC_API_KEY
  cache_verdicts: true
  token_budget: 100000
```

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | `anthropic` \| `openai` \| `ollama` |
| `model` | string | Model name (varies by provider) |
| `api_key` | string | Token as `env:VAR_NAME` |
| `cache_verdicts` | bool | Cache AI decisions (default: true) |
| `token_budget` | int | Tokens per hour before AI is bypassed |

## Minimal example

```yaml
data_dir: /var/lib/ezyshield

collectors:
  - kind: journald
    unit: sshd
  - kind: file
    path: /var/log/nginx/access.log

enforce:
  nftables:
    table: inet ezyshield
    set: blocked
```

## Environment variables

All secrets use `env:VAR_NAME` syntax:

- `EZYSHIELD_CF_TOKEN` — Cloudflare API token
- `ANTHROPIC_API_KEY` — Anthropic API key
- `EZYSHIELD_TELEGRAM_BOT_TOKEN` — Telegram bot token
- `EZYSHIELD_SLACK_WEBHOOK` — Slack webhook URL
- `EZYSHIELD_DISCORD_WEBHOOK` — Discord webhook URL
- `EZYSHIELD_SMTP_PASSWORD` — SMTP password

Load via systemd `LoadCredential=` or shell export before `ezyshield watch`.

## Validation

Validate your config after editing:

```bash
sudo ezyshield doctor
```

This checks file permissions, AI connectivity, and log source readability.

---
title: Config Reference
description: Complete config.yaml field reference
order: 2
---

# Config Reference

Complete reference for `/etc/ezyshield/config.yaml` — log sources, enforcement backends, notifications, AI, enrichment, and the dashboard. The file is strictly validated: unknown keys are rejected with exact line numbers.

> `ezyshield init` and the `ezyshield config <component>` wizards write to `/etc/ezyshield` and must run with `sudo` — they fail fast with a hint before asking any question. Validate any manual edit with `ezyshield config validate`.

## Top level

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `data_dir` | string | `/var/lib/ezyshield` | State directory; the SQLite database lives at `<data_dir>/ezyshield.db` |
| `socket_path` | string | `/run/ezyshield/ezyshield.sock` | Daemon control socket (unix socket — there is never a TCP listener for control) |
| `rules_path` | string | — | Optional path to a custom `rules.yaml` (defaults to the rules embedded in the binary) |
| `log.level` | string | `info` | `debug` \| `info` \| `warn` \| `error` |
| `collectors` | list | `[]` | Log sources to tail (see below) |
| `enforce` | object | — | Enforcement backends (optional — without it, decisions are log-only) |
| `notify` | object | — | Notification channels (optional) |
| `ai` | object | — | AI provider for ambiguous traffic (optional) |
| `enrich` | object | — | GeoIP/ASN enrichment (optional) |
| `dashboard` | object | — | Dashboard bind address and auth DB (optional) |

## collectors

Each entry tails one log source. `kind` selects the source; one extra field is required per kind.

```yaml
collectors:
  - kind: journald
    unit: ssh                    # systemd unit to follow

  - kind: file
    path: /var/log/nginx/access.log

  - kind: docker
    container: wordpress-nginx   # name, short ID, or full ID
    parser: nginx                # optional parser override
```

| Field | Required | Description |
|-------|----------|-------------|
| `kind` | yes | `file` \| `journald` \| `docker` |
| `path` | for `file` | file to tail |
| `unit` | for `journald` | systemd unit to follow |
| `container` | for `docker` | container name, short ID, or full ID |
| `parser` | no | force a parser: `nginx` \| `ssh` \| `apache` \| `apache-error` \| `traefik` \| `caddy` (default: routed automatically from the source) |

## enforce

```yaml
enforce:
  nftables:
    table: ezyshield             # default
    set: banned                  # default

  cloudflare:
    api_token: env:CF_API_TOKEN  # secrets are env: references, never inline
    account_id: "abc123..."      # required in the default "lists" mode
    # mode: lists                # "lists" (default) or "rulesets"
    # list_name: ezyshield_blocked
    # zone_ids: [ ... ]          # required only when mode: rulesets
    # action: block              # default
```

### nftables

| Field | Default | Description |
|-------|---------|-------------|
| `table` | `ezyshield` | nftables table (all EzyShield rules live inside it) |
| `set` | `banned` | set holding banned addresses |
| `socket` | `/run/ezyshield-enforcer/enforcer.sock` | privileged enforcer helper socket |

### cloudflare

| Field | Required | Description |
|-------|----------|-------------|
| `api_token` | yes | `env:VARNAME` reference to a scoped API token |
| `mode` | no | `lists` (default — account-level IP List + WAF rules) or `rulesets` (per-zone rules) |
| `account_id` | when `mode: lists` | Cloudflare account ID |
| `list_name` | no | IP list name (default `ezyshield_blocked`) |
| `zone_ids` | when `mode: rulesets` | zones to attach rules to |
| `action` | no | `block` (default), `challenge`, or `js_challenge` |
| `name` | no | label shown in status/test output |

Multiple Cloudflare accounts are supported: `cloudflare` also accepts a **list** of these objects. See the [Cloudflare guide](../guides/cloudflare.md).

## notify

```yaml
notify:
  rate_limit_per_minute: 5       # default — cap on notifications per minute
  dedup_window_sec: 600          # default — identical alerts collapsed

  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_TOKEN
    chat_ids: ["123456789"]
    severity: [warn, critical]   # optional filter: info | warn | critical

  email:
    host: smtp.example.com
    port: 587
    username: alerts@example.com
    password: env:EZYSHIELD_SMTP_PASSWORD
    tls: starttls                # starttls (default) | tls | none
    from: alerts@example.com
    to: [admin@example.com]

  slack:
    webhook_url: env:EZYSHIELD_SLACK_WEBHOOK
    channel: "#security"         # optional override

  discord:
    webhook_url: env:EZYSHIELD_DISCORD_WEBHOOK

  webhook:
    url: env:EZYSHIELD_WEBHOOK_URL
    headers:
      Authorization: env:EZYSHIELD_WEBHOOK_TOKEN   # value must be a full env: reference
```

Shared fields: `rate_limit_per_minute` (default 5) and `dedup_window_sec` (default 600) protect against notification storms. Every channel accepts an optional `severity` list (`info` \| `warn` \| `critical`).

> Secret-typed fields (`bot_token`, `password`, `webhook_url`, webhook `url`) only accept `env:VARNAME` references — inline values are rejected at load time. Webhook header **values** are sent verbatim unless the entire value is an `env:` reference, which is resolved.

## ai

Optional — with no `ai` block, the deterministic rule engine handles everything.

```yaml
# Single provider
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-3-5-haiku-latest
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]       # scores in this band consult the AI
  token_budget_daily: 50000      # hard daily cap; rule engine takes over beyond it
  cache_ttl: 1h                  # identical-verdict cache
```

```yaml
# Or multi-provider failover
ai:
  providers:
    - name: anthropic
      priority: 1
      model: claude-3-5-haiku-latest
      api_key: env:ANTHROPIC_API_KEY
    - name: ollama
      priority: 2
      model: llama3
      endpoint: http://localhost:11434
```

| Field | Description |
|-------|-------------|
| `provider` | `anthropic` \| `openai` \| `ollama` (single-provider form) |
| `model` | model name |
| `api_key` | `env:VARNAME` reference (never inline) |
| `endpoint` | base URL — used by ollama (default `http://localhost:11434`) and OpenAI-compatible endpoints |
| `ambiguous_band` | `[low, high]` — only scores inside the band consult the AI |
| `token_budget_daily` | daily token cap; when exhausted, decisions fall back to rules |
| `cache_ttl` | verdict cache duration |
| `providers` | multi-provider failover list (`name`, `priority`, `model`, `api_key`, `endpoint`, `token_budget_daily`); takes precedence over the single-provider fields |

The AI verdict is always advisory: schema-validated, clamped by policy, and never able to ban an allowlisted IP.

## enrich

GeoIP/ASN enrichment — enables `block_countries` / `block_asns` in policy and the country/ASN columns in `list` and `report`.

| Field | Description |
|-------|-------------|
| `db_path` | MaxMind country database path |
| `asn_path` | MaxMind ASN database path |
| `auto_update` | keep the databases updated automatically |
| `license_key` | `env:VARNAME` reference to a MaxMind license key |

## dashboard

| Field | Default | Description |
|-------|---------|-------------|
| `addr` | `127.0.0.1:9090` | Bind address — **loopback only**; non-loopback binds are refused at startup |
| `auth_db_path` | `<data_dir>/dashboard.db` | Dashboard auth database |

## Minimal example

```yaml
data_dir: /var/lib/ezyshield

collectors:
  - kind: journald
    unit: ssh

enforce:
  nftables: {}
```

## Secrets

Every secret field takes an `env:VARNAME` reference and is resolved by the daemon (`ezyshield run`) from its environment. The wizards write secret values to `/etc/ezyshield/.env` (mode 0600), which the systemd unit loads via `EnvironmentFile=`. Secrets never appear in config.yaml, logs, or error messages.

## Validation

```bash
sudo ezyshield config validate   # strict schema + constraints, exact line numbers on errors
sudo ezyshield doctor            # environment check (files, permissions, sockets)
sudo ezyshield test enforcer all # exercise enforcement backends for real
sudo ezyshield test notifier all # send a test notification to every channel
```

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
| `data_dir` | string | `/var/lib/ezyshield` | **Required** (`config validate` rejects an empty value). State directory for the **`dashboard`** command — its auth database is `<data_dir>/dashboard.db`. It does **not** set the daemon's SQLite database path: that is the `run --db` flag (default `/var/lib/ezyshield/ezyshield.db`). |
| `socket_path` | string | `/run/ezyshield/ezyshield.sock` | Control-socket path the **`dashboard`** connects to (unix socket — there is never a TCP listener for control). It does **not** set the daemon's socket: the daemon binds the `run --socket` flag (default `/run/ezyshield/ezyshield.sock`), so a custom value must match `run --socket` or the dashboard points at a socket the daemon never creates. |
| `rules_dir` | string | `/etc/ezyshield/rules.d` | Drop-in rule customizations: every `*.yaml` here merges over the built-in rules by `name` and survives updates (see the [rules guide](../guides/rules-customization.md)) |
| `rules_path` | string | — | **Deprecated.** Replaces the built-in rules entirely (no merge; `rules.d` ignored) — freezes the install out of upstream rule tuning |
| `log.level` | string | `info` | `debug` \| `info` \| `warn` \| `error` |
| `collectors` | list | `[]` | Log sources to tail (see below). An empty list is valid — `config validate` warns and the daemon simply tails nothing. |
| `enforce` | object | — | Enforcement backends (optional — without it, decisions are log-only) |
| `notify` | object | — | Notification channels (optional) |
| `ai` | object | — | AI provider for ambiguous traffic (optional) |
| `enrich` | object | — | GeoIP/ASN enrichment (optional) |
| `dashboard` | object | — | Dashboard bind address and auth DB (optional) |

> **The daemon ignores `data_dir` and `socket_path`; the `dashboard` command
> consumes them** (and `data_dir` is additionally required by `config validate`).
> The daemon (`ezyshield run`) takes its database path and control socket from
> its own `--db` and `--socket` flags (defaults `/var/lib/ezyshield/ezyshield.db`
> and `/run/ezyshield/ezyshield.sock`) and does not read these two keys. Setting
> them in `config.yaml` moves the dashboard's auth DB and its connection target,
> not the daemon's files — so keep `socket_path` in step with `run --socket`.
> See the [CLI reference](cli.md) for the `run` and `dashboard` flags.

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
| `parser` | no | force a parser: `nginx` \| `ssh` \| `apache` \| `apache-error` \| `traefik` \| `caddy` \| `postfix` \| `dovecot` (default: routed automatically from the source). `apache` reads the Apache **access** log (combined format, shared with `nginx`); `apache-error` reads the Apache **error_log** (`error.log` / `error_log`); `postfix` reads Postfix smtpd lines (`mail.log` / `maillog`, or the `postfix` / `postfix@*` journald units — SASL auth failures, relay-denied rejects, and connection-abuse signatures become `smtp_auth_fail` / `smtp_relay_denied` / `smtp_abuse` events); `dovecot` reads Dovecot login-process lines (`dovecot.log`, or the `dovecot` journald unit — IMAP/POP3 auth failures become `imap_auth_fail` and credential-less probes `imap_probe`; on shared `mail.log` setups, which route to `postfix` first, use the journald unit or this explicit override). **Honored only for `file` and `docker` collectors** — `journald` ignores it and always routes its parser from the unit. |

### SSH collector (unit name varies by distro)

The SSH systemd unit name **depends on the distro**: it's `ssh` on
Debian/Ubuntu and `sshd` on RHEL/CentOS/Fedora/Rocky/Alma, Arch, and
SUSE. Use whatever name `systemctl status <unit>` resolves on your
host — an alias that `journalctl -u` doesn't recognize collects zero
events.

```yaml
collectors:
  - kind: journald
    unit: ssh    # Debian/Ubuntu; use "sshd" on RHEL/CentOS/Arch/SUSE
```

To read SSH from a file instead of journald, point at your distro's
auth log — `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure`
(RHEL family). Both timestamp formats are accepted: the legacy syslog
format (`Jan  1 12:00:00`) and modern ISO-8601
(`2026-07-13T22:57:35+00:00`).

> **Configure only one SSH collector per host** — journald **or** the
> file it feeds, never both. Reading both ingests every event twice,
> which double-counts toward detection thresholds. (An already-banned
> IP is never banned again, so this never causes duplicate bans, only
> earlier detection.)

## enforce

```yaml
enforce:
  nftables: {}                   # local enforcement on; defaults are fine

  cloudflare:
    api_token: env:CLOUDFLARE_API_TOKEN  # secrets are env: references, never inline — this NAME is what init writes
    account_id: "abc123..."      # required in the default "lists" mode
    # mode: lists                # "lists" (default) or "rulesets"
    # list_name: ezyshield_blocked
    # zone_ids: [ ... ]          # required only when mode: rulesets
    # action: block              # default
```

### nftables

| Field | Default | Description |
|-------|---------|-------------|
| `table` | `inet ezyshield` | nftables table (all EzyShield rules live inside it). `<name>` or `inet <name>`; the `inet` family is the only one supported (dual-stack v4+v6 layout). Names: letters, digits, underscore |
| `set` | `blocked` | set holding banned IPv4 addresses; the IPv6 twin is derived automatically as `<set>6` (default `blocked6`). `allowed`/`allowed6` are reserved for the allowlist sets |
| `socket` | `/run/ezyshield-enforcer/enforcer.sock` | privileged enforcer helper socket |

Both are optional and genuinely honored: the daemon passes them to the
privileged enforcer, which re-validates them independently before any rule
is written. Two operational notes for custom names:

- The enforcer must support them (same version as the daemon). Against an
  older `ezyshield-enforcer`, the daemon refuses to enforce with a clear
  error instead of silently using the defaults.
- The enforcer applies one name set per run. After changing `table`/`set`,
  restart both services (`sudo systemctl restart ezyshield-enforcer
  ezyshield`); a previous table left behind by a rename can be removed with
  `nft delete table inet <old-name>`.

### cloudflare

| Field | Required | Description |
|-------|----------|-------------|
| `api_token` | yes | `env:VARNAME` reference to a scoped API token |
| `mode` | no | `lists` (default — account-level IP List + WAF rules) or `rulesets` (per-zone rules) |
| `account_id` | when `mode: lists` | Cloudflare account ID |
| `list_name` | no | IP list name (default `ezyshield_blocked`) |
| `instance` | no | Identity of this server when several servers share one Cloudflare account (the free plan allows a single list): each daemon tags its list items `ezyshield:<instance>` and manages only its own — bans from all servers add up instead of overwriting each other. Defaults to the hostname; must match `[A-Za-z0-9._-]{1,32}` and stay stable across restarts |
| `adopt_legacy_items` | no | Set on **exactly one** server sharing the account to take ownership of items written by older versions (bare `ezyshield` comment) so they expire again. Remove once those items are gone |
| `zone_ids` | when `mode: rulesets` | zones to attach rules to |
| `action` | no | `block` (default), `challenge`, or `js_challenge` |
| `name` | no | label shown in status/test output |
| `debounce` | no | how long rapid ban/unban mutations are coalesced before one batched API push (Go duration, default `15s`) |
| `expire_flush_interval` | no | cadence for batched item **removals** in `lists` mode (Go duration, default `3m`) — expired bans and unbans accumulate and go out in one API call per interval |

Multiple Cloudflare accounts are supported: `cloudflare` also accepts a **list** of these objects. See the [Cloudflare guide](../guides/cloudflare.md).

Tuning the two cadences trades edge-propagation speed for fewer API calls.
The defaults keep a busy server comfortably inside Cloudflare's Lists API
throttle; raise them if `ezyshield status` still reports throttling
(`ratelimited` in the enforcement detail), lower `debounce` if a new ban must
reach the edge faster. Removals are deliberately the slow path: an expired IP
staying blocked at the edge for up to `expire_flush_interval` is fail-closed
and harmless, while a delayed *ban* is real exposure — which is why bans ride
`debounce` and only removals wait for the flush interval. Manual `ezyshield
unban` also propagates to the edge on the flush cadence (the local nftables
unban is immediate).

### bunny

bunny.net edge enforcement via each pull zone's blocked-IP list. Presence of the section enables it. **EzyShield takes ownership of the blocked-IP list** on the configured zones — entries added by hand in the bunny panel are removed on reconcile. See the [bunny.net guide](../guides/bunny.md).

```yaml
enforce:
  bunny:
    api_key: env:BUNNY_API_KEY   # secrets are env: references, never inline
    pull_zones: [123456, 234567] # numeric pull zone IDs
```

| Field | Required | Description |
|-------|----------|-------------|
| `api_key` | yes | `env:VARNAME` reference to the bunny.net account API key |
| `pull_zones` | yes | numeric pull zone IDs (at least one, positive, unique) |
| `name` | no | label shown in logs as `bunny[<name>]` |

The enforcer caps each zone at 500 blocked IPs (bunny does not document a provider limit); beyond that the most recent bans win, with a warning.

## notify

```yaml
notify:
  rate_limit_per_minute: 5       # default — cap on notifications per minute
  dedup_window_sec: 600          # default — identical alerts collapsed
  notify_only_window_sec: 3600   # default — repeat notify_only per (IP, rule) folds into one summary

  telegram:
    bot_token: env:TELEGRAM_BOT_TOKEN
    chat_ids: ["123456789"]
    severity: [warn, critical]   # optional filter: info | warn | critical

  email:
    host: smtp.example.com
    port: 587
    username: alerts@example.com
    password: env:SMTP_PASSWORD
    tls: starttls                # starttls (default) | tls | none
    from: alerts@example.com
    to: [admin@example.com]

  slack:
    webhook_url: env:SLACK_WEBHOOK_URL
    channel: "#security"         # optional override

  discord:
    webhook_url: env:DISCORD_WEBHOOK_URL

  webhook:
    url: env:WEBHOOK_URL
    headers:
      Authorization: env:WEBHOOK_AUTH_TOKEN   # value must be a full env: reference
```

Shared fields: `rate_limit_per_minute` (default 5) and `dedup_window_sec` (default 600) protect against notification storms. `notify_only_window_sec` (default 3600) additionally windows below-threshold `notify_only` events per (IP, rule): the first event notifies immediately and repeats within the window fold into a single summary notification — set it negative to disable. Audit log entries are never suppressed. Every channel accepts an optional `severity` list (`info` \| `warn` \| `critical`).

> Secret-typed fields (`bot_token`, `password`, `webhook_url`, webhook `url`) only accept `env:VARNAME` references — inline values are rejected at load time. They are also **required** for their channel: a `telegram` block without `bot_token`, an `email` block without `password`, or a `slack`/`discord`/`webhook` block without its URL fails validation (the daemon resolves them at startup). Webhook header **values** are sent verbatim unless the entire value is an `env:` reference, which is resolved.

> Email `tls: starttls` **fails closed**: if the SMTP server does not advertise STARTTLS (or a capability-stripping proxy hides it), the send errors instead of silently downgrading to plaintext. Set `tls: none` explicitly if you really intend to send unencrypted.

## ai

Optional — with no `ai` block, the deterministic rule engine handles everything.

```yaml
# Single provider
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 69]       # scores in this band consult the AI (keep high < ban_threshold)
  token_budget_daily: 50000      # hard daily cap; rule engine takes over beyond it
  cache_ttl: 15m                 # identical-verdict cache (default 15m)
```

```yaml
# Or multi-provider failover
ai:
  providers:
    - name: anthropic
      priority: 1
      model: claude-haiku-4-5-20251001
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
| `endpoint` | base URL for the **`ollama`** provider only (default `http://localhost:11434`). The `anthropic` and `openai` providers ignore it and always call their official APIs (`https://api.anthropic.com`, `https://api.openai.com`) — there is no OpenAI-compatible-endpoint override. Same in the single-provider and `providers` failover forms. |
| `ambiguous_band` | `[low, high]` — only scores inside the band consult the AI. Omitted (or `[0, 0]`) defaults to `[30, ban_threshold − 1]`, following the ban_threshold CONFIGURED in policy.yaml (`[30, 69]` with the default threshold of 70) — so raising the threshold automatically widens the omitted band instead of silently leaving an unconsulted gap; any other band with `low >= high` or values outside 0–100 is rejected at load. Keep `high` **below** the policy `ban_threshold`: a score at or above the threshold has already decided a ban on rules alone, so the daemon never consults the AI for it — a band reaching into the threshold only triggers a startup/`validate` warning |
| `token_budget_daily` | daily token cap; when exhausted, decisions fall back to rules |
| `cache_ttl` | verdict cache duration; omitted or `0` means the default **15m** (the cache cannot be disabled — it is the second brake on repeated consults for the same behavior). Entries are keyed by behavior signature (event kind counts + window), not by IP, so identical attack patterns from different IPs reuse one verdict; on a hit the cached verdict is re-targeted to the IP being evaluated. Allowlist-clamped verdicts are never cached |
| `providers` | multi-provider failover list (`name`, `priority`, `model`, `api_key`, `endpoint`, `token_budget_daily`); takes precedence over the single-provider fields |

The AI verdict is always advisory: schema-validated, clamped by policy, and never able to ban an allowlisted IP.

### Async second layer (`async: true`)

```yaml
ai:
  provider: anthropic
  api_key: env:ANTHROPIC_API_KEY
  async: true                # analyze grey-zone traffic in the background
  # async_queue_size: 256    # bounded queue; overflow drops the OLDEST episode
```

With `async: true` the pipeline **never waits for a provider**: grey-zone
episodes (scores inside the ambiguous band) are queued — one entry per IP
at a time — and a background worker drains them, rate-capped at one
provider call per second. How the layer stays token-frugal:

1. The rule engine decides the obvious cases; only the ambiguous band ever
   enqueues (the same #419 gates apply — decisive scores and already-banned
   IPs never spend tokens).
2. The **Log Cleaner** runs before every call: static-asset noise is
   dropped from the samples, already-decided episodes (banned/allowlisted
   since queueing) are skipped, and the reduction is exposed as
   `ezyshield_ai_cleaner_reduction_permille`.
3. The provider receives only compact aggregates — counts, kind
   distributions, enrichment, and a sanitized behavior summary (top paths
   with querystrings cut, methods, status classes, capped user agents).
   Raw log lines never enter a payload.

Returned verdicts flow through the decision engine like any other verdict
source: allowlist-wins, anti-lockout, and policy clamps all apply. A slow
or dead provider degrades to rules-only detection — the bounded queue
drops the oldest episode on overflow (`ezyshield_ai_queue_dropped_total`).
The **agreement-rate metric** `ezyshield_ai_agreement_total`
(`<provider>_agree` / `<provider>_disagree`, compared against the rule
engine at the ban threshold) is the published proof the layer earns its
tokens.

Token cost expectations: one grey-zone episode costs one compact prompt
(typically a few hundred input tokens) per un-cached behavior signature;
the cache, the per-IP dedupe, and the #419 gates mean bursts do not
multiply spend. For a **fully local** deployment use `provider: ollama` —
the async layer works identically with zero outbound traffic and no API
key.

Every AI call is recorded in the `ai_usage` table with the analyzed IP, so cost attribution is a single query — the top spenders (an IP draining the budget is itself a leakage symptom):

```bash
sudo sqlite3 /var/lib/ezyshield/ezyshield.db \
  "SELECT ip, COUNT(*) calls, ROUND(SUM(cost_usd), 4) usd
   FROM ai_usage WHERE ip IS NOT NULL
   GROUP BY ip ORDER BY usd DESC LIMIT 10;"
```

## enrich

GeoIP/ASN enrichment — enables `block_countries` / `block_asns` in policy and the country/ASN columns in `list` and `report`. Optional: without an `enrich:` section the daemon runs normally with empty enrichment (no country/ASN anywhere, and those policy keys never match).

| Field | Description |
|-------|-------------|
| `db_path` | path to `GeoLite2-Country.mmdb` |
| `asn_path` | path to `GeoLite2-ASN.mmdb` |
| `auto_update` | let the daemon download and refresh the databases (weekly) |
| `license_key` | `env:VARNAME` reference to a MaxMind license key — required when `auto_update: true`, inline values are rejected |

The easiest path is the wizard, which walks through all of the below:

```bash
sudo ezyshield config enrich maxmind
sudo systemctl restart ezyshield
```

**Where the databases come from.** EzyShield uses MaxMind's free GeoLite2 databases, which require a (free) MaxMind account: [sign up](https://www.maxmind.com/en/geolite2/signup), then generate a license key under *Manage License Keys*. With `auto_update: true` the daemon downloads both databases itself on startup when the files are missing and refreshes them weekly — you never handle the files:

```yaml
enrich:
  db_path: /var/lib/ezyshield/GeoLite2-Country.mmdb
  asn_path: /var/lib/ezyshield/GeoLite2-ASN.mmdb
  auto_update: true
  license_key: env:MAXMIND_LICENSE_KEY
```

The key is a secret like any other: put `MAXMIND_LICENSE_KEY=...` in `/etc/ezyshield/.env` (mode 0600 — the wizard does this for you) and reference it as `env:MAXMIND_LICENSE_KEY`. It is only ever used in the download URL and never logged.

**Manual alternative.** With `auto_update: false` no account key is needed at runtime: download `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` from your MaxMind account (or mirror them from a host that has them) and place them at the configured paths. Missing or unreadable files are not an error — the daemon logs a warning and runs with empty enrichment until they appear.

## dashboard

| Field | Default | Description |
|-------|---------|-------------|
| `addr` | `127.0.0.1:9090` | Bind address — **loopback only**; non-loopback binds are refused at startup |
| `auth_db_path` | `<data_dir>/dashboard.db` | Dashboard auth database |

## webshell_watch

Opt-in webshell-drop tripwire: sweeps web roots for new or modified executable web files. Purely observational — audit + notification, never a ban. See the [Webshell Tripwire guide](../guides/webshell-tripwire.md).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Opt-in switch |
| `roots` | — | Absolute web-root directories to sweep (**required** when enabled) |
| `extensions` | `.php, .phtml, .php5, .php7, .phar` | Watched extensions (leading dot) |
| `ignore` | `[]` | Path patterns to skip — `path.Match` globs, or substring when the pattern has no glob metacharacters |
| `interval_sec` | `10` | Sweep cadence in seconds (floor 5) |

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

This is also enforced in reverse: if a value pasted into a *non-secret* field (provider, model, endpoint, ...) looks like a credential — a known key prefix such as `sk-`, or a long high-entropy token — the config is rejected at load with an error that names the field but never prints the value. Webhook header values are the one exemption (raw values are legal there and are redacted in `config show`).

## Validation

```bash
sudo ezyshield config validate   # strict schema + constraints, exact line numbers on errors
sudo ezyshield doctor            # environment check (files, permissions, sockets)
sudo ezyshield test enforcer all # exercise enforcement backends for real
sudo ezyshield test notifier all # send a test notification to every channel
```

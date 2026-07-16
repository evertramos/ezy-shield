---
title: CLI Reference
description: All commands and flags
order: 4
---

# CLI Reference

Complete command reference for the `ezyshield` CLI.

## Global conventions

### Exit codes

Every command follows the same exit-code contract:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Runtime error — the command started but failed (invalid config, API error, write failure) |
| `2` | Usage error — unknown command/flag, bad argument, or an input file that does not exist / cannot be read |
| `3` | Daemon unreachable — the control socket refused the connection (is the daemon running?) |

Two deliberate exceptions: `status` exits `0` even when the daemon is stopped
(it successfully reports the state), and `doctor` exits `0` even when
individual checks fail (its output is the report).

### JSON output (`--json`)

Every read command supports `--json` with stable field names, safe to script
against:

| Command | Shape |
|---------|-------|
| `status` | Object: `daemon`, `enforcer`, `mode`, `uptime`, `version`, `active_bans`, `bans_by_strike`, `message` |
| `list` | Envelope: `ok`, `error`, `data` (rows under `data`) |
| `report <ip>` | Object: versioned abuse report (`schema_version`, `ip`, `country`, `asn`, `current_ban`, `strikes`, `actions`, plus `evidence` with `--evidence`) |
| `report` | Array of offender summaries (`ip`, `first_seen`, `last_seen`, `total_strikes`, `banned`, `permanent`, `country`, `asn`) |
| `watch` | NDJSON: one event object per line |
| `scan` | Object: `listeners`, `new_listeners` |
| `doctor` | Object: `checks` (`name`, `status`, `hint`) and `summary` (`total`, `pass`, `fail`) |
| `config show` | Object: `config`, `policy` (effective values, secrets redacted) |
| `version` | Object: `version`, `commit`, `build_date` |

With `--json`, stdout carries only JSON; warnings and connection notices go to
stderr, so piping into `jq` is always safe.

### Color

Colored/styled output is enabled only when all of these hold: stdout is an
interactive terminal, the [`NO_COLOR`](https://no-color.org) environment
variable is unset, and `--no-color` was not passed. Piped or redirected output
is always plain text, so `ezyshield watch | grep ban` never sees escape codes.

## ezyshield init

Interactive setup wizard. Configures log sources, enforcement backends, AI providers, and notifications.

```bash
sudo ezyshield init
```

Creates `/etc/ezyshield/config.yaml` and `/etc/ezyshield/policy.yaml` with secure permissions (0600).

The wizard walks through named sections — **Environment** (what was detected
on the host), **Collectors**, **Allowlist**, **Edge enforcers**, **AI
analysis**, **Policy**, **Files**, and **System services** — with `✓`/`✗`/`!`
status marks per line. Styling follows the global
[color conventions](#color); piped output stays plain.

At the end it prints a **Summary** section:

- what was configured (collectors, enforcers, AI) and what was skipped, with
  the reason;
- every file written (including the `.env` that holds secret tokens, mode
  0600 — tokens never go into `config.yaml`);
- the current mode (`DRY-RUN` by default — nothing is blocked until you set
  `armed: true` in `policy.yaml`);
- numbered next steps (`doctor`, `status`, `watch`).

The summary complements — never replaces — warnings printed during the run,
such as the loud banner shown when Cloudflare enforcer setup aborts.

Flags:

- `--yes` — non-interactive: accept every default, skip CDN detection.
- `--config-dir <dir>` — write files to a different directory; skips systemd
  unit installation and service start (next steps then use foreground `run`).

## ezyshield run

Start the daemon in the foreground. Reads logs, makes decisions, enforces bans.

```bash
sudo ezyshield run
```

Runs in dry-run mode by default (`armed: false` in policy.yaml).

## ezyshield watch

Stream live security events from the running daemon: detections, strike
escalations, bans, dry-run bans, unbans, and allowlist changes. This is a live
view — for a point-in-time snapshot of active bans, use `list`.

```bash
# Stream everything
ezyshield watch

# Only bans and dry-run bans
ezyshield watch --kind ban,dry_ban

# Only events for one address or CIDR block
ezyshield watch --ip 203.0.113.0/24

# NDJSON: one JSON object per line, for jq or a log shipper
ezyshield watch --json | jq .kind
```

Flags:
- `--kind` — filter by event kind: `detection`, `record`, `notify_only`,
  `dry_ban`, `ban`, `already_banned`, `unban`, `allow` (repeatable or
  comma-separated)
- `--ip` — filter by IP address or CIDR block
- `--socket` — daemon control socket path

Each event carries a timestamp, kind, IP, and context fields (score, category,
rule, strike, TTL, enforcer, reason, source). Event text derived from log
lines is sanitized before display — ANSI escape sequences and control
characters are stripped so hostile log content cannot spoof your terminal.

If the daemon connection drops (e.g. a restart), `watch` reconnects
automatically with backoff. Press `Ctrl-C` to exit. The daemon must be running
(`ezyshield run` or `sudo systemctl start ezyshield`).

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

## ezyshield report

Generate a complete abuse report for one offender IP from the daemon's
records: identity and enrichment (country, ASN), the current ban, the full
strike history with detection verdicts, and the action trail. Without an IP,
list every offender on record.

```bash
# Full report for one IP (terminal text)
ezyshield report 203.0.113.7

# Markdown document, ready to attach to an abuse@ complaint
ezyshield report 203.0.113.7 -o md > abuse-203.0.113.7.md

# Same, including raw log excerpts mentioning the IP as evidence
ezyshield report 203.0.113.7 --evidence -o md > abuse-203.0.113.7.md

# Machine-readable (versioned schema, safe to script against)
ezyshield report 203.0.113.7 --json

# List all offenders on record / only permanently banned ones
ezyshield report
ezyshield report --permanent
```

Flags:
- `-o, --output` — output format: `text` (default) or `md` (markdown abuse
  report; requires an IP)
- `--evidence` — include raw log excerpts mentioning the IP, extracted on
  demand from the daemon's configured log sources (requires an IP). File
  sources are scanned directly, journald sources through `journalctl`, and
  docker sources through the Docker Engine socket. Excerpts are bounded
  (most recent window, 50 lines per source) and never persisted; a source
  that cannot be read (log rotated away, journal empty, engine socket
  unreachable, container removed) degrades to an explanatory note instead
  of failing the report
- `--permanent` — listing mode: only offenders with a permanent active ban
- `--limit` — max strike/action rows (0 = server default of 100)
- `--no-footer` — omit the "Generated by EzyShield" footer from markdown
  output
- `--socket` — daemon control socket path

The report is read-only and works in both enforce and dry-run modes. Fields
derived from log lines (reasons, categories) are sanitized before display —
ANSI escapes and control characters are stripped, and markdown table cells
are escaped — so hostile log content cannot spoof your terminal or break the
document. Evidence excerpts are rendered as indented code blocks in markdown,
so a log line cannot inject formatting into the report. Timestamps are UTC
(RFC 3339).

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

### ezyshield config enforcer `<name>`

Interactive wizard to add or reconfigure one enforcer on an existing installation — the same prompts and dry token validation the init wizard runs, without regenerating anything else.

```bash
sudo ezyshield config enforcer cloudflare
```

- The write is atomic (temp file + rename); the previous file is kept as `config.yaml.bak` and the merged configuration is re-validated before anything touches disk. Comments are not carried over — recover them from the `.bak` if needed.
- Secret tokens go to the `.env` file next to `config.yaml` (mode 0600), never into `config.yaml` itself (`api_token: env:CLOUDFLARE_API_TOKEN`).
- On success the command prints the changed keys and next steps (`config validate`, restart the daemon). If the wizard aborts, nothing is written.

Available names: `cloudflare`.

Exit codes: `0` saved, `1` wizard aborted or write failed, `2` config.yaml not found (run `init` first).

### ezyshield config notifier `<name>`

Interactive wizard to add, reconfigure, or remove one notification channel on an existing installation.

```bash
sudo ezyshield config notifier telegram
sudo ezyshield config notifier email
sudo ezyshield config notifier slack
sudo ezyshield config notifier discord
sudo ezyshield config notifier webhook
```

- Each channel asks for its own settings (telegram: chat IDs; email: from/to/SMTP host/port/TLS/username; slack: optional channel override; webhook: optional auth header) plus a severity filter (`info,warn,critical`; empty = all).
- Credential values — bot tokens, webhook URLs (capability URLs are secrets), SMTP passwords, auth header values — are read with input hidden and offered two ways: paste the value (stored in the `.env` file next to `config.yaml`, mode 0600, merged without touching other lines) or reference an env var you already manage (e.g. from sops/vault) — then the wizard writes `env:YOUR_VAR` and never touches `.env`. Secrets never land in `config.yaml`; it only carries references like `bot_token: env:TELEGRAM_BOT_TOKEN`.
- Pressing ENTER at the paste prompt is fine: an existing value in `.env` is kept as is; otherwise a placeholder is written for you to fill in later.
- For the generic `webhook` channel the auth header value is a secret too: `config.yaml` gets `Authorization: env:WEBHOOK_AUTH_HEADER` and the daemon resolves the reference at startup. Plain (non-`env:`) header values in hand-written configs keep working unchanged.
- Reconfiguring replaces that channel's entry; shared tuning (`rate_limit_per_minute`, `dedup_window_sec`) and other channels are preserved. To disable a channel, answer `n` at the configure prompt: the wizard then offers to remove the existing entry (default no). Declining leaves the file untouched.
- Write semantics match the other wizards: atomic write, `config.yaml.bak`, re-validation before saving, changed-keys summary on success. Verify delivery afterwards with the notification test command shown in the next steps.

Available names: `telegram`, `email`, `slack`, `discord`, `webhook`.

Exit codes: `0` saved, `1` wizard aborted or write failed, `2` config.yaml not found (run `init` first).

### ezyshield config ai `<provider>`

Interactive wizard to configure (or switch) the AI provider on an existing installation — the same model and API-key prompts the init wizard runs, without regenerating anything else.

```bash
sudo ezyshield config ai anthropic
sudo ezyshield config ai openai
sudo ezyshield config ai ollama
```

- The API key is read with input hidden and offered two ways: paste it (stored in the `.env` file next to `config.yaml`, mode 0600, merged without touching other lines) or reference an env var you already manage (e.g. from sops/vault) — in that case the wizard writes `api_key: env:YOUR_VAR` and never touches `.env`. Keys never land in `config.yaml`.
- Pressing ENTER at the paste prompt is fine: an existing key in `.env` is kept as is; otherwise a placeholder is written for you to fill in later. `ollama` runs locally and has no key.
- Reconfiguring replaces the provider fields (`provider`, `model`, `api_key`) but preserves your tuning (`ambiguous_band`, `token_budget_daily`). Write semantics match `config enforcer`: atomic write, `config.yaml.bak`, re-validation before saving.

Available providers: `anthropic`, `openai`, `ollama`.

Exit codes: `0` saved, `1` write failed, `2` config.yaml not found (run `init` first).

### ezyshield config collector `<name>`

Interactive wizard to add, reconfigure, or remove one log collector on an existing installation — the same prompts the init wizard runs for that source, without regenerating anything else.

```bash
sudo ezyshield config collector sshd
sudo ezyshield config collector nginx
sudo ezyshield config collector apache
```

- `sshd` manages the journald collector (confirm, then optionally override the systemd unit). Web server names (`nginx`, `apache`, `traefik`, `caddy`) first ask for the log source: `file` (host access-log path, default suggested per server) or `docker` (container name, reading its stdout).
- Reconfiguring replaces the existing entry for that source (matched by parser for web servers, by SSH unit for `sshd`) — the wizard never appends duplicates. Setups with several sources for the same server (e.g. two nginx vhost logs) are edited in `config.yaml` directly.
- To disable a source, answer `n` at the configure prompt: the wizard then offers to remove the existing entry (default no). Declining leaves the file untouched.
- Collectors carry no secrets; everything stays in `config.yaml`. Write semantics match the other wizards: atomic write, `config.yaml.bak`, re-validation before saving, changed-keys summary on success.

Available names: `sshd`, `nginx`, `apache`, `traefik`, `caddy`.

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

## ezyshield test

Run connectivity tests against configured components. Like `config`, the group follows the `<kind> <name>` pattern, so future component kinds plug into the same verbs.

### ezyshield test enforcer `<name>`

Test the configuration and permissions of an enforcer backend: token validity, account/zone access, and the exact API permissions the enforcer needs — with a fix suggestion for every failing check.

```bash
sudo ezyshield test enforcer cloudflare

# Test all configured enforcer backends
sudo ezyshield test enforcer all
```

Available names: `all`, `cloudflare`, `nftables`.

Exit code is `0` if all checks pass, non-zero if any check fails.

### ezyshield test notifier `<name>`

Send a synthetic alert to verify a notification channel end to end (secrets resolved from the environment, message actually delivered).

```bash
sudo ezyshield test notifier telegram

# Test all configured channels
sudo ezyshield test notifier all
```

Available names: `all`, `email`, `telegram`.

Exit code is non-zero on failure.

### Deprecated aliases

The pre-1.0 verbs `test-enforce <name>` and `test-notify <name>` keep working as hidden aliases of `test enforcer` / `test notifier` — same flags, same behavior — and print a one-line migration notice on stderr. They will be removed in 1.0.

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (see [Global conventions](#global-conventions) for shapes) |
| `--no-color` | Disable colored output (the `NO_COLOR` env var is also honored) |
| `--config` | Path to config.yaml (default: `/etc/ezyshield/config.yaml`) |
| `--policy` | Path to policy.yaml (default: `/etc/ezyshield/policy.yaml`) |
| `-h, --help` | Show help text |

## Examples

**Monitor daemon activity live:**

```bash
ezyshield watch --kind ban,dry_ban
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

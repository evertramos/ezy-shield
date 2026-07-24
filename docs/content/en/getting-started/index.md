---
title: Getting Started
description: Quick start guide to install and run EzyShield
order: 1
---

# EzyShield Quick Start

Get EzyShield running on your server in under 5 minutes.

---

## 1. Requirements

| Requirement | Minimum version |
|-------------|-----------------|
| Linux       | kernel 4.x+     |
| nftables    | 0.9+            |

---

## 2. Installation

### One-line install (recommended)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

This downloads the latest `ezyshield` and `ezyshield-enforcer` binaries,
verifies their checksum's cosign signature when `cosign` is installed
(falling back to a plain SHA-256 checksum check otherwise), and installs
them.

To install a specific version:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0 sh
```

### Build from source

Requires **Go 1.26+**.

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
go build -o ezyshield ./cmd/ezyshield
go build -o ezyshield-enforcer ./cmd/ezyshield-enforcer
sudo mv ezyshield ezyshield-enforcer /usr/local/bin/
```

### Verify

```bash
ezyshield version
```

---

## 3. Initial setup

### `ezyshield init`

Runs the interactive setup wizard: detects the environment, writes config files,
installs systemd units, and starts EzyShield in dry-run mode.

```bash
sudo ezyshield init
```

This creates:

- `/etc/ezyshield/config.yaml`
- `/etc/ezyshield/policy.yaml`
- `/etc/ezyshield/rules.d/` (drop-in rule customizations; WordPress installs also get a commented tuning template `10-wordpress.yaml`)
- `/etc/ezyshield/.env` (AI API key, mode 0600)
- `/etc/systemd/system/ezyshield.service.d/env.conf` (systemd drop-in)
- `/var/lib/ezyshield/` (runtime data, SQLite)

> **Tip:** If config files already exist, `ezyshield init` exits immediately
> listing the conflicting paths. Remove them and re-run to regenerate.

#### AI provider API key

When you enable AI analysis, the wizard prompts for your API key. The key is
stored in `/etc/ezyshield/.env` (mode `0600`) — never in config files or logs.

Supported providers:

| Provider    | Env var             |
|-------------|---------------------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai`    | `OPENAI_API_KEY`    |
| `ollama`    | *(no key needed)*   |

Use `--yes` for non-interactive mode (writes a placeholder you edit later).

### `ezyshield doctor`

Validates configuration and checks dependencies:

```bash
sudo ezyshield doctor
```

Expected output:

```
[PASS] config.yaml: exists
[PASS] config.yaml: parses
[PASS] policy.yaml: exists
[PASS] policy.yaml: parses
[PASS] nft: binary present
[PASS] journald: readable
[PASS] enforcer: socket connectivity
```

---

## 4. Configuration — config.yaml

Main file at `/etc/ezyshield/config.yaml`.

### Collectors (log sources)

```yaml
collectors:
  - kind: journald
    unit: sshd
  - kind: file
    path: /var/log/nginx/access.log
```

Available types:

- `journald` — requires `unit` field (systemd service name)
- `file` — requires `path` field (log file path)

### Enforce (local enforcement)

```yaml
enforce:
  nftables:
    table: inet ezyshield
    set: blocked
```

The privileged helper (`ezyshield-enforcer`) handles all firewall writes via a
unix socket. The daemon re-syncs the full ban set to the enforcer whenever the
**daemon** restarts, so blocks survive daemon restarts. Restarting only the
`ezyshield-enforcer` helper does not trigger that re-sync on its own — the ban
set catches up on the next periodic ban-expiry tick, or the next daemon
restart.

### AI (optional)

```yaml
ai:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]
  token_budget_daily: 500000
```

> **Important**: Secrets must use `env:VAR_NAME` references. Inline values are
> rejected at config load time.

---

## 5. Configuration — policy.yaml

File at `/etc/ezyshield/policy.yaml`. Controls blocking behavior.

### armed (operating mode)

```yaml
armed: false   # dry-run (default) — no real blocking
# armed: true  # enable only after validating with 'ezyshield doctor'
```

### Allowlist

IPs and CIDRs that are **never** blocked:

```yaml
allowlist:
  - 192.168.1.0/24
  - 10.0.0.1

admin_cidrs:
  - 203.0.113.50/32   # your SSH access IP
```

### Strike table (ban escalation)

```yaml
strikes:
  - ttl: 5m      # strike 1 — 5 minutes
  - ttl: 1h      # strike 2 — 1 hour
  - ttl: 24h     # strike 3 — 24 hours
  - ttl: 168h    # strike 4 — 7 days
  - ttl: 0       # strike 5 — permanent
```

Each strike represents an **attack episode**, not a single request. While an IP
is already banned, new detections are suppressed until the ban expires.

### Thresholds

```yaml
ban_threshold: 70       # score ≥ 70 → apply strike
observe_threshold: 40   # score 40–69 → log/notify, no ban
max_bans_per_minute: 30 # safety: pause enforcement if exceeded
```

---

## 6. Custom rules — rules.d drop-ins

The detection rules are embedded in the binary and update with it. To tune
or add rules, drop a `*.yaml` file in `/etc/ezyshield/rules.d/` — entries
merge over the built-in rules by `name` and survive updates. Full guide:
[Customizing Detection Rules](../guides/rules-customization.md).

### Rule structure

```yaml
rules:
  - name: ssh_bruteforce
    description: "Repeated SSH authentication failures"
    kinds: [ssh_fail, ssh_invalid_user]
    window: 60s
    threshold: 5
    score: 85
    category: bruteforce
```

### Fields

| Field        | Description                              |
|--------------|------------------------------------------|
| `name`       | Unique rule identifier                   |
| `description`| Human-readable description               |
| `kinds`      | Event types that activate the rule       |
| `window`     | Time window for counting                 |
| `threshold`  | Occurrences to trigger                   |
| `score`      | Assigned score (0–100)                   |
| `category`   | Category (`bruteforce`, `scanner`, etc.) |
| `field`      | Event field to filter (optional)         |
| `value`      | Exact field value (optional)             |
| `contains`   | Substring match (optional)               |

### Example: block API scanners

```yaml
  - name: api_scanner
    description: "Scan of non-existent API endpoints"
    kinds: [http_request]
    field: status
    value: "404"
    window: 30s
    threshold: 15
    score: 75
    category: scanner
```

> **Note**: A drop-in only touches the rules it names — everything else
> keeps riding binary updates. An invalid drop-in stops the daemon from
> starting (fail-closed). The legacy `rules_path` (whole-file replacement)
> is deprecated.

---

## 7. Notifications

### Telegram

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token.
2. Add the bot to your group/channel and get the `chat_id`.
3. Configure in `config.yaml`:

```yaml
notify:
  rate_limit_per_minute: 5
  dedup_window_sec: 600

  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_BOT_TOKEN
    chat_ids:
      - "-1001234567890"
    severity: []   # empty = all; or: [warn, critical]
```

### Email (SMTP)

```yaml
  email:
    from: ezyshield@yourdomain.com
    to:
      - admin@yourdomain.com
    host: smtp.yourdomain.com
    port: 587
    username: ezyshield@yourdomain.com
    password: env:EZYSHIELD_SMTP_PASSWORD
    tls: starttls   # starttls | tls | none
    severity: []
```

---

## 8. Test notifications

Validate delivery without waiting for a real event:

```bash
sudo ezyshield test notifier telegram
sudo ezyshield test notifier email
```

---

## 9. Run the daemon

```bash
sudo ezyshield run
```

While `armed: false`, EzyShield runs in **dry-run**: it processes everything,
records strikes and simulated bans so escalation mirrors production exactly
(ADR-0009), and logs what *would* be blocked — without ever touching the
firewall.

### As a systemd service

```bash
sudo systemctl enable --now ezyshield-enforcer
sudo systemctl enable --now ezyshield
```

### Checklist before arming

1. ✅ `ezyshield doctor` — no errors
2. ✅ `allowlist` includes your access IPs
3. ✅ `admin_cidrs` includes your SSH IP
4. ✅ Notifications tested with `test notifier`
5. ✅ Ran in dry-run, reviewed the logs
6. ⬜ Run `sudo ezyshield arm --for 1h` (pre-flight + auto-revert window), then `sudo ezyshield arm --keep` once you're confident

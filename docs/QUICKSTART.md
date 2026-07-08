# EzyShield Quick Start

> ⚠️ Pre-alpha project. Run in dry-run mode and report bugs via issues.
> Portuguese translation: [docs/QUICKSTART.pt-BR.md](QUICKSTART.pt-BR.md)

---

## 1. Requirements

| Requirement | Minimum version |
|-------------|-----------------|
| Go          | 1.24+           |
| Linux       | kernel 4.x+     |
| nftables    | 0.9+            |

Verify:

```bash
go version       # go1.24 or later
uname -s         # Linux
nft --version    # nftables v0.9+
```

---

## 2. Installation (build from source)

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
go build -o ezyshield ./cmd/ezyshield
sudo mv ezyshield /usr/local/bin/
```

Confirm the installation:

```bash
ezyshield version
```

---

## 3. Initial setup

### `ezyshield init`

Runs the interactive setup wizard: detects the environment, writes config files, installs systemd units, and starts EzyShield in dry-run mode.

```bash
sudo ezyshield init
```

This creates:
- `/etc/ezyshield/config.yaml`
- `/etc/ezyshield/policy.yaml`
- `/etc/ezyshield/rules.yaml` (when WordPress containers are detected)
- `/etc/ezyshield/.env` (AI API key, mode 0600)
- `/etc/systemd/system/ezyshield.service.d/env.conf` (systemd drop-in)
- `/var/lib/ezyshield/` (runtime data, SQLite)

> **Pre-flight (issue #5):** the wizard checks immediately whether `config.yaml`
> or `policy.yaml` already exist in the target directory (`--config-dir` or the
> default `/etc/ezyshield`). If either exists, `ezyshield init` fails in under
> 1 s — **before** printing the "Detecting environment..." banner — listing all
> pre-existing paths in a single error so you can remove them in one shot. To
> regenerate, delete the listed files and re-run `sudo ezyshield init`.

#### AI provider API key (issue #22)

When you enable AI analysis, the wizard presents a choice:

```
How do you want to provide the anthropic API key?
  1) Paste it here — stored in /etc/ezyshield/.env (recommended)
  2) I already have it in an env var (e.g. from sops / vault / LoadCredential)
```

**Option 1 (recommended for most people):** paste the key directly. Input is
echo-suppressed (like `sudo`). The key is written only to
`/etc/ezyshield/.env` (mode `0600 root:ezyshield`). `config.yaml` always
contains `api_key: env:ANTHROPIC_API_KEY` — the raw key value never touches
any config file, log, or process argument list.

**Option 2 (advanced — sops / vault / LoadCredential):** supply the env var
name where your platform already exposes the key. The wizard validates the
name with `^[A-Za-z_][A-Za-z0-9_]*$` and rejects any secret-shaped input
(issue #13 guard). Your key value is never touched or read by the wizard.

**`--yes` / non-interactive mode:** skips the key prompt. A placeholder entry
(`ANTHROPIC_API_KEY=YOUR_API_KEY_HERE`) is written to `/etc/ezyshield/.env`.
Edit the file and restart the daemon after provisioning.

In all cases the wizard also creates
`/etc/systemd/system/ezyshield.service.d/env.conf` containing:

```ini
[Service]
EnvironmentFile=-/etc/ezyshield/.env
```

This ensures the daemon picks up the key even on hosts running an older service
file. `systemctl daemon-reload` is run automatically before `enable --now`.

Canonical env var names (hardcoded, not user-configurable):

| Provider    | Env var             |
|-------------|---------------------|
| `anthropic` | `ANTHROPIC_API_KEY` |
| `openai`    | `OPENAI_API_KEY`    |
| `ollama`    | *(no key needed)*   |

> **Pré-flight (issue #5):** o wizard verifica logo no início se `config.yaml`
> ou `policy.yaml` já existem no diretório de destino (`--config-dir` ou o
> padrão `/etc/ezyshield`). Se qualquer um deles já existir, `ezyshield init`
> falha em menos de 1s — **antes** de imprimir o banner "Detecting
> environment..." — listando todos os caminhos pré-existentes num único erro
> para você removê-los de uma só vez. Isso evita responder o wizard inteiro
> só para descobrir no final que ele não conseguiria gravar. Para regenerar,
> remova os arquivos apontados e rode `sudo ezyshield init` de novo.

### `ezyshield doctor`

Validates all configuration and checks dependencies:

```bash
sudo ezyshield doctor
```

Expected output:

```
✓ config.yaml valid
✓ policy.yaml valid
✓ rules.yaml valid
✓ nftables accessible
✓ data directory writable
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
    socket: /run/ezyshield-enforcer/enforcer.sock   # default; omit to use default path
    table: inet ezyshield
    set: blocked
```

To enable local enforcement via nftables:

1. Make sure the privileged helper (`ezyshield-enforcer`) is running and listening on the configured unix socket (default: `/run/ezyshield-enforcer/enforcer.sock`).
2. Add the `enforce.nftables` section to `config.yaml` (as above).
3. Set `armed: true` in `policy.yaml`.
4. Start the daemon: `ezyshield watch`.

> **Note**: If the enforcer socket does not exist at startup, the daemon logs a WARN and continues operating — bans are stored in SQLite and applied when the helper becomes available (automatic reconnection).

### AI (optional — intelligent analysis)

```yaml
ai:
  provider: anthropic
  model: claude-haiku-4-5-20251001
  api_key: env:ANTHROPIC_API_KEY
  ambiguous_band: [30, 75]
  token_budget_daily: 500000
```

> **Important**: Secrets (tokens, passwords) must use `env:VAR_NAME` references.
> Inline values are rejected at config load time. The `ezyshield init` wizard
> always writes `env:CANONICAL_NAME` — the raw key value never enters
> `config.yaml`.

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

> **Deduplication semantics:** one *strike* represents one **attack episode**, not
> a single malicious request. While an IP is already banned (active record in
> `bans_active`), new detections are suppressed — no new strike is recorded, no
> RPC call to the enforcer is made, and only `offenders.last_seen` is updated.
> When the ban expires (via `ExpireBans`), the next detection advances to the next
> ladder level normally. This makes `offenders.total_strikes` a real recidivism
> indicator, not a raw request counter.

### Thresholds (score cutoffs)

```yaml
ban_threshold: 70       # score ≥ 70 → apply strike
observe_threshold: 40   # score 40–69 → log/notify, no ban
max_bans_per_minute: 30 # safety: pause enforcement if exceeded
```

---

## 6. Custom rules — rules.yaml

File at `/etc/ezyshield/rules.yaml`. Defines detection rules.

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

| Field        | Description                                        |
|--------------|----------------------------------------------------|
| `name`       | Unique rule identifier                             |
| `description`| Human-readable description                         |
| `kinds`      | Event types that activate the rule                 |
| `window`     | Time window for counting                           |
| `threshold`  | Number of occurrences to trigger                   |
| `score`      | Assigned score (0–100)                             |
| `category`   | Category (`bruteforce`, `scanner`, etc.)           |
| `field`      | Event field to filter (optional)                   |
| `value`      | Exact field value (optional)                       |
| `contains`   | Substring in the field (optional)                  |

### Example: custom rule for API scanners

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

> **Note**: A custom file completely replaces the default rules (no merge). Copy any built-in rules you want to keep.

---

## 7. Notifications

### Telegram

1. Create a bot via [@BotFather](https://t.me/BotFather) and get the token.
2. Add the bot to the group/channel and get the `chat_id`.
3. Export the token as an environment variable:

```bash
export EZYSHIELD_TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
```

4. Configure in `config.yaml`:

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

1. Export the SMTP password:

```bash
export EZYSHIELD_SMTP_PASSWORD="your-smtp-password"
```

2. Configure in `config.yaml`:

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

Available TLS modes:
- `starttls` — port 587 (default, recommended)
- `tls` — port 465 (implicit TLS)
- `none` — no encryption (not recommended)

---

## 8. Test notifications

After configuring, validate delivery without a real event:

```bash
# Test Telegram channel
sudo ezyshield test-notify telegram

# Test Email channel
sudo ezyshield test-notify email
```

If everything is correct, you will receive a test notification in the configured channel. On error, the output indicates the problem (invalid token, incorrect chat_id, SMTP failure, etc.).

Use `--json` for structured output:

```bash
sudo ezyshield test-notify telegram --json
```

---

## 9. Run the daemon

`watch` runs the full pipeline (collectors → detection → decision → enforcement
→ notification). While `armed: false` in `policy.yaml`, it operates in **dry-run**:
processes everything and logs what *would* be blocked, without touching the firewall.

```bash
# Foreground (dry-run while armed: false)
sudo ezyshield watch
```

> There is no separate `dry-run` command: dry-run is the default mode, controlled
> by `armed` in `policy.yaml`. Validate behavior with `armed: false` before
> switching to `armed: true`.

### As a systemd service

Ready-made units are included in [`configs/systemd/`](../configs/systemd/):
`ezyshield.service` (daemon) and `ezyshield-enforcer.service` (privileged helper
with `CAP_NET_ADMIN`). Install and activate:

```bash
sudo cp configs/systemd/ezyshield-enforcer.service /etc/systemd/system/
sudo cp configs/systemd/ezyshield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ezyshield-enforcer
sudo systemctl enable --now ezyshield
```

### Checklist before enabling

1. ✅ `ezyshield doctor` with no errors
2. ✅ `allowlist` with your access IPs
3. ✅ `admin_cidrs` with your SSH IP
4. ✅ Notifications tested with `test-notify`
5. ✅ `armed: false` to validate with dry-run first
6. ⬜ After validation, change to `armed: true`

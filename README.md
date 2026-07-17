<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/ezyshield-lockup-mono-white.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/logo/ezyshield-lockup-mono-dark.svg">
    <img src="assets/logo/ezyshield-lockup-mono-dark.svg" alt="EzyShield" width="400">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/evertramos/ezy-shield/actions/workflows/ci.yaml"><img src="https://github.com/evertramos/ezy-shield/actions/workflows/ci.yaml/badge.svg" alt="CI"></a>
  <a href="https://github.com/evertramos/ezy-shield/actions/workflows/codeql.yaml"><img src="https://github.com/evertramos/ezy-shield/actions/workflows/codeql.yaml/badge.svg" alt="CodeQL"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.24+-00ADD8.svg" alt="Go 1.24+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL%203.0-blue.svg" alt="License: AGPL-3.0"></a>
</p>

# EzyShield

**Intrusion blocking for Linux servers — fail2ban, a decade later.**

EzyShield watches your server logs, detects attacking IPs, and bans them with
escalating penalties: locally via nftables and at the edge via Cloudflare. A
deterministic rule engine scores every event offline and always works; AI is
consulted only for the ambiguous cases, so decisions stay cheap and the tool
runs fully offline if you never configure a provider. It ships as a single
static Go binary — no Python, no Java, no runtime to install.

> **Status: pre-alpha.** The pipeline, rule engine, nftables + Cloudflare
> enforcement, AI providers, and notifiers work today. Run in dry-run (the
> default) and please report bugs via [issues](https://github.com/evertramos/ezy-shield/issues).
> Interfaces may still change before 1.0.

---

## Quickstart

```sh
curl -sfL https://get.ezyshield.com | sudo sh    # install (verifies SHA-256)
sudo ezyshield init                              # guided setup — installs & starts the service
ezyshield status                                 # see what it *would* have banned (dry-run)
sudoedit /etc/ezyshield/policy.yaml              # set `armed: true` when you trust it
sudo systemctl restart ezyshield                 # apply the new policy
```

That's the whole loop: `init` leaves the daemon running in dry-run; observe
first, arm only once the decisions look right.

---

## Why EzyShield

| | fail2ban | CrowdSec | SSHGuard | EzyShield |
|---|---|---|---|---|
| Language / runtime | Python | Go | C | Go, single static binary |
| Setup | jails + regex filters | agent + Local API + remediation components (bouncers) | small config + firewall backend | `ezyshield init`, dry-run by default |
| Strike escalation | optional (`bantime.increment`, since 0.11) | per-scenario durations via profiles; escalation via custom expressions | yes — block time doubles per repeat offense | built in: 5min → 1h → 24h → 7d → permanent, history kept forever |
| Edge enforcement (CDN/WAF) | via bundled actions (incl. Cloudflare) | yes — remediation components incl. Cloudflare | no — local firewall backends only | built in (Cloudflare) |
| Shared threat intel | report-to actions (AbuseIPDB, DShield); no community blocklist | **yes — community blocklist + CTI; this is their core strength** | no | no — not built in today |
| Mandatory telemetry / account | none | signal sharing on by default (opt-out); console account optional | none | none |
| Anti-lockout guarantees | manual `ignoreip` | manual whitelists | manual whitelisting | automatic — SSH peer + admin CIDRs allowlisted before every rule write |
| AI usage | none | none | none | optional, ambiguous cases only; rule engine needs zero AI |

fail2ban is battle-tested and great at what it does; CrowdSec's community
blocklist is genuinely valuable and something EzyShield simply doesn't have;
SSHGuard is admirably small and fast. EzyShield's bet is different: strike
escalation, local **and** edge enforcement, and guardrails that make it hard
to ban yourself — out of the box, from a single binary. You can even run
EzyShield as the brain and keep fail2ban for enforcement.

<sub>Comparison verified against each project's docs as of July 2026 —
[fail2ban](https://github.com/fail2ban/fail2ban),
[CrowdSec](https://docs.crowdsec.net),
[SSHGuard](https://www.sshguard.net). Corrections welcome via
[issues](https://github.com/evertramos/ezy-shield/issues).</sub>

---

## How it works

```
logs (SSH, Nginx)
        │
        ▼
   [ Collector ]   ── tail file / journald
        │
        ▼
    [ Parser ]     ── structured event (IP, method, status, ...)
        │
        ▼
   [ Enricher ]    ── GeoIP / ASN / reputation
        │
        ▼
  [ Rule Engine ]  ── offline scoring (always runs)
        │
        ├──(ambiguous only)──▶ [ AI Analyzer ] ── Anthropic / OpenAI-compatible / Ollama
        │
        ▼
 [ Decision Engine ] ── strikes + TTL escalation + policy
        │
        ├──▶ [ Enforcer ] ── nftables (local) / Cloudflare (edge)
        └──▶ [ Notifier ] ── Telegram / Email / Slack / Discord / webhook
```

The whole path from parser to decision is side-effect-free and tested against
fixture logs. Firewall changes only happen through a small privilege-separated
helper (`ezyshield-enforcer`) that holds `CAP_NET_ADMIN` and accepts a fixed,
minimal verb set — the main daemon can never run arbitrary firewall commands.

### Strike escalation (configurable)

| Strike | Ban duration |
|--------|--------------|
| 1 | 5 minutes |
| 2 | 1 hour |
| 3 | 24 hours |
| 4 | 7 days |
| 5 | permanent |

Strike history is kept forever in SQLite, so a repeat offender from last month
still escalates today.

---

## Features (today)

- **Escalating bans** — short first ban, permanent after repeated offences
- **Local enforcement** — nftables, via a privilege-separated enforcer helper
- **Edge enforcement** — push IP bans to a Cloudflare list
- **SSH + Nginx parsers** with fuzz-tested, panic-safe parsing of hostile input
- **Deterministic rule engine** — thresholds + scanner signatures; works with zero AI configured
- **AI-assisted decisions (optional)** — Anthropic, any OpenAI-compatible endpoint, or local Ollama, with provider failover, a token budget, and verdict caching
- **Prompt-injection defense** — log lines are treated as data, never instructions; AI output is schema-validated and clamped by policy (it can only suggest within limits)
- **Anti-lockout** — active SSH peer + admin CIDRs auto-allowlisted before any rule write; allowlist always wins
- **Dry-run by default** — nothing is enforced until you set `armed: true`
- **Ban rate limit** — `max_bans_per_minute` (default 30) so a bad rule or poisoned feed can't ban the internet
- **Notifications** — Telegram, Email (SMTP), Slack, Discord, generic webhook
- **Service & port discovery** — `ezyshield scan` inventories what's actually listening on the host
- **Audit trail** — every action recorded in SQLite; JSON output for scripting
- **Localhost-only dashboard** — small web UI over 127.0.0.1 with status, active bans, allowlist, event log, live WebSocket updates and a strike timeline; CSRF-protected manual ban/unban/allow; access remotely via SSH tunnel or Cloudflare Tunnel (see [docs](docs/content/en/reference/dashboard.md) and the [remote-access guide](docs/content/en/guides/dashboard-remote-access.md))
- **Scriptable** — `--json` on commands; unix-socket control, no TCP port ever

---

## Your data is yours

No telemetry, no phone-home, no account, no data sharing required for any
feature. The rule engine scores everything offline; the only outbound
connections are the ones **you** configure (edge enforcement, notifiers, AI
providers) or run yourself (`ezyshield update`). AI is opt-in, and when
enabled the provider never sees your logs: it receives only aggregated
counters per IP — event kinds, counts, and GeoIP/ASN metadata if you've
configured the MaxMind databases — never raw log lines.
CI gates enforce that secrets and hostile log content can't reach the
request ([prompt-injection](internal/ai/prompt_injection_test.go) and
[secret-leak](internal/ai/secret_leak_test.go) tests).

### Our pledge

The local agent will never lose features to a paywall. The code is and stays
open under AGPL-3.0. If a paid offering ever exists, it will be about
coordination at scale — fleets, identity, compliance, support — never about
the protection itself. If EzyShield defends one server well, that part stays
free, forever. — [Evert](https://github.com/evertramos)

---

## Install

### Package manager (apt / dnf)

```sh
# Debian / Ubuntu
curl -fsSL https://packages.ezyshield.com/ezyshield.asc | sudo gpg --dearmor -o /usr/share/keyrings/ezyshield.gpg
echo "deb [signed-by=/usr/share/keyrings/ezyshield.gpg] https://packages.ezyshield.com/apt stable main" | sudo tee /etc/apt/sources.list.d/ezyshield.list
sudo apt update && sudo apt install ezyshield
```

GPG-signed repositories with `.deb` and `.rpm` for amd64/arm64 — dnf setup and details in the [install guide](docs/content/en/getting-started/install.md).

### Install script

```sh
curl -sfL https://get.ezyshield.com | sudo sh
```

Fetches the latest release binaries (`ezyshield` and `ezyshield-enforcer`) and
verifies their SHA-256 checksums.

### Specific version (including release candidates)

```sh
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0 sh
```

See the [install guide](docs/content/en/getting-started/install.md) for all options (air-gapped mirrors, from source, upgrading).

### From source (works today)

```sh
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
go build -o ezyshield ./cmd/ezyshield
go build -o ezyshield-enforcer ./cmd/ezyshield-enforcer
sudo mv ezyshield ezyshield-enforcer /usr/local/bin/
```

Requires **Go 1.24+** and Linux with **nftables** for local enforcement.

Then:

```sh
sudo ezyshield init      # create config under /etc/ezyshield
sudo ezyshield doctor    # validate config, permissions, and dependencies
```

> **Naming:** the binary is `ezyshield` and behaves exactly as `ezy shield`
> would in the wider `ezy` tool family — `ezyshield init` ≡ `ezy shield init`.

---

## Basic usage

```sh
# The daemon runs as a systemd service (installed and started by `init`)
sudo systemctl status ezyshield

# Inspect the running daemon
ezyshield status

# Manual ban / unban
sudo ezyshield ban 203.0.113.42
sudo ezyshield unban 203.0.113.42

# Permanently allow an IP or CIDR
sudo ezyshield allow 198.51.100.0/24

# See active bans / allowlist / recent events
ezyshield list

# Test a notification channel without waiting for a real event
sudo ezyshield test notifier telegram

# See what's listening on this host
sudo ezyshield scan
```

---

## Configuration

| File | Purpose |
|------|---------|
| `/etc/ezyshield/config.yaml` | Log sources, enforcement backends, AI providers, notifications |
| `/etc/ezyshield/policy.yaml` | Score thresholds, strike table, allowlists, rate limits |
| `/etc/ezyshield/rules.yaml` | Detection rules |

Secrets (API tokens, SMTP passwords) are **never** stored in YAML — reference
them as `env:VARNAME` or via systemd `LoadCredential=`. Inline secret values are
rejected when the config loads, and `ezyshield doctor` warns on bad file
permissions.

Minimal `config.yaml`:

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

notify:
  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_BOT_TOKEN
    chat_ids: ["-1001234567890"]
```

Start in dry-run (`armed: false` in `policy.yaml`), watch what it *would* block,
then arm it and restart the daemon (`sudo systemctl restart ezyshield` —
policy changes are read at startup). The full setup walkthrough — collectors, AI, notifications, custom
rules — is in [docs/content/en/getting-started/index.md](docs/content/en/getting-started/index.md).

---

## Roadmap

Everything listed under [Features](#features-today) is implemented, tested, and
shipping in the current release. We are preparing the roadmap for the next
versions — it will be published here. Ideas and requests are welcome in the
[issues](https://github.com/evertramos/ezy-shield/issues).

---

## Security

EzyShield is a root-capable security daemon and is built accordingly:
privilege separation for firewall writes, unix-socket control (no listening TCP
port), a localhost-only dashboard plan, anti-lockout, action rate limiting, and
secrets kept out of config and logs. Every change goes through a mandatory
security review.

Found a vulnerability? Please follow [SECURITY.md](SECURITY.md) — do not open a
public issue for security reports.

---

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first; a
[CLA](CLA.md) is required. Every PR ships code + tests + doc updates together,
and CI (lint, tests, CodeQL, fuzz, security gates) must be green to merge.

---

## ❤️ Sponsors

EzyShield is free and open source, and always will be (AGPL-3.0). If it keeps
your servers safer, consider sponsoring — it funds focused time to build this in
the open, independently.

[**→ Become a sponsor**](https://github.com/sponsors/evertramos)

<!-- sponsors --><!-- sponsors -->

---

## License

EzyShield is released under **AGPL-3.0** — see [LICENSE](LICENSE).

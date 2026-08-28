---
title: Unattended install (Ansible, cloud-init)
description: Provision EzyShield non-interactively with an answers file
order: 8
---

# Non-interactive install (automation)

`ezyshield init` is an interactive wizard by default. For Ansible, cloud-init,
Terraform, packer/golden images, or any scripted provisioning, run it
**non-interactively** instead: the same environment detection, the same
validation, and the exact same config the wizard produces — with no TTY and no
prompts.

```bash
ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
```

`--non-interactive` (short `-n`) is driven by an **answers file** (`--answers`)
and/or a small set of **override flags**. Passing `--answers` implies
`--non-interactive`. What it does:

- Detection still runs (nftables, Docker, web servers, SSH unit). Your answers
  **pin or override** the result.
- Missing or invalid answers produce **one error listing every problem at
  once**, a non-zero exit, and **nothing written** — a failed run never leaves
  a half-written `/etc/ezyshield`.
- The generated config is **always `armed: false`** (dry-run). You arm
  explicitly, later, after watching clean dry-run output.
- Re-running against an existing config **refuses without `--force`** (same as
  the wizard).
- Config and policy are written **atomically**.

> **Secrets are never passed as flags or answers-file values.** A flag or file
> value leaks into shell history and process lists. You reference an environment
> variable **NAME**; the real value goes in `/etc/ezyshield/.env` (mode `0600`)
> or a systemd credential. See [Secrets](#secrets) below.

## Answers file reference

The answers file is a YAML document. It mirrors the wizard's questions. **Every
key is optional** — omit a section to accept the detected/default behavior.
Unknown keys are rejected (so a typo fails loudly instead of doing nothing).

```yaml
# ── Collectors: where EzyShield reads logs from ────────────────────────────
collectors:
  # Monitor SSH via journald using the detected unit. Default: true.
  ssh: true

  # OPTIONAL. When present, this list REPLACES web-server auto-detection.
  # Omit the whole `web:` key to accept every detected web server instead.
  web:
    - kind: file                        # file | docker
      path: /var/log/nginx/access.log   # required for kind: file
      parser: nginx                     # nginx | apache | apache-error | traefik | caddy
    - kind: docker
      container: my-nginx               # required for kind: docker
      parser: nginx

# ── Allowlist: IPs/CIDRs that can NEVER be banned (anti-lockout) ───────────
allowlist:
  # Strongly recommended: your management IP(s). Omitting this leaves
  # admin_cidrs empty, and `ezyshield arm` will flag that before arming.
  admin_ips: [203.0.113.4, 10.0.0.0/24]

# ── AI analysis (optional) ─────────────────────────────────────────────────
ai:
  enabled: true
  provider: anthropic                   # anthropic | openai | ollama
  model: claude-haiku-4-5-20251001      # optional; per-provider default used when omitted
  # Env var NAME that holds the key — NOT the key itself. Optional; defaults to
  # the provider's canonical name (ANTHROPIC_API_KEY / OPENAI_API_KEY).
  api_key_env: ANTHROPIC_API_KEY

# ── Edge enforcement: Cloudflare (optional) ────────────────────────────────
enforce:
  cloudflare:
    - name: main                        # required when more than one account
      mode: lists                       # lists | rulesets (default: lists)
      account_id: 0123456789abcdef0123456789abcdef   # required for lists mode
      list_name: ezyshield_blocked      # optional (lists mode)
      zone_ids: []                      # required for rulesets; optional for lists
      action: block                     # block | challenge | js_challenge (default: block)
      # Env var NAME holding the token. Optional; derived from `name` when
      # omitted (CLOUDFLARE_API_TOKEN, or CLOUDFLARE_API_TOKEN_<NAME>).
      api_token_env: CLOUDFLARE_API_TOKEN

# ── Notification channels (optional) ───────────────────────────────────────
# One instance per channel type. Secrets follow the same rule as everywhere
# in this file: the *_env keys carry env var NAMES — a literal token/URL/
# password in the answers file is rejected before anything is written.
# Referenced vars are stubbed into .env as placeholders for you to fill.
notify:
  telegram:
    chat_ids: ["-1001234567890"]        # required
    severity: [critical]                # optional; empty = all
    bot_token_env: TELEGRAM_BOT_TOKEN   # optional; this is the default
  email:
    from: ezyshield@example.com         # required
    to: [admin@example.com]             # required
    host: smtp.example.com              # required
    port: 587                           # optional (default 587)
    username: ezyshield@example.com     # optional; empty = no auth
    tls: starttls                       # starttls | tls | none (default starttls)
    password_env: SMTP_PASSWORD         # optional; default when username set
  slack:
    channel: "#security"                # optional
    webhook_url_env: SLACK_WEBHOOK_URL  # optional; this is the default
  discord:
    webhook_url_env: DISCORD_WEBHOOK_URL
  webhook:
    url_env: WEBHOOK_URL
    auth_header_name: Authorization     # optional
    auth_header_value_env: WEBHOOK_AUTH_HEADER
```

`nftables` local enforcement is enabled automatically when `nft` is detected on
the host; there is no answer for it. Unlike the interactive wizard, which
offers to install a missing `nftables`, non-interactive init **never runs a
package manager** — it writes config only. On a host without `nft` it reports
the miss and continues (dry-run and edge enforcement still work); install
`nftables` beforehand, as the Ansible play below does.

## Override flags

Flags override the matching answers-file value (an unset flag never clobbers a
file value):

| Flag | Effect |
|------|--------|
| `--non-interactive`, `-n` | Activate the scripted path |
| `--answers PATH` | Read answers from PATH (implies `-n`) |
| `--force` | Overwrite an existing `config.yaml` / `policy.yaml` |
| `--config-dir DIR` | Write to DIR instead of `/etc/ezyshield` (skips system steps) |
| `--admin-ips "IP,CIDR"` | Override `allowlist.admin_ips` |
| `--monitor-ssh` | Override `collectors.ssh` |
| `--enable-ai` | Override `ai.enabled` |
| `--ai-provider NAME` | Override `ai.provider` |
| `--ai-model NAME` | Override `ai.model` |
| `--ai-key-env NAME` | Override `ai.api_key_env` (an env var **NAME**, never a key) |
| `--json` | Emit the summary as JSON on stdout (progress goes to stderr) |

A flags-only run needs no answers file at all:

```bash
ezyshield init -n --admin-ips "203.0.113.4" --enable-ai --ai-provider anthropic
```

## Secrets

The generated `config.yaml` never contains a secret — credential fields are
written as `env:VARNAME` references. For every referenced variable, init writes
a **placeholder** line into `/etc/ezyshield/.env` (mode `0600`) so you have a
discoverable slot and systemd's `EnvironmentFile=` never fails:

```
ANTHROPIC_API_KEY=YOUR_API_KEY_HERE
CLOUDFLARE_API_TOKEN=YOUR_API_KEY_HERE
```

Your automation replaces those placeholders with the real values from your
secret store (Ansible Vault, sops, cloud-init secrets, systemd
`LoadCredential=`). A re-run **preserves** any real value already present — it
only stubs what is missing.

## Ansible

```yaml
- name: Provision EzyShield in dry-run
  hosts: webservers
  become: true
  tasks:
    - name: Ensure nftables is installed (init never installs packages)
      ansible.builtin.package:
        name: nftables
        state: present

    - name: Write the answers file
      ansible.builtin.copy:
        dest: /etc/ezyshield/init.yaml
        mode: "0600"
        content: |
          collectors:
            ssh: true
          allowlist:
            admin_ips: ["{{ ansible_default_ipv4.address }}"]
          ai:
            enabled: true
            provider: anthropic
            api_key_env: ANTHROPIC_API_KEY

    - name: Run non-interactive init
      ansible.builtin.command:
        cmd: ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
        creates: /etc/ezyshield/config.yaml   # idempotent: skip if already provisioned

    - name: Install the API key from Vault into .env
      ansible.builtin.lineinfile:
        path: /etc/ezyshield/.env
        regexp: '^ANTHROPIC_API_KEY='
        line: "ANTHROPIC_API_KEY={{ vault_anthropic_api_key }}"
        mode: "0600"
      no_log: true

    - name: Enable and start services (still dry-run until you arm)
      ansible.builtin.systemd:
        name: "{{ item }}"
        enabled: true
        state: started
      loop:
        - ezyshield-enforcer
        - ezyshield
```

The `creates:` guard and init's own `--force`-less refusal give you two
independent layers of idempotency: re-running the playbook neither re-runs init
nor overwrites the config.

## cloud-init

```yaml
#cloud-config
write_files:
  - path: /etc/ezyshield/init.yaml
    permissions: "0600"
    content: |
      collectors:
        ssh: true
      allowlist:
        admin_ips: [203.0.113.4]
runcmd:
  - ezyshield init --non-interactive --answers /etc/ezyshield/init.yaml
  # Inject the real secret from your instance metadata / secret store here,
  # then: systemctl enable --now ezyshield-enforcer ezyshield
```

## Verifying in CI

`--json` gives a machine-readable summary you can assert on in a pipeline:

```bash
ezyshield init -n --config-dir ./out --json | jq -e '.armed == false'
```

```json
{
  "mode": "DRY-RUN (logging only, nothing blocked)",
  "armed": false,
  "config_dir": "/etc/ezyshield",
  "configured": ["collector: journald (SSH unit ssh)", "enforcer: nftables (/usr/sbin/nft)"],
  "skipped": ["AI analysis — disabled (rule engine only)"],
  "files": ["/etc/ezyshield/config.yaml", "/etc/ezyshield/policy.yaml (armed: false)"],
  "next_steps": ["ezyshield doctor — verify the configuration", "..."]
}
```

## Arming

Non-interactive init is deliberately always dry-run. When you have watched clean
output for a day or so, arm explicitly — from your automation or by hand:

```bash
ezyshield arm      # refuses if admin_cidrs is empty; verifies enforcement first
```

See the [CLI reference](../reference/cli.md) for `doctor`, `watch`, and `arm`.

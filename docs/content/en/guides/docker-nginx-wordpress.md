---
title: Docker + nginx + WordPress
description: Protect a Docker host with nginx proxy
order: 2
---

# Deploying EzyShield — Docker host with nginx-proxy + multiple WordPress containers

This walks a server admin through protecting a typical setup: one host running
Docker, an **nginx reverse proxy** container in front of several **WordPress**
containers. The attacks you care about here are SSH brute force on the host,
WordPress login brute force (`/wp-login.php`, `/xmlrpc.php`), and bot/scanner
scraping — all blocked at the host firewall (and optionally at Cloudflare).

---

## 0. The key idea (read this first)

EzyShield runs **on the host, not inside a container.** It needs to (a) read the
proxy's access logs and the host's SSH logs, and (b) write firewall rules in the
host kernel. A container can't safely do either. So we install the binary on the
host and just point it at the log files your containers already write.

The one thing you must get right: **the real visitor IP has to reach the logs.**
Behind Docker, your nginx proxy sees the Docker bridge IP unless it's configured
to record `X-Forwarded-For`. Section 3 handles this — if you skip it, EzyShield
will try to ban Docker's internal network. (Anti-lockout stops the worst of it,
but fix it properly.)

---

## 1. Prerequisites

- Linux host (Ubuntu 22.04+/Debian 12+/RHEL 9+), root/sudo access
- `nftables` available on the host (`nft --version`)
- Your proxy writing access logs to a path on the host (a bind-mount, see §3)
- Optional: a Telegram bot token, and/or a Cloudflare API token

---

## 2. Install (on the host)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
ezyshield version
```

Or install the signed `.deb`/`.rpm` — see the [install guide](../getting-started/install.md).

Until the installer exists, build from source:

```bash
git clone https://github.com/youruser/yourrepo.git && cd yourrepo
make build && sudo install -m0755 ./bin/ezyshield /usr/local/bin/ezyshield
```

---

## 3. Make sure the proxy logs the *real* client IP

Two parts: the proxy must **record** the real IP, and EzyShield must be able to
**read** the log file on the host.

### 3a. Expose the log file to the host

You have **two options** — pick one:

**Option A — bind-mount the proxy's log dir (explicit, simplest to reason about):**

```yaml
services:
  nginx-proxy:
    image: nginxproxy/nginx-proxy   # or your own nginx
    volumes:
      - /var/log/nginx-proxy:/var/log/nginx   # <-- host path : container path
    # ...
```

Now the host sees access logs at `/var/log/nginx-proxy/access.log`.

**Option B — just read Docker's own captured stdout (no bind-mount needed):**
If your containers log to stdout (the default for official nginx/WordPress images)
and you use the `json-file` driver with rotation — like the popular
[evertramos/nginx-proxy-automation](https://github.com/evertramos/nginx-proxy-automation)
setup does — Docker already stores those logs on the host at:

```
/var/lib/docker/containers/<container-id>/<container-id>-json.log
```

EzyShield can read these directly — find the container id with
`docker ps --no-trunc`. Set a sane rotation in your compose so the files
don't grow forever:

```yaml
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
```

> Option B is convenient and keeps your compose clean; Option A gives you a stable,
> human-readable path independent of container IDs (which change on recreate).
> If you recreate containers often, prefer A — the path in B changes with the
> container ID.

### 3b. Record the real client IP
If clients hit nginx **directly**, default logs already contain the real IP — done.

If there's something in front (Cloudflare, a load balancer, another proxy),
nginx sees *that* as the client. Configure `real_ip` so the logged `$remote_addr`
is the true visitor (and so EzyShield doesn't ban your CDN):

```nginx
# in the proxy's nginx config
set_real_ip_from 173.245.48.0/20;   # your trusted upstream / Cloudflare ranges
real_ip_header   X-Forwarded-For;
real_ip_recursive on;
```

> **Critical safety note:** only trust `X-Forwarded-For` from upstreams you
> actually control (the `set_real_ip_from` ranges above). If the proxy trusts it
> from everyone, attackers spoof the header and can get *innocent* IPs banned.
> EzyShield reads whatever real IP the proxy resolves into the log line — get the
> nginx side right and EzyShield bans the right address.

### 3c. Per-container WordPress logs (optional)
If you'd rather read each WordPress container's own access log, bind-mount each
one out and add them all in §4. Usually the single proxy log is enough and
simpler — start there.

---

## 4. Configure EzyShield

```bash
sudo ezyshield init      # interactive wizard; writes /etc/ezyshield/*.yaml
```

> **Pre-flight:** before printing the "Detecting environment..."
> banner, `ezyshield init` stats `<config-dir>/config.yaml` and
> `<config-dir>/policy.yaml`. If either already exists, the wizard fails fast
> (within ~1s) with a single error listing every pre-existing path — so you
> don't answer the entire questionnaire only to be told at the end that it
> couldn't write. To regenerate, delete the listed files and re-run. The same
> check honours `--config-dir <path>` for non-default target directories.

Or write `/etc/ezyshield/config.yaml` directly. Collectors read your logs;
enforcement and notifications are configured here, while thresholds and the
allowlist live in `policy.yaml`:

```yaml
# /etc/ezyshield/config.yaml — what to watch and how to act
collectors:
  - kind: journald            # host SSH brute force
    unit: ssh
  - kind: file                # the proxy's access log
    path: /var/log/nginx-proxy/access.log
    parser: nginx

enforce:
  nftables: {}                # local firewall (default table/set)

notify:
  telegram:
    bot_token: env:EZYSHIELD_TELEGRAM_TOKEN   # secrets come from env, never inline
    chat_ids: ["987654321"]
```

```yaml
# /etc/ezyshield/policy.yaml — decisions, escalation, and safety
armed: false                  # dry-run until you're confident (default)
ban_threshold: 70

strikes:
  - ttl: 5m
  - ttl: 1h
  - ttl: 24h
  - ttl: 168h
  - ttl: 0                    # permanent

# Never block these — your own access. Current SSH peer + admin_cidrs are
# auto-allowlisted before every ban.
allowlist:
  - 203.0.113.7               # your home/office IP  (CHANGE THIS)
admin_cidrs:
  - 192.0.2.0/24
```

WordPress signatures (wp-login.php / xmlrpc.php floods, exploit-probe paths)
are built into the shipped rules — no configuration needed. To customize
thresholds, point `rules_path` in config.yaml at your own copy of
`/etc/ezyshield/rules.yaml.example`.

Secrets go in an env file the systemd unit loads (`ezyshield init` creates it
at mode 0600; `doctor` checks its permissions):

```bash
sudo tee /etc/ezyshield/.env >/dev/null <<'EOF'
EZYSHIELD_TELEGRAM_TOKEN=123456:abc...
EOF
sudo chmod 600 /etc/ezyshield/.env
```

---

## 5. Verify before you arm it

```bash
sudo ezyshield doctor          # checks config, perms, nft, log readability
sudo ezyshield config validate # strict schema check
sudo ezyshield test notifier telegram
```

Then run the daemon in the foreground and watch what it *would* do (it stays in
dry-run until you set `armed: true`):

```bash
sudo ezyshield run             # logs "dry_ban (would ban ...)" decisions
```

Let this run during real traffic for a day. Confirm:
- it flags actual attackers (try a few bad SSH logins from your phone's hotspot)
- it does **not** flag your own IP, your CDN, or the Docker network
- the IPs shown are real visitor IPs, not `172.x` Docker addresses (if they are,
  fix §3b)

---

## 6. Arm it

Flip `armed: true` in config, then run it for real as a service:

The systemd units are installed by `ezyshield init` (or the deb/rpm package).
Enable and start:

```bash
sudo systemctl enable --now ezyshield-enforcer ezyshield
systemctl status ezyshield
```

Now bans are live. Watch them:

```bash
ezyshield status                 # daemon/enforcer health, mode, active bans
ezyshield list                   # currently banned IPs + strike # + expiry
ezyshield watch                  # live event stream in your terminal
```

Manual control any time:

```bash
sudo ezyshield ban 203.0.113.7 --ttl 24h --reason "manual"
sudo ezyshield unban 203.0.113.7
sudo ezyshield allow 198.51.100.9     # add to allowlist
```

---

## 7. Optional: also block at Cloudflare

If your WordPress sites sit behind Cloudflare, blocking at the edge stops
attackers before they even reach your host:

```yaml
enforce:
  nftables: {}
  cloudflare:
    api_token: env:CF_API_TOKEN     # scope it to "Account Filter Lists: Edit"
    account_id: "your-account-id"   # required in the default "lists" mode
```

EzyShield then writes bans to *both* the host firewall and Cloudflare, and keeps
them in sync. See the [Cloudflare guide](cloudflare.md) for token scoping and
the lists-vs-rulesets modes.

---

## 8. Optional: turn on AI analysis

The rule engine works with no AI at all. To let AI judge the ambiguous cases
(is this aggressive crawler a real user or a scraper?):

```yaml
ai:
  provider: anthropic            # anthropic | openai | ollama
  model: claude-3-5-haiku-latest
  api_key: env:ANTHROPIC_API_KEY
  token_budget_daily: 50000      # hard daily cap; rule engine takes over if exceeded
```

Only suspicious aggregates get sent, already minimized to summaries like
`IP 203.0.113.7 → 412 POSTs to /wp-login.php in 60s`, and verdicts are cached — so
token usage stays tiny.

---

## 9. If something goes wrong — panic button

Stop new bans immediately and drop every local block at once:

```bash
sudo systemctl stop ezyshield          # daemon stops deciding
sudo nft delete table inet ezyshield   # all local blocks gone in one command
```

EzyShield keeps every rule it writes inside its own `inet ezyshield` table and
never touches rules outside it — deleting that table clears all of EzyShield's
local blocks and nothing else. It also never blocks your active SSH session
(anti-lockout re-checks before every ban).

To unblock a specific IP everywhere (host **and** the configured Cloudflare
edge):

```bash
sudo ezyshield unban 203.0.113.7
```

Cloudflare edge entries are removed per-IP by `unban`. To clear an entire edge
list at once, use the Cloudflare dashboard (Manage Account → Configurations →
Lists) — a block at the edge keeps rejecting traffic even after you stop the
local daemon, so don't forget it.

To remove EzyShield from the host completely, use `scripts/wipe.sh` (stops and
removes services, units, binaries, nftables rules, the service user, and —
optionally — data).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| It's banning `172.x.x.x` / Docker IPs | proxy logs container IP, not client | configure nginx `real_ip` (§3b) |
| Nothing is detected | wrong log path or format | `ezyshield doctor`; check `format: json` vs `combined` |
| Got briefly locked out | allowlist missing your IP | anti-lockout should prevent it; add your IP to `allowlist` |
| Telegram silent | token/chat_id or env not loaded | `ezyshield test notifier telegram`; check `ezyshield.env` perms |
| Real visitors blocked | proxy trusts XFF from untrusted source | tighten `set_real_ip_from` to upstreams you control |
| Warned "this might be a Cloudflare IP" | logs show CDN edge, not visitor | fix nginx `real_ip` (§3b); never hard-ban a CDN range |
| Warned "source is internal/private" | attack from inside the LAN | real possibility (insider/compromised host) — investigate the box, don't just ban |

---

## TL;DR

1. Install the binary **on the host** (not in a container).
2. Bind-mount your proxy's access log to the host; make sure it logs the **real** client IP.
3. `ezyshield init`, set your IP in the allowlist, keep `armed: false`.
4. `ezyshield dry-run` for a day, confirm it's sane.
5. Flip `armed: true`, `systemctl enable --now ezyshield`.
6. (Optional) add Cloudflare edge blocking and/or AI analysis.

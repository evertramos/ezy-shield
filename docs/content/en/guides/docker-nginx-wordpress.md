---
title: Docker + nginx + WordPress
description: Protect a Docker host with nginx proxy
order: 2
---

# Deploying EzyShield — Docker host with nginx-proxy + multiple WordPress containers

> ⚠️ **Status: this is the *intended* user experience.** EzyShield is pre-alpha;
> commands marked 🚧 don't exist yet. This guide doubles as the spec for how the
> MVP must feel to use. Once Phase 1 lands, every step here should "just work."

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
# 🚧 planned installer
curl -sfL https://get.example.com | sh
ezyshield version
```

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

EzyShield can read these directly. Even better, you don't need to find the path
by hand: `ezyshield scan` (see §3d) discovers each container, its logging driver,
and the exact log path for you, then offers to add it to the config. Set a sane
rotation in your compose so the files don't grow forever:

```yaml
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
```

> Option B is convenient and keeps your compose clean; Option A gives you a stable,
> human-readable path independent of container IDs (which change on recreate).
> If you recreate containers often, prefer A or let `ezyshield scan` re-resolve B.

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
> actually control. If you trust it from everyone, attackers spoof the header and
> can get *innocent* IPs banned. You'll tell EzyShield the same trusted ranges in
> §4 (`trusted_proxies`) so it parses the header the same safe way.

### 3c. Per-container WordPress logs (optional)
If you'd rather read each WordPress container's own access log, bind-mount each
one out (or let `ezyshield scan` find them) and add them all in §4. Usually the
single proxy log is enough and simpler — start there.

### 3d. Let EzyShield discover your services (recommended)

Before configuring anything by hand, run a scan:

```bash
sudo ezyshield scan      # 🚧 inventory listeners, containers, and their logs
```

It walks every listening port and reports something like:

```
PORT   BIND       OWNER                         LOGS                          NOTE
443    0.0.0.0    container nginx-proxy (image)  /var/lib/docker/.../*-json.log  public
80     0.0.0.0    container nginx-proxy          (same)                          public
3306   127.0.0.1  container wordpress-db         journald                        local-only ✓
22     0.0.0.0    sshd (systemd)                 journald (sshd.service)         public
8080   0.0.0.0    container api (image foo)       NOT FOUND                       ⚠ no logs
```

Two things to act on:
- **`⚠ no logs`** — EzyShield can't protect what it can't see. It tells you exactly
  which service is exposed without a log source so you can point it at one (or
  decide it shouldn't be public at all).
- **anything public you didn't expect** — a scan is also a free audit of your
  attack surface. If `8080` shouldn't be open to the world, that's a finding.

If you re-run `ezyshield scan` later and a **new** listener appeared since the
baseline, EzyShield flags it as suspicious and (once armed) notifies you — an
unexpected new open port is a classic sign of a backdoor:

```
⚠ NEW listener since last scan: port 4444, /tmp/.sys (user www-data) — investigate
```

You can also have the daemon rescan on a schedule (`scan.interval` in config).

---

## 4. Configure EzyShield

```bash
sudo ezyshield init      # 🚧 interactive wizard; writes /etc/ezyshield/*.yaml
```

> **Pre-flight (issue #5):** before printing the "Detecting environment..."
> banner, `ezyshield init` stats `<config-dir>/config.yaml` and
> `<config-dir>/policy.yaml`. If either already exists, the wizard fails fast
> (within ~1s) with a single error listing every pre-existing path — so you
> don't answer the entire questionnaire only to be told at the end that it
> couldn't write. To regenerate, delete the listed files and re-run. The same
> check honours `--config-dir <path>` for non-default target directories.

Or write `/etc/ezyshield/config.yaml` directly:

```yaml
# What to watch
collectors:
  - type: authlog          # host SSH brute force
    path: /var/log/auth.log
  - type: nginx
    path: /var/log/nginx-proxy/access.log
    format: combined        # or "json" if your proxy logs JSON

# Trust X-Forwarded-For ONLY from these (must match §3b)
trusted_proxies:
  - 173.245.48.0/20         # e.g. Cloudflare; or 172.16.0.0/12 for docker bridge
                            # if your in-front proxy lives on the docker network

# Never block these — your own access
allowlist:
  - 203.0.113.7/32          # your home/office IP  (CHANGE THIS)
  # current SSH session + admin IPs are auto-added by anti-lockout

# Firewall backend
enforce:
  backend: nftables

# Start SAFE: observe only, block nothing yet
armed: false                # dry-run until you're confident (default)

notify:
  telegram:
    enabled: true
    bot_token: env:TELEGRAM_BOT_TOKEN   # secrets come from env, never inline
    chat_id: env:TELEGRAM_CHAT_ID
```

`/etc/ezyshield/policy.yaml` (the strike escalation — defaults shown):

```yaml
ban_threshold: 70
strikes:
  - 5m
  - 1h
  - 24h
  - 7d
  - permanent
# WordPress-specific signatures are built in (wp-login.php, xmlrpc.php floods);
# you can add your own:
signatures:
  paths: ["/wp-login.php", "/xmlrpc.php", "/.env", "/wp-config.php.bak"]
```

Put secrets in an env file readable only by root (perms enforced by `doctor`):

```bash
sudo tee /etc/ezyshield/ezyshield.env >/dev/null <<'EOF'
TELEGRAM_BOT_TOKEN=123456:abc...
TELEGRAM_CHAT_ID=987654321
EOF
sudo chmod 600 /etc/ezyshield/ezyshield.env
```

---

## 5. Verify before you arm it

```bash
sudo ezyshield doctor          # 🚧 checks config, perms, nft, log readability
sudo ezyshield test notifier telegram
```

Then watch what it *would* do, without blocking anything:

```bash
sudo ezyshield dry-run --since 1h     # 🚧 prints "would ban x.x.x.x — wp-login flood"
```

Let this run during real traffic for a day. Confirm:
- it flags actual attackers (try a few bad SSH logins from your phone's hotspot)
- it does **not** flag your own IP, your CDN, or the Docker network
- the IPs shown are real visitor IPs, not `172.x` Docker addresses (if they are,
  fix §3b)

---

## 6. Arm it

Flip `armed: true` in config, then run it for real as a service:

```bash
sudo ezyshield install-service   # 🚧 drops the hardened systemd units
sudo systemctl enable --now ezyshield
systemctl status ezyshield
```

Now bans are live. Watch them:

```bash
ezyshield status                 # health, providers, today's token spend
ezyshield list --active          # currently banned IPs + strike # + expiry
ezyshield watch --follow         # 🚧 live event stream in your terminal
```

Manual control any time:

```bash
sudo ezyshield ban 1.2.3.4 --ttl 24h --reason "manual"
sudo ezyshield unban 1.2.3.4
sudo ezyshield allow 5.6.7.8     # add to allowlist
```

---

## 7. Optional: also block at Cloudflare (Phase 2)

If your WordPress sites sit behind Cloudflare, blocking at the edge stops
attackers before they even reach your host:

```yaml
enforce:
  backend: nftables
  edge:
    - type: cloudflare
      api_token: env:CF_API_TOKEN     # scope it to "Firewall Services: Edit" only
      zone: example.com
      block_by: [ip, asn]             # can also block whole hostile ASNs
```

EzyShield then writes bans to *both* the host firewall and Cloudflare, and keeps
them in sync.

---

## 8. Optional: turn on AI analysis (Phase 1/2)

The rule engine works with no AI at all. To let AI judge the ambiguous cases
(is this aggressive crawler a real user or a scraper?):

```yaml
ai:
  provider: anthropic            # or claude-cli, ollama (local), openai-compat
  api_key: env:ANTHROPIC_API_KEY
  daily_token_budget: 50000      # hard cap; rule engine takes over if exceeded
```

Only suspicious aggregates get sent, already minimized to summaries like
`IP 1.2.3.4 → 412 POSTs to /wp-login.php in 60s`, and verdicts are cached — so
token usage stays tiny.

---

## 9. If something goes wrong — panic button

```bash
sudo ezyshield disable --all     # 🚧 flush ALL EzyShield blocks, everywhere
```

This removes EzyShield's blocks from **both** the host firewall **and every
configured edge** (Cloudflare, Bunny, AWS) — important, because a block at
Cloudflare keeps rejecting traffic even after you stop the local daemon. The
command reports each target's result, e.g.:

```
local nftables ........ flushed (1,204 entries)
cloudflare (example.com) flushed (1,180 rules)
```

If an edge API is slow or unreachable and you need the host unblocked *now*:

```bash
sudo ezyshield disable --local-only   # 🚧 host firewall only; edge left as-is
```

Worst case, drop the local table directly:

```bash
sudo nft delete table inet ezyshield
```

(That only clears the **local** firewall — Cloudflare rules would remain until
`disable --all` runs or you remove them in the Cloudflare dashboard.)

EzyShield never touches rules outside its own `inet ezyshield` table, and never
blocks your active SSH session — but the panic command is there regardless.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| It's banning `172.x.x.x` / Docker IPs | proxy logs container IP, not client | configure `real_ip` (§3b) + `trusted_proxies` (§4) |
| Nothing is detected | wrong log path or format | `ezyshield doctor`; check `format: json` vs `combined` |
| Got briefly locked out | allowlist missing your IP | anti-lockout should prevent it; add your IP to `allowlist` |
| Telegram silent | token/chat_id or env not loaded | `ezyshield test notifier telegram`; check `ezyshield.env` perms |
| Real visitors blocked | trusting XFF from untrusted source | tighten `trusted_proxies` to upstreams you control |
| Warned "this might be a Cloudflare IP" | logs show CDN edge, not visitor | fix `real_ip`/`trusted_proxies`; never hard-ban a CDN range |
| Warned "source is internal/private" | attack from inside the LAN | real possibility (insider/compromised host) — investigate the box, don't just ban |

---

## TL;DR

1. Install the binary **on the host** (not in a container).
2. Bind-mount your proxy's access log to the host; make sure it logs the **real** client IP.
3. `ezyshield init`, set your IP in the allowlist, keep `armed: false`.
4. `ezyshield dry-run` for a day, confirm it's sane.
5. Flip `armed: true`, `systemctl enable --now ezyshield`.
6. (Optional) add Cloudflare edge blocking and/or AI analysis.

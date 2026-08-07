---
title: Remote Access
description: How to securely access the dashboard from your local machine
order: 4
---

# Remote access to the dashboard

The EzyShield dashboard binds **only** to loopback (`127.0.0.1` or
`::1`). This is a hard rule: it will refuse to start on any other
address. That leaves the operator to bring the connection in from
outside — from a laptop, a phone, or a bastion — through a channel
that already speaks TLS or is otherwise trusted.

This guide covers the three transport patterns we recommend, in
order of "easiest first".

## Option 1: SSH port-forward (recommended)

The simplest option. Nothing extra runs on the server. From your
local machine:

```bash
ssh -L 9090:127.0.0.1:9090 operator@server.example.com
```

Then open `http://localhost:9090` in your browser. Traffic is
tunneled through the SSH channel; the dashboard on the server sees a
local connection.

### Background tunnel

If you want the tunnel to stay up without holding a terminal open:

```bash
ssh -fN -L 9090:127.0.0.1:9090 operator@server.example.com
```

- `-f` sends the process to the background *after* authentication.
- `-N` says "don't run a remote command" — the tunnel is the whole
  point.

To kill it later:

```bash
kill $(pgrep -f "ssh -fN -L 9090")
```

### Persistent setup via ~/.ssh/config

Put the tunnel definition in your SSH config so you can start it
with a single word:

```
Host ezyshield-dashboard
    HostName server.example.com
    User operator
    LocalForward 9090 127.0.0.1:9090
    # Optional: keep the connection alive through NATs.
    ServerAliveInterval 30
    ServerAliveCountMax 3
    # Optional: die quietly if the server disappears.
    ExitOnForwardFailure yes
```

Then:

```bash
ssh ezyshield-dashboard
# open http://localhost:9090 in your browser
```

Add `-fN` to send it to background, add `-o RemoteCommand=none` if
your account is set up with a forced command.

### Notes

- If port 9090 is already in use locally, pick any free port and
  change the first number: `-L 9091:127.0.0.1:9090` maps
  `http://localhost:9091` to the server-side 9090.
- The tunnel gives you exactly what a local session gives — no
  extra multi-user story, no team access controls, one login at a
  time. That's fine for the current single-admin scope.

## Option 2: Cloudflare Tunnel (persistent, no open ports)

Good when you want a stable URL you can bookmark and share with
Cloudflare Access policies gating who can reach it. The server never
opens a listening port beyond `cloudflared`'s outbound connection to
Cloudflare.

High-level steps:

1. Create a Cloudflare account and a zone you control.
2. Install `cloudflared` on the server:
   <https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/>
3. Authenticate: `cloudflared tunnel login` — this opens a browser
   flow tied to your Cloudflare account.
4. Create a tunnel: `cloudflared tunnel create ezyshield`.
5. Route it to a hostname: `cloudflared tunnel route dns ezyshield
   dashboard.your-domain.example`.
6. Configure the ingress in `~/.cloudflared/config.yml`:

   ```yaml
   tunnel: ezyshield
   credentials-file: /root/.cloudflared/<tunnel-uuid>.json
   ingress:
     - hostname: dashboard.your-domain.example
       service: http://127.0.0.1:9090
     - service: http_status:404
   ```

7. Run it: `cloudflared tunnel run ezyshield`, or install as a
   service.
8. **Gate access via Cloudflare Access.** In the Cloudflare Zero
   Trust dashboard, add an Access application for
   `dashboard.your-domain.example` and require an identity provider
   (Google, GitHub, Okta, one-time PIN via email, etc.). Without
   this step anyone with the URL can reach the login page.

Reference:
<https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/>

The dashboard on the server still binds only to `127.0.0.1` — only
`cloudflared` speaks to it, and only Cloudflare speaks to
`cloudflared`.

## Option 3: Tailscale (private mesh, zero config)

Good when you already have a Tailscale mesh across your team and
machines. Install Tailscale on the server and on your laptop and log
in to the same tailnet. Traffic goes peer-to-peer through the mesh,
encrypted with WireGuard — no public IP or DNS entry needed — and you
can restrict access with ACLs in the Tailscale admin panel.

**Important:** the dashboard binds `127.0.0.1:9090` only, and its
loopback check rejects any non-loopback bind, so you **cannot** just
browse the server's tailnet address on port 9090. A default
(kernel-mode) Tailscale install does not forward tailnet-destined
traffic to a loopback-only listener — a request to
`http://<server-tailnet-name>:9090` reaches `100.x.y.z:9090`, finds no
listener, and is refused. (It fails closed — no security hole — but it
does not work as a bare URL.) Bridge the tailnet to the loopback
dashboard one of two ways:

- **`tailscale serve`** — Tailscale's built-in reverse proxy. On the
  server:

  ```bash
  # Proxy the node's tailnet address (HTTPS) to the local dashboard on :9090.
  sudo tailscale serve --bg 9090
  tailscale serve status   # verify; run `tailscale serve --help` to undo
  ```

  Then open `https://<server>.<tailnet>.ts.net/` from any device on the
  tailnet. Tailscale terminates the connection and forwards it to
  `127.0.0.1:9090`, so the dashboard still sees a loopback client and its
  bind check is satisfied. (HTTPS serve requires HTTPS certificates enabled
  for your tailnet; exact flags vary by Tailscale version.)

- **SSH tunnel over Tailscale** — identical to Option 1, but point SSH at
  the tailnet name so no port is ever exposed:

  ```bash
  ssh -L 9090:127.0.0.1:9090 <user>@<server-tailnet-name>
  # then open http://localhost:9090
  ```

Reference: <https://tailscale.com/kb/1017/install/> ·
<https://tailscale.com/docs/features/tailscale-serve>

## Never expose 0.0.0.0

For completeness: don't. Even if you set the config to
`addr: 0.0.0.0:9090` the dashboard will refuse to start with an
explicit error citing `AGENTS.md §2`. This is intentional. If you
find yourself wanting to bypass it, one of the three options above
almost certainly meets your real need — a persistent remote path
without an exposed listener.

## What if the daemon is offline?

None of these transports interact with the daemon connection: the
dashboard reaches the daemon over a local unix socket in every case.
If the daemon is stopped, every remote-access option above still
delivers the dashboard's "Daemon is offline" banner instead of live
data. Fix the daemon (`systemctl status ezyshield`) — the tunnel
doesn't need to change.

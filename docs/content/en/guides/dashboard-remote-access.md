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
    HostName your-server.com
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
machines. Install Tailscale on the server and on your laptop, log in
to the same tailnet, then open `http://<server-tailnet-name>:9090`
from the laptop.

Since Tailscale doesn't need a public IP or DNS entry — traffic goes
peer-to-peer through the mesh, encrypted with WireGuard — the
dashboard remains as private as it was. You can restrict access
further with ACLs in the Tailscale admin panel.

Reference: <https://tailscale.com/kb/1017/install/>

Note that the dashboard's own loopback bind check does **not**
accept the tailnet interface. You still need to reach the daemon
through the tailscale interface on the client side, which is what
Tailscale does transparently — you type `http://kylian-s:9090` and
Tailscale routes it to the loopback on that host.

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

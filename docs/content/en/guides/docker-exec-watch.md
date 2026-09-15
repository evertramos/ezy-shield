---
title: Docker Exec Watch
description: Post-exploitation visibility — every `docker exec` into your containers, observed
order: 22
---

# Docker Exec Watch

Log-based detection is blind to what happens **after** a successful intrusion. On docker hosts one cheap, high-signal source exists: the docker events API emits an event for every `docker exec` into a container. A shell spawned inside your web container at 3am is a strong post-exploitation indicator that no log parser will ever see.

## Honest scope (read first)

This is **detection and visibility, not prevention**: EzyShield observes and reports exec activity; it does not block or kill anything, and **no ban ever derives from it** — an exec has no remote IP to ban, and inventing one would corrupt the offender history. What you get per observed exec:

- an `audit_log` row (`docker_exec`, with container, image, user, and the capped command),
- a live `docker_exec` event in `ezyshield watch`,
- a **warn**-severity notification through your normal channels (dedup/rate-limit applies).

## Enabling

```yaml
# /etc/ezyshield/config.yaml
docker_exec:
  enabled: true
  ignore:                  # tune out legitimate tooling
    - "healthcheck*"       # glob (path.Match) on container name or image
    - cron                 # plain text matches as substring
```

The watcher uses the same Engine endpoint and permission model as the docker log collector, subscribes to `exec_start` only (one event per exec, at the moment it actually runs), and reconnects with backoff when docker restarts.

## Engine access is a privilege decision

Reaching the docker events API means reaching the Docker Engine API. The
endpoint is [`docker.host`](../reference/config.md), shared with the docker log
collectors, and there are two ways to serve it — a file-based collector is not
one of them here, because events have no file equivalent.

**A read-only socket proxy (recommended).** A filtering proxy in front of the
Engine socket, published on `127.0.0.1`, serves events and container logs and
refuses container creation, exec and mounts:

```yaml
# /etc/ezyshield/config.yaml
docker:
  host: tcp://127.0.0.1:2375
```

The proxy must expose **both** `CONTAINERS` and `EVENTS` — this watcher needs
`GET /events` — and nothing else. The compose snippet is in
[Docker + nginx + WordPress](docker-nginx-wordpress.md); `ezyshield doctor`
verifies the endpoint answers `GET /_ping` and refuses
`POST /containers/create`.

**The `docker` group (last resort).** Access to the Engine socket comes from
membership in that group. The group is the Engine API, not a read permission:
anything that can talk to it can start a privileged container, i.e. become
root on the host. Granting it to the ezyshield service user makes the
log-parsing daemon root-equivalent.

`ezyshield init` therefore asks before granting it, defaults to no, and only
asks at all when the run configures a docker log source. In scripted runs the
opt-in is `--docker-group` (or `collectors.docker_group: true` in the answers
file); `--yes` alone never grants it. Without either kind of access, the
watcher stays enabled in the config but observes nothing.

An install provisioned earlier may already carry the membership — removing the
grant from `init` does not revoke it, and neither does a package upgrade.
Check it:

```bash
ezyshield doctor          # warns when the service user is in the docker group
getent group docker       # is ezyshield listed?
```

To revoke:

```bash
sudo gpasswd -d ezyshield docker
sudo systemctl restart ezyshield
```

That disables this watcher along with the docker log collectors, unless
`docker.host` points at a read-only proxy. See the
[security overview](../security/overview.md) for what the grant means and the
alternatives.

## Tuning the ignore list

Run a day with an empty list and review `ezyshield list --audit` (or your notifications): anything periodic and expected — health checks, cron containers, backup tooling, your own CI — goes into `ignore` by container-name or image pattern. What remains should be *rare and human*: that's the signal.

Everything docker reports (names, images, commands) is treated as untrusted input — capped and sanitized at render time like log content.

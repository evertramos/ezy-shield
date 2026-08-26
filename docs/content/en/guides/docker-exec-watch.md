---
title: Docker Exec Watch
description: Post-exploitation visibility — every `docker exec` into your containers, observed
order: 17
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

The watcher uses the same docker socket and permission model as the docker log collector, subscribes to `exec_start` only (one event per exec, at the moment it actually runs), and reconnects with backoff when docker restarts.

## Tuning the ignore list

Run a day with an empty list and review `ezyshield list --audit` (or your notifications): anything periodic and expected — health checks, cron containers, backup tooling, your own CI — goes into `ignore` by container-name or image pattern. What remains should be *rare and human*: that's the signal.

Everything docker reports (names, images, commands) is treated as untrusted input — capped and sanitized at render time like log content.

---
title: Keycloak
description: Banning Keycloak login brute force via LOGIN_ERROR events
order: 21
---

# Protecting Keycloak

Keycloak can log login events through the `org.keycloak.events` logger; `LOGIN_ERROR` lines carry the client `ipAddress`. EzyShield turns them into `keycloak_auth_fail` events (realm/username captured, capped, untrusted) and ships `keycloak_bruteforce` (5 failures / 5 min, score 85) plus a sustained 1 h variant.

## Enable event logging in Keycloak (required)

Keycloak does **not** log login events by default. Two pieces:

1. **The event listener** — in the admin console: *Realm settings → Events → Event listeners*, ensure `jboss-logging` is present (it is by default). Enable *Save events* is NOT required — the logger fires either way.
2. **The log level** — the `org.keycloak.events` category logs at DEBUG for successes but `LOGIN_ERROR` at WARN. Make sure your log level shows it (default WARN already does):

```bash
# quarkus-based Keycloak (conf/keycloak.conf or CLI):
log-level=INFO,org.keycloak.events:WARN
```

Sanity check: fail one login and confirm a `type=LOGIN_ERROR, … ipAddress=…` line reaches your journal/container log.

## Collectors

```yaml
collectors:
  # systemd service
  - kind: journald
    unit: keycloak

  # docker (container name containing "keycloak" is auto-routed)
  - kind: docker
    container: keycloak
```

A file source works too (`keycloak.log`, or any path with `parser: keycloak`).

## Reverse proxy note

`ipAddress` is what Keycloak sees. Behind a proxy, configure Keycloak's proxy headers (`proxy-headers=xforwarded` on Quarkus) so it resolves the real client — otherwise every failure appears to come from the proxy. Verify in dry-run with `ezyshield watch` before arming.

## Rollout

Dry-run first, allowlist your networks, watch a day of decisions, then `ezyshield arm`.

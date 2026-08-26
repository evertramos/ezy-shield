---
title: Nextcloud
description: Protecting Nextcloud logins via the structured nextcloud.log
order: 15
---

# Protecting Nextcloud

Nextcloud writes structured JSON to `nextcloud.log`, including failed logins with the client address. EzyShield parses those into `nextcloud_auth_fail` events (username captured, capped, untrusted) and ships `nextcloud_bruteforce` (5 failures / 5 min, score 85) plus a sustained 1 h variant.

Recognized entries: `app: core` with `Login failed: '<user>' …`, and the `admin_audit` app's failed-login lines.

## Collectors

```yaml
collectors:
  # bare metal / VM
  - kind: file
    path: /var/www/nextcloud/data/nextcloud.log   # routes to the nextcloud parser by name

  # docker (container name containing "nextcloud" is auto-routed)
  - kind: docker
    container: nextcloud-app-1
```

If your data directory lives elsewhere, point at it; a non-standard filename needs `parser: nextcloud` explicitly.

## The `trusted_proxies` requirement (read this)

The event IP comes from Nextcloud's own `remoteAddr` field. **Behind a reverse proxy, `remoteAddr` is the client only when Nextcloud's `trusted_proxies` is configured** (`config.php`):

```php
'trusted_proxies' => ['203.0.113.7'],   // your proxy's address
```

Without it, every failure appears to come from the proxy — banning that would block the proxy itself. Sanity-check in dry-run with `ezyshield watch`: if every detection shows the same internal address, fix `trusted_proxies` first. (EzyShield takes `remoteAddr` as authoritative, exactly as Nextcloud presents it — the resolution belongs in Nextcloud's config, same approach as the web parsers' trusted-proxy handling.)

Nextcloud's own built-in bruteforce throttling stays useful alongside — EzyShield adds the network-level ban and the strike ladder.

## Rollout

Dry-run first, allowlist your networks, watch a day of decisions, then `ezyshield arm`.

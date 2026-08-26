---
title: Deploying to bunny.net
description: Block IPs at the edge with bunny.net pull zones
order: 2
---

# bunny.net Edge Enforcement

Block malicious IPs at the bunny.net edge. When your server sits behind
bunny.net, the firewall only ever sees bunny's edge IPs at the TCP layer —
an nftables ban on the real client IP never matches. The bunny enforcer
closes that gap by pushing every ban to the blocked-IP list of your pull
zones.

## How it works

EzyShield uses the pull-zone blocked-IPs API (works on **every bunny.net
plan**, no Bunny Shield subscription needed):

- **Ban** adds the IP to each configured pull zone's blocked list.
- **Unban** removes it.
- On startup and periodically, **Sync** reconciles each zone's list to
  exactly the set of active bans — missing entries are added, stale ones
  removed.

> **EzyShield owns the list.** The bunny blocked-IP list is a flat list
> with no way to tag entries, so EzyShield takes ownership of it on the
> configured zones: IPs you block **by hand in the bunny panel are removed
> on the next reconcile**. Keep manual blocks in a zone EzyShield does not
> manage, or let EzyShield do the blocking.

## Setup

### 1. Find your API key and pull zone IDs

- **API key**: bunny panel → **Account** → **API**. This is the
  account-level key (bunny.net has no scoped tokens for the pull-zone API
  today — see Security Considerations below).
- **Pull zone IDs**: bunny panel → **CDN** → open the pull zone — the
  numeric ID is in the URL (e.g. `.../pullzone/123456`).

### 2. Configure

The `ezyshield init` wizard offers this setup when it detects bunny.net in
front of your domains (or when you answer yes to the CDN question). To
configure by hand:

```yaml
# /etc/ezyshield/config.yaml
enforce:
  nftables: {}          # keep local enforcement too
  bunny:
    api_key: env:BUNNY_API_KEY
    pull_zones:
      - 123456
      - 234567
```

The key lives in `/etc/ezyshield/.env` (mode 0600), never in config.yaml:

```bash
echo 'BUNNY_API_KEY=your-key-here' | sudo tee -a /etc/ezyshield/.env
sudo chmod 600 /etc/ezyshield/.env
```

### 3. Dry-run first

Like every enforcer, bunny respects `armed: false` in policy.yaml (the
default): decisions are logged and stored, but nothing is pushed to the
edge. Watch `ezyshield watch` for a day, then arm:

```bash
sudo ezyshield arm
```

### 4. Verify

```bash
sudo ezyshield doctor        # checks the key + every pull zone (read-only)
```

## Limits

- **500 IPs per pull zone** (EzyShield's own conservative cap — bunny does
  not document a provider limit). Beyond it, the most recent bans win:
  `Sync` keeps the newest, and a new ban at the cap evicts the oldest,
  with a clear warning in the logs.
- Outbound API calls are rate-limited to 4 requests/second and retried
  with backoff on 429/5xx.
- IPv6: EzyShield sends IPv6 bans like any other; bunny's documentation
  does not state IPv6 support explicitly, so a rejection is logged and
  skipped without breaking the reconcile.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `doctor` fails "key rejected (HTTP 401)" | key rotated or mistyped | copy the key from Account → API into `/etc/ezyshield/.env`, restart the daemon |
| `doctor` fails "pull zone not found (HTTP 404)" | wrong numeric ID | check the ID in the pull zone URL in the bunny panel |
| manual panel blocks disappear | EzyShield reconciled the list | expected — see "EzyShield owns the list" above |
| bans work locally but attackers still reach the site via bunny | `enforce.bunny` missing or key unresolved at startup | check `journalctl -u ezyshield` for "bunny enforcer unavailable" |

## Security Considerations

- The API key is **account-level** — it can manage everything in your
  bunny account. Treat it like a root credential: `.env` mode 0600, never
  in config.yaml (the loader rejects inline values), never in logs
  (EzyShield never prints it, and its absence from error messages is
  covered by tests).
- All API responses are treated as untrusted input: bounded reads, typed
  decoding, non-IP entries in the remote list ignored.
- The allowlist is enforced before any ban reaches bunny (Hard Rule §1).

## See Also

- [Cloudflare Edge Enforcement](cloudflare.md) — the sibling enforcer;
  both can run at once behind multi-CDN setups.
- [Config Reference](../reference/config.md#bunny)

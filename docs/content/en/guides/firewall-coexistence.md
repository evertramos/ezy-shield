---
title: Firewall Coexistence
description: Running EzyShield alongside ufw or firewalld
order: 9
---

# Firewall Coexistence (ufw / firewalld)

Many hosts already run ufw or firewalld. EzyShield is designed to coexist with them: it never touches their rules, and they normally never touch EzyShield's. This page explains how the interaction works, what to watch out for, and how `ezyshield doctor` detects real conflicts.

## How coexistence works

EzyShield manages its **own** nftables table — `inet ezyshield` — created by the `ezyshield-enforcer` helper. Nothing else writes to it, and EzyShield writes nowhere else.

- **Hook priority.** The blocked-set drop rules hook at `raw` priority — *before* ufw's and firewalld's filter chains. A banned IP is dropped before the other firewall ever sees the packet; for every other packet, EzyShield's chains accept and your existing firewall applies its policy unchanged.
- **Independent tables.** nftables tables are namespaced. `ufw reload` and `firewall-cmd --reload` rewrite *their* tables and normally leave foreign tables (like ours) alone. The reverse also holds.
- **Allowlist first.** Inside EzyShield's own table, allowlisted ranges accept before any drop rule — the other firewall's opinion of those IPs is unaffected either way.

## What to watch out for

- **Full ruleset flushes delete our table.** `nft flush ruleset` (some hardening scripts), restarting `nftables.service` with a static `/etc/nftables.conf`, or `iptables -F`-style scripts on iptables-nft backends can wipe **all** tables — including `inet ezyshield`. Bans stay recorded in EzyShield's store, but nothing is enforced until the enforcer recreates the table. This is the one *real* conflict, and doctor fails loudly on it (below).
- **Double management.** Banning the same IP in both tools works but is confusing to audit: the other firewall may log/reject a packet EzyShield would have dropped one hook earlier, or vice versa. Prefer letting EzyShield own attacker bans and your firewall own service policy (open/closed ports).
- **Ordering on boot.** The shipped units start the enforcer before the daemon; ufw/firewalld start whenever they like — order does not matter, because the tables are independent.

## What doctor checks

```console
$ sudo ezyshield doctor
[PASS] firewall: coexistence
       hint: ufw active alongside EzyShield -- coexistence works: ...
[FAIL] firewall: ezyshield nftables table
       hint: 5 active ban(s) recorded but the ezyshield nftables table is GONE -- nothing is being enforced. ...
```

- `firewall: coexistence` — detects active ufw/firewalld (via systemd unit state, read-only; doctor never runs their CLIs) and explains the interaction.
- `firewall: ezyshield nftables table` — the conflict detector. **FAIL** when active bans are recorded but the table is gone: enforcement is silently absent. **WARN** when the table is missing with no bans recorded (nothing lost yet). Needs root to list tables; without it the check reports N/A.

## Recovering from a flushed table

```bash
sudo systemctl restart ezyshield-enforcer ezyshield
sudo ezyshield doctor        # table check should PASS again
```

The enforcer recreates the table on start, and the daemon re-syncs every active ban from its store — nothing is lost as long as the store is intact (the periodic reconcile also repairs drift on its own within minutes).

EzyShield never edits, reloads, or migrates ufw/firewalld rules — coexistence is detection and honest reporting only.

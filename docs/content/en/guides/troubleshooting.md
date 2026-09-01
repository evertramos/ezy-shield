---
title: Troubleshooting
description: The common failure questions, each with the doctor check that diagnoses it
order: 14
---

# Troubleshooting

The four questions that cover most support cases. Start every session the same way:

```bash
sudo ezyshield doctor
```

Doctor is read-only and each check prints a **hint with the exact fix**. The sections below map the common symptoms to the checks that diagnose them.

## "The daemon runs but nothing is detected"

Detection needs a log source, a matching parser, and events actually flowing.

1. **`collectors: configured`** (doctor) — zero collectors means nothing is ever read. Add a `collectors:` section (or re-run `ezyshield init`).
2. **`journald: readable`** (doctor) — the journald collector runs as the `ezyshield` user, which needs the `systemd-journal` group. The hint gives the `usermod` fix.
3. **Wrong unit or path.** Debian names the SSH unit `ssh`, RHEL `sshd`; a `file` collector needs the *access* log for HTTP rules. Compare your config against what's really logging: `sudo ezyshield scan` lists listening services and their log sources.
4. **Still quiet?** `ezyshield status` shows `CollectorsState: DEGRADED` with the failing collector named when a source repeatedly errors; `ezyshield watch` confirms events the moment parsing works.

## "A collector is configured but cannot read its source"

A collector can be configured, started, and still read nothing. The usual cause is permissions on the source itself: a `kind: docker` collector on a host where the `ezyshield` service user cannot reach the Docker Engine socket, or a journald collector without the `systemd-journal` group. Detection on that source is dead while enforcement looks perfectly healthy.

Two checks answer this together:

```
[FAIL] docker: socket access
       hint: service user ezyshield (uid 999) cannot read+write /var/run/docker.sock
       (owner 0:994, mode 0660) -- the configured docker collectors observe NOTHING.
       Access paths, cheapest privilege first: (1) collect a host-mounted log file
       instead of the container's stream (no docker privilege at all); (2) expose a
       read-only, filtered Docker socket proxy to ezyshield; (3) add ezyshield to the
       'docker' group -- that group is root-equivalent on this host ...
[FAIL] collectors: observation state
       hint: DEGRADED — a configured collector is NOT reading its source
       (docker:proxy-web is not reading (5 consecutive failures: docker: permission
       denied on /var/run/docker.sock)); nothing from that source is detected,
       however healthy enforcement looks ...
```

1. **`docker: socket access`** evaluates the **service user**, not the account running doctor. An operator who is in the `docker` group would otherwise read a green check for access the daemon does not have.
2. **`collectors: observation state`** asks the running daemon what it is actually reading. `ezyshield status` shows the same verdict as a `CollectorsState: DEGRADED` banner naming the collector and its last error, and the daemon writes a `collector_degraded` audit row plus one critical notification when a source stops being read.
3. Pick an access path by what it costs: a host-mounted log file needs no Docker privilege at all; a read-only, filtering socket proxy exposes only what it is configured to expose; the `docker` group is root-equivalent on the host (a member can start a privileged container), so grant it deliberately and only while docker collectors are configured.

`service user: docker group` reports the membership when it exists; when it does not, `docker: socket access` is the check with the verdict, because another path may already grant the access.

## "A ban is recorded but the IP is not blocked"

The worst failure mode — and the one most instrumented.

1. **`ezyshield status`** first: `EnforcementState` is the honest answer. `DRY-RUN` means `armed: false` — recorded bans are *simulated* by design. `DEGRADED` names the failing backend.
2. **`enforcer: socket connectivity`** (doctor) — the helper is down or its socket unreachable: `systemctl status ezyshield-enforcer`.
3. **`enforcer: netlink probe`** (doctor) — the helper runs but its sandbox lost netlink access (a modified unit): the hint names the `RestrictAddressFamilies` fix.
4. **`firewall: ezyshield nftables table`** (doctor) — the table is GONE while bans are active: something flushed the ruleset (see the [firewall coexistence guide](firewall-coexistence.md)); `systemctl restart ezyshield-enforcer ezyshield` recreates and re-syncs.
5. **`bans: ban_ineffective diagnostics`** (doctor) — the daemon itself flags bans that kept generating events after the grace period.

## "Permission errors on the socket"

```
dial unix /run/ezyshield/ezyshield.sock: connect: permission denied
```

The control socket is `root:ezyshield`, mode `0660` — membership in the `ezyshield` group is the access control.

1. `id` — are you in the `ezyshield` group? `ezyshield init` adds the installing admin; for anyone else: `sudo usermod -aG ezyshield <user>` then re-login.
2. Socket missing entirely → the daemon isn't running (`systemctl status ezyshield`); `exit code 3` from any CLI command means exactly "daemon unreachable".
3. **`ezyshield-enforcer.service: runtime directory`** / **`ezyshield.service: runtime directory`** (doctor) — a stripped unit never creates `/run/ezyshield*`; the hint carries the drop-in fix.

## "The journald source is not matched"

Events exist in `journalctl -u ssh` but EzyShield sees nothing.

1. The collector's `unit:` must match the *exact* unit name — `ssh` vs `sshd` again. `systemctl list-units 'ssh*'` settles it.
2. **`journald: readable`** (doctor) — reads the journal *as the daemon's identity*; a PASS here plus silence usually means the unit name.
3. Container setups: journald inside the container is not the host's journal — run the collector where the logs are, or use a `file` collector on a mounted log.

## Escalation paths

- False positive banning real users → `sudo ezyshield allow <ip>` (allowlist always wins), then tune via `rules.d`.
- Everything on fire → `sudo ezyshield disable --all` (removes every block, disarms, keeps history — see the [CLI reference](../reference/cli.md)).
- Bug reports: attach `ezyshield doctor --json` and `ezyshield status --json` output — both are safe to share (no secrets).

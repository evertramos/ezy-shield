---
title: Migrate from fail2ban
description: Read your fail2ban jails and generate an equivalent EzyShield setup
order: 12
---

# Migrating from fail2ban

`ezyshield migrate fail2ban` reads your fail2ban installation — `jail.conf`, `jail.local`, and `jail.d/` with fail2ban's own precedence — and generates a **proposal**: a `config.yaml`, a `policy.yaml`, and a `REPORT.md` explaining every decision. It never touches `/etc` unless you explicitly ask.

```console
$ sudo ezyshield migrate fail2ban
wrote ezyshield-migration (config.yaml, policy.yaml, REPORT.md)
mapped 3 jail(s), 1 unmapped, 4 disabled/skipped — details in REPORT.md
the generated policy is armed: false (dry-run) — review, run 'ezyshield doctor', watch a
week of dry-run output, then arm with 'ezyshield arm'
```

Flags:

- `--from DIR` — fail2ban config directory (default `/etc/fail2ban`)
- `--out DIR` — where to write the proposal (default `./ezyshield-migration`)
- `--write` — write directly to `/etc/ezyshield` instead; refuses to overwrite existing files without `--force`. Still **always** `armed: false`.
- `--json` — machine-readable summary (`mapped`, `unmapped`, `skipped`, `allowlist`, `warnings`)

## What maps to what (v1)

| fail2ban | EzyShield |
|---|---|
| `sshd` jail | journald SSH collector + built-in `ssh_bruteforce` rule family |
| `nginx-*` jails | nginx-parser file collectors + built-in HTTP rules |
| `apache-*` jails | apache-parser file collectors |
| `recidive` | covered natively — the strike ladder escalates repeat offenders |
| `ignoreip` | `allowlist:` entries in policy.yaml (validated IPs/CIDRs; hostnames are never resolved, they are reported) |
| `maxretry` / `findtime` | no 1:1 equivalent — built-in rules carry tuned thresholds, adjustable via `rules.d` drop-ins (noted in the report) |
| `bantime` | strike-1 TTL **suggestion** in the report only — EzyShield escalates, fail2ban bans for a fixed time |
| `postfix*` / `dovecot` jails | reported as *parser planned* — keep those jails on fail2ban until the parsers ship |
| custom jails/filters | listed in the report with the filter name; regex filters are never translated |

Disabled jails are skipped (and listed). The reader is defensive: unreadable or malformed files, oversized inputs, and interpolated `%(...)s` values are reported in the *Reader warnings* section — a broken file never aborts the run.

## Recommended sequence

1. Run the migration and **read REPORT.md** — it explains what mapped, what didn't, and why.
2. Install the proposal (copy the files, or re-run with `--write`).
3. `ezyshield doctor`, then run **a week in dry-run** — both tools can run side by side safely (redundant, not harmful).
4. `ezyshield arm` once the dry-run output looks right.
5. Only then disable fail2ban.

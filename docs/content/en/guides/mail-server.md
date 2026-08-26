---
title: Mail Servers
description: Protecting Postfix and Dovecot from SMTP/IMAP brute force
order: 18
---

# Protecting Mail Servers

Mail services are among the most brute-forced on the internet. EzyShield parses Postfix smtpd and Dovecot login logs and ships default rules that ban credential brute force, open-relay probing, and connection abuse — with the same strike ladder, allowlist supremacy, and dry-run default as everything else.

## What gets detected

| Event | Emitted by | Meaning |
|---|---|---|
| `smtp_auth_fail` | postfix parser | SASL LOGIN/PLAIN/… authentication failed |
| `smtp_relay_denied` | postfix parser | `NOQUEUE: reject … Relay access denied` (ordinary user-unknown rejects stay silent) |
| `smtp_abuse` | postfix parser | "too many errors after RCPT", "lost connection after AUTH" |
| `imap_auth_fail` | dovecot parser | IMAP/POP3 `(auth failed, N attempts …)` |
| `imap_probe` | dovecot parser | `Disconnected (no auth attempts …)` — credential-less probing, low signal |

Built-in rules (tune via `rules.d` drop-ins, merged by name):

| Rule | Window | Threshold | What it catches |
|---|---|---|---|
| `mail_bruteforce` | 5 min | 5 | SMTP + IMAP/POP3 credential guessing (kinds combined) |
| `mail_relay_probe` | 5 min | 3 | open-relay probing |
| `mail_bruteforce_sustained` | 1 h | 10 | low & slow failures + connection abuse |
| `mail_probe_aggressive` | — | — | **disabled by default** — counts `imap_probe`; uncomment in rules.yaml/rules.d if probe noise bothers you (higher FP risk) |

## Bare-metal Postfix / Dovecot

The journald units are the recommended sources (they work regardless of which file syslog writes to):

```yaml
# /etc/ezyshield/config.yaml
collectors:
  - kind: journald
    unit: postfix        # postfix@- on some Debian setups: use the unit systemctl shows
  - kind: journald
    unit: dovecot
```

File-based alternative: `mail.log`/`maillog` routes to the **postfix** parser automatically. Dovecot lines living in that same shared file need their own source — either the journald unit above, or a dedicated `log_path = /var/log/dovecot.log` in Dovecot plus:

```yaml
  - kind: file
    path: /var/log/dovecot.log     # routes to the dovecot parser by name
```

## Mailcow / containerized stacks

Postfix and Dovecot in mailcow log through docker. Point docker collectors at the containers and force the parser:

```yaml
collectors:
  - kind: docker
    container: mailcowdockerized-postfix-mailcow-1
    parser: postfix
  - kind: docker
    container: mailcowdockerized-dovecot-mailcow-1
    parser: dovecot
```

(The parsers unwrap docker's json-file format automatically.)

## Rollout

Same as everything in EzyShield: start in **dry-run**, watch `ezyshield watch --kind dry_ban` while a day of real traffic flows, allowlist your own networks (`policy.yaml` or `ezyshield allow`), then `ezyshield arm`. A banned mail client is recoverable — the first strike is 5 minutes.

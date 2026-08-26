---
title: Webshell Tripwire
description: Detect webshell drops in your web roots — a tripwire, not an antivirus
order: 12
---

# Webshell Tripwire

## What it is

Log parsers see the *requests* that hit your server. But the highest-value
compromise artifact never shows up in an access log: the **file** an
attacker dropped into your web root — a `shell.php` written through an
upload form, a vulnerable plugin, or a stolen FTP credential.

The webshell tripwire watches your web roots for **new or modified files
with executable web extensions** and tells you the moment one appears.

It is **a tripwire, not an antivirus**:

- It detects *change*, not malware. A legitimate deploy also fires it
  (folded into one summary — see below).
- The content heuristic is a hint, not a verdict. A flagged file deserves
  a look; an unflagged file is not proven clean.
- It is **purely observational**. A filesystem event has no remote IP, so
  it can never create a ban. You get an audit-log entry, a live `watch`
  stream event, and a notification — nothing else changes on your system.

## Enabling it

Opt-in via `config.yaml`:

```yaml
webshell_watch:
  enabled: true
  roots:
    - /var/www/html
    - /srv/www/wordpress
  ignore:
    - cache            # substring: skips any path containing "cache"
    - "*.bak.php"      # glob: path.Match pattern
  # extensions: [".php", ".phtml", ".php5", ".php7", ".phar"]  # default
  # interval_sec: 10   # sweep cadence in seconds (floor 5)
```

`roots` must be absolute paths and is required when enabled. Typical roots:

| Stack | Root |
|---|---|
| Debian/Ubuntu Apache or nginx | `/var/www/html` |
| WordPress (common layouts) | `/var/www/html`, `/srv/www/<site>` |
| Docker bind mounts | the **host side** of the mount |

## How it detects

EzyShield sweeps the roots on a bounded polling loop (default every 10s),
diffing each watched file's mtime and size against the previous sweep —
the same stat-based approach used for log tailing (ADR-0004). The first
sweep is a silent baseline; only changes after startup fire events.

Polling means there are no inotify watch descriptors to exhaust, no kernel
limits to tune, and a worst-case detection latency of one sweep interval —
fine for a tripwire.

On each new or changed file, EzyShield reads at most the first 32 KB
(read-only) and checks for high-signal webshell constructs — `eval(`,
`base64_decode`, `shell_exec`, `$_POST[`, `move_uploaded_file`, and
similar. A match raises the notification severity to **critical**
("possible webshell dropped"); otherwise you get a **warn**
("web-root change observed"). File content is treated as hostile data:
it is only byte-compared against fixed markers, never executed or logged.

## Bounds and flood behavior

- A **mass change** (a deploy touching more than 20 files in one sweep)
  is folded into a single summary event with a file count, instead of a
  notification storm. If deploys are frequent, add their target dirs to
  `ignore`.
- At most 50,000 files are tracked per daemon; beyond that a warning is
  logged once and extra files are not watched.
- Paths recorded on events are capped at 256 bytes; hostile filenames
  (control characters, ANSI escapes) are sanitized at render time like all
  attacker-controlled data.
- Deletions are silent — removing a file is not a drop signal (but
  re-creating it is).

## What to do when it fires

1. Look at the file: `ls -la` the path from the notification, check the
   owner uid and timestamp against your deploy history.
2. If you didn't put it there, treat the host as compromised at the
   web-application level: take the file out of the web root (move, don't
   just delete — it's evidence), rotate credentials the app holds, and
   find the upload vector in your access logs around the file's mtime.
3. If it was a legitimate deploy or cache churn, tune
   `webshell_watch.ignore` so the tripwire stays quiet on routine change
   and loud on surprises.

## Out of scope (v1)

Quarantine/auto-removal, kernel-level integrity monitoring, non-web paths,
and correlating a drop with the HTTP request that caused it. The tripwire
tells you *that* and *where* — the investigation is yours.

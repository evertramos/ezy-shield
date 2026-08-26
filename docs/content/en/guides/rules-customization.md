---
title: Customizing Detection Rules
description: Tune or add rules with rules.d drop-ins that survive updates
order: 7
---

# Customizing Detection Rules

EzyShield's detection rules ship **embedded in the binary** — every install
runs the full, current ruleset with zero files on disk, and every
`ezyshield update` delivers the latest rule tuning automatically.

To adjust a rule (or add your own) you don't fork that base: you drop a
file in `/etc/ezyshield/rules.d/`.

## How drop-ins work

- Every `*.yaml` file in `rules.d/` is loaded in **lexical order**
  (`10-wordpress.yaml` before `50-local.yaml`).
- Entries merge over the built-in rules **by `name`**: a drop-in entry with
  the same name as a built-in rule **replaces it**; a new name **adds** a
  rule. Later files win over earlier ones.
- Everything you do *not* override keeps riding binary updates — you tune
  one threshold, and the other rules stay current forever.
- Overriding a built-in rule logs a **WARN** at startup (deliberately loud:
  a drop-in that weakens a shipped protective rule should be visible).
- An invalid drop-in **stops the daemon from starting** (fail-closed) — a
  typo can never silently degrade detection. After editing, restart and
  check: `sudo systemctl restart ezyshield && sudo systemctl status ezyshield`.

## Example: raise the wp-login threshold

```yaml
# /etc/ezyshield/rules.d/50-local.yaml
rules:
  - name: http_wp_probe        # same name as the built-in => override
    description: "WordPress login probe (site-tuned)"
    kinds: [http_request]
    field: path
    contains: wp-login
    window: 60s
    threshold: 10              # built-in default is 3
    score: 80
    category: scanner
```

## Example: add your own rule

```yaml
# /etc/ezyshield/rules.d/60-admin-panel.yaml
rules:
  - name: local_admin_probe    # new name => added alongside the built-ins
    description: "Probing our internal admin path"
    kinds: [http_request]
    field: path
    contains: /internal-admin
    window: 60s
    threshold: 3
    score: 85
    category: scanner
```

The rule schema (fields, matchers, windows) is documented in
[Getting Started §6](../getting-started/index.md); the full current ruleset
ships as `/etc/ezyshield/rules.yaml.example` for reference.

## Test a rule before enabling it

Writing a rule blind — enable it and wait — is how false positives ship.
`rule test` dry-evaluates one rule against the event history the daemon
already stores, with **zero side effects** (no strikes, no bans, no audit
writes; the daemon doesn't even need to be running):

```console
$ ezyshield rule test ssh_bruteforce_daily --since 7d
Rule test: ssh_bruteforce_daily
  kinds: ssh_fail, ssh_invalid_user | window: 24h0m0s | threshold: 5 | ...

  Would have fired : 12 time(s)
  Unique IPs       : 4
  Allowlisted hits : 1 — this rule would fire on protected addresses; tune it before enabling
```

The argument is a loaded rule's name (built-in or drop-in) or a path to a
standalone YAML file — so you can test `rules.d/60-admin-panel.yaml`
*before* copying it into place. The rule goes through the same fail-closed
validation as the daemon's loader first; an invalid rule is a clear error
and a non-zero exit.

The **allowlisted hits** line is the false-positive early warning: it counts
would-be detections on addresses covered by your `allowlist`/`admin_cidrs`
or the runtime allowlist. A rule that fires on your own ranges needs tuning,
not enabling. `--json` gives the full result for scripting.

Honest limitation: evaluation uses the stored hourly aggregates, so
granularity is bounded by 1-hour buckets and by retention — and only kinds
referenced by long-window (>1h) rules are persisted at all. Field-level
matchers (`field`/`value`/`contains`) can't be applied to counts, so such
rules are reported as a kind-level **upper bound**, loudly marked.

## WordPress installs

When `ezyshield init` detects WordPress containers it writes a
**fully-commented tuning template** to `rules.d/10-wordpress.yaml`. The
WordPress rules are built in and already active — the template exists so
the most commonly tuned rules are one uncomment away. Re-running `init`
never overwrites your edits.

## Legacy: `rules_path` (deprecated)

Setting `rules_path` in `config.yaml` replaces the built-in rules with your
file **entirely** — no merge, and `rules.d/` is ignored. That freezes the
install out of all upstream rule tuning (updates change the binary, never
your file), so the daemon logs a warning at startup when it is set. Prefer
drop-ins; to migrate, move only your *actual changes* into a
`rules.d/50-local.yaml` and remove `rules_path` from `config.yaml`.

## Safety boundary

Rules — built-in or drop-in — only ever *suggest* verdicts. The allowlist
and anti-lockout checks run downstream in the decision engine on every
target, regardless of which rule fired. No rule can allowlist, unban, or
bypass those guarantees.

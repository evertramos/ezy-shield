---
title: Low-and-Slow Detection
description: Catching SSH attackers who pace themselves below hourly thresholds
order: 10
---

# Low-and-Slow SSH Detection

Bursty brute force is easy: many failures from one IP in seconds. The harder opponent paces itself — one attempt every 10 minutes, every hour, or once a day — staying under every short-window threshold forever. EzyShield closes that blind spot with **persistent per-IP hourly counters** and two long-window rules.

## The detection tiers

| Tier | Rule | Window | Threshold | Catches |
|---|---|---|---|---|
| Burst | `ssh_bruteforce` | 60s | 5 | classic brute force, immediately |
| Sustained | `ssh_bruteforce_sustained` | 1h | 10 | ~1 attempt every 6 min |
| Daily | `ssh_bruteforce_daily` | 24h | 5 | every 10 min / hourly pacing |
| Weekly | `ssh_bruteforce_weekly` | 7d | 5 | the ~once-a-day retrier |

The same shape exists for the WordPress login and XML-RPC endpoints, where botnets pace themselves just under the hourly tier:

| Tier | Rule | Window | Threshold | Catches |
|---|---|---|---|---|
| Burst | `http_wp_probe` | 60s | 3 | password spraying |
| Sustained | `http_wp_probe_sustained` | 1h | 10 | ~1 attempt every 6 min |
| Daily | `http_wp_probe_daily` | 24h | 25 | a node trying 5–9 times an hour, all day |
| Daily | `http_xmlrpc_daily` | 24h | 20 | the same pacing against `xmlrpc.php` |

All of them feed the same decision pipeline: allowlist supremacy, anti-lockout, dry-run default, and the strike ladder (first strike = a recoverable 5-minute ban) apply unchanged.

## How it works

Windows up to 1 hour are served by the in-memory sliding-window aggregator, as before. Its per-IP memory is bounded regardless of how busy a client is: each IP retains at most 4096 raw events — always the newest ones, so evidence lines show the current traffic — and every event beyond that cap is still counted, per kind and per field-level rule it matches, in short fixed-width buckets (five seconds with the default 60-second tier). Rule counts over the retained hour therefore stay exact for busy clients too, including field-level rules such as the wp-login probe while a benign flood continues; a bucket is only counted when it lies entirely inside the window, so the count never includes older traffic and may miss at most one bucket of evicted events at the window edge. The bound is per client address; the number of addresses is capped separately by the aggregator LRU. Windows **above** 1 hour are served by aggregate counters on disk: one SQLite row per `(ip, kind, hour)`, incremented in place. That design matters for three reasons:

- **Near-zero RAM.** An IP failing 100× in an hour is one row incremented 100 times — no 24h horizon of events is ever held in memory.
- **Survives eviction and restarts.** The in-memory aggregator's LRU cap and daemon restarts are exactly what a slow attacker outlasts; disk counters don't forget.
- **Counts only.** The table stores `ip + kind + hour + count` — never usernames, paths, or raw log lines. Only kinds referenced by kind-level long-window rules are written wholesale (the SSH failure kinds). Buckets older than the longest long window are pruned automatically.

A long-window rule with a `field` matcher (`http_wp_probe_daily` matches `path` containing `wp-login`) does not count its whole event kind — that would mean writing a row for every HTTP request. Instead the rule's own matcher runs as each event arrives, and only a **hit** is counted, under a counter named after the rule (`rule:http_wp_probe_daily`). The daily evaluation reads that counter back. An HTTP request that matches no long-window rule never touches the table and never triggers a long-window query. Because the counter is keyed by rule name, the history a drop-in override accumulates is the history the rule reads: renaming a rule starts it from zero.

## The false-positive trade-off

A human who fat-fingers a password fails once or twice and then fixes it or gives up. Automation grinding a dead credential retries forever. The thresholds encode that difference:

- 1–2 failures, any pacing: never actioned.
- 3–4 failures spread across days: still below every threshold.
- 5 failures accumulated in a day (or across 5 days for the weekly tier): actioned — and the first strike is a 5-minute ban, so even a false positive is recoverable and self-clears.
- For the WordPress tiers the daily bar is 25 login-page hits: a person logging in a few times a day loads `wp-login.php` a handful of times; 25 in a day is automation. Put the site admin's address in the allowlist regardless — allowlist supremacy applies before any rule.

**Detection latency is inherent**: a 1-attempt-per-hour attacker is caught on the 5th attempt (~5 hours in); a once-a-day retrier on day 5. Once on the strike ladder, repeat offenses escalate through the normal TTLs (5m → 1h → 24h → 7d → permanent).

## Tuning

Override thresholds with a `rules.d` drop-in (merged by rule name):

```yaml
# /etc/ezyshield/rules.d/60-local-tuning.yaml
rules:
  - name: ssh_bruteforce_daily
    description: "Low-and-slow SSH brute force (daily accumulation)"
    kinds: [ssh_fail, ssh_invalid_user]
    window: 86400s
    threshold: 8        # more tolerant host (shared office NAT)
    score: 75
    category: bruteforce
```

Lowering thresholds below 5 increases false-positive exposure on shared IPs (office NAT, CGNAT); raising the windows extends how long counter buckets are retained on disk.

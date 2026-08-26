---
title: Detection Benchmark
description: Reproducible detection-rate and false-positive numbers on a labeled corpus
order: 8
---

# Detection Benchmark

The e2e suite proves the pipeline assembles; this benchmark proves the **decisions are good** — and guards them against regression. It runs the full detection pipeline (parse → aggregate → rules → decision, dry-run, rules-only) over a labeled corpus and reports detection rate, false positives, and time-to-first-strike.

```bash
make bench        # = go test -tags bench ./internal/bench/ -v
```

## Methodology

- **Corpus**: labeled scenarios under `fixtures/bench/corpus/`, one YAML per scenario. All traffic is **synthetic but real-shaped** (log lines in the exact formats the parsers see in production); IPs come only from documentation ranges (RFC 5737) — no real user data, ever.
- **Labeling rules**: a scenario is `attack` when a human operator would want the source banned (brute force, scanning, exploit probes) and lists its `attacker_ips`; it is `legit` when banning would be a false positive (normal logins with a typo, well-behaved crawlers, busy API clients, an admin using wp-login). Attack scenarios must be *caught*; legit scenarios must produce **no ban-band decision at all**.
- **Determinism**: every scenario replays on a virtual clock (fixed epoch + per-line `interval_ms`); parser timestamps are overridden with virtual time, so results are identical across machines and runs. The AI layer is never consulted (rules-only, by design); nothing is enforced (dry-run policy, no enforcer wired).
- **Metrics**: `detection_rate` = detected attacks / attack scenarios; `false_positives` = legit scenarios that produced any ban-band decision; `time_to_first_strike_sec` = virtual seconds from scenario start to the first ban-band decision.
- **Regression gate**: `fixtures/bench/baseline.json` is the committed contract. CI fails when the detection rate drops, a baselined detection goes missing, or a false positive appears. Baseline changes are explicit, reviewable diffs.

## Current numbers

As of the corpus's introduction (10 scenarios):

| Metric | Value |
|---|---|
| Detection rate | **6/6 attacks (100%)** |
| False positives | **0/4 legit scenarios** |

| Scenario | Label | Result | Time to first strike | Rule |
|---|---|---|---|---|
| attack-ssh-burst | attack | detected | 8s | ssh_bruteforce |
| attack-ssh-sustained | attack | detected | 36 min | ssh_bruteforce_sustained |
| attack-wp-scan | attack | detected | 10s | http_wp_probe |
| attack-env-probe | attack | detected | 0s | http_env_probe |
| attack-rce-probe | attack | detected | 0s | http_rce_probe |
| attack-404-scan | attack | detected | 19s | http_scanner |
| legit-ssh-typo | legit | clean | — | — |
| legit-crawler | legit | clean | — | — |
| legit-api-client | legit | clean | — | — |
| legit-admin-wp | legit | clean | — | — |

A 100% rate on 10 scenarios is a **floor being guarded**, not a marketing claim: the corpus is small and grows over time; every addition re-runs against the whole rule set.

## Contributing a scenario

1. Add a YAML file under `fixtures/bench/corpus/`:

   ```yaml
   name: attack-my-scenario          # unique, kebab-case, attack-/legit- prefix
   description: one honest sentence
   label: attack                     # attack | legit
   source: "file:/var/log/nginx/access.log"   # selects the parser
   attacker_ips: ["203.0.113.99"]    # required for attacks
   interval_ms: 1000                 # virtual spacing between lines
   lines:
     - '203.0.113.99 - - [01/Jan/2026:12:00:00 +0000] "GET /x HTTP/1.1" 404 162 "-" "ua"'
   ```

2. Use **only** RFC 5737 / RFC 3849 documentation IPs, and synthetic content — never paste real logs with real user data.
3. Run `make bench`; it will fail telling you to add the scenario to `fixtures/bench/baseline.json` — that diff is the review surface.
4. An attack the rules *miss* is a legitimate contribution too: baseline it as `false` with a comment in the PR; it becomes the target for a rule improvement.

---
title: Metrics
description: Prometheus metrics endpoint reference
order: 8
---

# Prometheus Metrics

EzyShield exposes Prometheus metrics at **`GET /metrics` on the dashboard
listener** (`127.0.0.1:9090` by default). No new network listener is
created — the metrics ride the existing loopback-only dashboard, per the
project's no-new-listeners rule. The counters live in the daemon and are
proxied over the control unix socket, so the dashboard process needs the
daemon running to serve a scrape (503 otherwise).

Zero dependencies: the text exposition format (0.0.4) is hand-rolled — a
Prometheus client library would be the largest dependency in the binary
for a page of writer code.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ezyshield_build_info` | gauge | `version` | Always 1; carries the build version |
| `ezyshield_collector_lines_total` | counter | `collector` | Raw log lines received, by collector type (`filetail`, `journald`, `docker`, …) |
| `ezyshield_parser_events_total` | counter | `parser` | Structured events produced, by parser (`ssh`, `nginx`, …) |
| `ezyshield_actions_total` | counter | `op` | Decision-engine actions (`ban`, `dry_ban`, `notify_only`, `record`, …) |
| `ezyshield_strikes_total` | counter | `level` | Strikes recorded, by escalation level (1–5) |
| `ezyshield_bans_applied_total` | counter | `enforcer` | Bans successfully applied, by enforcer backend |
| `ezyshield_ai_requests_total` | counter | `provider` | AI analyze calls per provider |
| `ezyshield_ai_tokens_total` | counter | `provider` | AI tokens consumed (input+output) per provider |
| `ezyshield_active_bans` | gauge | — | Active bans in the store at scrape time (−1 = store query failed) |

Label cardinality is **bounded by construction**: only enumerable labels
exist (collector/parser types, operation names, strike levels, enforcer
and provider names). IPs, usernames, and paths can never become label
values — hostile or unexpected values fold into `invalid`, and each
family caps distinct values, folding overflow into `other`.

## Auth

By default `/metrics` requires the dashboard session auth, like every
other dashboard route. Since Prometheus cannot perform a session login,
scraping normally uses:

```yaml
# /etc/ezyshield/config.yaml
dashboard:
  metrics_auth: false
```

This allows unauthenticated scrapes and is acceptable **only because the
listener is loopback-only** — any local process can already observe most
of this information. The route is throttled either way (120 requests/min).

## Scrape config

```yaml
# prometheus.yml — Prometheus running on the same host
scrape_configs:
  - job_name: ezyshield
    scrape_interval: 30s
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

For a remote Prometheus, do not expose the dashboard — tunnel instead
(`ssh -L 9090:127.0.0.1:9090 host`) or run a local agent that
remote-writes. The dashboard refuses non-loopback binds by design.

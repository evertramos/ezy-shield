---
title: SIEM Forwarding
description: Ship every audited action to Wazuh, Splunk, or any syslog collector
order: 17
---

# SIEM Forwarding

EzyShield can forward **every audited action** — bans, dry-run bans,
unbans, expiries, allowlist changes, arm/disarm, daemon start/stop — to
one or more SIEM endpoints. Outbound only (no new listener), asynchronous,
and bounded: a slow or dead SIEM can never block or destabilize the
decision pipeline. When a sink's queue (default 1024 events) fills, the
**oldest** events are dropped and counted.

```yaml
# /etc/ezyshield/config.yaml
siem:
  - name: wazuh
    address: tls://siem.example.com:6514
    format: rfc5424
    ca_file: /etc/ezyshield/siem-ca.pem   # optional CA pin
  - name: audit-copy
    address: file:///var/log/ezyshield-forward.log
    format: json
```

## Transports

| Scheme | Transport | Framing |
|---|---|---|
| `tls://host:port` | TCP + TLS (ServerName verified; optional `ca_file` pin) | RFC 6587 octet counting for `rfc5424`, newline for `json`/`cef` |
| `tcp://host:port` | plaintext TCP (**requires `allow_insecure_transport: true`**) | same as tls |
| `udp://host:port` | plaintext UDP (**requires `allow_insecure_transport: true`**) | one datagram per event |
| `uds:///path` | unix socket (stream, falling back to datagram) | stream framed, datagram unframed |
| `file:///path` | append to a local file | one line per event |

Plaintext transports are refused at config load unless you explicitly set
`allow_insecure_transport: true`, and `ezyshield doctor` keeps warning
loudly — audit events carry IPs and rule reasons that can quote log
content. Delivery reconnects with capped backoff; on shutdown one bounded
flush attempt drains the queue.

## Event kinds

The `events:` filter (empty = all) matches the audit operation names:
`ban`, `dry_ban`, `unban`, `expire`, `allow`, `unallow`, `ban_refused`,
`arm`, `disarm`, plus the synthesized lifecycle events `daemon_start` and
`daemon_stop`. (The list follows the audit log; new audited operations are
forwarded automatically.)

## Wazuh recipe

Wazuh ingests RFC 5424 syslog natively. On the Wazuh manager, enable a
syslog remote (`/var/ossec/etc/ossec.conf`):

```xml
<remote>
  <connection>syslog</connection>
  <port>6514</port>
  <protocol>tcp</protocol>
  <allowed-ips>203.0.113.0/24</allowed-ips>  <!-- your server's IP -->
</remote>
```

Front it with TLS (Wazuh's syslog remote is plaintext) via a stunnel/nginx
stream terminator, or — inside a trusted private network only — use
`tcp://` with `allow_insecure_transport: true`. EzyShield side:

```yaml
siem:
  - name: wazuh
    address: tls://wazuh.internal:6514
    format: rfc5424
```

Events arrive as standard syslog with structured data
(`[ezyShield@32473 action="ban" ip="..." rule="..." ...]`), ready for
Wazuh decoders/rules.

## Splunk recipe

Use a Splunk Universal Forwarder or an indexer TCP input. For a TCP input
with TLS (Settings → Data inputs → TCP → with SSL), EzyShield side:

```yaml
siem:
  - name: splunk
    address: tls://splunk.internal:5140
    format: json
```

Set the input's sourcetype to `_json` (or define
`sourcetype = ezyshield:audit`) — the JSON events are flat objects with
stable field names (`schema_version`, `action`, `ip`, `rule`, `score`,
`strike`, `ttl_seconds`, `actor`, `node`). Alternatively, write to a file
sink (`file:///var/log/ezyshield-forward.log`) and let the Universal
Forwarder monitor the file.

## Verifying

```bash
sudo ezyshield doctor    # per sink: transport-security warning, reachability (non-fatal)
```

Reachability problems are warnings, not failures — EzyShield keeps
protecting and buffering regardless of SIEM health.

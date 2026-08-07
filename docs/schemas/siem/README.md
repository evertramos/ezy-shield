# EzyShield SIEM event formats

This directory documents the wire formats produced by the `internal/siem`
package: the neutral audit **Event** model rendered as **JSON**, **CEF**
(ArcSight Common Event Format), and **RFC 5424** structured-data syslog. These
are the formats SIEMs such as Wazuh, Splunk, and generic syslog collectors
ingest natively.

This is a *contributor / integration* document. The user-facing forwarding
guide ships separately with the transport work (issue #203); nothing in this
package opens a socket, reads config, or talks to the network — the formatters
are pure functions.

> **Security note.** Every string field of an Event may derive from hostile log
> content (usernames, request paths, rule names, reasons). Each formatter
> escapes its own delimiters and neutralises control characters, so a crafted
> field can never forge a log line, break out of a field, or inject a second
> event. Raw log lines are never carried in an Event and never rendered.

## The Event model

| Event field | Source (audit write path, `internal/store`) | Notes |
|-------------|----------------------------------------------|-------|
| `Time`      | `audit_log.recorded_at`                      | rendered as RFC 3339 **UTC** |
| `Action`    | `audit_log.op`                               | `ban`, `dry_ban`, `unban`, `expire`, `allow`, `arm`, … |
| `IP`        | `audit_log.ip`                               | `netip.Addr`; omitted from output when the zero value (system events) |
| `Rule`      | `audit_log.reason`                           | matched rule / reason text — **untrusted** |
| `Score`     | decision context (`sdk.Verdict.Score`)       | 0–100; `0` when unknown (not in `audit_log`) |
| `Strike`    | `audit_log.strike_num`                       | 0–5 |
| `TTL`       | `audit_log.ttl_seconds`                      | `0` = permanent / not applicable |
| `Actor`     | decision context (`sdk.Verdict.Source`)      | `rules`, `ai:anthropic`, `manual`, … — **untrusted** |
| `Node`      | caller-supplied host name                    | **untrusted** |
| `Product` / `Vendor` / `Version` | caller-injected build info      | defaults `EzyShield` / `ezy` / `unknown` when unset |

### Length cap

Every rendered string field is capped to **512 bytes**, applied *before*
encoding so total output size is bounded regardless of input (a multi-megabyte
"path" attack is truncated long before it reaches a SIEM). The cap never splits
a multi-byte UTF-8 rune. Escaping may expand a capped field by a small constant
factor; output remains bounded.

## Severity mapping

Both severity-bearing formats derive severity from the same internal tier, so
they stay consistent. CEF uses 0–10 (higher = worse); syslog uses 0–7 (**lower
= worse**).

| Event | Tier | CEF severity | Syslog severity |
|-------|------|-------------|-----------------|
| `ban`, strike 5 (permanent) | Critical | 10 | 2 (Critical) |
| `ban`, strike 3–4           | High     | 8  | 3 (Error) |
| `ban`, strike 1–2           | Medium   | 6  | 4 (Warning) |
| `dry_ban`, `notify_only`    | Low      | 4  | 5 (Notice) |
| `unban`, `expire`, `allow`, `allow_expire`, `arm`, `disarm`, `arm_revert` | Info | 2 | 6 (Informational) |
| any unknown op              | Low      | 4  | 5 (Notice) |

## JSON format

A single-line JSON object following the stable schema in
[`event.schema.json`](./event.schema.json); see [`example.json`](./example.json).

- `schema_version` is `1`. It is bumped on any field addition, removal, rename,
  or meaning change.
- `timestamp` is RFC 3339 in UTC, or `""` when the event time is zero.
- `ip` is omitted entirely for system-level events with no target address.
- Numeric fields (`score`, `strike`, `ttl_seconds`) are always present.
- `encoding/json` escapes control characters (a raw newline becomes `\n`), so
  the output is always valid JSON on a single line.

## CEF format

```
CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
```

- **Header fields** escape `\` → `\\` and `|` → `\|`, so an attacker-controlled
  value can never introduce a new pipe-delimited column. CR/LF render as
  `\r`/`\n`; other control characters (including ANSI ESC) become spaces.
- **SignatureID** is the audit op (`unknown` for the zero event). **Name** is a
  human-readable label mapped from the op.
- **Extension** is space-separated `key=value` pairs. Values escape `\` → `\\`
  and `=` → `\=`; CR/LF render as `\r`/`\n`; other control characters become
  spaces. Pipe is *not* a metacharacter here (it follows the final header pipe)
  and is passed through.

Extension keys used: `src` (IP, omitted when absent), `act` (action), `rt`
(event time, epoch ms), `cs1`/`cs1Label` (rule), `cs2`/`cs2Label` (actor),
`cn1`/`cn1Label` (score), `cn2`/`cn2Label` (strike), `cn3`/`cn3Label`
(ttlSeconds), `dvchost` (node).

## RFC 5424 format

```
<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
```

- **PRI** = facility × 8 + severity. Facility is `local0` (16); severity is the
  syslog value from the table above. Example: `<131>` = local0 + Error (a
  strike-3 ban).
- **VERSION** is `1`. **TIMESTAMP** is RFC 3339 UTC (or `-`, the NILVALUE, for a
  zero time). **HOSTNAME**/**APP-NAME**/**MSGID** are reduced to printable-ASCII
  tokens within their RFC length limits (255 / 48 / 32); empty → `-`.
- **STRUCTURED-DATA** carries the event under SD-ID `ezyShield@32473`. The
  enterprise number **32473** is IANA's reserved example/documentation Private
  Enterprise Number (RFC 5612 §3) — a deliberate placeholder until EzyShield
  registers its own PEN. SD-PARAM values escape `"`, `\`, and `]` per RFC 5424
  §6.3.3; all control characters are neutralised, so no field can terminate the
  quoted value or the SD element early and no raw newline can appear.
- **MSG** is a short human-readable summary with control characters neutralised.

SD-PARAMs: `action`, `ip` (when present), `rule` (when present), `actor` (when
present), `score`, `strike`, `ttlSeconds`, `node` (when present).

## Golden fixtures

`fixtures/siem/*.golden` bundle all three renderings of one event (one line per
format) and are the regression corpus for the escaping. Regenerate with:

```
go test ./internal/siem -run TestFormatters_Golden -update
```

Always hand-inspect a regenerated golden before committing — the correctness of
the escaping is the whole point, so a blindly-updated golden proves nothing.
`FuzzSIEMFormatters` additionally asserts, on arbitrary input, that no output
ever contains an unescaped delimiter or a raw newline and that JSON always
validates.

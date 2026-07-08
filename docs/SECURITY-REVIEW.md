# SECURITY-REVIEW.md — Playbook for AI & human security review

> Read this **before reviewing or writing any PR**. .ezy/agents/AGENTS.md has the day-to-day
> rules; this file is the adversarial lens. EzyShield is a root-capable security
> daemon — a bug here isn't a crash, it's a server compromise or a self-inflicted
> outage. Review like an attacker who has read this whole repo.
>
> **How an agent uses this:** for every PR, walk the relevant sections below,
> and in the PR review explicitly state, per section, either a concrete finding
> (file:line + why + fix) or "N/A — this PR doesn't touch X". Never approve a PR
> that touches a 🔴 area without addressing every checklist item in that section.

---

## 0. The threat model in one paragraph

EzyShield ingests **attacker-controlled input** (log lines are written, in part,
by the very attackers we block), runs with the ability to **modify the host
firewall**, holds **secrets** (edge API tokens, bot tokens), talks to **external
APIs**, and exposes a **local control surface** (unix socket, localhost
dashboard) and a **plugin system** (third-party code). The attacker's goals, in
priority order: (1) get EzyShield to ban a legitimate IP / the admin (denial of
service, lock-out), (2) inject content that reaches a privileged action or the
admin's screen, (3) escalate from log-write or plugin access to host root, (4)
exfiltrate secrets, (5) evade detection. Every review asks: *does this change
give the attacker a step toward any of those?*

---

## 1. 🔴 Input handling — logs are hostile data

Log fields (User-Agent, request path, username, referrer) are chosen by the
attacker. Treat every parsed field as adversarial.

- [ ] Parsed fields are **never** interpolated into a shell command, ever. No
      `exec.Command("sh", "-c", ...)` with log-derived strings. Firewall changes
      go only through the enforcer helper with structured args.
- [ ] SQL uses **parameterized queries** only. No string-built SQL with field data.
- [ ] Fields shown to the admin (Telegram, dashboard, CLI) are **escaped/encoded**
      for that sink: Telegram MarkdownV2 escaping, HTML escaping in dashboard,
      control-char stripping in terminal output (an attacker can put ANSI escape
      sequences or `\r` in a UA to forge terminal output or spoof log lines).
- [ ] Length caps on every field before storage/forwarding (a 4MB "path" is an
      attack); reject or truncate, never buffer unbounded.
- [ ] IP parsing uses `netip`, validates, and **never trusts `X-Forwarded-For`**
      except from configured `trusted_proxies`; XFF spoofing test exists.
- [ ] Malformed/oversized/binary lines are skipped safely, never panic the daemon
      (fuzz the parser — see §9).
- [ ] Unicode/homoglyph tricks in usernames/paths don't bypass signature matching
      (normalize before matching, match on bytes where appropriate).

## 2. 🔴 Decision engine — the lock-out / false-ban surface

The worst non-root bug is banning the admin or a whole CDN. (See .ezy/agents/AGENTS.md Hard
Rules; this is the verification side.)

- [ ] Allowlist is checked **first** and is **unbypassable** — no code path bans
      an allowlisted IP/CIDR. Test asserts it.
- [ ] Anti-lockout re-derives the active SSH peer + admin CIDRs **before every
      ban write**, not just at startup.
- [ ] CDN/edge ranges and RFC1918/loopback get the documented guardrail (warn +
      `--force` required); a PR can't quietly remove it.
- [ ] Global ban-rate limit is enforced; a poisoned feed or parser bug can't ban
      thousands of IPs per minute. Breaching it pauses + alerts, doesn't silently
      drop the limit.
- [ ] `armed: false` (dry-run) truly enforces nothing — grep for any enforce call
      not gated by the armed check.
- [ ] Strike/TTL math can't underflow/overflow into "permanent" or "never expire"
      unexpectedly; expired bans actually get removed (no stuck bans).
- [ ] AI verdicts are clamped to policy: cannot exceed max TTL, cannot target
      allowlisted IPs, cannot trigger ASN/country bans alone. Test both.

## 3. 🔴 Privilege separation & the enforcer

`ezyshield-enforcer` holds `CAP_NET_ADMIN`; the brain must never gain arbitrary
command execution through it.

- [ ] Enforcer accepts **only** the fixed verb set (`add/del/flush/list`) with
      typed, validated args (IP/CIDR/ASN/country) — reject anything else. No
      pass-through of raw nft/iptables syntax from the caller.
- [ ] The enforcer socket is root-owned, mode `0660`, group-restricted; verify
      perms on creation. No TCP, ever.
- [ ] Main daemon runs as a **dedicated unprivileged user**, not root; only the
      enforcer has the capability, scoped via systemd `CapabilityBoundingFor`/
      `AmbientCapabilities=CAP_NET_ADMIN` and nothing more.
- [ ] systemd hardening present and not weakened: `NoNewPrivileges=yes`,
      `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
      `RestrictAddressFamilies`, `SystemCallFilter=@system-service`, read-only
      paths except the state dir. A PR that removes a hardening directive must
      justify it.
- [ ] No `setuid` binaries; privilege is via capabilities + systemd only.
- [ ] Rule writes are **atomic** (generate a full ruleset, apply in one
      transaction) so a crash mid-write can't leave the host half-open or fully
      blocked.

## 4. 🔴 Secrets handling

- [ ] No secret in YAML config, source, tests, fixtures, logs, error messages,
      or AI prompts. (grep the diff for token-shaped strings.)
- [ ] Secrets come only from env / systemd `LoadCredential=` / a `0600` file;
      `doctor` fails on bad perms.
- [ ] Secrets are **not logged** even at debug; redact in any struct dump.
      Telegram/Cloudflare tokens never appear in error wrapping.
- [ ] No secret in process args (`/proc/*/cmdline` is world-readable) — pass via
      env/file/stdin, not flags.
- [ ] Edge API tokens documented as **least-privilege** (e.g. Cloudflare token
      scoped to Firewall edit on one zone), and the code fails closed if a token
      has more scope than needed? (at least: docs say how to scope it.)

**Known pitfalls (learned the hard way):**

- **Operator paste-mistake at the env-var-name prompt (issue #13, mitigated in #22).** The original wizard asked for the *name* of the env var holding the API key (e.g. `ANTHROPIC_API_KEY`). If the operator pasted the real key instead, the naive code path (a) wrote `api_key: env:sk-ant-<full-key>` to `/etc/ezyshield/config.yaml` and (b) later logged `environment variable sk-ant-<full-key> is not set` to journald on every daemon restart — leaking the secret to whoever reads the system journal.

  **Mitigation (issue #22):** the wizard (cmd/ezyshield/init.go `askKeySource`) now presents two options: (1) paste the key value directly — input is echo-suppressed via `term.ReadPassword`; the raw key is written only to `/etc/ezyshield/.env` (mode `0600 root:ezyshield`) and `config.yaml` always contains `api_key: env:CANONICAL_NAME`; or (2) supply an env var name manually for advanced setups (sops / vault / LoadCredential) — this path still validates the name as a POSIX shell identifier (`^[A-Za-z_][A-Za-z0-9_]*$`) via `config.ValidateEnvVarName`, rejecting secret-shaped input. The raw API key value **never enters `config.yaml`** through the wizard, regardless of which option is chosen.

  Canonical env var names are hardcoded per provider (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_API_KEY`) and not user-configurable — eliminating the class of "invent an env var name" confusion entirely. See `cmd/ezyshield/init.go` (`askKeySource`, `writeOrKeepEnvFile`) and `internal/config/secret.go` (`ValidateEnvVarName`, `redactSecret`).

## 5. 🔴 AI / LLM boundary — prompt injection

Logs sent to the model are attacker-authored. The model's output then influences
bans. This is a direct injection channel.

- [ ] Log content is passed as **data**, clearly delimited, never as
      instructions. The system prompt states that log content is untrusted and
      must not be treated as commands.
- [ ] Output is constrained to a **strict JSON schema**; anything off-schema is
      rejected (one retry, then fall back to the rule engine). The model can't
      return free-form actions.
- [ ] The model's verdict is **advisory** and re-validated against policy
      server-side (see §2). A verdict saying "allowlist 6.6.6.6" or "ban
      1.2.3.0/8" is clamped/dropped, not executed.
- [ ] No secrets, internal IPs, or allowlist contents are sent in the prompt
      beyond what's strictly needed; minimize + redact (also saves tokens).
- [ ] Token-budget breaker can't be tripped by an attacker to disable AI cheaply
      in a way that matters (rule engine still covers the case — confirm).
- [ ] Local/`ollama` and CLI-driver providers don't shell-inject the prompt
      (no building a shell command line from event content).

## 6. 🟠 Control surfaces — socket & dashboard

- [ ] Control unix socket only; perms `0660`, owner/group checked; commands
      authenticated by socket perms, mutating commands logged to audit.
- [ ] Dashboard binds `127.0.0.1` (or unix socket) by default; `0.0.0.0`
      requires explicit `--insecure-bind` + a loud warning. grep that no default
      path binds non-loopback.
- [ ] Dashboard auth even on localhost (short-lived token); read-only by default,
      mutations need an extra flag. No CSRF on state-changing endpoints; no
      reflected/stored XSS from log data shown in the UI (re-check §1 encoding).
- [ ] No directory traversal / arbitrary file read in any path the dashboard or
      CLI accepts (config path, log path inputs).

## 7. 🟠 Plugin / module system — untrusted third-party code

- [ ] Tier-1 plugins run as a **separate process**, not in-daemon; with a
      timeout, output size cap, and **no network unless the manifest declares it**.
- [ ] Plugin can't write firewall rules directly — it can only *suggest*
      verdicts that go through the decision engine + policy clamps.
- [ ] Manifest permissions are enforced, not just displayed; install prompts on
      capabilities; checksum/signature verified before run.
- [ ] Plugin output is parsed as hostile data (it is — §1 applies to it too).
- [ ] A crashing/hanging/malicious plugin can't take down the daemon or block the
      pipeline (isolation + timeout + circuit-breaker).

## 8. 🟠 Edge / external API calls

- [ ] All outbound HTTPS validates certs (no `InsecureSkipVerify`); pinned or
      system roots; timeouts on every call; context cancellation honored.
- [ ] Edge sync is **idempotent** and reconciles; `disable --all` removes edge
      blocks too (a CDN block outliving the daemon is an outage). Test the unban
      path, not just the ban path.
- [ ] API responses are treated as untrusted (don't trust an edge API to return
      well-formed data); handle rate-limit/4xx/5xx without crashing or
      hot-looping.
- [ ] No SSRF: any URL/endpoint that comes from config is validated; reputation
      feed URLs can't be pointed at internal services.

## 9. 🟡 Dependencies, build & supply chain

- [ ] Every **new dependency** is justified in the PR (stdlib first). Check it's
      maintained, widely used, and license-compatible (no GPL-incompatible deps
      into an AGPL binary; no surprise network calls).
- [ ] `govulncheck` clean; `go.sum` updated; no replaced/forked deps without note.
- [ ] CGO stays **off** (static binary, smaller attack surface). gosec passes;
      CodeQL security-and-quality clean.
- [ ] Parsers have **fuzz tests** (`go test -fuzz`) — parsers are the primary
      untrusted-input boundary.
- [ ] Releases signed (cosign/minisign); SBOM generated; reproducible if feasible.

## 10. 🟡 Logging, audit & error handling

- [ ] Every state-changing action writes an **append-only** audit record
      (who/what/why/when); no code path updates/deletes audit rows.
- [ ] Errors are wrapped with context but **never leak secrets or full attacker
      input** into logs at info level (debug may include redacted samples).
- [ ] Failures **fail safe**: on doubt, don't ban (avoid weaponizing the tool);
      on enforcer error, alert rather than silently continue thinking a ban
      applied.
- [ ] No panic in library code reaches the daemon's main loop unrecovered; the
      watchdog flushes partial rules on crash.

---

## Review output format (what the agent must produce)

For each PR, post a review comment shaped like:

```
## Security review (per SECURITY-REVIEW.md)
§1 Input handling: FINDING — internal/parser/nginx.go:88 logs raw UA at info
   level (leaks attacker-controlled content / possible ANSI injection). Fix:
   strip control chars + cap length before logging.
§2 Decision engine: OK — allowlist checked first, test added.
§3 Privilege sep: N/A — PR doesn't touch enforcer.
...
Verdict: REQUEST CHANGES (one §1 finding must be fixed before merge).
```

Be specific (file:line, why, fix). "Looks fine" is not a review. If unsure
whether something is exploitable, flag it as a question rather than approving.

## Severity legend
🔴 critical area — a finding here can mean host compromise, root escalation, or
mass false-ban / lock-out. Block merge until resolved.
🟠 high — meaningful exposure (control surface, third-party code, external APIs).
🟡 important hygiene — supply chain, audit, error handling.

## Things reviewers here get wrong
- Approving a parser change without a fuzz test or a control-char/escaping check.
- Treating AI output as trusted because "it's just a classifier."
- Letting a hardening systemd directive get dropped "to make tests pass."
- Reviewing the ban path but not the **unban/expiry/edge-cleanup** path.
- Forgetting that plugin output and edge-API responses are *also* untrusted input.
- Focusing only on remote attackers and missing the **lock-out / self-DoS** class,
  which is the most likely real incident for this kind of tool.

---

## 10. 🟡 Code quality self-review (mandatory before opening PR)

Before opening a PR, the authoring agent MUST walk through this checklist on
every function written or modified. These are not style nits — each item has
caused real bugs in this project.

### Dead code & reachability
- [ ] Every `if/else/switch` branch is **reachable**. Trace through: can the
      condition actually be true given prior guards? Remove dead branches.
- [ ] Every `return` early-exit doesn't orphan logic below it.

### Error paths & secrets
- [ ] Error messages from `fmt.Errorf` or returned `error` values **never**
      contain secrets (API keys, tokens, passwords). Use `%w` on inner errors
      but verify the chain doesn't surface a URL with embedded credentials.
- [ ] HTTP clients: if the URL contains secrets, wrap errors without `%v` on
      the request/URL. Use `req.URL.Query()` to build parameterized URLs.

### Retry & backoff
- [ ] Any retry loop has a **bounded** delay. If parsing a delay header fails,
      fall back to exponential backoff — never retry with delay=0.
- [ ] Rate limit handling: `hasExplicitDelay` or similar flags are only set when
      the delay value is **successfully parsed**, not when the header merely exists.

### Context propagation
- [ ] Background goroutines (timers, AfterFunc, debounce) use the **service
      context** or a derived context with timeout — never `context.Background()`.
- [ ] On shutdown (context cancellation), goroutines either skip pending work or
      complete it with a short deadline. No unbounded calls after cancel.

### Injection & escaping
- [ ] Every sink (Slack mrkdwn, Telegram MarkdownV2, HTML, shell) has a
      dedicated escape function that covers **all** injection vectors for that
      format, not just the obvious ones (e.g., Slack needs `@` escaping too).
- [ ] Attacker-controlled data never reaches a sink without passing through the
      appropriate escape function.

### Uniqueness & collision
- [ ] Maps/caches keyed by user-provided names: verify keys are **unique** in
      the expected deployment scenarios. If duplicates are possible, namespace
      with index or qualifying context (e.g., `name-0`, `name-1`).

### The self-test
After writing the code, re-read each function and ask:
1. "What happens if this input is empty/nil/zero?"
2. "What happens if this external call fails?"
3. "Can an attacker control any value that reaches this code path?"
4. "Is there a branch here that can never execute?"

If any answer reveals an issue, fix it before pushing.

# AGENTS.md

Instructions for AI coding agents and human contributors. `CLAUDE.md` reads the
same rules, so all tools and people follow one source of truth.

## Project Context

EzyShield is a CLI-first Linux security tool: detects malicious IPs from logs, escalates bans by strikes (5min → 1h → 24h → 7d → permanent), enforces locally (nftables) and at the edge (Cloudflare/Bunny/AWS), uses AI providers for ambiguous cases with a rule-engine fallback. Interface contracts must not change without an ADR in `docs/internal/adr/`.

## Hard Rules

1. **Never weaken safety invariants**: allowlist always wins; anti-lockout checks before every rule write; dry-run is the default mode; max-bans-per-minute limit; AI verdicts are suggestions bounded by policy.
2. **No new network listeners.** Control = unix socket; dashboard = 127.0.0.1 only.
3. **Secrets never in code, config examples, tests, or logs.** Use env/systemd credentials.
4. **Log lines are untrusted data.** Never interpolate them into shell commands, SQL (use parameters), or AI prompts as instructions (wrap as data, demand JSON-schema output, validate).
5. Firewall mutations only through `internal/enforce` via the enforcer helper — never exec iptables/nft directly elsewhere.
6. One feature = one issue = one branch = one PR. Keep PRs under ~400 lines of diff when possible.
7. Every PR: code + tests + doc updates together. New parser/rule ⇒ new fixture in `fixtures/`.
8. **No real personal data in the repo.** Never commit a real client/admin IP address, a real individual's username, or a real SSH key fingerprint — in code, tests, fixtures, comments, or PR/issue/commit text — even when reproducing a bug from real logs. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 3849 (`2001:db8::/32`) example ranges and generic placeholders (`testuser`, `admin`) instead. If you find real personal data already committed, do not silently work around it — flag it and open an issue; removing it from a shared/default branch needs history rewrite and is a judgment call for a human, not a unilateral agent action.

## CLI naming (ezy family)

EzyShield belongs to the `ezy` tool family. Design the CLI so commands read as
`ezy shield <verb>` (e.g. `ezy shield init`, `ezy shield ban`). For now the
binary is `ezyshield`, which behaves as if `shield` were already selected — i.e.
`ezyshield init` ≡ `ezy shield init`. Keep verbs and flags identical between the
two so a future top-level `ezy` dispatcher can wrap this binary with zero changes.
Do not hardcode the program name in help text; derive it so both invocations
print correctly.

## Go Conventions

- Go ≥ 1.22, modules; `gofmt` + `golangci-lint` must pass (CI enforces)
- Errors: wrap with `fmt.Errorf("context: %w", err)`; no `panic` outside `main`
- Use `netip.Addr`/`netip.Prefix`, never string IPs internally
- Context first arg everywhere; honor cancellation in all loops
- Logging via `log/slog`, structured, no `fmt.Println` in library code
- No CGO (we use modernc.org/sqlite); binary must stay statically linkable
- Public SDK = `pkg/sdk` only; everything else under `internal/`
- Table-driven tests; golden files for parsers; `-race` in CI

## Security review (mandatory)

EzyShield is a root-capable security daemon, so **every PR gets a security pass
against `docs/internal/SECURITY-REVIEW.md`** — by the authoring agent before opening the
PR, and by the reviewing agent before approving. In the PR description, include
the per-section output that file specifies (FINDING / OK / N/A per §). A PR that
touches a 🔴 area (input parsing, decision engine, enforcer/privilege, secrets,
AI boundary) cannot be approved until every checklist item in that section is
addressed. "Looks fine" is not a review — cite file:line, why, and the fix.

## Workflow for Agents

1. Read the GitHub issue; restate acceptance criteria in the PR description.
2. Check `docs/internal/adr/` for relevant decisions before proposing design changes.
3. Write/extend tests first when fixing bugs (reproduce, then fix).
4. Run locally before pushing: `make lint test` (must be green).
5. **Before opening the PR**: walk `docs/internal/SECURITY-REVIEW.md §10` (code quality self-review) on every function you wrote or modified. This is mandatory — PRs that skip this step will be rejected.
6. If a task seems to require breaking a Hard Rule, stop and open a discussion issue instead.

## Commit / PR Style

- Conventional commits: `feat(enforce): add bunny edge blocker`, `fix(parser): nginx ipv6`
- PR template checklist must be completed; CI (lint, test, CodeQL) is required to merge.

## Security test gates (mandatory CI — do not break)

| Gate | What it guards |
|------|---------------|
| `FuzzSSHParser` / `FuzzNginxParser` | Parser panic-safety on hostile bytes; run with `-fuzztime=10s` in CI, longer locally |
| `govulncheck ./...` | Known CVEs in module graph |
| `gosec` (via golangci-lint) | Static security linting |
| `internal/decision/antilockout_test.go` | SSH peer / allowlist / CDN range can never be banned (§2 SECURITY-REVIEW) |
| `internal/ai/prompt_injection_test.go` | Hostile log content excluded from AI payload; off-schema responses fall back to rules; policy clamps (§5 SECURITY-REVIEW) |
| `internal/config/secret_leak_test.go` + `internal/ai/secret_leak_test.go` | Tokens never appear in errors, logs, or request bodies (§4 SECURITY-REVIEW) |
| `ip-hygiene-gate` (`scripts/ip-hygiene-gate.sh`) | Hard Rule 8: IP literals added to tests/`fixtures/`/`configs/` must be RFC 5737/3849 documentation ranges; `internal/cdndetect/` (real CDN range data) is exempt. Usernames/key fingerprints have no reserved range — still review-only |

Adding a new parser → add a `FuzzXxxParser` with seeds: malformed, oversized (>4 KB), binary, ANSI, CRLF injection.

## Things Agents Commonly Get Wrong Here (read twice)

- Forgetting TTL expiry/reconcile when adding a new Enforcer (implement `Sync`)
- Sending raw log lines to AI providers (must go through Normalizer/redaction)
- Binding the dashboard to 0.0.0.0 "for convenience" — forbidden
- Adding a dependency for something stdlib does; justify every new dependency in the PR
- Writing migrations that edit old migration files — always append a new one
- Pasting real log lines from a live host straight into a test/fixture without sanitizing the IP/username/key-fingerprint first (Hard Rule 8) — this reached a public commit once already

# Contributing

1. Read AGENTS.md — its rules apply to humans and AI agents alike.
2. Pick an issue (or open one to discuss first). One issue = one branch = one PR.
3. PRs must include tests + doc updates and pass CI (lint, test -race, CodeQL).
4. New parsers/rules require fixtures in fixtures/ (anonymize real logs first!).
5. CLA: by submitting a contribution you agree to the project CLA (to be set up
   with cla-assistant before the first external PR), which allows the project
   to remain sustainably licensed. Your code stays AGPL-3.0 in this repo.

## Security test gates (mandatory for 🔴 areas)

These CI gates must stay green. A PR that breaks them cannot merge:

| Gate | Location | What it checks |
|------|----------|---------------|
| **Fuzz — SSH parser** | `internal/parser/ssh_fuzz_test.go` | No panic on arbitrary/binary/ANSI/CRLF input |
| **Fuzz — Nginx parser** | `internal/parser/nginx_fuzz_test.go` | No panic on arbitrary/binary/ANSI/CRLF/JSON-injection input |
| **govulncheck** | CI `govulncheck` job | No Go module with known CVEs |
| **gosec** | `.golangci.yml` via golangci-lint | Static security linting (hard-coded creds, shell injection, etc.) |
| **Anti-lockout** | `internal/decision/antilockout_test.go` | Active SSH peer, allowlisted IP, CDN range → Op="record", RecordStrike never called |
| **Prompt injection** | `internal/ai/prompt_injection_test.go` | Hostile log content excluded from API payload; off-schema verdicts fall back to rules; policy clamps apply |
| **Secret leak** | `internal/config/secret_leak_test.go`, `internal/ai/secret_leak_test.go` | Tokens never in error strings or request bodies |

When adding a new parser, add a corresponding `FuzzXxxParser` target and a seed corpus entry for each of: malformed, oversized (>4096 bytes), binary, ANSI/control-char injection, and CRLF injection.

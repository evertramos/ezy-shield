## What & why
<!-- Link the issue. Restate the acceptance criteria you're satisfying. -->
Closes #

## Changes
<!-- Short bullet list of what changed. -->

## Tests
- [ ] Unit tests added/updated
- [ ] New parser/rule? fixture added in `fixtures/`
- [ ] Parser change? fuzz test present (`go test -fuzz`)
- [ ] `make lint test` green locally (`-race`)

## Blast radius (per docs/internal/INVARIANTS.md)
<!-- Which invariant(s) does this touch (A1…D4)? List every OTHER reader/writer of that invariant
     and how each was re-verified (test name, or "unchanged path, covered by X"). Write "none" only
     if the change touches no path named in INVARIANTS.md. -->
- Invariant(s):
- Other readers/writers re-verified:
- Harness scenario that failed before the fix:

## Security review (per docs/internal/SECURITY-REVIEW.md)
<!-- For each section: FINDING (file:line + why + fix), OK, or N/A. -->
- §1 Input handling (hostile logs):
- §2 Decision engine (lock-out / false-ban):
- §3 Privilege separation / enforcer:
- §4 Secrets:
- §5 AI / prompt-injection boundary:
- §6 Control surfaces (socket/dashboard):
- §7 Plugins:
- §8 Edge / external APIs:
- §9 Dependencies / supply chain:
- §10 Logging / audit / fail-safe:

**Self-assessment:** does this change give an attacker a step toward
lock-out / injection / privilege-escalation / secret-exfil / evasion? Explain.

## Checklist
- [ ] Follows AGENTS.md Hard Rules (no new listeners, allowlist supremacy, dry-run default, secrets out of code)
- [ ] No hardening systemd directive removed (or justified above)
- [ ] Docs updated (PLAN/ARCHITECTURE/guide) if behavior changed
- [ ] New dependency justified (or none added)

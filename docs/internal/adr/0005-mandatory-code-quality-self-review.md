# ADR-0005: Mandatory code quality self-review (SECURITY-REVIEW.md §10)

**Status:** Accepted  
**Date:** 2026-06-20

## Context

CI catches compilation errors and lint issues but misses subtle bugs — dead code reachability, secret leaks in error paths, unbounded retries, missing context propagation, injection escaping gaps, and key uniqueness violations. Seven such bugs were caught by Copilot review that CI did not detect.

## Decision

AI agents must walk a mandatory checklist (SECURITY-REVIEW.md §10) before opening any PR.

## Consequences

- Catches classes of bugs that linters and tests miss, before review
- Adds a small time cost per PR but prevents expensive post-merge fixes
- Checklist evolves as new bug patterns emerge from reviews

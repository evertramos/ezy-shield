# ADR-0006: Copilot + Claude dual review process

**Status:** Accepted  
**Date:** 2026-06-20

## Context

A single AI reviewer misses things — different models have different blind spots. We want higher coverage of code quality issues without adding human review burden for routine fixes.

## Decision

Copilot reviews PRs for code quality issues; each comment becomes an issue. Claude then analyzes whether it agrees and either implements the fix or flags it for human review.

## Consequences

- Two AI reviewers with different training catch more issues than one
- Routine fixes get implemented automatically, reducing human toil
- Disagreements between reviewers surface genuinely ambiguous cases for human judgment

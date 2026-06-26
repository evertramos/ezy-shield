# ADR-0004: Stat-based polling fallback for file tailing

**Status:** Accepted  
**Date:** 2026-06-20

## Context

EzyShield tails log files to detect attacks. inotify does not reliably deliver events on all kernel/filesystem combinations — we confirmed missing events on Debian 12 with overlay2. We cannot depend solely on inotify for correctness.

## Decision

We poll file size via stat every 500ms as a fallback. The inotify fast path remains active where the kernel supports it reliably.

## Consequences

- Detection works correctly on all supported Linux configurations, including containers
- 500ms polling adds negligible CPU overhead but bounds worst-case detection latency to ~500ms
- Dual-path code requires care to avoid duplicate reads when both inotify and poll fire

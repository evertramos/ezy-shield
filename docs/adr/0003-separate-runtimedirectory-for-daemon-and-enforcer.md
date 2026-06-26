# ADR-0003: Separate RuntimeDirectory for daemon and enforcer

**Status:** Accepted  
**Date:** 2026-06-20

## Context

EzyShield runs two systemd services: the main daemon and the enforcer. Both use Unix sockets in `/run/`. When systemd restarts one service, it cleans that service's RuntimeDirectory — if both share the same directory, one service loses its socket when the other restarts.

## Decision

Daemon uses `/run/ezyshield/`, enforcer uses `/run/ezyshield-enforcer/`. Each service owns its own RuntimeDirectory.

## Consequences

- Restarting one service never disrupts the other's socket
- Each unit file declares its own `RuntimeDirectory=`, making ownership explicit
- Slightly more paths to document, but eliminates a class of subtle restart bugs

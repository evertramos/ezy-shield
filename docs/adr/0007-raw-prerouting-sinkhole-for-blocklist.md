# ADR-0007: raw/prerouting sinkhole for the block list

**Status:** Accepted
**Date:** 2026-07-03

## Context

The initial enforcer placement (ADR-0001) put the block-list drops at `filter/input` and `filter/forward` (priority `0`). This works for traffic destined for the host — SSH, exposed control panels, etc. It does **not** work for a large class of deployments:

- **Docker with `docker-proxy` on** (default): the packet is accepted by a userspace TCP proxy on the host before either the input or forward chain sees the original source IP. The new connection docker-proxy opens to the container has source `172.18.0.1`, so `ip saddr @blocked` never matches.
- **Docker with `--userland-proxy: false`**: DNAT rewrites the destination in `nat/prerouting` (priority `-100`). Source IP is preserved, so `filter/forward` (priority `0`) can catch it — but only in this non-default configuration.
- **Podman rootless (slirp4netns / pasta)**: userspace networking, same failure mode as docker-proxy.

Discovered live on the maintainer's kylian-s host — a banned IP kept hitting a Docker-published nginx container for 44 minutes after being permaban'd (issue #23). The ban had entered `bans_active`, `ezyshield list`, and the nftables `blocked` set. Every observable surface said "the ban worked". Every observable surface was wrong.

## Decision

Register an additional chain on the `inet ezyshield` table:

```nft
chain prerouting {
    type filter hook prerouting priority raw; policy accept;

    # Anti-lockout invariant (AGENTS.md §2) — allowlist accepts first,
    # on the same hook, or the invariant only holds for packets that reach the
    # daemon.
    ip  saddr @allowed  accept
    ip6 saddr @allowed6 accept

    # notrack skips conntrack for packets we're about to drop, saving state
    # table slots under scanner floods (nftables wiki recommendation).
    ip  saddr @blocked  notrack
    ip6 saddr @blocked6 notrack
    ip  saddr @blocked  drop
    ip6 saddr @blocked6 drop
}
```

The existing `input` and `forward` chains at `priority filter` are **kept** as defense in depth. If for any reason a packet bypasses the `raw` drop (module reload race, external `nft flush ruleset`), the existing chains still catch it.

Two new nftables sets — `allowed` / `allowed6` — mirror the shape of `blocked` / `blocked6` but without native `timeout`; the daemon owns allowlist TTLs and syncs the set on entry expiry.

## Why priority `raw` (-300)

The kernel evaluates prerouting hooks in strict priority order (lower = earlier):

| Priority | Purpose | Registered by |
|---|---|---|
| **-300** | `raw` — no conntrack, no NAT | **This ADR** |
| -200 | conntrack lookup | Kernel |
| -150 | `mangle` | QoS / marking |
| -100 | `dstnat` | **Docker publish, Podman netavark** |
| 0 | `filter` | Existing EzyShield chains |
| 100 | `srcnat` | Masquerading |

`raw` runs before every party that could steal or rewrite the packet. Nothing Docker or Podman does at ingress runs earlier. The packet arrives with the original source IP, no state has been committed, and dropping it is essentially free.

## Alternatives considered

| Alternative | Rejected because |
|---|---|
| `mangle/prerouting` (-150) | Runs after conntrack. If `raw` works, `mangle` is strictly worse — same coverage, more overhead. |
| Docker's `DOCKER-USER` chain | Docker's recommended integration point, but only covers docker-native forwarding. Misses `docker-proxy` and Podman rootless (both use userspace networking, bypass DOCKER-USER entirely). |
| Insert at `nat/prerouting priority -101` | Priority conflict — Docker registers at `-100`, and any rule at `-101` breaks legitimate NAT consumers. Fragile. |
| eBPF/XDP drop | Best performance, but requires modern kernel and specialized tooling. Overkill for the current stage of the project. |
| Keep existing chains, tell operators to disable `docker-proxy` (`userland-proxy: false`) | Requires per-operator configuration change with unrelated side effects (loses hairpin, some containers break). Not a solution — a workaround. |

## Community precedent

- **[Netfilter wiki — nftables best practices](https://wiki.nftables.org/)**: `raw/prerouting` with `notrack + drop` is the documented canonical placement for pure-drop IP blocklists. Pattern explicitly recommended by Pablo Neira Ayuso.
- **[CrowdSec `cs-firewall-bouncer`](https://github.com/crowdsecurity/cs-firewall-bouncer)** — the closest architectural sibling to EzyShield. Its `nftables` backend registers the drop chain at `raw/prerouting` for exactly the reasons above. Production-grade precedent.
- **fail2ban's modern `nftables-common.conf`**: moved the sinkhole to prerouting after the same class of container-bypass reports.

## Consequences

**Positive:**

- Bans apply uniformly across Docker (any config), Podman (rootful and rootless), LXC, and future container runtimes that use userspace networking.
- `notrack` before `drop` saves conntrack table entries under scanner floods — real DoS-mitigation benefit.
- Rule audit surface stays inside one nftables table (`inet ezyshield`) — no new tables, no cross-namespace surprises.

**Trade-offs:**

- Allowlist rules now live in two places (raw/prerouting and the daemon-side check). Both must be kept in sync. The daemon calls `SyncAllowlist` on startup, on every operator `allow` call, and on entry expiry.
- If an operator has pre-existing rules at `raw` for other reasons (rare — `raw` is typically empty), those rules coexist with the ezyshield chain but priority-tied ordering between multiple chains at the same hook+priority is undefined. Not expected to matter in practice; `raw` is essentially unused space in most deployments.
- The `allowed` sets have no nft-native `timeout` — allowlist TTLs are enforced by the daemon's expiry loop. If the daemon crashes and stays down, allowed entries persist in nft until the daemon comes back and syncs. Acceptable — allow entries persisting a bit too long is failure-open in the right direction.

**Future work not blocked by this ADR:**

- `ezyshield doctor` gaining a check for the prerouting chain being registered correctly (right priority, right rule order).
- QEMU e2e harness gaining a Docker-container-target test that would have caught this from the start.
- Possible future move to XDP/eBPF for the busiest scanner hosts, once justified by measured overhead.

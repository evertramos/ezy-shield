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

    # notrack skips conntrack for packets we're about to drop, keeping the
    # kernel conntrack table lean under scanner floods. Standard nftables
    # idiom (see the References section below).
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
| Docker's [`DOCKER-USER` chain](https://docs.docker.com/engine/network/packet-filtering-firewalls/#docker-on-linux) | Docker's own recommended integration point for user firewall rules, but it only sees traffic Docker forwards to containers through DNAT. Traffic accepted by the userspace `docker-proxy` never reaches this chain; Podman rootless (slirp4netns / pasta) never touches it either. |
| Insert at `nat/prerouting priority -101` | Priority conflict — Docker registers at `-100`, and any rule at `-101` breaks legitimate NAT consumers. Fragile. |
| eBPF/XDP drop | Best performance, but requires modern kernel and specialized tooling. Overkill for the current stage of the project. |
| Keep existing chains, tell operators to disable `docker-proxy` (`userland-proxy: false`) | Requires per-operator configuration change with unrelated side effects (loses hairpin, some containers break). Not a solution — a workaround. |

## References

**Primary documentation** — everything the design above relies on is in these pages:

- **[nftables wiki — Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)** — canonical documentation of the netfilter hook priorities (`raw`, `mangle`, `dstnat`, `filter`, `srcnat`) reproduced in the priority table above, and the top-down rule-evaluation model on which the allow-before-drop ordering depends.
- **[nftables wiki — Sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets)** — how `flags interval, timeout, auto-merge` sets work, which is what `blocked` / `blocked6` and `allowed` / `allowed6` are built on.
- **[nftables wiki — Simple ruleset for a server](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server)** — the wiki's own worked example uses allow-first ordering (accept rules before the terminating drop), the same pattern applied here on the prerouting chain.
- **[Docker — Packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)** — Docker's official documentation of `DOCKER-USER`, how docker-proxy is spawned, and how user-installed firewall rules interact (or don't) with Docker's own NAT rules. Justifies why the `DOCKER-USER` alternative was rejected.

**Precedent in similar OSS:**

- **[CrowdSec `cs-firewall-bouncer` — nftables backend](https://github.com/crowdsecurity/cs-firewall-bouncer/tree/main/pkg/nftables)** — the closest architectural sibling to EzyShield (adaptive IP-blocklist bouncer for a Linux host). Its nftables backend registers a chain at `hook prerouting priority -300` for exactly the reasons in this ADR. Production-grade precedent maintained by the CrowdSec team.

**Honesty about paraphrase:** in the pull request description and earlier reviews I attributed "the `raw/prerouting` + `notrack + drop` pattern" to a specific recommendation by Pablo Neira Ayuso (nftables maintainer). I don't have a specific talk, mailing-list post, or wiki page from him to point at — that was my paraphrase of the pattern being standard practice, not a literal quotation. The design still stands on the sources above; the attribution to a single person was overstated. Similarly, an earlier draft mentioned fail2ban having "moved to prerouting in modern releases"; I could not verify that in fail2ban's current documentation before writing this ADR and have dropped the claim.

## Consequences

**Positive:**

- Bans apply uniformly across Docker (any config), Podman (rootful and rootless), LXC, and future container runtimes that use userspace networking.
- `notrack` before `drop` saves conntrack table entries under scanner floods — real DoS-mitigation benefit.
- Rule audit surface stays inside one nftables table (`inet ezyshield`) — no new tables, no cross-namespace surprises.

**Defense in depth (intentional, not a trade-off):**

The allowlist now has representations at four layers, each defending against a different failure mode. This is layered design, not accidental duplication — collapsing to a single copy would remove protection in every direction we care about.

| Layer | Where | What it protects against |
|---|---|---|
| Canonical | SQLite `allowlist` table (`store.AddAllow` / `ListAllow`) | Persistence, restart survival, audit. Single source of truth. |
| Runtime — daemon | `d.runtimeAllowlist` in-memory | Pipeline (rules → AI → decision) checks BEFORE generating a ban. Avoids inflating audit_log with bans that never should have existed, and avoids paying to consult Claude on IPs we'd never ban anyway. |
| Runtime — enforcer client | `NftablesEnforcer.allowlist` in-memory | Client-side belt-and-suspenders: refuses to send `add` to the enforcer even if the daemon layer above missed. Documented in `NftablesEnforcer` as an anti-lockout guard against direct invocation. |
| Kernel | nft `@allowed` / `@allowed6` sets (this ADR) | Last line: if any bug in the layers above lets an allowlisted IP land in `@blocked`, the kernel's `accept` runs before `drop` and the packet gets through. Prevents admin/CI lockout even under a bugged daemon. |

The layers reference the same canonical source but are consulted at different points in the packet's life and at different levels of privilege. Fusing them would either lock users out on any daemon bug (drop layer 4) or force the pipeline to hit external state on every event (drop layer 2). Neither is acceptable.

Sync is a mechanical problem, not an architectural one, and is already implemented: `d.syncEnforcerAllowlist` runs on startup, on every operator `allow` call, and after every expiry sweep. See "Future work" for further hardening.

**Other trade-offs:**

- If an operator has pre-existing rules at `raw` for other reasons (rare — `raw` is typically empty), those rules coexist with the ezyshield chain but priority-tied ordering between multiple chains at the same hook+priority is undefined. Not expected to matter in practice; `raw` is essentially unused space in most deployments.
- The `allowed` sets have no nft-native `timeout` — allowlist TTLs are enforced by the daemon's expiry loop. If the daemon crashes and stays down, allowed entries persist in nft until the daemon comes back and syncs. Acceptable — allow entries persisting a bit too long is failure-open in the right direction.

**Future work not blocked by this ADR:**

- `ezyshield doctor` gaining a check for the prerouting chain being registered correctly (right priority, right rule order).
- `ezyshield doctor` gaining an "allowlist consistency" check — reads `store.ListAllow`, `d.runtimeAllowlist`, and the nft `@allowed` / `@allowed6` sets, and reports divergence between any two of them. Turns silent sync drift into a doctor `[FAIL]` instead of a lockout waiting to happen.
- Periodic reconciliation loop in the daemon: a low-frequency ticker (every ~5 min) that runs `syncEnforcerAllowlist` unconditionally. `SyncAllowlist` is already idempotent, so the cost is a single `nft list set` + set-diff; the payoff is that any transient sync failure (nft unreachable during an operator `allow` call, race during expiry) is self-healing within the tick period instead of persisting until the next daemon restart.
- Counter for "kernel-level accept saved us": every time the `@allowed accept` rule at prerouting fires with the same IP that was written to `@blocked` in the last few minutes, we know the upper layers had a bug and layer 4 caught it. Exporting that counter (log or metrics) turns "defense in depth" from an untestable claim into an observable one — a sustained rise means there's a real bug in the daemon-side check to hunt.
- QEMU e2e harness gaining a Docker-container-target test that would have caught this from the start.
- Possible future move to XDP/eBPF for the busiest scanner hosts, once justified by measured overhead.

# syntax=docker/dockerfile:1
#
# Official EzyShield container image (issue #101).
#
# This Dockerfile is consumed by goreleaser (`dockers_v2:` in .goreleaser.yaml),
# which builds `ezyshield` and `ezyshield-enforcer` (static, CGO off) and lays
# them out per platform in the build context (linux/amd64/…, linux/arm64/…) —
# so the COPY lines below reference the prebuilt binaries via $TARGETPLATFORM,
# not source. There is no build stage: the release binaries are byte-for-byte
# the ones published as raw artifacts and inside the deb/rpm, so the container
# `version` always matches the release.
#
# Build/test locally the same way CI does (never pushes; needs a buildx
# builder — `docker buildx create --use` once):
#   goreleaser release --snapshot --clean --skip=sign,sbom
#   docker run --rm ghcr.io/evertramos/ezyshield:<snapshot-tag>-amd64 version
#
# Design:
#   - Final image is FROM scratch — nothing but the two binaries, a CA bundle,
#     zoneinfo, and a single non-root account. No shell, no package manager,
#     no libc: the smallest possible attack surface for a root-capable tool.
#   - Runs as non-root (uid/gid 65532) by DEFAULT. The main daemon needs no
#     privileges. The enforcer, which needs CAP_NET_ADMIN, is started with an
#     explicit entrypoint override and runtime capability grant (compose
#     example + guide are the follow-up issue) — the image never bakes in a
#     privileged default.
#   - Both binaries ship in one image; ENTRYPOINT is the main CLI.

# Stage 1 — assemble the arch-independent runtime data (CA certificates,
# timezone database, a minimal passwd/group) on the BUILD platform. Pinning to
# $BUILDPLATFORM means this stage always runs natively: cross-building the
# arm64 image on an amd64 runner needs no QEMU emulation, because the only
# arch-specific payload (the Go binaries) is prebuilt and merely COPYed.
FROM --platform=$BUILDPLATFORM alpine:3.21 AS base
RUN apk add --no-cache ca-certificates tzdata \
 && printf 'nonroot:x:65532:65532:nonroot:/nonexistent:/sbin/nologin\n' > /etc/passwd.nonroot \
 && printf 'nonroot:x:65532:\n' > /etc/group.nonroot

# Stage 2 — the shipped image.
FROM scratch

LABEL org.opencontainers.image.title="ezyshield" \
      org.opencontainers.image.description="Adaptive intrusion blocking for Linux servers — detects malicious IPs from logs, escalates bans by strikes, enforces locally (nftables) and at the edge (Cloudflare). Dry-run by default." \
      org.opencontainers.image.url="https://github.com/evertramos/ezy-shield" \
      org.opencontainers.image.source="https://github.com/evertramos/ezy-shield" \
      org.opencontainers.image.documentation="https://github.com/evertramos/ezy-shield/blob/main/README.md" \
      org.opencontainers.image.vendor="EzyShield" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

# Runtime data from the base stage (all architecture-neutral).
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/passwd.nonroot /etc/passwd
COPY --from=base /etc/group.nonroot /etc/group

# Both binaries. dockers_v2 lays each platform's builds under $TARGETPLATFORM
# (e.g. linux/amd64/) in the context; buildx sets TARGETPLATFORM per platform.
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/ezyshield /usr/local/bin/ezyshield
COPY ${TARGETPLATFORM}/ezyshield-enforcer /usr/local/bin/ezyshield-enforcer

# scratch defines no PATH; set one so the bare ENTRYPOINT resolves and so an
# operator can `docker run <img> ezyshield <verb>` explicitly.
ENV PATH=/usr/local/bin:/usr/bin:/bin

# Non-root by default (matches the distroless "nonroot" uid/gid).
USER 65532:65532

ENTRYPOINT ["ezyshield"]

---
title: Supported platforms
description: Distros and CPU architectures EzyShield is tested on, and how to run the QEMU end-to-end matrix
order: 6
---

# Supported platforms

EzyShield is a single static Go binary with no runtime dependencies, so it runs
on any modern 64-bit Linux with `nftables` and `systemd`. "Supported" here means
something stronger than "should run": each green cell in the matrix below is
exercised by the **armed end-to-end round-trip** — a throwaway VM installs
EzyShield the real way (`curl … | sudo sh`), runs `ezyshield init`, arms the
daemon, bans a test IP, and asserts it lands in the live `nftables` set. That is
the exact path a real ban takes, so a green cell means the whole
privilege-separated daemon↔enforcer chain works on that platform.

The matrix grows with the project and is refreshed every release.

## Support matrix

Legend:

- ✅ **verified** — the armed QEMU e2e passes end-to-end on this platform
- 🟢 **live host** — additionally validated on a production server (real attackers detected and banned)
- 🧪 **candidate** — wired into the harness, not yet confirmed green
- ☐ **planned** — on the roadmap, not yet run

| Distro | Version | x86_64 | arm64 |
|--------|---------|:------:|:-----:|
| Ubuntu | 24.04 LTS (noble) | ✅ | ☐ |
| Ubuntu | 25.04 (plucky) | 🟢 | ☐ |
| Debian | 12 (bookworm) | ✅ | ☐ |
| Debian | 13 (trixie) | 🧪 | 🧪 |
| AlmaLinux | 9 | 🧪 | 🧪 |
| Rocky Linux | 9 | 🧪 | 🧪 |

x86_64 runs use KVM; arm64 is emulated with `qemu-system-aarch64` (TCG) on an
x86_64 host, or accelerated with KVM on a native arm64 runner. arm64 guests boot
a cross-compiled binary (`GOARCH=arm64`) — the same artifact the release pipeline
ships — so an arm64 cell exercises the real arm64 build, not a translation shim.

> **RHEL-family (Alma/Rocky) is a candidate.** The harness knows their cloud
> images, guest user, `wheel` sudoers and package set, but the round-trip has
> not been confirmed green yet — treat those cells as best-effort until a run
> lands.

## Running a matrix cell

The harness lives in [`scripts/qemu-e2e.sh`](https://github.com/evertramos/ezy-shield/blob/main/scripts/qemu-e2e.sh).
It builds your working-tree binary, serves it over a loopback HTTP server, boots
a cloud image, and runs the installer against it — nothing is published, and
nothing touches your host firewall (the destructive steps run **inside** the
disposable guest).

Pick a distro and architecture with two environment variables:

```bash
# Preflight — print the resolved plan (image, qemu binary, firmware) without booting
EZY_DISTRO=ubuntu2404 EZY_ARCH=amd64 scripts/qemu-e2e.sh config

# Full armed round-trip: build → install → init → ban → assert
EZY_DISTRO=ubuntu2404 EZY_ARCH=amd64 scripts/qemu-e2e.sh up

# Inspect, re-run just the assertions, or tear it all down
scripts/qemu-e2e.sh ssh
scripts/qemu-e2e.sh verify
scripts/qemu-e2e.sh down
```

`EZY_DISTRO` accepts `debian12`, `debian13`, `ubuntu2404`, `ubuntu2504`,
`alma9`, `rocky9`; `EZY_ARCH` accepts `amd64` (default: your host) and `arm64`.
For an image not in the table, set `EZY_IMG_URL`, `EZY_GUEST_USER` and
`EZY_FAMILY` (`deb` or `rhel`) instead of `EZY_DISTRO`, and pin the image with
`EZY_IMG_SHA256=<hex>`.

Cloud images are downloaded over HTTPS and verified against the distro's
published checksum file (`SHA512SUMS` / `SHA256SUMS` / `CHECKSUM`) before first
boot. The verified digest is cached next to the image, so re-runs re-check the
cached file without re-downloading — a corrupted cached image aborts the run
instead of being silently reused. A custom `EZY_IMG_URL` is only verified when
`EZY_IMG_SHA256` is set; without it the harness warns and skips verification.

### Host requirements

| Target | Needs |
|--------|-------|
| x86_64 guest on an x86_64 host | `qemu-system-x86` + `/dev/kvm` |
| arm64 guest on an x86_64 host | `qemu-system-arm` + `qemu-efi-aarch64` (UEFI firmware); runs under TCG — slow |
| arm64 guest on an arm64 host | `qemu-system-arm` + `qemu-efi-aarch64` + `/dev/kvm` |

Every target also needs `cloud-image-utils` (for `cloud-localds`), `qemu-utils`
(for `qemu-img`), `go`, `python3`, and an SSH public key (`~/.ssh/id_rsa.pub` by
default, or point `EZY_SSH_KEY` at another one).

> ⚠️ `scripts/qemu-e2e.sh up` and the in-guest `scripts/e2e-install-test.sh` are
> **destructive by design** — they create the `ezyshield` user, install systemd
> units, and write `nftables` rules. Run them only in the throwaway VM, never on
> a workstation.

See the [install guide](../getting-started/install.md) for supported package
formats and the from-source path.

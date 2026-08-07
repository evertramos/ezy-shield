#!/usr/bin/env bash
#
# qemu-e2e.sh — spin up a throwaway VM and exercise EzyShield's REAL install
# path (`curl … | sudo sh`) against your local working-tree build, across the
# distros and CPU architectures we officially target.
#
# How it works: the host builds the binaries (cross-compiled for the guest's
# GOARCH), serves them + scripts/get.sh over a loopback HTTP server, and boots a
# cloud image (cloud-init injects your SSH key). The guest then runs the actual
# installer pointed at the local server (EZYSHIELD_BASE_URL), runs
# `ezyshield init`, and finally the verifier (scripts/e2e-install-test.sh
# --verify). The guest is disposable: an overlay on a cached base image, so
# every `up` starts clean.
#
# Matrix knobs (env vars):
#   EZY_DISTRO   debian12 | debian13 | ubuntu2404 | ubuntu2504 | alma9 | rocky9
#                (default: debian12)
#   EZY_ARCH     amd64 | arm64            (default: this host's arch)
#                arm64 on an x86_64 host runs under TCG software emulation
#                (slow) and needs qemu-system-aarch64 + UEFI firmware
#                (Debian/Ubuntu: `apt install qemu-system-arm qemu-efi-aarch64`).
#   Custom image escape hatch: EZY_IMG_URL, EZY_GUEST_USER, EZY_FAMILY (deb|rhel),
#                EZY_SUDO_GROUP override the preset for an image not in the table.
#                Preset images are verified against the distro's published
#                checksum file before first boot; a custom EZY_IMG_URL can be
#                pinned with EZY_IMG_SHA256=<hex> (otherwise it is unverified).
#
#   ./scripts/qemu-e2e.sh config   # print the resolved plan (no VM) — CI-safe preflight
#   ./scripts/qemu-e2e.sh up       # build + serve + boot + install(curl|sh) + init + verify
#   ./scripts/qemu-e2e.sh verify   # re-run just the verifier on the running VM
#   ./scripts/qemu-e2e.sh ssh      # ssh into the guest to poke around
#   ./scripts/qemu-e2e.sh logs     # tail the serial console (boot debugging)
#   ./scripts/qemu-e2e.sh down     # power off, stop the HTTP server, drop the overlay
#
# Examples:
#   EZY_DISTRO=ubuntu2404 ./scripts/qemu-e2e.sh up
#   EZY_DISTRO=debian13 EZY_ARCH=arm64 ./scripts/qemu-e2e.sh up
#
# Inside the guest (after `up`): sudo ezyshield status | doctor;
#   stat -c '%U %G %a' /run/ezyshield-enforcer/enforcer.sock /run/ezyshield/ezyshield.sock;
#   sudo nft list table inet ezyshield
#
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/ezyshield-e2e"
RUNDIR="$CACHE/run"
SERVE="$RUNDIR/serve"
OVERLAY="$RUNDIR/overlay.qcow2"
SEED="$RUNDIR/seed.iso"
SERIAL="$RUNDIR/serial.log"
PIDFILE="$RUNDIR/qemu.pid"
HTTP_PIDFILE="$RUNDIR/http.pid"
UEFI_VARS_RUN="$RUNDIR/uefi-vars.fd"     # per-run writable UEFI varstore (arm64)
VM_ENV="$RUNDIR/vm.env"                  # records the distro/arch/user of the running VM

SSH_PORT="${EZY_SSH_PORT:-2222}"
HTTP_PORT="${EZY_HTTP_PORT:-8000}"
GW=10.0.2.2                        # host as seen from a QEMU user-net guest
SSH_KEY_PUB="${EZY_SSH_KEY:-$HOME/.ssh/id_rsa.pub}"
MEM="${EZY_MEM:-2048}"
CPUS="${EZY_CPUS:-2}"

DISTRO="${EZY_DISTRO:-debian12}"

die()  { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }
info() { printf '\033[36m▸ %s\033[0m\n' "$1"; }
warn() { printf '\033[33m! %s\033[0m\n' "$1" >&2; }

# host_arch — normalize `uname -m` to the amd64/arm64 spelling get.sh uses.
host_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *)             uname -m ;;
  esac
}
HOST_ARCH="$(host_arch)"
ARCH="${EZY_ARCH:-$HOST_ARCH}"

# resolve_arch — set QEMU_BIN / GOARCH / SUFFIX for the target guest arch.
# SUFFIX must match get.sh's "${OS}-${ARCH}" (linux-amd64 / linux-arm64) so the
# guest installer finds the artifacts we stage.
resolve_arch() {
  case "$ARCH" in
    amd64) QEMU_BIN=qemu-system-x86_64  ; GOARCH=amd64 ;;
    arm64) QEMU_BIN=qemu-system-aarch64 ; GOARCH=arm64 ;;
    *)     die "unsupported EZY_ARCH: $ARCH (use amd64 or arm64)" ;;
  esac
  SUFFIX="linux-$ARCH"
}

# resolve_distro — map EZY_DISTRO (× EZY_ARCH) to a cloud image + guest settings.
# Sets DISTRO_NAME FAMILY IMG_URL GUEST_USER SUDO_GROUP PKG_LIST BASE_IMG,
# plus SUMS_URL/SUMS_ALGO (the distro's published checksum file for the image).
# Explicit EZY_* overrides win, so an image not in the table is still runnable.
resolve_distro() {
  local url="" user="" family="" name="" sums="" algo=""
  case "$DISTRO" in
    debian12)
      name="Debian 12 (bookworm)"; family=deb; user=debian; sums=SHA512SUMS; algo=sha512
      case "$ARCH" in
        amd64) url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2" ;;
        arm64) url="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2" ;;
      esac ;;
    debian13)
      name="Debian 13 (trixie)"; family=deb; user=debian; sums=SHA512SUMS; algo=sha512
      case "$ARCH" in
        amd64) url="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2" ;;
        arm64) url="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-arm64.qcow2" ;;
      esac ;;
    ubuntu2404)
      name="Ubuntu 24.04 LTS (noble)"; family=deb; user=ubuntu; sums=SHA256SUMS; algo=sha256
      case "$ARCH" in
        amd64) url="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img" ;;
        arm64) url="https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img" ;;
      esac ;;
    ubuntu2504)
      name="Ubuntu 25.04 (plucky)"; family=deb; user=ubuntu; sums=SHA256SUMS; algo=sha256
      case "$ARCH" in
        amd64) url="https://cloud-images.ubuntu.com/releases/25.04/release/ubuntu-25.04-server-cloudimg-amd64.img" ;;
        arm64) url="https://cloud-images.ubuntu.com/releases/25.04/release/ubuntu-25.04-server-cloudimg-arm64.img" ;;
      esac ;;
    alma9)
      name="AlmaLinux 9"; family=rhel; user=almalinux; sums=CHECKSUM; algo=sha256
      case "$ARCH" in
        amd64) url="https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2" ;;
        arm64) url="https://repo.almalinux.org/almalinux/9/cloud/aarch64/images/AlmaLinux-9-GenericCloud-latest.aarch64.qcow2" ;;
      esac ;;
    rocky9)
      name="Rocky Linux 9"; family=rhel; user=rocky; sums=CHECKSUM; algo=sha256
      case "$ARCH" in
        amd64) url="https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2" ;;
        arm64) url="https://download.rockylinux.org/pub/rocky/9/images/aarch64/Rocky-9-GenericCloud-Base.latest.aarch64.qcow2" ;;
      esac ;;
    *)
      [ -n "${EZY_IMG_URL:-}" ] || die "unknown EZY_DISTRO: $DISTRO (known: debian12 debian13 ubuntu2404 ubuntu2504 alma9 rocky9; or set EZY_IMG_URL + EZY_GUEST_USER + EZY_FAMILY for a custom image)" ;;
  esac

  DISTRO_NAME="${name:-$DISTRO}"
  FAMILY="${EZY_FAMILY:-${family:-deb}}"
  IMG_URL="${EZY_IMG_URL:-$url}"
  GUEST_USER="${EZY_GUEST_USER:-$user}"
  [ -n "$IMG_URL" ]    || die "no cloud image for $DISTRO/$ARCH (set EZY_IMG_URL to override)"
  [ -n "$GUEST_USER" ] || die "no guest user for $DISTRO (set EZY_GUEST_USER to override)"

  # Image integrity source: presets verify against the checksum file the distro
  # publishes next to the image (same directory, so the arch is covered too).
  # A custom EZY_IMG_URL has no known checksum file — only EZY_IMG_SHA256 can
  # pin it (see fetch_base_image).
  if [ -n "${EZY_IMG_URL:-}" ]; then
    SUMS_URL=""; SUMS_ALGO=sha256
  else
    SUMS_URL="${IMG_URL%/*}/$sums"; SUMS_ALGO="$algo"
  fi

  case "$FAMILY" in
    deb)  SUDO_GROUP=sudo;  PKG_LIST=(curl nftables) ;;
    # RHEL cloud images ship curl-minimal already; installing the `curl`
    # package conflicts, so we only add nftables there.
    rhel) SUDO_GROUP=wheel; PKG_LIST=(nftables) ;;
    *)    SUDO_GROUP=sudo;  PKG_LIST=(nftables) ;;
  esac
  SUDO_GROUP="${EZY_SUDO_GROUP:-$SUDO_GROUP}"
  BASE_IMG="$CACHE/${DISTRO}-${ARCH}.qcow2"
}

# detect_uefi — find aarch64 UEFI firmware (CODE + a VARS template) for -pflash.
# Sets UEFI_CODE (read-only) and UEFI_VARS_TMPL (may be empty). Never dies; the
# caller decides whether a missing firmware is fatal (up) or informational (config).
detect_uefi() {
  UEFI_CODE=""; UEFI_VARS_TMPL=""
  local pair code vars
  for pair in \
    "/usr/share/AAVMF/AAVMF_CODE.fd|/usr/share/AAVMF/AAVMF_VARS.fd" \
    "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw|/usr/share/edk2/aarch64/vars-template-pflash.raw" \
    "/usr/share/edk2/aarch64/QEMU_EFI.fd|/usr/share/edk2/aarch64/vars-template-pflash.raw" \
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd|"; do
    code="${pair%%|*}"; vars="${pair#*|}"
    if [ -f "$code" ]; then
      UEFI_CODE="$code"
      [ "$vars" != "$code" ] && [ -f "$vars" ] && UEFI_VARS_TMPL="$vars"
      break
    fi
  done
}

# load_vm_env — pull the distro/arch/user recorded at `up` time so `verify`,
# `ssh` and `down` act on the VM that is actually running, not the current env.
load_vm_env() {
  [ -f "$VM_ENV" ] || return 0
  # shellcheck source=/dev/null  # runtime state file written by cmd_up
  . "$VM_ENV"
}

ssh_opts=(-p "$SSH_PORT"
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR -o ConnectTimeout=8)
scp_opts=(-P "$SSH_PORT"
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
# shellcheck disable=SC2029  # by design: we want $@ to expand host-side into a shell command for the guest
gssh() { ssh "${ssh_opts[@]}" "$GUEST_USER@localhost" "$@"; }

wait_ssh() {
  info "Waiting for SSH on port $SSH_PORT (cloud-init provisioning)..."
  for _ in $(seq 1 90); do
    gssh true 2>/dev/null && break
    sleep 2
  done
  gssh true 2>/dev/null || die "SSH not reachable — check '$0 logs'"
  # SSH comes up before cloud-init finishes installing packages. Block until
  # it's fully done, or the installer/init will race a bare package manager.
  info "Waiting for cloud-init to finish (installs ${PKG_LIST[*]})..."
  gssh "sudo cloud-init status --wait >/dev/null 2>&1 || true"
}

start_http() {
  command -v python3 >/dev/null || die "python3 required to serve artifacts to the guest"
  python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$SERVE" >/dev/null 2>&1 &
  echo $! > "$HTTP_PIDFILE"
  info "Serving working-tree artifacts on 127.0.0.1:$HTTP_PORT (guest sees $GW:$HTTP_PORT)"
}
stop_http() {
  if [ -f "$HTTP_PIDFILE" ]; then
    kill "$(cat "$HTTP_PIDFILE")" 2>/dev/null || true
    rm -f "$HTTP_PIDFILE"
  fi
}

# expected_sum — extract the digest for file $2 from checksum file $1.
# Handles both formats our distros publish: GNU coreutils lines
# ("<hash>  <file>" — Debian SHA512SUMS, Alma CHECKSUM; "<hash> *<file>" —
# Ubuntu SHA256SUMS) and BSD-style lines ("SHA256 (<file>) = <hash>" — Rocky).
expected_sum() {
  awk -v f="$2" '
    ($1 == "SHA256" || $1 == "SHA512") && $2 == "(" f ")" { print $4; exit }
    $2 == f || $2 == "*" f                                { print $1; exit }
  ' "$1"
}

# file_sum — print the $SUMS_ALGO digest of file $1.
file_sum() { "${SUMS_ALGO}sum" "$1" | awk '{print $1}'; }

# fetch_base_image — download the cloud image (once, cached) and verify it
# against the distro's published checksum file BEFORE it is ever booted.
# The verified digest is recorded next to the image ("$BASE_IMG.<algo>"), so
# re-runs re-check the cached file locally — a corrupted cache dies instead of
# being silently reused — without re-downloading anything. The upstream URLs
# are mutable `latest` aliases, so a cached image is compared against the
# digest it was verified with at download time, not against today's upstream.
fetch_base_image() {
  local stamp="$BASE_IMG.$SUMS_ALGO" expected="" got=""

  if [ -f "$BASE_IMG" ]; then
    if [ -f "$stamp" ]; then
      info "Verifying cached image against its recorded $SUMS_ALGO digest"
      got="$(file_sum "$BASE_IMG")"
      [ "$got" = "$(cat "$stamp")" ] || die "cached image failed verification: $BASE_IMG
  expected $(cat "$stamp")
  got      $got
Remove it to force a fresh verified download:  rm '$BASE_IMG' '$stamp'"
      return 0
    fi
    # Cache predates checksum verification (or the stamp was deleted). The
    # upstream `latest` image may have legitimately moved on since this file
    # was downloaded, so the only safe option is a fresh verified download.
    warn "cached image has no verification record — re-downloading a verified copy"
    rm -f "$BASE_IMG"
  fi

  # wget's --https-only (below) only constrains recursive follows, so enforce
  # the transport explicitly. A non-https custom image is tolerated only when
  # its content is pinned with EZY_IMG_SHA256.
  case "$IMG_URL" in
    https://*) ;;
    *) if [ -n "${EZY_IMG_URL:-}" ] && [ -n "${EZY_IMG_SHA256:-}" ]; then
         warn "EZY_IMG_URL is not https — relying on EZY_IMG_SHA256 for integrity"
       else
         die "refusing non-https image URL: $IMG_URL (use https, or pin a custom image with EZY_IMG_SHA256)"
       fi ;;
  esac

  if [ -n "$SUMS_URL" ]; then
    info "Fetching checksum file: $SUMS_URL"
    wget -q --https-only -O "$RUNDIR/image.sums" "$SUMS_URL" \
      || die "could not fetch checksum file: $SUMS_URL"
    expected="$(expected_sum "$RUNDIR/image.sums" "${IMG_URL##*/}")"
    [ -n "$expected" ] || die "no entry for ${IMG_URL##*/} in $SUMS_URL — refusing an unverifiable image"
  elif [ -n "${EZY_IMG_SHA256:-}" ]; then
    expected="$EZY_IMG_SHA256"
  else
    warn "custom EZY_IMG_URL without EZY_IMG_SHA256 — image integrity will NOT be verified"
  fi

  info "Downloading $DISTRO_NAME $ARCH cloud image (once, cached in $CACHE)"
  wget -q --show-progress --https-only -O "$BASE_IMG.tmp" "$IMG_URL"

  if [ -n "$expected" ]; then
    info "Verifying download ($SUMS_ALGO)"
    got="$(file_sum "$BASE_IMG.tmp")"
    if [ "$got" != "$expected" ]; then
      rm -f "$BASE_IMG.tmp"
      die "checksum mismatch for $IMG_URL
  expected $expected
  got      $got
Refusing to boot an unverified image."
    fi
    printf '%s\n' "$got" > "$stamp"
  else
    rm -f "$stamp"
  fi
  mv "$BASE_IMG.tmp" "$BASE_IMG"
}

provision() {
  info "Installing via the REAL installer: curl … | sudo sh -s -- --local  (EZYSHIELD_BASE_URL=$GW:$HTTP_PORT)"
  # --local + EZYSHIELD_LOCAL_ACK=1 (issue #17): custom-mirror installs are
  # explicitly acknowledged as unauthenticated — exactly what this dev
  # harness is: the host serves binaries it just built.
  gssh "curl -sfL http://$GW:$HTTP_PORT/get.sh | sudo EZYSHIELD_LOCAL_ACK=1 EZYSHIELD_BASE_URL=http://$GW:$HTTP_PORT sh -s -- --local"
  info "Running 'ezyshield init --yes' in the guest"
  gssh "sudo ezyshield init --yes"
  info "Copying + running the verifier (e2e-install-test.sh --verify)"
  scp "${scp_opts[@]}" "$REPO/scripts/e2e-install-test.sh" "$GUEST_USER@localhost:e2e-install-test.sh" >/dev/null
  gssh "sudo EZYSHIELD_E2E_DESTROY=1 bash e2e-install-test.sh --verify --keep"
}

# boot_vm — assemble the arch-specific QEMU invocation and daemonize it.
boot_vm() {
  local accel=() machine=() fw=()
  case "$ARCH" in
    amd64)
      # Unspecified machine type → the historical default (identical to the
      # pre-matrix harness). KVM only when the guest matches the host.
      if [ "$HOST_ARCH" = amd64 ] && [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); fi
      ;;
    arm64)
      machine=(-machine virt)
      if [ "$HOST_ARCH" = arm64 ] && [ -w /dev/kvm ]; then
        accel=(-cpu host -enable-kvm)
      else
        accel=(-cpu max)     # cross-arch: TCG software emulation (slow)
        warn "arm64 on a $HOST_ARCH host runs under TCG — expect a slow boot."
      fi
      detect_uefi
      [ -n "$UEFI_CODE" ] || die "aarch64 UEFI firmware not found — install qemu-efi-aarch64 (Debian/Ubuntu) or edk2-aarch64 (Fedora/EL)"
      # CODE stays read-only in place; VARS needs a fresh writable copy per run.
      if [ -n "$UEFI_VARS_TMPL" ]; then
        cp -f "$UEFI_VARS_TMPL" "$UEFI_VARS_RUN"
      else
        truncate -s 64M "$UEFI_VARS_RUN"
      fi
      fw=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$UEFI_CODE"
          -drive "if=pflash,format=raw,unit=1,file=$UEFI_VARS_RUN")
      ;;
  esac

  info "Booting VM ($QEMU_BIN, ssh on $SSH_PORT, serial → $SERIAL)"
  : > "$SERIAL"
  "$QEMU_BIN" \
    "${accel[@]}" "${machine[@]}" "${fw[@]}" \
    -m "$MEM" -smp "$CPUS" \
    -drive file="$OVERLAY",if=virtio \
    -drive file="$SEED",if=virtio,format=raw \
    -nic user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:"$SSH_PORT"-:22 \
    -display none -serial file:"$SERIAL" \
    -pidfile "$PIDFILE" -daemonize
}

cmd_config() {
  resolve_arch
  resolve_distro
  local accel firmware="n/a (amd64 firmware is built into QEMU)"
  if [ "$ARCH" = "$HOST_ARCH" ] && [ -w /dev/kvm ]; then accel="kvm (native)"; else accel="tcg (software emulation)"; fi
  if [ "$ARCH" = arm64 ]; then
    detect_uefi
    if [ -n "$UEFI_CODE" ]; then firmware="$UEFI_CODE"; else firmware="MISSING — install qemu-efi-aarch64 / edk2-aarch64"; fi
  fi
  local qemu_state="present"; command -v "$QEMU_BIN" >/dev/null 2>&1 || qemu_state="MISSING — install it"
  printf 'distro      : %s  (%s)\n' "$DISTRO" "$DISTRO_NAME"
  printf 'family      : %s\n'       "$FAMILY"
  printf 'guest arch  : %s  (host: %s)\n' "$ARCH" "$HOST_ARCH"
  printf 'accel       : %s\n'       "$accel"
  printf 'qemu binary : %s  [%s]\n' "$QEMU_BIN" "$qemu_state"
  printf 'firmware    : %s\n'       "$firmware"
  printf 'image URL   : %s\n'       "$IMG_URL"
  local cksum
  if [ -n "$SUMS_URL" ]; then cksum="$SUMS_URL  ($SUMS_ALGO)"
  elif [ -n "${EZY_IMG_SHA256:-}" ]; then cksum="pinned via EZY_IMG_SHA256"
  else cksum="NONE — custom EZY_IMG_URL without EZY_IMG_SHA256 (unverified)"; fi
  printf 'checksums   : %s\n'       "$cksum"
  printf 'base image  : %s\n'       "$BASE_IMG"
  printf 'guest user  : %s  (sudo group: %s)\n' "$GUEST_USER" "$SUDO_GROUP"
  printf 'guest pkgs  : %s\n'       "${PKG_LIST[*]}"
  printf 'artifact    : ezyshield-%s  (GOARCH=%s)\n' "$SUFFIX" "$GOARCH"
  printf 'ssh port    : %s\n'       "$SSH_PORT"
}

cmd_up() {
  resolve_arch
  resolve_distro
  command -v "$QEMU_BIN"   >/dev/null || die "$QEMU_BIN not found (arm64 needs 'qemu-system-arm'; amd64 needs 'qemu-system-x86')"
  command -v cloud-localds >/dev/null || die "cloud-localds not found (apt install cloud-image-utils)"
  command -v go            >/dev/null || die "go not found (needed to build the binaries)"
  command -v qemu-img      >/dev/null || die "qemu-img not found (apt install qemu-utils)"
  [ -f "$SSH_KEY_PUB" ] || die "SSH pubkey not found: $SSH_KEY_PUB (set EZY_SSH_KEY=/path/to/key.pub)"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    die "a VM is already running (pid $(cat "$PIDFILE")). Run '$0 down' first."
  fi

  mkdir -p "$RUNDIR" "$SERVE"

  info "Building binaries on host (CGO_ENABLED=0 GOARCH=$GOARCH → bin/)"
  ( cd "$REPO" && mkdir -p bin \
                && CGO_ENABLED=0 GOARCH="$GOARCH" go build -o bin/ezyshield ./cmd/ezyshield \
                && CGO_ENABLED=0 GOARCH="$GOARCH" go build -o bin/ezyshield-enforcer ./cmd/ezyshield-enforcer )

  info "Staging install artifacts + checksums (as get.sh expects them)"
  cp "$REPO/scripts/get.sh"         "$SERVE/get.sh"
  cp "$REPO/bin/ezyshield"          "$SERVE/ezyshield-$SUFFIX"
  cp "$REPO/bin/ezyshield-enforcer" "$SERVE/ezyshield-enforcer-$SUFFIX"
  ( cd "$SERVE" && sha256sum "ezyshield-$SUFFIX" "ezyshield-enforcer-$SUFFIX" > checksums.txt )

  fetch_base_image

  info "Creating fresh overlay disk"
  rm -f "$OVERLAY"
  qemu-img create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "$OVERLAY" 12G >/dev/null

  info "Generating cloud-init seed (SSH key + ${PKG_LIST[*]})"
  local pubkey; pubkey="$(cat "$SSH_KEY_PUB")"
  local pkgs_yaml="" p
  for p in "${PKG_LIST[@]}"; do pkgs_yaml+="  - $p"$'\n'; done
  cat > "$RUNDIR/user-data" <<EOF
#cloud-config
hostname: ezyshield-e2e
ssh_pwauth: false
users:
  - name: $GUEST_USER
    groups: [$SUDO_GROUP]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $pubkey
package_update: true
packages:
${pkgs_yaml}final_message: "cloud-init done — ready for provisioning"
EOF
  printf 'instance-id: ezyshield-e2e\nlocal-hostname: ezyshield-e2e\n' > "$RUNDIR/meta-data"
  cloud-localds "$SEED" "$RUNDIR/user-data" "$RUNDIR/meta-data"

  # Record what we booted so verify/ssh/down don't need the env re-set.
  # %q: the file is sourced later, and EZY_DISTRO/EZY_GUEST_USER are an escape
  # hatch that can carry arbitrary strings — quote them, don't interpolate.
  printf 'DISTRO=%q\nARCH=%q\nGUEST_USER=%q\n' "$DISTRO" "$ARCH" "$GUEST_USER" > "$VM_ENV"

  start_http
  boot_vm

  wait_ssh
  provision

  echo
  info "VM is up and left running (services armed via --verify --keep)."
  info "Inspect:  $0 ssh     Re-verify:  $0 verify     Tear down:  $0 down"
}

cmd_verify() {
  resolve_distro
  load_vm_env
  [ -f "$PIDFILE" ] || die "no VM running — run '$0 up'"
  scp "${scp_opts[@]}" "$REPO/scripts/e2e-install-test.sh" "$GUEST_USER@localhost:e2e-install-test.sh" >/dev/null
  gssh "sudo EZYSHIELD_E2E_DESTROY=1 bash e2e-install-test.sh --verify --keep"
}

cmd_ssh() {
  resolve_distro
  load_vm_env
  [ -f "$PIDFILE" ] || die "no VM running — run '$0 up'"
  exec ssh "${ssh_opts[@]}" "$GUEST_USER@localhost"
}

cmd_logs() { [ -f "$SERIAL" ] || die "no serial log yet — run '$0 up'"; tail -f "$SERIAL"; }

cmd_down() {
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    info "Powering off VM (pid $(cat "$PIDFILE"))"
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    sleep 1
  fi
  stop_http
  rm -f "$PIDFILE" "$OVERLAY" "$SEED" "$UEFI_VARS_RUN" "$VM_ENV"
  info "Overlay removed, HTTP server stopped. Base image cached in $CACHE."
}

usage() {
  cat >&2 <<EOF
qemu-e2e.sh — throwaway-VM install/init/ban smoke test across target distros.

Usage: $0 {config|up|verify|ssh|logs|down}

  config   print the resolved distro/arch plan (no VM booted)
  up       build + serve + boot + install(curl|sh) + init + verify
  verify   re-run just the verifier on the running VM
  ssh      ssh into the running guest
  logs     tail the serial console
  down     power off, stop the HTTP server, drop the overlay

Matrix: EZY_DISTRO={debian12|debian13|ubuntu2404|ubuntu2504|alma9|rocky9}
        EZY_ARCH={amd64|arm64}   (default: this host)
EOF
  exit "${1:-0}"
}

case "${1:-}" in
  config) cmd_config ;;
  up)     cmd_up ;;
  verify) cmd_verify ;;
  ssh)    cmd_ssh ;;
  logs)   cmd_logs ;;
  down)   cmd_down ;;
  -h|--help|help) usage 0 ;;
  *)      usage 2 ;;   # no subcommand or unknown one → usage error (exit 2)
esac

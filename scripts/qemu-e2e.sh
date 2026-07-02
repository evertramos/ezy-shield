#!/usr/bin/env bash
#
# qemu-e2e.sh — spin up a throwaway Debian VM and exercise EzyShield's REAL
# install path (`curl … | sudo sh`) against your local working-tree build.
#
# How it works: the host builds the binaries, serves them + scripts/get.sh over
# a loopback HTTP server, and boots a Debian cloud image (cloud-init injects your
# SSH key). The guest then runs the actual installer pointed at the local server
# (EZYSHIELD_BASE_URL), runs `ezyshield init`, and finally the verifier
# (scripts/e2e-install-test.sh --verify). The guest is disposable: an overlay on
# a cached base image, so every `up` starts clean.
#
#   ./scripts/qemu-e2e.sh up      # build + serve + boot + install(curl|sh) + init + verify
#   ./scripts/qemu-e2e.sh verify  # re-run just the verifier on the running VM
#   ./scripts/qemu-e2e.sh ssh     # ssh into the guest to poke around
#   ./scripts/qemu-e2e.sh logs    # tail the serial console (boot debugging)
#   ./scripts/qemu-e2e.sh down    # power off, stop the HTTP server, drop the overlay
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
BASE_IMG="$CACHE/debian-12-genericcloud-amd64.qcow2"
IMG_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
OVERLAY="$RUNDIR/overlay.qcow2"
SEED="$RUNDIR/seed.iso"
SERIAL="$RUNDIR/serial.log"
PIDFILE="$RUNDIR/qemu.pid"
HTTP_PIDFILE="$RUNDIR/http.pid"

SSH_PORT="${EZY_SSH_PORT:-2222}"
HTTP_PORT="${EZY_HTTP_PORT:-8000}"
GW=10.0.2.2                        # host as seen from a QEMU user-net guest
SSH_KEY_PUB="${EZY_SSH_KEY:-$HOME/.ssh/id_rsa.pub}"
MEM="${EZY_MEM:-2048}"
CPUS="${EZY_CPUS:-2}"
GUEST_USER=debian

# Artifact suffix must match get.sh (${OS}-${ARCH}).
case "$(uname -m)" in
  x86_64|amd64) SUFFIX=linux-amd64 ;;
  aarch64|arm64) SUFFIX=linux-arm64 ;;
  *) SUFFIX="linux-$(uname -m)" ;;
esac

die()  { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }
info() { printf '\033[36m▸ %s\033[0m\n' "$1"; }

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
  # SSH comes up before cloud-init finishes installing packages (curl, nftables).
  # Block until it's fully done, or the installer/init will race a bare apt.
  info "Waiting for cloud-init to finish (installs curl + nftables)..."
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

provision() {
  info "Installing via the REAL installer: curl … | sudo sh  (EZYSHIELD_BASE_URL=$GW:$HTTP_PORT)"
  gssh "curl -sfL http://$GW:$HTTP_PORT/get.sh | sudo EZYSHIELD_BASE_URL=http://$GW:$HTTP_PORT sh"
  info "Running 'ezyshield init --yes' in the guest"
  gssh "sudo ezyshield init --yes"
  info "Copying + running the verifier (e2e-install-test.sh --verify)"
  scp "${scp_opts[@]}" "$REPO/scripts/e2e-install-test.sh" "$GUEST_USER@localhost:e2e-install-test.sh" >/dev/null
  gssh "sudo EZYSHIELD_E2E_DESTROY=1 bash e2e-install-test.sh --verify --keep"
}

cmd_up() {
  command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 not found"
  command -v cloud-localds       >/dev/null || die "cloud-localds not found (apt install cloud-image-utils)"
  command -v go                  >/dev/null || die "go not found (needed to build the binaries)"
  [ -f "$SSH_KEY_PUB" ] || die "SSH pubkey not found: $SSH_KEY_PUB (set EZY_SSH_KEY=/path/to/key.pub)"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    die "a VM is already running (pid $(cat "$PIDFILE")). Run '$0 down' first."
  fi

  mkdir -p "$RUNDIR" "$SERVE"

  info "Building binaries on host (CGO_ENABLED=0 → bin/)"
  ( cd "$REPO" && mkdir -p bin \
                && CGO_ENABLED=0 go build -o bin/ezyshield ./cmd/ezyshield \
                && CGO_ENABLED=0 go build -o bin/ezyshield-enforcer ./cmd/ezyshield-enforcer )

  info "Staging install artifacts + checksums (as get.sh expects them)"
  cp "$REPO/scripts/get.sh"        "$SERVE/get.sh"
  cp "$REPO/bin/ezyshield"          "$SERVE/ezyshield-$SUFFIX"
  cp "$REPO/bin/ezyshield-enforcer" "$SERVE/ezyshield-enforcer-$SUFFIX"
  ( cd "$SERVE" && sha256sum "ezyshield-$SUFFIX" "ezyshield-enforcer-$SUFFIX" > checksums.txt )

  if [ ! -f "$BASE_IMG" ]; then
    info "Downloading Debian 12 cloud image (once, cached in $CACHE)"
    wget -q --show-progress -O "$BASE_IMG.tmp" "$IMG_URL"
    mv "$BASE_IMG.tmp" "$BASE_IMG"
  fi

  info "Creating fresh overlay disk"
  rm -f "$OVERLAY"
  qemu-img create -q -f qcow2 -b "$BASE_IMG" -F qcow2 "$OVERLAY" 12G >/dev/null

  info "Generating cloud-init seed (SSH key + curl + nftables only)"
  local pubkey; pubkey="$(cat "$SSH_KEY_PUB")"
  cat > "$RUNDIR/user-data" <<EOF
#cloud-config
hostname: ezyshield-e2e
ssh_pwauth: false
users:
  - name: $GUEST_USER
    groups: [sudo]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    shell: /bin/bash
    ssh_authorized_keys:
      - $pubkey
package_update: true
packages:
  - curl
  - nftables
final_message: "cloud-init done — ready for provisioning"
EOF
  printf 'instance-id: ezyshield-e2e\nlocal-hostname: ezyshield-e2e\n' > "$RUNDIR/meta-data"
  cloud-localds "$SEED" "$RUNDIR/user-data" "$RUNDIR/meta-data"

  start_http

  local accel=() ; [ -w /dev/kvm ] && accel=(-enable-kvm -cpu host)
  info "Booting VM (ssh on $SSH_PORT, serial → $SERIAL)"
  : > "$SERIAL"
  qemu-system-x86_64 \
    "${accel[@]}" \
    -m "$MEM" -smp "$CPUS" \
    -drive file="$OVERLAY",if=virtio \
    -drive file="$SEED",if=virtio,format=raw \
    -nic user,model=virtio-net-pci,hostfwd=tcp::"$SSH_PORT"-:22 \
    -display none -serial file:"$SERIAL" \
    -pidfile "$PIDFILE" -daemonize

  wait_ssh
  provision

  echo
  info "VM is up and left running (services armed via --verify --keep)."
  info "Inspect:  $0 ssh     Re-verify:  $0 verify     Tear down:  $0 down"
}

cmd_verify() {
  [ -f "$PIDFILE" ] || die "no VM running — run '$0 up'"
  scp "${scp_opts[@]}" "$REPO/scripts/e2e-install-test.sh" "$GUEST_USER@localhost:e2e-install-test.sh" >/dev/null
  gssh "sudo EZYSHIELD_E2E_DESTROY=1 bash e2e-install-test.sh --verify --keep"
}

cmd_ssh() {
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
  rm -f "$PIDFILE" "$OVERLAY" "$SEED"
  info "Overlay removed, HTTP server stopped. Base image cached in $CACHE."
}

case "${1:-}" in
  up)     cmd_up ;;
  verify) cmd_verify ;;
  ssh)    cmd_ssh ;;
  logs)   cmd_logs ;;
  down)   cmd_down ;;
  *) sed -n '2,28p' "$0"; exit "${1:+1}" ;;
esac

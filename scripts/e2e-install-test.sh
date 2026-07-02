#!/usr/bin/env bash
#
# e2e-install-test.sh — end-to-end install/init smoke test for EzyShield.
#
# WHY: the class of bug in issue #6 (enforcer socket ownership under the
# systemd CapabilityBoundingSet) is INVISIBLE to unit tests and to dry-run —
# it only bites when the daemon must actually reach the privileged enforcer to
# apply a real ban. This script installs, runs `ezyshield init`, and then ARMS
# the daemon and bans a test IP, asserting it lands in the nftables set. That
# round-trip is the real proof that the daemon↔enforcer socket works.
#
# ⚠️  DESTRUCTIVE — creates the `ezyshield` user/group, installs systemd units,
#     starts services, and writes nftables rules. Run ONLY inside a throwaway
#     VM (your QEMU guest), never on a machine you care about.
#
# Usage (inside the guest, as root):
#   ./e2e-install-test.sh --run            # install + init + assertions
#   ./e2e-install-test.sh --run --keep     # don't auto-clean at the end
#   ./e2e-install-test.sh --verify         # assertions only (install done elsewhere,
#                                          #   e.g. via get.sh + `ezyshield init`)
#   ./e2e-install-test.sh --cleanup        # tear everything back down
#
# --run binaries: if ./ezyshield and ./ezyshield-enforcer exist next to the repo
# (or in --bin-dir), they're used as-is; otherwise the script builds them with go.
# --verify assumes EzyShield is already installed AND `ezyshield init` has run.
#
set -euo pipefail

CONFIG_DIR=/etc/ezyshield
STATE_DIR=/var/lib/ezyshield
INSTALL_DIR=/usr/local/bin
ENFORCER_SOCK=/run/ezyshield-enforcer/enforcer.sock
DAEMON_SOCK=/run/ezyshield/ezyshield.sock
NFT_TABLE="inet ezyshield"
NFT_SET=blocked
TEST_IP=203.0.113.7            # TEST-NET-3, safe to ban

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$REPO_ROOT/bin"    # matches the Makefile BINARY_DIR (gitignored)
MODE=""
KEEP=0

pass=0; fail=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗ %s\033[0m\n' "$1"; fail=$((fail+1)); }
info() { printf '\033[36m▸ %s\033[0m\n' "$1"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# check "<description>" <command...> — runs the command, records pass/fail.
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

usage() { sed -n '2,30p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --run)     MODE=run ;;
    --verify)  MODE=verify ;;
    --cleanup) MODE=cleanup ;;
    --keep)    KEEP=1 ;;
    --bin-dir) BIN_DIR="$2"; shift ;;
    -h|--help) usage 0 ;;
    *) die "unknown arg: $1 (try --help)" ;;
  esac
  shift
done
[ -n "$MODE" ] || usage 1

[ "$(id -u)" = 0 ] || die "must run as root (creates users, systemd units, nft rules)"

# Refuse to run anywhere that isn't obviously a throwaway box, unless forced.
guard_destructive() {
  if [ "${EZYSHIELD_E2E_DESTROY:-}" != 1 ]; then
    cat <<MSG >&2
This test is DESTRUCTIVE (creates the ezyshield user, installs+starts systemd
units, writes nftables rules). Run it ONLY in a throwaway VM.

If this really is a disposable guest, re-run with:
    EZYSHIELD_E2E_DESTROY=1 $0 $MODE
MSG
    exit 2
  fi
}

# ── cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
  info "Tearing down EzyShield"
  systemctl disable --now ezyshield 2>/dev/null || true
  systemctl disable --now ezyshield-enforcer 2>/dev/null || true
  rm -f /etc/systemd/system/ezyshield.service /etc/systemd/system/ezyshield-enforcer.service
  systemctl daemon-reload 2>/dev/null || true
  nft delete table $NFT_TABLE 2>/dev/null || true
  userdel -r ezyshield 2>/dev/null || true
  groupdel ezyshield 2>/dev/null || true
  rm -rf "$CONFIG_DIR" "$STATE_DIR"
  rm -f "$INSTALL_DIR/ezyshield" "$INSTALL_DIR/ezyshield-enforcer"
  echo "  done."
}

if [ "$MODE" = cleanup ]; then
  guard_destructive
  cleanup
  exit 0
fi

# ── run / verify ─────────────────────────────────────────────────────────────
guard_destructive

command -v systemctl >/dev/null || die "systemd (systemctl) required"
command -v nft       >/dev/null || die "nftables (nft) required — apt install nftables"
if ! systemctl is-system-running >/dev/null 2>&1; then
  # 'degraded' is fine; we only need systemd to be PID 1 and managing units.
  [ -d /run/systemd/system ] || die "systemd is not managing this system (no /run/systemd/system)"
fi

# assert_owner <path> <user> <group> <mode> — records a pass/fail on ownership.
assert_owner() {
  local path="$1" want_user="$2" want_group="$3" want_mode="$4"
  local got; got="$(stat -c '%U %G %a' "$path" 2>/dev/null || echo '? ? ?')"
  if [ "$got" = "$want_user $want_group $want_mode" ]; then
    ok "$path is $got"
  else
    bad "$path is '$got', want '$want_user $want_group $want_mode'"
  fi
}

# install_and_init — the --run install path (prebuilt or go-built binaries).
# --verify skips this: the install is expected to have happened externally
# (e.g. `curl .../get.sh | sudo sh` + `ezyshield init`).
install_and_init() {
  info "Obtaining binaries"
  if [ -x "$BIN_DIR/ezyshield" ] && [ -x "$BIN_DIR/ezyshield-enforcer" ]; then
    echo "  using prebuilt binaries in $BIN_DIR"
  elif command -v go >/dev/null; then
    echo "  building from source ($REPO_ROOT)"
    mkdir -p "$BIN_DIR"
    ( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$BIN_DIR/ezyshield" ./cmd/ezyshield \
                      && CGO_ENABLED=0 go build -o "$BIN_DIR/ezyshield-enforcer" ./cmd/ezyshield-enforcer )
  else
    die "no prebuilt binaries in $BIN_DIR and no 'go' to build them"
  fi
  install -m 755 "$BIN_DIR/ezyshield"          "$INSTALL_DIR/ezyshield"
  install -m 755 "$BIN_DIR/ezyshield-enforcer" "$INSTALL_DIR/ezyshield-enforcer"

  info "Running 'ezyshield init --yes'"
  ezyshield init --yes
}

# run_assertions — everything we actually verify; shared by --run and --verify.
run_assertions() {
  info "Install / service assertions"
  check "user 'ezyshield' exists"          id ezyshield
  check "group 'ezyshield' exists"         getent group ezyshield
  check "ezyshield-enforcer.service active" systemctl is-active --quiet ezyshield-enforcer
  check "ezyshield.service active"          systemctl is-active --quiet ezyshield
  check "enforcer socket exists"           test -S "$ENFORCER_SOCK"
  check "daemon socket exists"             test -S "$DAEMON_SOCK"
  # 'doctor' is the built-in health check — if it exits 0 all its own perms,
  # ownership, and enforcer-connectivity checks pass. Cheap cross-verification.
  check "'ezyshield doctor' exits 0"       ezyshield doctor
  check "'ezyshield status' works"         ezyshield status

  info "Socket ownership (the issue #6 fix)"
  # Enforcer socket MUST be root:ezyshield 0660 — before the fix it stayed
  # root:root because os.Chown failed with EPERM under CapabilityBoundingSet.
  assert_owner "$ENFORCER_SOCK" root ezyshield 660
  assert_owner "$DAEMON_SOCK"   ezyshield ezyshield 660

  info "Armed ban round-trip (proves daemon → enforcer path)"
  # Arm the daemon, then ban a test IP and confirm it reaches nftables. This is
  # what actually exercises the enforcer socket — the exact path #6 broke.
  sed -i -E 's/^([[:space:]]*armed:[[:space:]]*)false/\1true/' "$CONFIG_DIR/policy.yaml"
  if grep -Eq '^[[:space:]]*armed:[[:space:]]*true' "$CONFIG_DIR/policy.yaml"; then
    ok "policy.yaml armed: true"
  else
    bad "could not set armed: true in policy.yaml (check the key)"
  fi
  systemctl restart ezyshield
  for _ in $(seq 1 20); do [ -S "$DAEMON_SOCK" ] && break; sleep 0.5; done

  ezyshield ban "$TEST_IP" --reason "e2e-test" 2>/dev/null || ezyshield ban "$TEST_IP" || true
  local banned=0
  for _ in $(seq 1 10); do
    if nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -q "$TEST_IP"; then banned=1; break; fi
    sleep 0.5
  done
  [ "$banned" = 1 ] && ok "banned $TEST_IP present in nft set '$NFT_TABLE $NFT_SET'" \
                     || bad "banned $TEST_IP NOT in nft set — daemon can't reach enforcer (issue #6 regressed?)"

  # 'ezyshield list' must show the ban we just made. Before the store fix, the
  # manual ban only wrote to audit_log so `list` returned "no active bans"
  # while the IP was live in nft — a silent inconsistency that this asserts.
  if ezyshield list 2>&1 | grep -q "$TEST_IP"; then
    ok "'ezyshield list' shows $TEST_IP"
  else
    bad "'ezyshield list' does NOT show $TEST_IP (store not updated for manual ban)"
  fi

  ezyshield unban "$TEST_IP" 2>/dev/null || true
  local gone=1
  for _ in $(seq 1 10); do
    if nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -q "$TEST_IP"; then gone=0; sleep 0.5; else gone=1; break; fi
  done
  [ "$gone" = 1 ] && ok "unban removed $TEST_IP from nft set" || bad "unban did not remove $TEST_IP"

  info "Socket clobber refusal (the issue #14 fix)"
  # Manually invoking `ezyshield watch` while the systemd daemon is already up
  # used to unlink the live socket and clobber control. The fix probes first
  # and refuses to start. We assert:
  #   1. the manual `watch` exits nonzero (fails fast, doesn't silently degrade)
  #   2. the daemon's socket file is still on disk and still owned right
  #   3. `ezyshield status` still answers (proves the socket wasn't clobbered)
  local sock_ino_before; sock_ino_before="$(stat -c '%i' "$DAEMON_SOCK" 2>/dev/null || echo missing)"
  # Run with a 3s timeout: if the fix works, watch exits <3s with error;
  # without the fix it would hijack the socket and hang until timeout.
  if timeout 3 ezyshield watch >/dev/null 2>&1; then
    bad "clobber test: manual 'ezyshield watch' unexpectedly succeeded (should refuse: another daemon is running)"
  else
    ok "manual 'ezyshield watch' refused to start (daemon socket in use)"
  fi
  local sock_ino_after; sock_ino_after="$(stat -c '%i' "$DAEMON_SOCK" 2>/dev/null || echo missing)"
  if [ "$sock_ino_before" = "$sock_ino_after" ] && [ "$sock_ino_after" != missing ]; then
    ok "daemon socket file survived (same inode $sock_ino_after)"
  else
    bad "daemon socket file was clobbered (inode was $sock_ino_before, now $sock_ino_after)"
  fi
  if ezyshield status >/dev/null 2>&1; then
    ok "'ezyshield status' still answers (control surface intact)"
  else
    bad "'ezyshield status' broken after clobber attempt — socket was hijacked"
  fi
}

[ "$MODE" = run ] && install_and_init
if [ "$MODE" = verify ]; then
  command -v ezyshield >/dev/null || die "--verify: ezyshield not installed (run get.sh first)"
  [ -f "$CONFIG_DIR/policy.yaml" ] || die "--verify: $CONFIG_DIR/policy.yaml missing (run 'ezyshield init' first)"
fi
run_assertions

# ── summary ──────────────────────────────────────────────────────────────────
echo
info "Result: $pass passed, $fail failed"
if [ "$KEEP" != 1 ] && [ "$fail" = 0 ]; then
  echo "  (all green — cleaning up; pass --keep to inspect the running system)"
  cleanup
elif [ "$fail" != 0 ]; then
  echo "  (failures above — leaving the system up so you can inspect;"
  echo "   run '$0 --cleanup' when done. Useful commands:)"
  echo "     journalctl -u ezyshield -u ezyshield-enforcer --no-pager | tail -50"
  echo "     stat -c '%U %G %a' $ENFORCER_SOCK $DAEMON_SOCK"
  echo "     nft list table $NFT_TABLE"
fi

[ "$fail" = 0 ]

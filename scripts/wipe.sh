#!/usr/bin/env bash
#
# wipe.sh — completely remove EzyShield from this host.
#
# Runs the six-step teardown from issue #10
# (https://github.com/evertramos/ezy-shield/issues/10):
#
#   1. Stop + disable services
#   2. Remove systemd units + daemon-reload
#   3. Remove binaries
#   4. Remove config, state, runtime dirs
#   5. Remove ezyshield user + group
#   6. Remove the nftables table
#
# Every step is idempotent — safe to re-run after a partial wipe.
#
# ⚠️  DESTRUCTIVE. Requires root and an explicit --yes.
#
# Usage:
#   sudo ./wipe.sh --yes                 # do it
#   sudo ./wipe.sh --dry-run             # show what would run, change nothing
#   sudo ./wipe.sh --yes --backup /path  # tar /etc/ezyshield + /var/lib/ezyshield
#                                        #   into <path>/ezyshield-wipe-<date>.tar.gz
#                                        #   BEFORE deleting anything
#
set -euo pipefail

# These five paths are the only things this script touches. They are marked
# `readonly` so a future edit that accidentally reassigns one — anywhere below
# this point in the file — fails at bash-parse time instead of at `rm -rf`.
# Combined with the `${VAR:?…}` guards on every destructive call below, this
# closes the "empty variable + rm -rf" disaster class even against a bug
# introduced by an editor of this script.
readonly CONFIG_DIR=/etc/ezyshield
readonly STATE_DIR=/var/lib/ezyshield
readonly INSTALL_DIR=/usr/local/bin
readonly NFT_TABLE="inet ezyshield"
readonly SYSTEMD_DIR=/etc/systemd/system

YES=0
DRY=0
BACKUP_TO=""

usage() { sed -n '2,25p' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --yes)      YES=1 ;;
    --dry-run)  DRY=1 ;;
    --backup)
      # Reject if no arg or if $2 is another flag: `wipe.sh --backup --yes`
      # would otherwise silently set BACKUP_TO="--yes" and try to tar into a
      # directory called "--yes". Absolute path is a soft ergonomic guard;
      # the operator ran as root and could pass any path anyway.
      case "${2:-}" in
        ""|--*) echo "ERROR: --backup requires a path argument (got: '${2:-}')" >&2; exit 2 ;;
        /*)     BACKUP_TO="$2" ;;
        *)      echo "ERROR: --backup requires an absolute path (got: '$2')" >&2; exit 2 ;;
      esac
      shift
      ;;
    -h|--help)  usage 0 ;;
    *)          echo "unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

info() { printf '\033[36m▸ %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m! %s\033[0m\n' "$1"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$1" >&2; exit 1; }

# run <cmd...> — echo in dry-run, execute otherwise. Never abort on nonzero
# because the whole script is meant to converge on "gone" — a missing file
# from a partial previous wipe is not a failure.
run() {
  if [ "$DRY" = 1 ]; then
    printf '  \033[33m[dry-run]\033[0m %s\n' "$*"
  else
    "$@" 2>/dev/null || true
  fi
}

[ "$(id -u)" = 0 ] || die "must run as root"

if [ "$YES" != 1 ] && [ "$DRY" != 1 ]; then
  cat <<MSG >&2
This will PERMANENTLY remove EzyShield from this host:
  - stop + disable both services
  - delete /etc/ezyshield, /var/lib/ezyshield, /run/ezyshield*
  - delete the systemd units
  - delete /usr/local/bin/ezyshield{,-enforcer}
  - remove the ezyshield user + group
  - drop the 'inet ezyshield' nftables table (and every rule in it)

If that's what you want, re-run with:
    sudo $0 --yes

To just see what would happen:
    sudo $0 --dry-run
MSG
  exit 2
fi

# ── optional backup (before anything is destroyed) ───────────────────────────
if [ -n "$BACKUP_TO" ]; then
  info "0/6  Backup of config + state before wipe"
  if [ "$DRY" = 1 ]; then
    printf '  \033[33m[dry-run]\033[0m tar czf %s/ezyshield-wipe-%s.tar.gz %s %s\n' \
      "$BACKUP_TO" "$(date +%F-%H%M%S)" "$CONFIG_DIR" "$STATE_DIR"
  else
    mkdir -p "$BACKUP_TO"
    dest="$BACKUP_TO/ezyshield-wipe-$(date +%F-%H%M%S).tar.gz"
    # -P keeps absolute paths so restore lands back in the same place.
    # Missing dirs are silently skipped — a partial install is normal here.
    # SC2046 is deliberate: CONFIG_DIR and STATE_DIR are hardcoded constants
    # at the top of this script (no spaces, no globs), and the whole point of
    # the unquoted expansion is to insert zero-or-one path tokens into tar's
    # argv depending on which directories currently exist.
    # shellcheck disable=SC2046
    tar czPf "$dest" \
      $( [ -d "$CONFIG_DIR" ] && printf '%s ' "$CONFIG_DIR" ) \
      $( [ -d "$STATE_DIR"  ] && printf '%s ' "$STATE_DIR" ) \
      2>/dev/null || true
    if [ -s "$dest" ]; then
      ok "backup written: $dest ($(du -h "$dest" | cut -f1))"
    else
      warn "nothing to back up (config + state dirs already gone)"
      rm -f "$dest"
    fi
  fi
fi

# ── 1. Stop + disable services ───────────────────────────────────────────────
info "1/6  Stop + disable services"
run systemctl stop ezyshield ezyshield-enforcer
run systemctl disable ezyshield ezyshield-enforcer
ok "services stopped and disabled"

# ── 2. Remove systemd units ──────────────────────────────────────────────────
# `${VAR:?msg}` aborts the script (with `msg` on stderr) if VAR is unset OR
# empty. Belt-and-suspenders against a script edit that accidentally wipes
# one of the constants above — the abort happens before any `rm` runs, so
# there is no path from "empty variable" to a wrong-directory delete.
info "2/6  Remove systemd units"
run rm -f  "${SYSTEMD_DIR:?SYSTEMD_DIR unset -- refusing to touch systemd}/ezyshield.service"
run rm -f  "${SYSTEMD_DIR:?}/ezyshield-enforcer.service"
run rm -rf "${SYSTEMD_DIR:?}/ezyshield.service.d"
run systemctl daemon-reload
ok "units removed"

# ── 3. Remove binaries ───────────────────────────────────────────────────────
info "3/6  Remove binaries"
run rm -f "${INSTALL_DIR:?INSTALL_DIR unset -- refusing to rm binaries}/ezyshield" \
          "${INSTALL_DIR:?}/ezyshield-enforcer"
ok "binaries removed"

# ── 4. Remove config, state, runtime ─────────────────────────────────────────
info "4/6  Remove config, state, runtime dirs"
run rm -rf "${CONFIG_DIR:?CONFIG_DIR unset -- refusing to rm -rf}"
run rm -rf "${STATE_DIR:?STATE_DIR unset -- refusing to rm -rf}"
run rm -rf /run/ezyshield /run/ezyshield-enforcer
ok "config + state + runtime gone"

# ── 5. Remove user + group ───────────────────────────────────────────────────
info "5/6  Remove ezyshield user + group"
run userdel ezyshield
run groupdel ezyshield
ok "user + group removed"

# ── 6. Remove nftables table ─────────────────────────────────────────────────
info "6/6  Drop the '$NFT_TABLE' nftables table"
if command -v nft >/dev/null 2>&1; then
  run nft delete table "${NFT_TABLE:?NFT_TABLE unset -- refusing to touch nftables}"
  ok "nftables table dropped"
else
  warn "nft binary not present, skipping (nothing to drop)"
fi

echo
if [ "$DRY" = 1 ]; then
  info "Dry-run complete — nothing was changed."
else
  info "EzyShield fully wiped. You can now run the installer from scratch."
  echo "  curl -sfL https://get.ezyshield.com | sudo sh"
  echo "  sudo ezyshield init"
fi

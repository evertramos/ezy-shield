#!/bin/sh
#
# ezyshield package preremove (deb + rpm): on REMOVAL, stop the units so
# files can be removed cleanly. On UPGRADE, deliberately do nothing — the
# old binary keeps running while files are replaced, and postinstall
# try-restarts running units, so a package upgrade can never leave the
# protection stack down (issue #354, fail-open upgrade).
#
# Never deletes /var/lib/ezyshield — offender history and the audit log
# belong to the operator; removing data is an explicit human action.
#
# Arguments: deb passes "remove", "upgrade", "deconfigure" or
# "failed-upgrade"; rpm passes the number of package instances that will
# remain after this step — "1" on upgrade, "0" on erase. An unknown or
# missing argument is treated as removal (stopping is the conservative
# default for file replacement; it never loses data).
#
# EZYSHIELD_SYSTEMD_DIR is a test-only override for the systemd detection
# directory (see scripts/package-lifecycle-test.sh).

set -e

case "${1:-}" in
upgrade | failed-upgrade | deconfigure | 1)
	exit 0
	;;
esac

SYSTEMD_DIR="${EZYSHIELD_SYSTEMD_DIR:-/run/systemd/system}"

if command -v systemctl >/dev/null 2>&1 && [ -d "$SYSTEMD_DIR" ]; then
	for unit in ezyshield.service ezyshield-enforcer.service; do
		if systemctl is-active --quiet "$unit" 2>/dev/null; then
			systemctl stop "$unit" || true
		fi
	done
fi

#!/bin/sh
#
# ezyshield package postinstall (deb + rpm): create the service user/group
# and the directories the units expect. On a FRESH INSTALL it deliberately
# does NOT enable or start any unit (issue #98) — `ezyshield init` guides
# the operator and everything stays dry-run by default. On an UPGRADE it
# try-restarts the units: a unit that was running comes back on the new
# binary, a stopped or disabled unit stays untouched — so an upgrade never
# leaves the protection stack down (issue #354) and never starts anything
# the operator didn't have running.
#
# Arguments: deb passes "configure <old-version>" ($2 set only on upgrade);
# rpm passes the number of installed instances — "1" on fresh install,
# "2" on upgrade.
#
# EZYSHIELD_SYSTEMD_DIR is a test-only override for the systemd detection
# directory (see scripts/package-lifecycle-test.sh).

set -e

UPGRADE=0
if [ "${1:-}" = "configure" ] && [ -n "${2:-}" ]; then
	UPGRADE=1 # deb upgrade
elif [ "${1:-}" = "2" ]; then
	UPGRADE=1 # rpm upgrade
fi

if ! getent group ezyshield >/dev/null 2>&1; then
	groupadd --system ezyshield
fi

if ! getent passwd ezyshield >/dev/null 2>&1; then
	# nologin lives in /usr/sbin on Debian and /sbin on RHEL-family.
	NOLOGIN="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
	useradd --system --gid ezyshield --no-create-home \
		--home-dir /var/lib/ezyshield --shell "$NOLOGIN" \
		--comment "EzyShield daemon" ezyshield
fi

install -d -m 0750 -o root -g ezyshield /etc/ezyshield
install -d -m 0750 -o ezyshield -g ezyshield /var/lib/ezyshield

SYSTEMD_DIR="${EZYSHIELD_SYSTEMD_DIR:-/run/systemd/system}"

# daemon-reload only when systemd is actually running (not in containers).
if command -v systemctl >/dev/null 2>&1 && [ -d "$SYSTEMD_DIR" ]; then
	systemctl daemon-reload || true

	if [ "$UPGRADE" = 1 ]; then
		# try-restart is a no-op for inactive units: only what the operator
		# already had running is restarted. Enforcer first, then the daemon
		# that talks to it.
		for unit in ezyshield-enforcer.service ezyshield.service; do
			systemctl try-restart "$unit" 2>/dev/null || true
		done
	fi
fi

if [ "$UPGRADE" = 1 ]; then
	echo "EzyShield upgraded. Units that were running have been restarted;"
	echo "stopped units stay stopped."
else
	echo "EzyShield installed. Units are present but NOT enabled."
	echo "Next step:"
	echo "  sudo ezyshield init"
fi

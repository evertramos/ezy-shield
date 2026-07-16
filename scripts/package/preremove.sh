#!/bin/sh
#
# ezyshield package preremove (deb + rpm): stop the units if they are
# running so files can be replaced/removed cleanly. Never deletes
# /var/lib/ezyshield — offender history and the audit log belong to the
# operator; removing data is an explicit human action.

set -e

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	for unit in ezyshield.service ezyshield-enforcer.service; do
		if systemctl is-active --quiet "$unit" 2>/dev/null; then
			systemctl stop "$unit" || true
		fi
	done
fi

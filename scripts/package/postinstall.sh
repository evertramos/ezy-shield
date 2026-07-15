#!/bin/sh
#
# ezyshield package postinstall (deb + rpm): create the service user/group
# and the directories the units expect. Deliberately does NOT enable or
# start any unit (issue #98) — `ezyshield init` guides the operator and
# everything stays dry-run by default.

set -e

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

# daemon-reload only when systemd is actually running (not in containers).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi

echo "EzyShield installed. Units are present but NOT enabled."
echo "Next step:"
echo "  sudo ezyshield init"

#!/usr/bin/env bash
#
# spdx-gate.sh — CI gate for issue #187: every .go file must carry the
# correct SPDX header for its tree as its FIRST line.
#
#   pkg/sdk/**            → // SPDX-License-Identifier: Apache-2.0
#   cmd/ internal/ configs/ → // SPDX-License-Identifier: AGPL-3.0-only
#
# The header is the first line so build constraints (//go:build) stay legal:
# constraints may be preceded only by blank lines and other line comments.
#
# Usage: scripts/spdx-gate.sh   (run from the repo root)

set -euo pipefail

fail=0

check() {
	local file="$1" want="$2"
	local first
	first=$(head -n 1 "$file")
	if [ "$first" != "$want" ]; then
		echo "::error file=$file::missing or wrong SPDX header (want: $want)"
		fail=1
	fi
}

while IFS= read -r f; do
	case "$f" in
	pkg/sdk/*) check "$f" "// SPDX-License-Identifier: Apache-2.0" ;;
	*) check "$f" "// SPDX-License-Identifier: AGPL-3.0-only" ;;
	esac
done < <(find cmd internal pkg configs -name '*.go' -type f | sort)

if [ "$fail" -ne 0 ]; then
	echo "spdx-gate: FAILED — add the missing SPDX header(s) above (see pkg/sdk/README.md for the license boundary)"
	exit 1
fi
echo "spdx-gate: all .go files carry the correct SPDX header"

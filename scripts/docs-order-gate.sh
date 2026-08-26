#!/usr/bin/env bash
#
# docs-order-gate.sh — fail when a docs/content section directory (guides,
# reference, getting-started, security; any locale) has a page missing the
# `order:` frontmatter key, or two pages sharing the same value. The site
# now generates the sidebar navigation from this field (issue #568), so a
# duplicate makes the nav order depend on an arbitrary tie-break instead of
# author intent, and a missing value sorts unpredictably against the rest.

set -euo pipefail

python3 - <<'PY'
import glob, re, sys
from collections import defaultdict

# Section dirs are decided by the site generator's own convention: any
# subdirectory directly under a locale (docs/content/<locale>/<section>/).
bad = []
for locale_dir in sorted(glob.glob('docs/content/*/')):
    for section_dir in sorted(glob.glob(f'{locale_dir}*/')):
        section = section_dir.rstrip('/')
        pages = sorted(glob.glob(f'{section_dir}*.md'))
        if not pages:
            continue
        seen = defaultdict(list)
        for page in pages:
            with open(page, encoding='utf-8') as f:
                text = f.read()
            m = re.search(r'^order:\s*(\d+)\s*$', text, re.M)
            if not m:
                bad.append(f"{page}: missing `order:` frontmatter key")
                continue
            seen[int(m.group(1))].append(page)
        for order, files in sorted(seen.items()):
            if len(files) > 1:
                bad.append(f"{section}: order: {order} used by {len(files)} pages — " + ', '.join(files))

if bad:
    print("::error::docs/content order: frontmatter is duplicated or missing (breaks sidebar ordering):")
    print('\n'.join(bad))
    sys.exit(1)
print("docs-order-gate: every docs/content page has a unique order: within its section")
PY

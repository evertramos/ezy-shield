#!/usr/bin/env bash
#
# docs-placeholder-gate.sh — fail when a raw <placeholder> tag appears in
# docs/content markdown outside code spans/fences. The docs site (VitePress)
# compiles markdown as Vue components: an unbackticked `<name>` is parsed as
# an open HTML/Vue tag and aborts the ENTIRE site build. Placeholders must
# be written as `<name>` (backtick-wrapped). Real HTML elements (details,
# br, ...) are allowed.

set -euo pipefail

python3 - <<'PY'
import re, glob, sys

HTML = set(('a abbr b blockquote br code details div em h1 h2 h3 h4 h5 h6 hr '
            'i img kbd li ol p pre source span strong sub summary sup table '
            'tbody td th thead tr ul video').split())
bad = []
for f in sorted(glob.glob('docs/content/**/*.md', recursive=True)):
    text = open(f, encoding='utf-8').read()
    text = re.sub(r'```.*?```', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)
    for i, line in enumerate(text.splitlines(), 1):
        line = re.sub(r'`[^`]*`', '', line)
        for m in re.finditer(r'<([A-Za-z][A-Za-z0-9_-]*)>', line):
            if m.group(1).lower() not in HTML:
                bad.append(f"{f}:{i}: raw {m.group(0)} — wrap it in backticks: `{m.group(0)}`")
if bad:
    print("::error::Raw placeholder tags in docs markdown break the VitePress site build:")
    print('\n'.join(bad))
    sys.exit(1)
print("docs-placeholder-gate: no raw placeholder tags in docs/content")
PY

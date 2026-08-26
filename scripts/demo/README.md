# EzyShield launch demo (issue #232)

A scripted, reproducible demo: a synthetic attacker probes `wp-login.php`
against a throwaway **dry-run** instance; the rule fires, strike 1 lands
(simulated), the attacker comes back, the ladder escalates to strike 2, and
`report` shows the receipt. No root, no real IPs (RFC 5737 only), nothing
outside a temp dir — safe to re-run and re-record any time CLI output
changes.

```bash
bash scripts/demo/demo.sh          # just run it (~90s)
DEMO_PAUSE=0 bash scripts/demo/demo.sh   # fast, for testing the script itself
```

**Honesty contract**: everything on screen is shipped behavior on a live
daemon. The one demo-specific tweak — the first strike's TTL is 15s instead
of 5m so escalation fits a short recording — is visible in the policy file
the demo itself writes, and the screen says DRY-RUN throughout.

## Recording

GIF via [vhs](https://github.com/charmbracelet/vhs) (writes
`assets/demo/ezyshield-demo.gif`):

```bash
vhs scripts/demo/demo.tape
```

Or asciinema (idle compression makes the strike-expiry wait cheap, so the
cast plays much shorter than the ~90s wall time):

```bash
asciinema rec -c "bash scripts/demo/demo.sh" --idle-time-limit 2 demo.cast
agg --idle-time-limit 2 demo.cast assets/demo/ezyshield-demo.gif   # GIF fallback
```

After recording, commit the GIF and uncomment the demo block near the top
of the README (marked `<!-- demo: ... -->`); the pt-br getting-started
index links the same asset.

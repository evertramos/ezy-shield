# VHS tape for the EzyShield launch demo (issue #232).
# Requires https://github.com/charmbracelet/vhs — record with:
#
#   vhs scripts/demo/demo.tape
#
# Output lands in assets/demo/ezyshield-demo.gif. The demo itself is
# scripts/demo/demo.sh (reproducible, dry-run, temp-dir only); total
# runtime is ~90s dominated by the real strike-expiry wait — see
# scripts/demo/README.md for the asciinema alternative with idle
# compression if you want a shorter artifact.

Output assets/demo/ezyshield-demo.gif

Set FontSize 15
Set Width 1100
Set Height 650
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

Type "bash scripts/demo/demo.sh"
Enter
Sleep 115s

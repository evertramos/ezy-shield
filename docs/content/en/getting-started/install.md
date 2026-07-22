---
title: Installing EzyShield
description: Install from release, source, or air-gapped mirror
order: 2
---

# Installing EzyShield

This guide covers all ways to install EzyShield: from a pre-built release, a specific version or release candidate, a custom mirror, or from source.

---

## Install via package manager (apt / dnf)

Native packages ship the binaries, systemd units, the `ezyshield` service
user, and clean upgrades. Repository metadata is GPG-signed; stable releases
live in the `stable` suite, release candidates in `testing`.

> **Before v0.1.0 ships:** every published release is a release candidate,
> so the snippets below use the `testing` suite — the one that works today.
> Once v0.1.0 is out, replace `testing` with `stable` in both to track
> stable releases only.

**Debian / Ubuntu:**

```bash
curl -fsSL https://packages.ezyshield.com/ezyshield.asc | sudo gpg --dearmor -o /usr/share/keyrings/ezyshield.gpg
echo "deb [signed-by=/usr/share/keyrings/ezyshield.gpg] https://packages.ezyshield.com/apt testing main" | sudo tee /etc/apt/sources.list.d/ezyshield.list
sudo apt update && sudo apt install ezyshield
```

**RHEL / Rocky / Alma:**

```bash
sudo tee /etc/yum.repos.d/ezyshield.repo <<'EOF'
[ezyshield]
name=EzyShield
baseurl=https://packages.ezyshield.com/rpm/testing/$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://packages.ezyshield.com/ezyshield.asc
EOF
sudo dnf install ezyshield
```

> `repo_gpgcheck=1` validates the signed repository metadata, which in turn
> pins the SHA-256 of every package — integrity is covered end to end.
> Per-package rpm signatures arrive with the upcoming artifact-signing work,
> at which point `gpgcheck=1` becomes the documented default.

Signing key fingerprint (verify after import with `gpg --show-keys`):

```
810E EEB0 1802 38F7 E800  4A9E E1AD 3D15 A121 3612
```

To switch to the stable channel once v0.1.0 ships, replace `testing` with
`stable` in either snippet. Packages do **not** enable or start any
service — run `sudo ezyshield init` after installing.

---

## Installing a specific version or release candidate

If you want a specific version (including release candidates like
`v0.1.0-rc.N` — check the [releases page](https://github.com/evertramos/ezy-shield/releases)
for the current tag), set `EZYSHIELD_VERSION`:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0-rc.N sh
```

The version must start with `v`. Available versions are listed at [github.com/evertramos/ezy-shield/releases](https://github.com/evertramos/ezy-shield/releases).

> **Before v0.1.0 ships:** this is the install-script method that works
> today — every published release is a release candidate. Copy the exact
> tag from the releases page above.

---

## Quick install

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

This one-liner is **package-first**: on a host with `apt-get` or `dnf`/`yum`
where the package repository is reachable, it sets up the same repo shown
above (GPG key + source entry) and installs via the package manager —
identical result to following the apt/dnf steps by hand. Raw binaries in
`/usr/local/bin/` are used only when:

- the host has no `apt-get`/`dnf`/`yum` at all,
- `EZYSHIELD_BASE_URL` points at a custom mirror (air-gapped install), or
- the package repo setup or reachability check fails — the script prints a
  warning and falls back automatically so the install still completes.

You can force either path explicitly with `EZYSHIELD_METHOD`:

```bash
# Always install packages (fails loudly if that's not possible)
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=packages sh

# Always install raw binaries, even if a package manager is present
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary sh
```

If the script finds a previous script install (binaries in
`/usr/local/bin`, units in `/etc/systemd/system`) while routing to a
package install, it prints the exact cleanup commands so the new package
isn't silently shadowed — see
[Migrating from the script install to packages](#migrating-from-the-script-install-to-packages)
below.

> **Before v0.1.0 ships:** when neither install method resolves a stable
> release, the command above prints install instructions instead of
> installing (see the `testing` package repo further up) — no flags needed
> once v0.1.0 ships.

---

## Installing from a custom mirror (air-gapped environments)

For air-gapped installs or CI environments, point the installer at a custom mirror with both the binaries and `checksums.txt`:

```bash
curl -sfL https://get.ezyshield.com | EZYSHIELD_BASE_URL=https://mirror.example.com/ezyshield/v0.3.0 sudo sh
```

The script will:
1. Download `checksums.txt`, `ezyshield-linux-amd64`, and `ezyshield-enforcer-linux-amd64` (or appropriate arch)
2. Verify SHA-256 checksums
3. Install to `/usr/local/bin/`

**Security note:** Checksums protect against transfer corruption, but do NOT authenticate a compromised mirror. Use this only for trusted mirrors or artifacts you have already vetted.

When using `EZYSHIELD_BASE_URL`, you can also set `EZYSHIELD_VERSION` for your own versioning:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=internal-rc1 EZYSHIELD_BASE_URL=https://mirror.example.com/ezyshield/v0.3.0 sh
```

---

## Building from source

If pre-built binaries are not available for your platform, or if you prefer to build yourself:

```bash
git clone https://github.com/evertramos/ezy-shield.git
cd ezy-shield
make build
sudo install -m 755 bin/ezyshield /usr/local/bin/
sudo install -m 755 bin/ezyshield-enforcer /usr/local/bin/
```

---

## Upgrading to a new version

**Installed via apt / dnf** (recommended — upgrades arrive with your normal system updates):

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install --only-upgrade ezyshield

# RHEL / Rocky / Alma
sudo dnf upgrade ezyshield
```

Config files in `/etc/ezyshield` are never touched by package upgrades. Restart the services afterwards:

```bash
sudo systemctl restart ezyshield-enforcer ezyshield
```

**Installed via the install script** (binaries in `/usr/local/bin`) — re-run
it. On a host with `apt-get`/`dnf` now available, the script is
package-first by default (see [Quick install](#quick-install)) and will
offer to migrate you to packages instead of just replacing the binaries —
see the next section. To keep upgrading in binary mode explicitly:

```bash
# Latest stable, staying on the raw-binary install
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary sh

# Or a specific version (check the releases page for the current tag,
# e.g. v0.1.0-rc.N before v0.1.0 ships)
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_METHOD=binary EZYSHIELD_VERSION=v0.1.0-rc.N sh

sudo systemctl restart ezyshield-enforcer ezyshield
```

---

## Migrating from the script install to packages

A host first installed via the script (binaries in `/usr/local/bin`, units
in `/etc/systemd/system`) that later gets `apt install`/`dnf install`
ezyshield can end up silently running the **old** build everywhere:
`/usr/local/bin` precedes `/usr/bin` in `PATH`, and unit files in
`/etc/systemd/system` take precedence over the package's units in
`/usr/lib/systemd/system` — the package manager reports the new version
installed, but the binary and service that actually run are the old ones.

Two ways to fix or avoid this:

**Let get.sh do it.** Re-running the one-liner on a host with `apt-get`/`dnf`
routes to the package install by default (see [Quick install](#quick-install))
and detects a shadowing script install automatically, printing the exact
cleanup commands:

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

It only executes the cleanup when you opt in — pass `EZYSHIELD_CLEANUP=1`
for a non-interactive run, or answer the interactive prompt:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_CLEANUP=1 sh
```

**Or clean up manually** (same commands the script prints):

```bash
sudo systemctl stop ezyshield ezyshield-enforcer
sudo rm -f /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer
sudo rm -f /etc/systemd/system/ezyshield.service /etc/systemd/system/ezyshield-enforcer.service
sudo systemctl daemon-reload
sudo systemctl enable --now ezyshield-enforcer ezyshield
```

Either way, run `ezyshield doctor` afterwards — it FAILs loudly if a script
install is still shadowing the package (binary present in more than one
`PATH` location with differing content, or a `/etc/systemd/system` unit
override whose `ExecStart` still points at `/usr/local/bin`), and the hint
it prints repeats the exact cleanup commands above.

---

## Uninstalling

**Installed via apt / dnf:**

```bash
# Debian / Ubuntu
sudo apt remove ezyshield

# RHEL / Rocky / Alma
sudo dnf remove ezyshield

# Also remove configuration (if desired)
sudo rm -rf /etc/ezyshield
```

**Installed via the install script** — `get.sh` itself removes exactly the
files it installed (binaries in `/usr/local/bin`, units in
`/etc/systemd/system`) and never touches package-managed files:

```bash
curl -sfL https://get.ezyshield.com | sudo sh -s -- --uninstall
# equivalent: curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_UNINSTALL=1 sh

# Also remove configuration (if desired)
sudo rm -rf /etc/ezyshield
```

---

## Environment variables reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `EZYSHIELD_METHOD` | `auto` (default), `packages`, or `binary` — force the install method instead of auto-detecting | `EZYSHIELD_METHOD=binary` |
| `EZYSHIELD_VERSION` | Install a specific release (must start with `v`). Binary mode only | `EZYSHIELD_VERSION=v0.1.0-rc.N` |
| `EZYSHIELD_BASE_URL` | Install from a custom mirror (overrides version selection, forces binary mode) | `EZYSHIELD_BASE_URL=https://mirror.example.com/ezyshield/v0.1.0` |
| `EZYSHIELD_API_BASE_URL` | Override the GitHub API base used to resolve release metadata (private API mirrors, testing) | `EZYSHIELD_API_BASE_URL=https://api.mirror.example.com` |
| `EZYSHIELD_PACKAGES_BASE_URL` | Override the package repo base used for repo setup and the reachability check (private mirrors, testing) | `EZYSHIELD_PACKAGES_BASE_URL=https://packages.mirror.example.com` |
| `EZYSHIELD_CLEANUP` | Set to `1` to non-interactively remove a shadowing script install when routing to a package install | `EZYSHIELD_CLEANUP=1` |
| `EZYSHIELD_UNINSTALL` | Set to `1` (equivalent to `--uninstall`) to remove script-install artifacts and exit | `EZYSHIELD_UNINSTALL=1` |

---

## Verifying the installation

```bash
# Check binaries are in place
ezyshield version
ezyshield-enforcer --help

# Interactive setup (requires root/sudo)
sudo ezyshield init
```

If you see version info and help text, the installation is successful.

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

**Debian / Ubuntu:**

```bash
curl -fsSL https://packages.ezyshield.com/ezyshield.asc | sudo gpg --dearmor -o /usr/share/keyrings/ezyshield.gpg
echo "deb [signed-by=/usr/share/keyrings/ezyshield.gpg] https://packages.ezyshield.com/apt stable main" | sudo tee /etc/apt/sources.list.d/ezyshield.list
sudo apt update && sudo apt install ezyshield
```

**RHEL / Rocky / Alma:**

```bash
sudo tee /etc/yum.repos.d/ezyshield.repo <<'EOF'
[ezyshield]
name=EzyShield
baseurl=https://packages.ezyshield.com/rpm/stable/$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://packages.ezyshield.com/ezyshield.asc
EOF
sudo dnf install ezyshield
```

> `repo_gpgcheck=1` validates the signed repository metadata, which in turn
> pins the SHA-256 of every package — integrity is covered end to end.
> Per-package rpm signatures arrive with the artifact-signing work (#100),
> at which point `gpgcheck=1` becomes the documented default.

Signing key fingerprint (verify after import with `gpg --show-keys`):

```
<KEY-FINGERPRINT — maintainer fills in after first publish>
```

To follow release candidates instead, replace `stable` with `testing` in
either snippet. Packages do **not** enable or start any service — run
`sudo ezyshield init` after installing.

---

## Quick install (latest stable)

```bash
curl -sfL https://get.ezyshield.com | sudo sh
```

This downloads the latest stable release, verifies checksums, and installs binaries to `/usr/local/bin/`.

---

## Installing a specific version or release candidate

If you want a specific version (including release candidates like `v0.3.0-rc.1`), set `EZYSHIELD_VERSION`:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.3.0-rc.1 sh
```

The version must start with `v`. Available versions are listed at [github.com/evertramos/ezy-shield/releases](https://github.com/evertramos/ezy-shield/releases).

---

## Installing from a custom mirror (air-gapped environments)

For air-gapped installs or CI environments, point the installer at a custom mirror with both the binaries and `checksums.txt`:

```bash
curl -sfL https://get.ezyshield.com | EZYSHIELD_BASE_URL=https://mirror.internal.com/ezyshield/v0.3.0 sudo sh
```

The script will:
1. Download `checksums.txt`, `ezyshield-linux-amd64`, and `ezyshield-enforcer-linux-amd64` (or appropriate arch)
2. Verify SHA-256 checksums
3. Install to `/usr/local/bin/`

**Security note:** Checksums protect against transfer corruption, but do NOT authenticate a compromised mirror. Use this only for trusted mirrors or artifacts you have already vetted.

When using `EZYSHIELD_BASE_URL`, you can also set `EZYSHIELD_VERSION` for your own versioning:

```bash
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=internal-rc1 EZYSHIELD_BASE_URL=https://mirror.internal.com/ezyshield/v0.3.0 sh
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

**Installed via the install script** (binaries in `/usr/local/bin`) — re-run it; it replaces the binaries in place:

```bash
# Latest stable
curl -sfL https://get.ezyshield.com | sudo sh

# Or a specific version
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.1.0 sh

sudo systemctl restart ezyshield-enforcer ezyshield
```

---

## Uninstalling

```bash
sudo rm /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer

# Also remove configuration (if desired)
sudo rm -rf /etc/ezyshield
```

---

## Environment variables reference

| Variable | Purpose | Example |
|----------|---------|---------|
| `EZYSHIELD_VERSION` | Install a specific release (must start with `v`) | `EZYSHIELD_VERSION=v0.3.0-rc.1` |
| `EZYSHIELD_BASE_URL` | Install from a custom mirror (overrides version selection) | `EZYSHIELD_BASE_URL=https://mirror.internal.com/ezyshield/v0.3.0` |

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

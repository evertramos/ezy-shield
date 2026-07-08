---
title: Installing EzyShield
description: Install from release, source, or air-gapped mirror
order: 2
---

# Installing EzyShield

This guide covers all ways to install EzyShield: from a pre-built release, a specific version or release candidate, a custom mirror, or from source.

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

To upgrade an existing installation:

```bash
# Uninstall
sudo rm /usr/local/bin/ezyshield /usr/local/bin/ezyshield-enforcer

# Reinstall (latest)
curl -sfL https://get.ezyshield.com | sudo sh

# Or specific version
curl -sfL https://get.ezyshield.com | sudo EZYSHIELD_VERSION=v0.4.0 sh
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

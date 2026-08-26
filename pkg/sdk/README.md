# EzyShield SDK (`pkg/sdk`)

Public types and interfaces for building EzyShield modules and plugins:
`Event`, `Verdict`, `Action`, `Target`, and the `Collector` / `Parser` /
`Enforcer` / `Notifier` / `AIProvider` interfaces.

## License boundary

**This package is licensed under Apache-2.0** (see [`LICENSE`](LICENSE) in
this directory) **so that plugin and module authors can build proprietary
or differently-licensed integrations against the SDK types without AGPL
obligations.**

Everything else in this repository — the daemon, the enforcer helper, all
`cmd/` and `internal/` code — is **AGPL-3.0-only** (see the repository
root [`LICENSE`](../../LICENSE)).

Practically:

- Importing `pkg/sdk` in your own plugin/tool: Apache-2.0 terms apply to
  the SDK code; your code stays yours.
- Modifying or embedding the daemon itself: AGPL-3.0-only applies.

Every `.go` file carries an `SPDX-License-Identifier` header stating which
side of the boundary it is on, and CI enforces the headers
(`scripts/spdx-gate.sh`).

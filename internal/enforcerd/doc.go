// SPDX-License-Identifier: AGPL-3.0-only

// Package enforcerd is the privileged nftables helper behind the
// ezyshield-enforcer binary: a unix-socket server with a fixed verb set
// (ping, caps, add, del, list, flush, feeds_sync, netcheck, allow_*) that
// is the only process allowed to mutate the kernel sets.
//
// It lives under internal/ rather than in cmd/ so the integration harness
// (issue #605) can run the real helper — cache, replace-on-re-add,
// auto-merge migration, allowlist mirror — in-process against a scripted
// nft runner and a virtual clock, instead of re-modelling those behaviours
// in fakes. cmd/ezyshield-enforcer/main.go only parses flags and wires
// signals.
package enforcerd

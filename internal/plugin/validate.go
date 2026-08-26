// SPDX-License-Identifier: AGPL-3.0-only

package plugin

// Author-facing dry run for `ezyshield plugins validate` (issue #207):
// start the executable once, perform the handshake, kill the process
// group. No requests are ever sent.

import (
	"context"
	"fmt"
	"log/slog"
)

// DryRunHandshake starts the manifest's executable, performs the
// handshake, and kills the process group. Returns the plugin's announced
// identity. The manifest must already be loaded (validated + resolved).
func DryRunHandshake(ctx context.Context, m *Manifest) (HandshakeResponse, error) {
	if m.ResolvedExec == "" {
		return HandshakeResponse{}, fmt.Errorf("plugin: manifest not resolved")
	}
	cfg := Config{
		Path:           m.ResolvedExec,
		Type:           m.Type,
		RequestTimeout: m.RequestTimeout(),
		Logger:         slog.Default(),
	}
	proc, hs, err := startProcess(ctx, cfg, cfg.Logger)
	if err != nil {
		return HandshakeResponse{}, err
	}
	proc.kill()
	return *hs, nil
}

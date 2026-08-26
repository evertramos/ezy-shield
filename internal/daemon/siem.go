package daemon

// SIEM forwarding (issue #203): the daemon tails the audit log — the single
// choke point every audited action already passes through — and hands each
// new row to the injected forwarder. Following the log (instead of hooking
// every writer) guarantees "every audited action emitted" by construction,
// preserves ordering, and keeps the emit path fully decoupled from the
// decision pipeline: a dead SIEM can at worst drop events from its own
// bounded queue, never block a ban.

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/evertramos/ezy-shield/internal/siem"
	"github.com/evertramos/ezy-shield/internal/store"
)

// defaultSIEMTailTick is how often new audit rows are picked up.
const defaultSIEMTailTick = 2 * time.Second

// runSIEMTail forwards audit rows and daemon lifecycle events until ctx is
// done. No-op when no forwarder was injected.
func (d *Daemon) runSIEMTail(ctx context.Context) {
	if d.siemEmit == nil {
		return
	}
	tick := d.siemTailTick
	if tick <= 0 {
		tick = defaultSIEMTailTick
	}

	// Start from the current tail: forwarding begins with events from THIS
	// run, not a replay of the whole history.
	var lastID int64
	if rows, err := d.store.ListAuditLog(ctx, 1); err == nil && len(rows) > 0 {
		lastID = rows[0].ID
	}

	// Lifecycle: daemon start (armed state in the reason), per the AC.
	d.siemEmit(siem.Event{
		Time:   time.Now().UTC(),
		Action: "daemon_start",
		Rule:   "armed=" + boolStr(d.policy.IsArmed()),
		Actor:  "daemon",
	})
	defer d.siemEmit(siem.Event{
		Time:   time.Now().UTC(),
		Action: "daemon_stop",
		Actor:  "daemon",
	})

	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.forwardNewAudits(context.WithoutCancel(ctx), &lastID) // final pickup
			return
		case <-t.C:
			d.forwardNewAudits(ctx, &lastID)
		}
	}
}

// forwardNewAudits emits every audit row recorded since *lastID.
func (d *Daemon) forwardNewAudits(ctx context.Context, lastID *int64) {
	for {
		rows, err := d.store.AuditLogAfter(ctx, *lastID, 500)
		if err != nil {
			slog.WarnContext(ctx, "daemon: siem audit tail query failed", "err", err)
			return
		}
		for _, r := range rows {
			d.siemEmit(auditToSIEM(r))
			*lastID = r.ID
		}
		if len(rows) < 500 {
			return
		}
	}
}

// auditToSIEM converts one audit row to the transport-neutral event. Every
// string stays untrusted — the formatters escape defensively.
func auditToSIEM(r store.AuditEntry) siem.Event {
	e := siem.Event{
		Action: r.Op,
		Rule:   r.Reason,
		Strike: r.Strike,
		TTL:    time.Duration(r.TTLSeconds) * time.Second,
		Actor:  "daemon",
	}
	if t, err := time.Parse(time.RFC3339Nano, r.RecordedAt); err == nil {
		e.Time = t.UTC()
	}
	if r.IP != "" {
		// The audit ip column stores both bare addresses and CIDR prefixes
		// (AuditOp writes prefixes); the SIEM event carries the address.
		if addr, err := netip.ParseAddr(r.IP); err == nil {
			e.IP = addr
		} else if pfx, err := netip.ParsePrefix(r.IP); err == nil {
			e.IP = pfx.Addr()
		}
	}
	return e
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

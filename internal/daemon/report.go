package daemon

// Handlers for the read-only "report" socket verb (issue #54): a per-IP
// abuse report (request IP set) or a summary listing of offenders (request
// IP empty). Aggregation happens here in the daemon — store reads plus
// in-memory GeoIP enrichment — so CLI clients only format.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// reportDefaultLimit is the server default for list-shaped report queries
// (strike history, action trail, offender listing) when the request carries
// no explicit limit. The store additionally caps every limit at 1000.
const reportDefaultLimit = 100

// handleReport dispatches the report verb.
//
// Security (§6 control surfaces): this verb is strictly read-only — it never
// touches the enforcer, the allowlist, or daemon state. §1: the target is
// parsed with netip.ParseAddr before any query; report payloads may embed
// hostile log content (reasons, categories), so terminal clients MUST
// sanitize before rendering (see sdk.AbuseReport doc).
func (d *Daemon) handleReport(ctx context.Context, req SocketRequest) SocketResponse {
	limit := req.Limit
	if limit <= 0 {
		limit = reportDefaultLimit
	}

	if req.IP == "" {
		return d.handleReportList(ctx, req.Filter, limit)
	}

	// report is per-address: reject CIDR and anything else ParseAddr refuses.
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("invalid ip %q: report takes a single address, not a range", req.IP)}
	}

	rep, err := d.buildAbuseReport(ctx, addr, limit)
	if err != nil {
		return SocketResponse{Error: err.Error()}
	}
	raw, _ := json.Marshal(rep)
	return SocketResponse{OK: true, Data: raw}
}

// handleReportList returns ReportSummaryEntry rows for the listing mode.
func (d *Daemon) handleReportList(ctx context.Context, filter string, limit int) SocketResponse {
	permanentOnly := false
	switch filter {
	case "", "all":
	case "permanent":
		permanentOnly = true
	default:
		return SocketResponse{Error: fmt.Sprintf("invalid filter %q; valid: all permanent", filter)}
	}

	offenders, err := d.store.ListOffenders(ctx, permanentOnly, limit)
	if err != nil {
		return SocketResponse{Error: fmt.Sprintf("list offenders: %v", err)}
	}

	out := make([]ReportSummaryEntry, 0, len(offenders))
	for _, o := range offenders {
		e := ReportSummaryEntry{
			IP:           o.IP,
			FirstSeen:    o.FirstSeen,
			LastSeen:     o.LastSeen,
			TotalStrikes: o.TotalStrikes,
			Banned:       o.Banned,
			Permanent:    o.Permanent,
		}
		if d.enricher != nil {
			if addr, perr := netip.ParseAddr(o.IP); perr == nil {
				enr := d.enricher.Lookup(addr)
				e.Country = enr.Country
				e.ASN = asnString(enr.ASN)
			}
		}
		out = append(out, e)
	}
	raw, _ := json.Marshal(out)
	return SocketResponse{OK: true, Data: raw}
}

// buildAbuseReport aggregates everything the store and enricher know about
// addr into a versioned sdk.AbuseReport. It returns an error when the IP has
// no offender history and no active ban.
func (d *Daemon) buildAbuseReport(ctx context.Context, addr netip.Addr, limit int) (*sdk.AbuseReport, error) {
	offender, err := d.store.GetOffender(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("offender lookup: %w", err)
	}
	ban, err := d.store.ActiveBanForIP(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("ban lookup: %w", err)
	}
	if offender == nil && ban == nil {
		return nil, fmt.Errorf("no records for %s", addr)
	}

	strikes, err := d.store.StrikesForIP(ctx, addr, limit)
	if err != nil {
		return nil, fmt.Errorf("strike history: %w", err)
	}
	actions, err := d.store.AuditLogForIP(ctx, addr, limit)
	if err != nil {
		return nil, fmt.Errorf("audit trail: %w", err)
	}

	rep := &sdk.AbuseReport{
		SchemaVersion: sdk.AbuseReportSchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		IP:            addr.String(),
	}
	if offender != nil {
		rep.FirstSeen = offender.FirstSeen
		rep.LastSeen = offender.LastSeen
		rep.TotalStrikes = offender.TotalStrikes
	}
	if d.enricher != nil {
		enr := d.enricher.Lookup(addr)
		rep.Country = enr.Country
		rep.ASN = asnString(enr.ASN)
		rep.ASNOrg = enr.ASNOrg
	}
	if ban != nil {
		rep.CurrentBan = &sdk.AbuseReportBan{
			BannedAt:  ban.BannedAt,
			ExpiresAt: ban.ExpiresAt,
			Permanent: ban.Permanent,
			Strike:    ban.StrikeNum,
			Reason:    ban.Reason,
		}
	}
	rep.Strikes = reportStrikes(strikes)
	rep.Actions = reportActions(actions)
	return rep, nil
}

// reportStrikes maps store strike rows to their wire form.
func reportStrikes(in []store.StrikeRecord) []sdk.AbuseReportStrike {
	if len(in) == 0 {
		return nil
	}
	out := make([]sdk.AbuseReportStrike, 0, len(in))
	for _, s := range in {
		ws := sdk.AbuseReportStrike{
			RecordedAt: s.RecordedAt,
			Strike:     s.StrikeNum,
			TTLSeconds: s.TTLSeconds,
			Reason:     s.Reason,
		}
		for _, v := range s.Verdicts {
			ws.Verdicts = append(ws.Verdicts, sdk.AbuseReportVerdict{
				Score:      v.Score,
				Category:   v.Category,
				Confidence: v.Confidence,
				Reason:     v.Reason,
				Source:     v.Source,
			})
		}
		out = append(out, ws)
	}
	return out
}

// reportActions maps audit rows to their wire form.
func reportActions(in []store.AuditEntry) []sdk.AbuseReportAction {
	if len(in) == 0 {
		return nil
	}
	out := make([]sdk.AbuseReportAction, 0, len(in))
	for _, e := range in {
		out = append(out, sdk.AbuseReportAction{
			RecordedAt: e.RecordedAt,
			Op:         e.Op,
			TTLSeconds: e.TTLSeconds,
			Strike:     e.Strike,
			Reason:     e.Reason,
		})
	}
	return out
}

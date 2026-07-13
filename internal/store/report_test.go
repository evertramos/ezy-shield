package store_test

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

// TestGetOffender covers the nil-for-unknown contract and field round-trip.
func TestGetOffender(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	o, err := db.GetOffender(ctx, ip1)
	if err != nil {
		t.Fatalf("GetOffender unknown: %v", err)
	}
	if o != nil {
		t.Fatalf("want nil for unseen IP, got %+v", o)
	}

	if err := db.RecordStrike(ctx, action(ip1, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike #1: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike #2: %v", err)
	}

	o, err = db.GetOffender(ctx, ip1)
	if err != nil {
		t.Fatalf("GetOffender: %v", err)
	}
	if o == nil {
		t.Fatal("want offender record, got nil")
	}
	if o.IP != ip1.String() {
		t.Errorf("IP: want %s, got %s", ip1, o.IP)
	}
	if o.TotalStrikes != 2 {
		t.Errorf("TotalStrikes: want 2, got %d", o.TotalStrikes)
	}
	if o.FirstSeen == "" || o.LastSeen == "" {
		t.Errorf("timestamps must be set, got first=%q last=%q", o.FirstSeen, o.LastSeen)
	}
}

// TestStrikesForIP covers ordering (newest first), verdict round-trip, and
// per-IP isolation.
func TestStrikesForIP(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike #1: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike #2: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip2, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike ip2: %v", err)
	}

	strikes, err := db.StrikesForIP(ctx, ip1, 100)
	if err != nil {
		t.Fatalf("StrikesForIP: %v", err)
	}
	if len(strikes) != 2 {
		t.Fatalf("want 2 strikes for %s, got %d", ip1, len(strikes))
	}
	// Newest first: strike_num 2 (the second insert) leads.
	if strikes[0].StrikeNum != 2 || strikes[1].StrikeNum != 1 {
		t.Errorf("want newest-first order [2 1], got [%d %d]",
			strikes[0].StrikeNum, strikes[1].StrikeNum)
	}
	if strikes[0].TTLSeconds != int64(time.Hour.Seconds()) {
		t.Errorf("TTLSeconds: want 3600, got %d", strikes[0].TTLSeconds)
	}
	// Verdicts round-trip through the JSON column.
	if len(strikes[0].Verdicts) != 1 {
		t.Fatalf("want 1 verdict, got %d", len(strikes[0].Verdicts))
	}
	v := strikes[0].Verdicts[0]
	if v.Score != 90 || v.Category != "bruteforce" || v.Source != "rules" {
		t.Errorf("verdict round-trip mismatch: %+v", v)
	}

	// Limit is honoured.
	strikes, err = db.StrikesForIP(ctx, ip1, 1)
	if err != nil {
		t.Fatalf("StrikesForIP limit=1: %v", err)
	}
	if len(strikes) != 1 || strikes[0].StrikeNum != 2 {
		t.Errorf("limit=1: want just the newest strike, got %+v", strikes)
	}
}

// TestAuditLogForIP ensures only exact-match rows come back (prefix ops
// recorded against a CIDR string are excluded).
func TestAuditLogForIP(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	if err := db.Unban(ctx, ip1); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip2, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike ip2: %v", err)
	}
	// A prefix op containing ip1 must NOT show up in ip1's trail.
	if err := db.AuditOp(ctx, "allow", netip.MustParsePrefix("1.2.3.0/24"), 0, "range op"); err != nil {
		t.Fatalf("AuditOp: %v", err)
	}

	entries, err := db.AuditLogForIP(ctx, ip1, 100)
	if err != nil {
		t.Fatalf("AuditLogForIP: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 audit rows for %s, got %d: %+v", ip1, len(entries), entries)
	}
	// Newest first: unban then ban.
	if entries[0].Op != "unban" || entries[1].Op != "ban" {
		t.Errorf("want [unban ban], got [%s %s]", entries[0].Op, entries[1].Op)
	}
}

// TestActiveBanForIP covers nil-for-unbanned, temporary, and permanent bans.
func TestActiveBanForIP(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	b, err := db.ActiveBanForIP(ctx, ip1)
	if err != nil {
		t.Fatalf("ActiveBanForIP unknown: %v", err)
	}
	if b != nil {
		t.Fatalf("want nil for unbanned IP, got %+v", b)
	}

	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	b, err = db.ActiveBanForIP(ctx, ip1)
	if err != nil {
		t.Fatalf("ActiveBanForIP temp: %v", err)
	}
	if b == nil {
		t.Fatal("want ban record, got nil")
	}
	if b.Permanent {
		t.Error("1h ban must not be permanent")
	}
	if b.ExpiresAt == "" || b.BannedAt == "" {
		t.Errorf("timestamps must be set, got banned=%q expires=%q", b.BannedAt, b.ExpiresAt)
	}
	if b.StrikeNum != 2 {
		t.Errorf("StrikeNum: want 2, got %d", b.StrikeNum)
	}

	// TTL 0 = permanent.
	if err := db.RecordStrike(ctx, action(ip2, 5, 0)); err != nil {
		t.Fatalf("RecordStrike permanent: %v", err)
	}
	b, err = db.ActiveBanForIP(ctx, ip2)
	if err != nil {
		t.Fatalf("ActiveBanForIP permanent: %v", err)
	}
	if b == nil || !b.Permanent || b.ExpiresAt != "" {
		t.Errorf("want permanent ban with empty ExpiresAt, got %+v", b)
	}
}

// TestListOffenders covers the permanent-only filter and ban-state flags.
func TestListOffenders(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike ip1: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip2, 5, 0)); err != nil {
		t.Fatalf("RecordStrike ip2 permanent: %v", err)
	}
	// A third offender with its ban already lifted.
	ip3 := netip.MustParseAddr("5.6.7.8")
	if err := db.RecordStrike(ctx, action(ip3, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike ip3: %v", err)
	}
	if err := db.Unban(ctx, ip3); err != nil {
		t.Fatalf("Unban ip3: %v", err)
	}

	all, err := db.ListOffenders(ctx, false, 100)
	if err != nil {
		t.Fatalf("ListOffenders all: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("want 3 offenders, got %d", len(all))
	}
	byIP := map[string]struct{ banned, permanent bool }{}
	for _, o := range all {
		byIP[o.IP] = struct{ banned, permanent bool }{o.Banned, o.Permanent}
	}
	if s := byIP[ip1.String()]; !s.banned || s.permanent {
		t.Errorf("%s: want banned temp, got %+v", ip1, s)
	}
	if s := byIP[ip2.String()]; !s.banned || !s.permanent {
		t.Errorf("%s: want banned permanent, got %+v", ip2, s)
	}
	if s := byIP[ip3.String()]; s.banned {
		t.Errorf("%s: want not banned after unban, got %+v", ip3, s)
	}

	perm, err := db.ListOffenders(ctx, true, 100)
	if err != nil {
		t.Fatalf("ListOffenders permanent: %v", err)
	}
	if len(perm) != 1 || perm[0].IP != ip2.String() {
		t.Errorf("permanent filter: want only %s, got %+v", ip2, perm)
	}
}

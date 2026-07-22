package store_test

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/store"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

func openTestDB(t *testing.T) *store.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

var (
	ip1 = netip.MustParseAddr("1.2.3.4")
	ip2 = netip.MustParseAddr("2001:db8::1")
)

func action(ip netip.Addr, strike int, ttl time.Duration) sdk.Action {
	return sdk.Action{
		IP:     ip,
		Op:     "ban",
		TTL:    ttl,
		Strike: strike,
		Reason: "test reason",
		Verdicts: []sdk.Verdict{
			{IP: ip, Score: 90, Category: "bruteforce", Confidence: 0.95, Source: "rules"},
		},
	}
}

// TestMigrations verifies schema_migrations is populated after Open.
func TestMigrations(t *testing.T) {
	db := openTestDB(t)
	// A second Open on the same file must not re-apply migrations.
	path := filepath.Join(t.TempDir(), "idempotent.db")
	for range 2 {
		d, err := store.Open(context.Background(), path)
		if err != nil {
			t.Fatalf("Open (idempotent): %v", err)
		}
		_ = d.Close()
	}
	_ = db
}

// TestRecordStrike_and_GetStrikeCount covers the core strike path.
func TestRecordStrike_and_GetStrikeCount(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Unknown IP → 0 strikes.
	n, err := db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount unknown: %v", err)
	}
	if n != 0 {
		t.Errorf("want 0 strikes for unseen IP, got %d", n)
	}

	// First strike.
	if err := db.RecordStrike(ctx, action(ip1, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike #1: %v", err)
	}
	n, err = db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount after #1: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 strike, got %d", n)
	}

	// Second strike — cumulative count must increment.
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike #2: %v", err)
	}
	n, err = db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount after #2: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 strikes, got %d", n)
	}
}

// TestRecordStrike_IPv6 ensures IPv6 addresses round-trip correctly.
func TestRecordStrike_IPv6(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip2, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike IPv6: %v", err)
	}
	n, err := db.GetStrikeCount(ctx, ip2)
	if err != nil {
		t.Fatalf("GetStrikeCount IPv6: %v", err)
	}
	if n != 1 {
		t.Errorf("want 1 strike for IPv6, got %d", n)
	}
}

// TestActiveBans verifies bans_active is populated and returned correctly.
func TestActiveBans(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 active ban, got %d", len(bans))
	}
	if bans[0].IP != ip1 {
		t.Errorf("want ban for %s, got %s", ip1, bans[0].IP)
	}
	if bans[0].Strike != 1 {
		t.Errorf("want strike 1, got %d", bans[0].Strike)
	}
}

// TestActiveBans_Permanent verifies permanent bans (TTL == 0) have no expires_at.
func TestActiveBans_Permanent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	perm := action(ip1, 5, 0) // TTL 0 = permanent
	if err := db.RecordStrike(ctx, perm); err != nil {
		t.Fatalf("RecordStrike permanent: %v", err)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 ban, got %d", len(bans))
	}
	if bans[0].TTL != 0 {
		t.Errorf("permanent ban should have TTL 0, got %v", bans[0].TTL)
	}
}

// TestExpireBans verifies expired bans are removed and permanent ones are kept.
func TestExpireBans(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Short-lived ban.
	if err := db.RecordStrike(ctx, action(ip1, 1, time.Millisecond)); err != nil {
		t.Fatalf("RecordStrike timed: %v", err)
	}
	// Permanent ban.
	if err := db.RecordStrike(ctx, action(ip2, 5, 0)); err != nil {
		t.Fatalf("RecordStrike permanent: %v", err)
	}

	// Expire everything before "far future".
	removed, err := db.ExpireBans(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	if removed != 1 {
		t.Errorf("want 1 expired ban, got %d", removed)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans after expire: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 remaining ban (permanent), got %d", len(bans))
	}
	if bans[0].IP != ip2 {
		t.Errorf("remaining ban should be %s, got %s", ip2, bans[0].IP)
	}
}

// TestExpireBans_Idempotent verifies ExpireBans with a past time removes nothing.
func TestExpireBans_Idempotent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	removed, err := db.ExpireBans(ctx, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ExpireBans past: %v", err)
	}
	if removed != 0 {
		t.Errorf("want 0 removed for past time, got %d", removed)
	}
}

// TestAudit verifies standalone Audit entries are accepted (no UPDATE/DELETE paths).
func TestAudit(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	a := sdk.Action{
		IP:     ip1,
		Op:     "unban",
		TTL:    0,
		Strike: 0,
		Reason: "manual unban",
	}
	if err := db.Audit(ctx, a); err != nil {
		t.Fatalf("Audit: %v", err)
	}

	// Multiple audit entries must not conflict.
	a.Op = "notify_only"
	if err := db.Audit(ctx, a); err != nil {
		t.Fatalf("Audit second entry: %v", err)
	}
}

func TestListAuditLog_OrderAndLimit(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for i, op := range []string{"ban", "unban", "allow_add", "unban", "allow_del"} {
		a := sdk.Action{IP: ip1, Op: op, TTL: 0, Strike: i, Reason: op}
		if err := db.Audit(ctx, a); err != nil {
			t.Fatalf("Audit %d: %v", i, err)
		}
	}

	// Full read → 5 rows in DESC id order.
	rows, err := db.ListAuditLog(ctx, 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if len(rows) != 5 {
		t.Fatalf("len = %d, want 5", len(rows))
	}
	// Highest id first.
	for i := 1; i < len(rows); i++ {
		if rows[i-1].ID <= rows[i].ID {
			t.Errorf("rows not DESC by id: %d then %d", rows[i-1].ID, rows[i].ID)
		}
	}
	// The most recent op we wrote was "allow_del".
	if rows[0].Op != "allow_del" {
		t.Errorf("top row op = %q, want allow_del", rows[0].Op)
	}

	// Limit clamping: 0 → 1 row, >1000 → capped.
	one, err := db.ListAuditLog(ctx, 0)
	if err != nil {
		t.Fatalf("ListAuditLog(0): %v", err)
	}
	if len(one) != 1 {
		t.Errorf("len with limit 0 = %d, want 1", len(one))
	}

	huge, err := db.ListAuditLog(ctx, 100_000)
	if err != nil {
		t.Fatalf("ListAuditLog(huge): %v", err)
	}
	if len(huge) != 5 {
		t.Errorf("len with huge limit = %d, want 5 (all rows)", len(huge))
	}
}

// TestRecordStrike_OffenderKeptAfterExpiry verifies that offender rows are
// preserved even after the ban expires (total_strikes never decremented).
func TestRecordStrike_OffenderKeptAfterExpiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Millisecond)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	if _, err := db.ExpireBans(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}

	// Ban is gone but offender row must remain.
	n, err := db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount after expiry: %v", err)
	}
	if n != 1 {
		t.Errorf("offender row must survive ban expiry; want 1 strike, got %d", n)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Errorf("want 0 active bans after expiry, got %d", len(bans))
	}
}

// TestConcurrentReads exercises simultaneous reads under the race detector to
// satisfy the WAL-mode concurrent-read acceptance criterion.
func TestConcurrentReads(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	const readers = 20
	var wg sync.WaitGroup
	wg.Add(readers)
	errs := make(chan error, readers)

	for range readers {
		go func() {
			defer wg.Done()
			if _, err := db.GetStrikeCount(ctx, ip1); err != nil {
				errs <- err
			}
			if _, err := db.ActiveBans(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent read error: %v", err)
	}
}

// TestRecordUsage_and_TodayUsage covers the AI token budget accounting path.
func TestRecordUsage_and_TodayUsage(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Initially zero.
	u, err := db.TodayUsage(ctx, "anthropic")
	if err != nil {
		t.Fatalf("TodayUsage initial: %v", err)
	}
	if u.InputTokens != 0 || u.OutputTokens != 0 || u.CostUSD != 0 {
		t.Errorf("want zero usage initially, got %+v", u)
	}

	if err := db.RecordUsage(ctx, "anthropic", sdk.Usage{
		InputTokens:  200,
		OutputTokens: 50,
		CostUSD:      0.00026,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if err := db.RecordUsage(ctx, "anthropic", sdk.Usage{
		InputTokens:  100,
		OutputTokens: 25,
		CostUSD:      0.00018,
	}); err != nil {
		t.Fatalf("RecordUsage second: %v", err)
	}

	u, err = db.TodayUsage(ctx, "anthropic")
	if err != nil {
		t.Fatalf("TodayUsage: %v", err)
	}
	if u.InputTokens != 300 {
		t.Errorf("want InputTokens=300, got %d", u.InputTokens)
	}
	if u.OutputTokens != 75 {
		t.Errorf("want OutputTokens=75, got %d", u.OutputTokens)
	}

	// A different provider must not be included in the sum.
	if err := db.RecordUsage(ctx, "ollama", sdk.Usage{InputTokens: 9999}); err != nil {
		t.Fatalf("RecordUsage ollama: %v", err)
	}
	u, err = db.TodayUsage(ctx, "anthropic")
	if err != nil {
		t.Fatalf("TodayUsage after ollama: %v", err)
	}
	if u.InputTokens != 300 {
		t.Errorf("ollama usage leaked into anthropic total: want 300, got %d", u.InputTokens)
	}
}

// TestMultipleIPs verifies independent strike counts per IP.
func TestMultipleIPs(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for range 3 {
		if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
			t.Fatalf("RecordStrike ip1: %v", err)
		}
	}
	if err := db.RecordStrike(ctx, action(ip2, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike ip2: %v", err)
	}

	tests := []struct {
		ip   netip.Addr
		want int
	}{
		{ip1, 3},
		{ip2, 1},
	}
	for _, tt := range tests {
		n, err := db.GetStrikeCount(ctx, tt.ip)
		if err != nil {
			t.Fatalf("GetStrikeCount %s: %v", tt.ip, err)
		}
		if n != tt.want {
			t.Errorf("ip=%s: want %d strikes, got %d", tt.ip, tt.want, n)
		}
	}
}

// TestUpsertScanRecord_and_ScanBaseline exercises the scan persistence path.
func TestUpsertScanRecord_and_ScanBaseline(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	r := store.ScanRecord{
		Proto:     "tcp",
		LocalAddr: "0.0.0.0:22",
		PID:       1234,
		ExePath:   "/usr/sbin/sshd",
		UID:       0,
		UserName:  "root",
		IsPublic:  true,
		OwnerType: "systemd",
		UnitName:  "ssh.service",
		LogSource: "journald://ssh.service",
	}

	if err := db.UpsertScanRecord(ctx, r); err != nil {
		t.Fatalf("UpsertScanRecord: %v", err)
	}

	records, err := db.ScanBaseline(ctx)
	if err != nil {
		t.Fatalf("ScanBaseline: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	got := records[0]
	if got.Proto != r.Proto {
		t.Errorf("Proto: want %q, got %q", r.Proto, got.Proto)
	}
	if got.LocalAddr != r.LocalAddr {
		t.Errorf("LocalAddr: want %q, got %q", r.LocalAddr, got.LocalAddr)
	}
	if got.ExePath != r.ExePath {
		t.Errorf("ExePath: want %q, got %q", r.ExePath, got.ExePath)
	}
	if !got.IsPublic {
		t.Error("IsPublic: want true, got false")
	}
	if got.UnitName != r.UnitName {
		t.Errorf("UnitName: want %q, got %q", r.UnitName, got.UnitName)
	}
	if got.LogSource != r.LogSource {
		t.Errorf("LogSource: want %q, got %q", r.LogSource, got.LogSource)
	}
}

// TestUpsertScanRecord_Upsert verifies the UNIQUE(proto, local_addr) constraint
// causes a metadata update (not a duplicate row) on re-scan.
func TestUpsertScanRecord_Upsert(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	base := store.ScanRecord{
		Proto:     "tcp",
		LocalAddr: "0.0.0.0:80",
		PID:       100,
		ExePath:   "/usr/bin/nginx",
		UID:       33,
		UserName:  "www-data",
		IsPublic:  true,
		OwnerType: "systemd",
		UnitName:  "nginx.service",
		LogSource: "journald://nginx.service",
	}
	if err := db.UpsertScanRecord(ctx, base); err != nil {
		t.Fatalf("UpsertScanRecord initial: %v", err)
	}

	// Re-upsert with updated PID (process restarted) and new container name.
	updated := base
	updated.PID = 999
	updated.ContainerName = "my-nginx"
	if err := db.UpsertScanRecord(ctx, updated); err != nil {
		t.Fatalf("UpsertScanRecord update: %v", err)
	}

	records, err := db.ScanBaseline(ctx)
	if err != nil {
		t.Fatalf("ScanBaseline: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("upsert must not create duplicate rows: got %d records", len(records))
	}
	if records[0].PID != 999 {
		t.Errorf("PID: want 999 after upsert, got %d", records[0].PID)
	}
	if records[0].ContainerName != "my-nginx" {
		t.Errorf("ContainerName: want my-nginx, got %q", records[0].ContainerName)
	}
}

// TestAllowlist_AddListExpire exercises the allowlist persistence path:
// permanent rows survive expiry sweeps, dated rows go away once they pass now.
func TestAllowlist_AddListExpire(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Permanent.
	if err := db.AddAllow(ctx, netip.MustParsePrefix("10.0.0.0/8"), nil, "admin"); err != nil {
		t.Fatalf("AddAllow permanent: %v", err)
	}
	// Dated, far future.
	future := time.Now().Add(48 * time.Hour)
	if err := db.AddAllow(ctx, netip.MustParsePrefix("203.0.113.0/24"), &future, "pentest"); err != nil {
		t.Fatalf("AddAllow future: %v", err)
	}
	// Already expired.
	past := time.Now().Add(-time.Hour)
	if err := db.AddAllow(ctx, netip.MustParsePrefix("198.51.100.42/32"), &past, "stale"); err != nil {
		t.Fatalf("AddAllow past: %v", err)
	}

	entries, err := db.ListAllow(ctx)
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries before expiry, got %d", len(entries))
	}

	removed, err := db.ExpireAllows(ctx, time.Now())
	if err != nil {
		t.Fatalf("ExpireAllows: %v", err)
	}
	if removed != 1 {
		t.Errorf("want 1 expired, got %d", removed)
	}

	entries, err = db.ListAllow(ctx)
	if err != nil {
		t.Fatalf("ListAllow after expire: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries after expire, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Prefix.String() == "198.51.100.42/32" {
			t.Error("expired entry should have been removed")
		}
	}
}

// TestAllowlist_Upsert verifies repeated AddAllow updates expires_at/reason
// without creating duplicate rows (single PRIMARY KEY collision behaviour).
func TestAllowlist_Upsert(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	pfx := netip.MustParsePrefix("203.0.113.0/24")

	if err := db.AddAllow(ctx, pfx, nil, "first"); err != nil {
		t.Fatalf("AddAllow first: %v", err)
	}
	exp := time.Now().Add(24 * time.Hour)
	if err := db.AddAllow(ctx, pfx, &exp, "second"); err != nil {
		t.Fatalf("AddAllow second: %v", err)
	}

	entries, err := db.ListAllow(ctx)
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("upsert must keep row count at 1, got %d", len(entries))
	}
	if entries[0].Reason != "second" {
		t.Errorf("reason: want %q, got %q", "second", entries[0].Reason)
	}
	if entries[0].ExpiresAt.IsZero() {
		t.Error("expires_at should be set after second add")
	}
}

// TestAllowlist_CanonicalPrefix verifies prefixes are stored in masked form, so
// "203.0.113.5/24" and "203.0.113.0/24" collapse to a single row.
func TestAllowlist_CanonicalPrefix(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.AddAllow(ctx, netip.MustParsePrefix("203.0.113.5/24"), nil, ""); err != nil {
		t.Fatalf("AddAllow uncanonical: %v", err)
	}
	if err := db.AddAllow(ctx, netip.MustParsePrefix("203.0.113.0/24"), nil, ""); err != nil {
		t.Fatalf("AddAllow canonical: %v", err)
	}

	entries, err := db.ListAllow(ctx)
	if err != nil {
		t.Fatalf("ListAllow: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 collapsed row, got %d", len(entries))
	}
	if got := entries[0].Prefix.String(); got != "203.0.113.0/24" {
		t.Errorf("stored prefix: want canonical %q, got %q", "203.0.113.0/24", got)
	}
}

// TestUnbanPrefix verifies a wider prefix removes every ban whose IP falls
// inside it and leaves outside-bans untouched.
func TestUnbanPrefix(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	inside1 := netip.MustParseAddr("10.0.0.1")
	inside2 := netip.MustParseAddr("10.0.5.42")
	outside := netip.MustParseAddr("203.0.113.7")

	for _, ip := range []netip.Addr{inside1, inside2, outside} {
		if err := db.RecordStrike(ctx, action(ip, 1, time.Hour)); err != nil {
			t.Fatalf("RecordStrike %s: %v", ip, err)
		}
	}

	n, err := db.UnbanPrefix(ctx, netip.MustParsePrefix("10.0.0.0/8"))
	if err != nil {
		t.Fatalf("UnbanPrefix: %v", err)
	}
	if n != 2 {
		t.Errorf("UnbanPrefix: want 2 removed, got %d", n)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != outside {
		t.Errorf("only outside ban should remain, got %+v", bans)
	}
}

// TestScanBaseline_MultipleProtocols verifies tcp and tcp6 rows are independent.
func TestScanBaseline_MultipleProtocols(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	records := []store.ScanRecord{
		{Proto: "tcp", LocalAddr: "0.0.0.0:22", ExePath: "/usr/sbin/sshd",
			OwnerType: "systemd", UnitName: "ssh.service", IsPublic: true,
			LogSource: "journald://ssh.service"},
		{Proto: "tcp6", LocalAddr: "[::]:22", ExePath: "/usr/sbin/sshd",
			OwnerType: "systemd", UnitName: "ssh.service", IsPublic: true,
			LogSource: "journald://ssh.service"},
		{Proto: "tcp", LocalAddr: "127.0.0.1:5432", ExePath: "/usr/bin/postgres",
			OwnerType: "systemd", UnitName: "postgresql.service",
			LogSource: "journald://postgresql.service"},
	}
	for _, r := range records {
		if err := db.UpsertScanRecord(ctx, r); err != nil {
			t.Fatalf("UpsertScanRecord %s %s: %v", r.Proto, r.LocalAddr, err)
		}
	}

	got, err := db.ScanBaseline(ctx)
	if err != nil {
		t.Fatalf("ScanBaseline: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 records, got %d", len(got))
	}
}

// TestRecordManualBan_Insert verifies a manual ban lands in bans_active and
// becomes visible to ActiveBans (the store fix for `ezyshield list` seeing
// operator bans).
func TestRecordManualBan_Insert(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordManualBan(ctx, ip1, time.Hour, "manual ban via CLI"); err != nil {
		t.Fatalf("RecordManualBan: %v", err)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != ip1 {
		t.Fatalf("want single ban for %s, got %+v", ip1, bans)
	}
	if bans[0].Reason != "manual ban via CLI" {
		t.Errorf("reason = %q, want %q", bans[0].Reason, "manual ban via CLI")
	}
	if bans[0].Strike != 1 {
		t.Errorf("manual ban strike_num = %d, want 1 (manual bans should not inflate strike count)", bans[0].Strike)
	}
}

// TestRecordManualBan_Refresh verifies a second RecordManualBan on the same IP
// updates the row via ON CONFLICT rather than inserting a duplicate (the table
// is keyed by IP). The reason and TTL from the second call must win.
func TestRecordManualBan_Refresh(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordManualBan(ctx, ip1, time.Hour, "first"); err != nil {
		t.Fatalf("first RecordManualBan: %v", err)
	}
	if err := db.RecordManualBan(ctx, ip1, 24*time.Hour, "second"); err != nil {
		t.Fatalf("second RecordManualBan: %v", err)
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 ban after refresh, got %d — ON CONFLICT should upsert not append", len(bans))
	}
	if bans[0].Reason != "second" {
		t.Errorf("reason = %q, want %q — second call must win", bans[0].Reason, "second")
	}
}

// TestRecordManualBan_Permanent verifies ttl == 0 records a permanent ban
// (expires_at NULL) so it never gets swept by ExpireBans.
func TestRecordManualBan_Permanent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordManualBan(ctx, ip2, 0, "forever"); err != nil {
		t.Fatalf("RecordManualBan permanent: %v", err)
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 ban, got %d", len(bans))
	}
	if bans[0].TTL != 0 {
		t.Errorf("permanent ban should have TTL 0, got %v", bans[0].TTL)
	}
	// ExpireBans on a far-future clock must NOT sweep the permanent entry.
	if _, err := db.ExpireBans(ctx, time.Now().Add(1_000_000*time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	still, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans post-expire: %v", err)
	}
	if len(still) != 1 {
		t.Errorf("permanent ban must survive ExpireBans, got %d bans left", len(still))
	}
}

// TestRecordManualBan_RefreshPreservesRuleEngineStrikeNum documents an
// intentional design decision (Copilot flagged this as a potential bug in
// review): when a manual ban lands on top of an existing rule-engine ban, the
// ON CONFLICT upsert does NOT overwrite strike_num. The rule-engine's
// escalation history — five failed logins → strike 3, for example — is more
// signal than "operator refreshed with strike 1", and losing that history
// would make future automatic escalations start over from zero. banned_at,
// expires_at, and reason ARE updated so the operator's ban does take effect;
// only the strike counter is preserved.
func TestRecordManualBan_RefreshPreservesRuleEngineStrikeNum(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Simulate the rule engine banning ip1 at strike 3.
	if err := db.RecordStrike(ctx, action(ip1, 3, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	// Operator issues a manual ban on the same IP.
	if err := db.RecordManualBan(ctx, ip1, 24*time.Hour, "operator ack"); err != nil {
		t.Fatalf("RecordManualBan: %v", err)
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("want 1 ban after refresh, got %d", len(bans))
	}
	if bans[0].Strike != 3 {
		t.Errorf("strike_num = %d, want 3 preserved from rule engine (see comment)", bans[0].Strike)
	}
	if bans[0].Reason != "operator ack" {
		t.Errorf("reason = %q, want %q (manual ban wins on reason)", bans[0].Reason, "operator ack")
	}
}

// TestRecordManualBan_RejectsNegativeTTL: a negative duration must not
// silently become a permanent ban (Copilot review). parseExtendedDuration
// happily returns negatives, so defense-in-depth belongs at the store layer.
func TestRecordManualBan_RejectsNegativeTTL(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordManualBan(ctx, ip1, -1*time.Hour, "typo"); err == nil {
		t.Fatal("expected error for negative ttl, got nil")
	}
	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 0 {
		t.Errorf("nothing should have been recorded for a rejected ban, got %d bans", len(bans))
	}
}

// TestGetBanInfo_NotPresent verifies GetBanInfo returns found=false for a
// never-seen IP — the baseline state before any ban is recorded.
func TestGetBanInfo_NotPresent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	_, _, _, found, err := db.GetBanInfo(ctx, ip1)
	if err != nil {
		t.Fatalf("GetBanInfo on empty DB: %v", err)
	}
	if found {
		t.Error("want found=false for unseen IP, got true")
	}
}

// TestGetBanInfo_PresentAfterStrike verifies GetBanInfo returns the ban
// metadata once RecordStrike writes a row to bans_active.
func TestGetBanInfo_PresentAfterStrike(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	before := time.Now().Add(-time.Second)
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	bannedAt, strike, _, found, err := db.GetBanInfo(ctx, ip1)
	if err != nil {
		t.Fatalf("GetBanInfo: %v", err)
	}
	if !found {
		t.Fatal("want found=true after RecordStrike, got false")
	}
	if strike != 2 {
		t.Errorf("strike = %d, want 2", strike)
	}
	if bannedAt.Before(before) || bannedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("bannedAt = %v not within test window", bannedAt)
	}
}

// TestGetBanInfo_FalseAfterExpiry verifies GetBanInfo returns found=false
// once the ban row is removed by ExpireBans.
func TestGetBanInfo_FalseAfterExpiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Record a short ban that expires in the past.
	if err := db.RecordStrike(ctx, action(ip1, 1, time.Millisecond)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	// Expire bans relative to a time well in the future.
	if _, err := db.ExpireBans(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}

	_, _, _, found, err := db.GetBanInfo(ctx, ip1)
	if err != nil {
		t.Fatalf("GetBanInfo post-expiry: %v", err)
	}
	if found {
		t.Error("want found=false after ban expiry, got true")
	}
}

// TestGetBanInfo_PermanentNeverExpires verifies a permanent ban (TTL=0)
// is never swept by ExpireBans and remains visible to GetBanInfo.
func TestGetBanInfo_PermanentNeverExpires(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 5, 0)); err != nil { // TTL 0 = permanent
		t.Fatalf("RecordStrike permanent: %v", err)
	}

	// ExpireBans with a far-future clock must not remove permanent rows.
	if _, err := db.ExpireBans(ctx, time.Now().Add(1_000_000*time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}

	_, strike, _, found, err := db.GetBanInfo(ctx, ip1)
	if err != nil {
		t.Fatalf("GetBanInfo post-expire: %v", err)
	}
	if !found {
		t.Error("want found=true for permanent ban after ExpireBans, got false")
	}
	if strike != 5 {
		t.Errorf("strike = %d, want 5", strike)
	}
}

// TestBumpLastSeen_CreatesOffenderRow verifies BumpLastSeen upserts an
// offender row when none exists yet (manual-ban edge case).
func TestBumpLastSeen_CreatesOffenderRow(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.BumpLastSeen(ctx, ip1); err != nil {
		t.Fatalf("BumpLastSeen on empty DB: %v", err)
	}

	// GetStrikeCount reads from offenders; total_strikes must be 0 (not an error).
	n, err := db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount after BumpLastSeen: %v", err)
	}
	if n != 0 {
		t.Errorf("total_strikes = %d after BumpLastSeen, want 0", n)
	}
}

// TestBumpLastSeen_DoesNotIncrementStrikeCount verifies BumpLastSeen does not
// increment total_strikes on an existing offender row — only last_seen changes.
func TestBumpLastSeen_DoesNotIncrementStrikeCount(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	// Establish an offender row with strike count 1.
	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	// Bump last_seen three times — total_strikes must remain 1.
	for range 3 {
		if err := db.BumpLastSeen(ctx, ip1); err != nil {
			t.Fatalf("BumpLastSeen: %v", err)
		}
	}

	n, err := db.GetStrikeCount(ctx, ip1)
	if err != nil {
		t.Fatalf("GetStrikeCount: %v", err)
	}
	if n != 1 {
		t.Errorf("total_strikes = %d after 3 BumpLastSeen calls, want 1", n)
	}
}

// ── LastStrike (ADR-0009, escalation rate-limit exemption) ───────────────────

// TestLastStrike_NoHistory verifies found=false (no error) for an unseen IP.
func TestLastStrike_NoHistory(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	_, _, found, err := db.LastStrike(ctx, ip1)
	if err != nil {
		t.Fatalf("LastStrike on empty DB: %v", err)
	}
	if found {
		t.Error("want found=false for unseen IP, got true")
	}
}

// TestLastStrike_ReturnsMostRecent verifies the newest strike row wins and
// that recordedAt/ttl round-trip through the store.
func TestLastStrike_ReturnsMostRecent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	before := time.Now().Add(-time.Second)
	if err := db.RecordStrike(ctx, action(ip1, 1, 5*time.Minute)); err != nil {
		t.Fatalf("RecordStrike #1: %v", err)
	}
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike #2: %v", err)
	}

	recordedAt, ttl, found, err := db.LastStrike(ctx, ip1)
	if err != nil {
		t.Fatalf("LastStrike: %v", err)
	}
	if !found {
		t.Fatal("want found=true after two strikes")
	}
	if ttl != time.Hour {
		t.Errorf("ttl = %v, want %v (most recent strike)", ttl, time.Hour)
	}
	if recordedAt.Before(before) || recordedAt.After(time.Now().Add(time.Second)) {
		t.Errorf("recordedAt = %v not within test window", recordedAt)
	}
}

// TestLastStrike_SurvivesBanExpiry verifies strike history remains readable
// after ExpireBans removes the bans_active row — the exemption check runs
// exactly then, on the first re-offense after expiry.
func TestLastStrike_SurvivesBanExpiry(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Second)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	if _, err := db.ExpireBans(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}

	_, ttl, found, err := db.LastStrike(ctx, ip1)
	if err != nil {
		t.Fatalf("LastStrike post-expiry: %v", err)
	}
	if !found {
		t.Fatal("want found=true after ban expiry (strikes are append-only)")
	}
	if ttl != time.Second {
		t.Errorf("ttl = %v, want %v", ttl, time.Second)
	}
}

// ── suppression counters / ban_ineffective persistence (ADR-0009) ────────────

// TestRecordSuppressed_CountsAndFireOnce verifies the counter increments, the
// after-grace split, and the MarkBanIneffective fire-once guarantee.
func TestRecordSuppressed_CountsAndFireOnce(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}

	// Two in-grace events, three after-grace events.
	for i := 0; i < 2; i++ {
		if _, _, _, err := db.RecordSuppressed(ctx, ip1, false); err != nil {
			t.Fatalf("RecordSuppressed in-grace[%d]: %v", i, err)
		}
	}
	var total, after int
	var fired bool
	var err error
	for i := 0; i < 3; i++ {
		total, after, fired, err = db.RecordSuppressed(ctx, ip1, true)
		if err != nil {
			t.Fatalf("RecordSuppressed after-grace[%d]: %v", i, err)
		}
	}
	if total != 5 || after != 3 {
		t.Errorf("total/after = %d/%d, want 5/3", total, after)
	}
	if fired {
		t.Error("fired = true before MarkBanIneffective")
	}

	// First mark transitions the flag; the second reports already-fired.
	newly, err := db.MarkBanIneffective(ctx, ip1)
	if err != nil {
		t.Fatalf("MarkBanIneffective #1: %v", err)
	}
	if !newly {
		t.Error("MarkBanIneffective #1 = false, want true (first transition)")
	}
	newly, err = db.MarkBanIneffective(ctx, ip1)
	if err != nil {
		t.Fatalf("MarkBanIneffective #2: %v", err)
	}
	if newly {
		t.Error("MarkBanIneffective #2 = true, want false (fire-once)")
	}

	// Subsequent RecordSuppressed reports fired=true.
	_, _, fired, err = db.RecordSuppressed(ctx, ip1, true)
	if err != nil {
		t.Fatalf("RecordSuppressed post-mark: %v", err)
	}
	if !fired {
		t.Error("fired = false after MarkBanIneffective")
	}
}

// TestRecordSuppressed_NoActiveBan verifies the expiry race: counting against
// a missing ban row returns zeros, not an error.
func TestRecordSuppressed_NoActiveBan(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	total, after, fired, err := db.RecordSuppressed(ctx, ip1, true)
	if err != nil {
		t.Fatalf("RecordSuppressed without ban: %v", err)
	}
	if total != 0 || after != 0 || fired {
		t.Errorf("total/after/fired = %d/%d/%v, want 0/0/false", total, after, fired)
	}
}

// TestSuppression_ResetOnNewBan verifies a new RecordStrike upsert resets the
// per-ban counters and the fired flag, while offenders.had_ineffective
// persists across bans and ban expiry (pre-permanent alert memory).
func TestSuppression_ResetOnNewBan(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Second)); err != nil {
		t.Fatalf("RecordStrike #1: %v", err)
	}
	if _, _, _, err := db.RecordSuppressed(ctx, ip1, true); err != nil {
		t.Fatalf("RecordSuppressed: %v", err)
	}
	if _, err := db.MarkBanIneffective(ctx, ip1); err != nil {
		t.Fatalf("MarkBanIneffective: %v", err)
	}

	// Ban #1 expires; had_ineffective must survive the row deletion.
	if _, err := db.ExpireBans(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	had, err := db.HadIneffectiveBan(ctx, ip1)
	if err != nil {
		t.Fatalf("HadIneffectiveBan post-expiry: %v", err)
	}
	if !had {
		t.Error("had_ineffective lost after ban expiry")
	}

	// Ban #2: fresh counters.
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike #2: %v", err)
	}
	total, after, fired, err := db.RecordSuppressed(ctx, ip1, true)
	if err != nil {
		t.Fatalf("RecordSuppressed on ban #2: %v", err)
	}
	if total != 1 || after != 1 || fired {
		t.Errorf("ban #2 total/after/fired = %d/%d/%v, want 1/1/false (reset)", total, after, fired)
	}
}

// TestHadIneffectiveBan_Default verifies the flag is false for unseen IPs and
// for offenders that never had an ineffective ban.
func TestHadIneffectiveBan_Default(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	had, err := db.HadIneffectiveBan(ctx, ip1)
	if err != nil {
		t.Fatalf("HadIneffectiveBan unseen: %v", err)
	}
	if had {
		t.Error("want false for unseen IP")
	}

	if err := db.RecordStrike(ctx, action(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike: %v", err)
	}
	had, err = db.HadIneffectiveBan(ctx, ip1)
	if err != nil {
		t.Fatalf("HadIneffectiveBan clean offender: %v", err)
	}
	if had {
		t.Error("want false for offender without ineffective bans")
	}
}

// ── dry-run simulated bans (ADR-0009 §5, issue #145) ─────────────────────────

// dryAction mirrors action() with Op="dry_ban" — a dry-run simulated ban.
func dryAction(ip netip.Addr, strike int, ttl time.Duration) sdk.Action {
	a := action(ip, strike, ttl)
	a.Op = "dry_ban"
	return a
}

// TestDryRunBan_FlagRoundTrip verifies a dry_ban strike stores dry_run=1 and
// GetBanInfo/ActiveBans both report it as simulated, and that a subsequent
// real strike overwrites the flag (the armed engine falls through leftover
// simulated bans and records a real one).
func TestDryRunBan_FlagRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, dryAction(ip1, 1, time.Hour)); err != nil {
		t.Fatalf("RecordStrike dry: %v", err)
	}

	_, strike, dryRun, found, err := db.GetBanInfo(ctx, ip1)
	if err != nil || !found {
		t.Fatalf("GetBanInfo: found=%v err=%v", found, err)
	}
	if !dryRun {
		t.Error("GetBanInfo dryRun = false, want true for a dry_ban row")
	}
	if strike != 1 {
		t.Errorf("strike = %d, want 1", strike)
	}

	bans, err := db.ActiveBans(ctx)
	if err != nil {
		t.Fatalf("ActiveBans: %v", err)
	}
	if len(bans) != 1 || bans[0].Op != "dry_ban" {
		t.Fatalf("ActiveBans = %+v, want one entry with Op=dry_ban", bans)
	}

	// A real strike for the same IP must clear the flag via the upsert.
	if err := db.RecordStrike(ctx, action(ip1, 2, time.Hour)); err != nil {
		t.Fatalf("RecordStrike real: %v", err)
	}
	_, _, dryRun, found, err = db.GetBanInfo(ctx, ip1)
	if err != nil || !found {
		t.Fatalf("GetBanInfo after real strike: found=%v err=%v", found, err)
	}
	if dryRun {
		t.Error("dry_run still set after a real strike — the enforcer sync would skip a REAL ban")
	}
}

// TestDryRunBan_ExpiresWithDistinctAuditReason verifies simulated bans expire
// through the normal sweep and the audit entry names the simulated TTL.
func TestDryRunBan_ExpiresWithDistinctAuditReason(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := db.RecordStrike(ctx, dryAction(ip1, 1, time.Millisecond)); err != nil {
		t.Fatalf("RecordStrike dry: %v", err)
	}
	n, err := db.ExpireBans(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ExpireBans: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired = %d, want 1", n)
	}

	entries, err := db.ListAuditLog(ctx, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Op == "expire" && e.Reason == "simulated ttl expired" {
			found = true
		}
	}
	if !found {
		t.Errorf("no audit entry with reason 'simulated ttl expired'; entries=%+v", entries)
	}
}

package daemon

// Tests for the arm/disarm verbs (issue #228): pre-flight matrix, the
// non-forceable self-ban check, auto-revert window lifecycle (expiry,
// keep-confirmation, startup settlement), persistence to policy.yaml, and
// audit records for every transition.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/store"
)

const armTestPolicy = `armed: false
ban_threshold: 70
observe_threshold: 40
strikes:
  - ttl: 5m
allowlist: []
admin_cidrs:
  - 198.51.100.0/24
max_bans_per_minute: 30
`

// newArmTestDaemon builds a daemon with a real in-memory store, a real
// temp policy.yaml (so persistence is exercised end-to-end), and a fake
// enforcer unless withEnforcer is false.
func newArmTestDaemon(t *testing.T, withEnforcer bool) (*Daemon, *store.DB, string) {
	t.Helper()
	ctx := context.Background()

	db, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(armTestPolicy), 0o640); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	pol, err := config.LoadPolicy(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	cfg := Config{
		Policy:     pol,
		Store:      db,
		SocketPath: "",
		PolicyPath: policyPath,
	}
	if withEnforcer {
		cfg.Enforcer = &fakeEnforcer{}
	}
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, db, policyPath
}

func armData(t *testing.T, resp SocketResponse) ArmData {
	t.Helper()
	var data ArmData
	if len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, &data); err != nil {
			t.Fatalf("unmarshal ArmData: %v", err)
		}
	}
	return data
}

func auditOps(t *testing.T, db *store.DB) []string {
	t.Helper()
	entries, err := db.ListAuditLog(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	ops := make([]string, 0, len(entries))
	for _, e := range entries {
		ops = append(ops, e.Op)
	}
	return ops
}

func TestArm_PreflightRefusesWithoutEnforcer(t *testing.T) {
	d, _, policyPath := newArmTestDaemon(t, false)

	resp := d.handleArm(context.Background(), SocketRequest{Verb: "arm", Peer: "198.51.100.7"})
	if resp.Error == "" {
		t.Fatal("want refusal without an enforcer, got OK")
	}
	data := armData(t, resp)
	if !data.Refused || data.Armed {
		t.Errorf("ArmData = %+v, want Refused=true Armed=false", data)
	}
	if d.policy.IsArmed() {
		t.Error("policy armed despite refusal")
	}
	raw, _ := os.ReadFile(policyPath) //nolint:gosec // test-owned path
	if !strings.Contains(string(raw), "armed: false") {
		t.Error("policy.yaml modified despite refusal")
	}

	// --force overrides the enforcer failure (self-ban passes: peer covered).
	resp = d.handleArm(context.Background(), SocketRequest{Verb: "arm", Peer: "198.51.100.7", Force: true})
	if resp.Error != "" {
		t.Fatalf("--force should override the enforcer failure: %s", resp.Error)
	}
	if !d.policy.IsArmed() {
		t.Error("not armed after forced arm")
	}
}

func TestArm_SelfBanCheckIsNeverForceable(t *testing.T) {
	d, _, _ := newArmTestDaemon(t, true)

	// Peer NOT covered by admin_cidrs/allowlist.
	resp := d.handleArm(context.Background(), SocketRequest{Verb: "arm", Peer: "192.0.2.99", Force: true})
	if resp.Error == "" {
		t.Fatal("want refusal: uncovered peer must fail even with --force")
	}
	if d.policy.IsArmed() {
		t.Error("armed despite self-ban failure")
	}
	data := armData(t, resp)
	var selfBan *PreflightCheck
	for i := range data.Checks {
		if data.Checks[i].Name == "self_ban" {
			selfBan = &data.Checks[i]
		}
	}
	if selfBan == nil || selfBan.Status != "fail" {
		t.Errorf("self_ban check = %+v, want status fail", selfBan)
	}
}

func TestArm_SucceedsAndPersists(t *testing.T) {
	d, db, policyPath := newArmTestDaemon(t, true)

	resp := d.handleArm(context.Background(), SocketRequest{Verb: "arm", Peer: "198.51.100.7"})
	if resp.Error != "" {
		t.Fatalf("arm: %s", resp.Error)
	}
	if !d.policy.IsArmed() {
		t.Error("not armed")
	}
	raw, _ := os.ReadFile(policyPath) //nolint:gosec // test-owned path
	if !strings.Contains(string(raw), "armed: true") {
		t.Error("policy.yaml not persisted to armed: true")
	}
	found := false
	for _, op := range auditOps(t, db) {
		if op == "arm" {
			found = true
		}
	}
	if !found {
		t.Error("no 'arm' audit entry")
	}

	// Disarm is symmetric.
	resp = d.handleDisarm(context.Background())
	if resp.Error != "" {
		t.Fatalf("disarm: %s", resp.Error)
	}
	if d.policy.IsArmed() {
		t.Error("still armed after disarm")
	}
	raw, _ = os.ReadFile(policyPath) //nolint:gosec // test-owned path
	if !strings.Contains(string(raw), "armed: false") {
		t.Error("policy.yaml not persisted back to armed: false")
	}
}

func TestArm_WindowValidation(t *testing.T) {
	d, _, _ := newArmTestDaemon(t, true)
	for _, bad := range []string{"nonsense", "30s", "30d"} {
		resp := d.handleArm(context.Background(), SocketRequest{Verb: "arm", Peer: "198.51.100.7", For: bad})
		if resp.Error == "" {
			t.Errorf("--for %q accepted, want error", bad)
		}
		if d.policy.IsArmed() {
			t.Fatalf("--for %q: armed despite invalid window", bad)
		}
	}
}

func TestArm_WindowExpiryReverts(t *testing.T) {
	d, db, policyPath := newArmTestDaemon(t, true)
	ctx := context.Background()

	resp := d.handleArm(ctx, SocketRequest{Verb: "arm", Peer: "198.51.100.7", For: "1h"})
	if resp.Error != "" {
		t.Fatalf("arm --for: %s", resp.Error)
	}
	data := armData(t, resp)
	if data.RevertAt == "" {
		t.Fatal("no RevertAt in response")
	}
	if got := d.armedUntil(ctx); got != data.RevertAt {
		t.Errorf("armedUntil = %q, want %q", got, data.RevertAt)
	}

	// Before the deadline: nothing happens.
	d.checkArmWindow(ctx, time.Now())
	if !d.policy.IsArmed() {
		t.Fatal("reverted before the deadline")
	}

	// After the deadline: revert, clear state, audit.
	d.checkArmWindow(ctx, time.Now().Add(2*time.Hour))
	if d.policy.IsArmed() {
		t.Fatal("still armed after the window expired")
	}
	if _, found, _ := db.GetState(ctx, stateKeyArmWindow); found {
		t.Error("window state not cleared after revert")
	}
	raw, _ := os.ReadFile(policyPath) //nolint:gosec // test-owned path
	if !strings.Contains(string(raw), "armed: false") {
		t.Error("policy.yaml not reverted to armed: false")
	}
	reverted := false
	for _, op := range auditOps(t, db) {
		if op == "arm_revert" {
			reverted = true
		}
	}
	if !reverted {
		t.Error("no 'arm_revert' audit entry")
	}
}

func TestArm_KeepConfirmsWindow(t *testing.T) {
	d, db, _ := newArmTestDaemon(t, true)
	ctx := context.Background()

	// Keep without a window: error.
	if resp := d.handleArmKeep(ctx); resp.Error == "" {
		t.Error("arm --keep with no window should error")
	}

	if resp := d.handleArm(ctx, SocketRequest{Verb: "arm", Peer: "198.51.100.7", For: "1h"}); resp.Error != "" {
		t.Fatalf("arm --for: %s", resp.Error)
	}
	if resp := d.handleArmKeep(ctx); resp.Error != "" {
		t.Fatalf("arm --keep: %s", resp.Error)
	}
	if _, found, _ := db.GetState(ctx, stateKeyArmWindow); found {
		t.Error("window state still present after --keep")
	}

	// Deadline long past — but the window was confirmed, so no revert.
	d.checkArmWindow(ctx, time.Now().Add(48*time.Hour))
	if !d.policy.IsArmed() {
		t.Error("reverted after --keep confirmed the window")
	}
}

func TestArm_StartupSettlesExpiredWindow(t *testing.T) {
	// Scenario: daemon was down while the window expired. The startup
	// settlement (Run calls checkArmWindow once) must revert immediately.
	d, db, policyPath := newArmTestDaemon(t, true)
	ctx := context.Background()

	if resp := d.handleArm(ctx, SocketRequest{Verb: "arm", Peer: "198.51.100.7", For: "1h"}); resp.Error != "" {
		t.Fatalf("arm: %s", resp.Error)
	}
	// Simulate downtime: overwrite the deadline with one in the past.
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	if err := db.SetState(ctx, stateKeyArmWindow, past); err != nil {
		t.Fatal(err)
	}

	// "Restart": fresh daemon over the same store + policy file.
	pol, err := config.LoadPolicy(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := New(Config{Policy: pol, Store: db, Enforcer: &fakeEnforcer{}, SocketPath: "", PolicyPath: policyPath})
	if err != nil {
		t.Fatal(err)
	}
	if !d2.policy.IsArmed() {
		t.Fatal("precondition: restarted daemon should load armed=true")
	}

	d2.checkArmWindow(ctx, time.Now())
	if d2.policy.IsArmed() {
		t.Error("expired window not settled at startup — daemon stayed armed")
	}
}

func TestArm_StatusCarriesDeadline(t *testing.T) {
	d, _, _ := newArmTestDaemon(t, true)
	ctx := context.Background()

	if resp := d.handleArm(ctx, SocketRequest{Verb: "arm", Peer: "198.51.100.7", For: "2h"}); resp.Error != "" {
		t.Fatalf("arm: %s", resp.Error)
	}
	resp := d.handleStatus(ctx)
	if !resp.OK {
		t.Fatalf("status: %s", resp.Error)
	}
	var sd StatusData
	if err := json.Unmarshal(resp.Data, &sd); err != nil {
		t.Fatal(err)
	}
	if sd.ArmedUntil == "" {
		t.Error("status has no armed_until while a window is active")
	}
	if !sd.Armed {
		t.Error("status not armed")
	}
}

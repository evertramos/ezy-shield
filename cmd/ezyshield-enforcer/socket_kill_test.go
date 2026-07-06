package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// mockSsCalls records the args the ssRunner is invoked with. Optional errStub
// lets a test simulate ss failure without pulling in a real binary.
type mockSsCalls struct {
	calls   [][]string
	errStub error
}

func (m *mockSsCalls) runner() ssRunner {
	return func(_ context.Context, args []string) error {
		// copy to defeat aliasing by callers that reuse a slice
		cp := make([]string, len(args))
		copy(cp, args)
		m.calls = append(m.calls, cp)
		return m.errStub
	}
}

// TestKillSocketsForIP_v4 asserts the ssRunner is invoked with exactly
// `-K dst <ip>` for an IPv4 target.
func TestKillSocketsForIP_v4(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", "1.2.3.4"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_v6 asserts the ssRunner is invoked with `-K dst <ip>/128`
// for an IPv6 target (issue #38): a bare v6 address makes ss misparse the last
// hextet as a port ("does not look like a port" / "an inet prefix is expected"),
// so we always send the /128 prefix form which is unambiguous and doubles as
// an explicit host-scope indicator when someone eyeballs `ps auxf`.
func TestKillSocketsForIP_v6(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "2001:db8::1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", "2001:db8::1/128"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_v6Full asserts the /128 prefix form is applied to the
// full-form address that was seen failing on the live host in issue #38
// (2804:...:9753 — every hextet present, last one previously misparsed as a
// port).
func TestKillSocketsForIP_v6Full(t *testing.T) {
	mock := &mockSsCalls{}
	const addr = "2001:db8:2ab:15c0:f499:c95a:6962:9753"
	if err := killSocketsForIP(context.Background(), mock.runner(), addr); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", addr + "/128"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_v4MappedV6 asserts that an IPv4-mapped IPv6 address
// (::ffff:1.2.3.4) is passed to ss as bare-v4. Rationale: the v4 form is
// what ss's routing/socket table actually stores for these connections
// (kernel presents IPv4 connections through v6-mapped listeners as v4 in
// diag), so unmapping avoids surprising the parser and keeps the ban path
// identical to the pure-v4 case.
func TestKillSocketsForIP_v4MappedV6(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "::ffff:1.2.3.4"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
	want := []string{"-K", "dst", "1.2.3.4"}
	if !reflect.DeepEqual(mock.calls[0], want) {
		t.Errorf("ss args: got %v, want %v", mock.calls[0], want)
	}
}

// TestKillSocketsForIP_Invalid verifies that a non-parseable address is not
// passed to ss at all — we short-circuit and return nil so the nft ban stands.
func TestKillSocketsForIP_Invalid(t *testing.T) {
	mock := &mockSsCalls{}
	if err := killSocketsForIP(context.Background(), mock.runner(), "not-an-ip"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mock.calls) != 0 {
		t.Fatalf("expected zero ss calls for invalid input, got %d", len(mock.calls))
	}
}

// TestKillSocketsForIP_BestEffort verifies the best-effort semantics from
// Hard Rule §1: a failing ss call must NOT propagate an error that could
// roll back a successful nft ban.
func TestKillSocketsForIP_BestEffort(t *testing.T) {
	mock := &mockSsCalls{errStub: errors.New("ss: exit 1: not permitted")}
	if err := killSocketsForIP(context.Background(), mock.runner(), "1.2.3.4"); err != nil {
		t.Errorf("killSocketsForIP must swallow ss errors, got: %v", err)
	}
	if len(mock.calls) != 1 {
		t.Fatalf("expected exactly 1 ss call, got %d", len(mock.calls))
	}
}

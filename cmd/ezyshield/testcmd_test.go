package main

import (
	"bytes"
	"strings"
	"testing"
)

// execRoot runs the full root command with args and returns stdout, stderr,
// and the Execute error — the same path a real invocation takes.
// Tests using it must NOT call t.Parallel(): newRootCmd binds the package
// global jsonOutput, so concurrent constructions race on it.
func execRoot(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func TestLookupComponentTest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		kind    string
		comp    string
		wantErr string // empty = expect success
	}{
		{"known enforcer", "enforcer", "cloudflare", ""},
		{"known enforcer all", "enforcer", "all", ""},
		{"known notifier", "notifier", "telegram", ""},
		{"unknown kind", "collector", "sshd", `unknown component kind "collector"`},
		{"unknown enforcer name", "enforcer", "akamai", `unknown enforcer "akamai"`},
		{"unknown notifier name", "notifier", "sms", `unknown notifier "sms"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			run, err := lookupComponentTest(tt.kind, tt.comp)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if run == nil {
					t.Fatal("resolved test func is nil")
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "available:") {
				t.Errorf("error should list available names, got %q", err)
			}
		})
	}
}

// TestTestGroup_UnknownNameListsAvailable drives the real command tree:
// a typo'd name must fail with the registry's "available:" listing before
// any config is read or network touched.
func TestTestGroup_UnknownNameListsAvailable(t *testing.T) {
	_, _, err := execRoot(t, "test", "enforcer", "bogus")
	if err == nil {
		t.Fatal("expected error for unknown enforcer name")
	}
	for _, want := range []string{`unknown enforcer "bogus"`, "all", "cloudflare", "nftables"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// TestTestEnforcer_RoutesToEnforceFlow proves `test enforcer <name>` reaches
// the same flow test-enforce ran: with no cloudflare block configured it
// reports "No cloudflare enforcer configured" and exits cleanly.
func TestTestEnforcer_RoutesToEnforceFlow(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", validConfig)

	out, _, err := execRoot(t, "test", "enforcer", "cloudflare", "--config-dir", dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "No cloudflare enforcer configured") {
		t.Errorf("output = %q, want the enforce flow's 'No cloudflare enforcer configured' message", out)
	}
}

// TestTestNotifier_RoutesToNotifyFlow proves `test notifier <name>` reaches
// the same flow test-notify ran: with no notify: section it fails with that
// flow's specific error.
func TestTestNotifier_RoutesToNotifyFlow(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", validConfig)

	_, _, err := execRoot(t, "test", "notifier", "telegram", "--config-dir", dir)
	if err == nil {
		t.Fatal("expected error for missing notify section")
	}
	if !strings.Contains(err.Error(), "no notify section") {
		t.Errorf("error = %q, want the notify flow's 'no notify section' message", err)
	}
}

// TestDeprecatedAliases_DelegateAndWarn covers the migration contract:
// the old verbs still work (same underlying flow), print exactly one
// deprecation line on stderr naming the new verb, and stay hidden from help.
func TestDeprecatedAliases_DelegateAndWarn(t *testing.T) {
	tests := []struct {
		alias      string
		kind       string
		arg        string
		wantOut    string // substring of stdout on success paths
		wantErrMsg string // substring of the returned error, if any
	}{
		{alias: "test-enforce", kind: "enforcer", arg: "cloudflare",
			wantOut: "No cloudflare enforcer configured"},
		{alias: "test-notify", kind: "notifier", arg: "telegram",
			wantErrMsg: "no notify section"},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			dir := t.TempDir()
			writeFile(t, dir, "config.yaml", validConfig)

			out, errOut, err := execRoot(t, tt.alias, tt.arg, "--config-dir", dir)

			wantNotice := "use 'ezyshield test " + tt.kind + " " + tt.arg + "' instead"
			if !strings.Contains(errOut, "deprecated") || !strings.Contains(errOut, wantNotice) {
				t.Errorf("stderr = %q, want deprecation notice containing %q", errOut, wantNotice)
			}
			if n := strings.Count(errOut, "deprecated"); n != 1 {
				t.Errorf("deprecation notice printed %d times, want exactly 1", n)
			}
			if tt.wantOut != "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.Contains(out, tt.wantOut) {
					t.Errorf("stdout = %q, want it to contain %q", out, tt.wantOut)
				}
			}
			if tt.wantErrMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Errorf("error = %v, want it to contain %q", err, tt.wantErrMsg)
				}
			}
		})
	}
}

func TestDeprecatedAliases_Hidden(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"test-enforce", "test-notify"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil || cmd == nil || cmd.Name() != name {
			t.Fatalf("alias %q not registered: %v", name, err)
		}
		if !cmd.Hidden {
			t.Errorf("alias %q must be hidden from help", name)
		}
	}
	// The new group itself must be visible.
	cmd, _, err := root.Find([]string{"test"})
	if err != nil || cmd.Name() != "test" {
		t.Fatalf("test group not registered: %v", err)
	}
	if cmd.Hidden {
		t.Error("test group must be visible in help")
	}
}

// TestDeprecationNotice_DerivesProgramName guards the "never hardcode the
// program name" rule: renaming the root (future `ezy shield`) must rename
// the program in the migration notice too.
func TestDeprecationNotice_DerivesProgramName(t *testing.T) {
	root := newRootCmd()
	root.Use = "ezy"

	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"test-enforce", "bogus"})
	_ = root.Execute() // fails on unknown backend; only the notice matters here

	if !strings.Contains(errOut.String(), "use 'ezy test enforcer bogus' instead") {
		t.Errorf("stderr = %q, want notice derived from the root command name", errOut.String())
	}
	if strings.Contains(errOut.String(), "ezyshield") {
		t.Errorf("stderr = %q, must not hardcode 'ezyshield'", errOut.String())
	}
}

// TestTestKindHelp_ListsRegistryNames keeps help text in sync with the
// registry: names shown to the operator are derived, never hardcoded.
func TestTestKindHelp_ListsRegistryNames(t *testing.T) {
	out, _, err := execRoot(t, "test", "enforcer", "--help")
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !strings.Contains(out, "Available names: all, cloudflare, nftables") {
		t.Errorf("enforcer help missing derived name list:\n%s", out)
	}

	out, _, err = execRoot(t, "test", "notifier", "--help")
	if err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !strings.Contains(out, "Available names: all, email, telegram") {
		t.Errorf("notifier help missing derived name list:\n%s", out)
	}
}

// TestBuildTestNotification_SourceDerived: the synthetic alert body names the
// command that produced it, derived from the actual invocation path.
func TestBuildTestNotification_SourceDerived(t *testing.T) {
	t.Parallel()
	msg := buildTestNotification("ezy test notifier")
	if !strings.Contains(msg.Body, "'ezy test notifier'") {
		t.Errorf("body = %q, want it to contain the derived source", msg.Body)
	}
	if msg.Action == nil || msg.Action.IP.String() != "192.0.2.1" {
		t.Errorf("test notification must keep the RFC 5737 TEST-NET-1 address")
	}
}

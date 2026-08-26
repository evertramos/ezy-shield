// SPDX-License-Identifier: AGPL-3.0-only

package parser_test

// Regression tests for issue #358 item 4: Docker json-file unwrapping was
// applied by the three HTTP parsers but not by ssh and apache-error — an sshd
// or Apache running in a container reached those parsers still wrapped in
// {"log":"...","stream":"..."} and every line silently missed the regexes.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/evertramos/ezy-shield/internal/parser"
	"github.com/evertramos/ezy-shield/pkg/sdk"
)

// dockerWrap wraps a raw log line the way Docker's json-file driver does.
func dockerWrap(t *testing.T, line string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{
		"log":    line + "\n",
		"stream": "stdout",
		"time":   "2026-08-25T12:00:00.000000000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSSHParser_UnwrapsDockerJSONFile(t *testing.T) {
	t.Parallel()
	p := parser.NewSSHParser(discardLogger())
	const inner = "Aug 25 12:00:00 host sshd[123]: Failed password for root from 192.0.2.66 port 4242 ssh2"

	evs, err := p.Parse(sdk.RawLine{
		Source: "docker:sshd-container",
		Line:   dockerWrap(t, inner),
		At:     time.Now(),
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("wrapped sshd line produced %d events, want 1 (docker json-file not unwrapped)", len(evs))
	}
	if got := evs[0].SourceIP.String(); got != "192.0.2.66" {
		t.Errorf("event IP = %s, want 192.0.2.66", got)
	}
}

func TestApacheErrorParser_UnwrapsDockerJSONFile(t *testing.T) {
	t.Parallel()
	p := parser.NewApacheErrorParser(discardLogger())
	const inner = "[Mon Aug 25 12:00:00.123456 2026] [auth_basic:error] [pid 123] [client 192.0.2.67:4242] AH01617: user admin: authentication failure for \"/admin\": Password Mismatch"

	evs, err := p.Parse(sdk.RawLine{
		Source: "apache-error:web-container",
		Line:   dockerWrap(t, inner),
		At:     time.Now(),
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("wrapped apache-error line produced %d events, want 1 (docker json-file not unwrapped)", len(evs))
	}
	if got := evs[0].SourceIP.String(); got != "192.0.2.67" {
		t.Errorf("event IP = %s, want 192.0.2.67", got)
	}
}

package daemon

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeFakeJournalctl writes a shell script standing in for journalctl. It
// verifies the unit argument (argv position from evidenceFromJournald: -u
// <unit> ...) and prints body to stdout. Returns the script path.
func writeFakeJournalctl(t *testing.T, wantUnit, body string) string {
	t.Helper()
	script := "#!/bin/sh\n" +
		"[ \"$2\" = \"" + wantUnit + "\" ] || { echo \"unexpected unit: $2\" >&2; exit 9; }\n" +
		"cat <<'EOF'\n" + body + "EOF\n"
	path := filepath.Join(t.TempDir(), "journalctl")
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { //nolint:gosec // test-only script
		t.Fatalf("write fake journalctl: %v", err)
	}
	return path
}

func TestEvidenceFromJournald_Match(t *testing.T) {
	body := "2026-07-13T10:00:01+0000 host sshd[7]: Failed password for root from 203.0.113.7 port 51544 ssh2\n" +
		"2026-07-13T10:00:02+0000 host sshd[7]: Accepted password for admin from 198.51.100.9 port 2222 ssh2\n" +
		"2026-07-13T10:00:03+0000 host sshd[7]: near miss from 1203.0.113.7 here\n" +
		"2026-07-13T10:00:04+0000 host sshd[7]: Connection closed by 203.0.113.7 port 51544\n"
	bin := writeFakeJournalctl(t, "sshd", body)

	ev := evidenceFromJournald(context.Background(), bin, "sshd", netip.MustParseAddr("203.0.113.7"))
	if ev.Source != "journald:sshd" {
		t.Errorf("source: got %q, want journald:sshd", ev.Source)
	}
	if len(ev.Lines) != 2 {
		t.Fatalf("want 2 matching lines, got %d: %q", len(ev.Lines), ev.Lines)
	}
	if !strings.Contains(ev.Lines[0], "Failed password") || !strings.Contains(ev.Lines[1], "Connection closed") {
		t.Errorf("wrong lines extracted: %q", ev.Lines)
	}
	if ev.Note != "" || ev.Truncated {
		t.Errorf("clean extraction: want no note/truncation, got %+v", ev)
	}
}

func TestEvidenceFromJournald_CommandFails(t *testing.T) {
	// The fake exits 9 for any unit other than "sshd".
	bin := writeFakeJournalctl(t, "sshd", "")

	ev := evidenceFromJournald(context.Background(), bin, "nginx", netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(ev.Note, "journalctl failed") {
		t.Errorf("want failure note, got %+v", ev)
	}
	if len(ev.Lines) != 0 {
		t.Errorf("failed run must not carry lines: %+v", ev)
	}
}

func TestEvidenceFromJournald_BinaryMissing(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "no-such-journalctl")

	ev := evidenceFromJournald(context.Background(), bin, "sshd", netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(ev.Note, "journalctl unavailable") {
		t.Errorf("want unavailable note, got %+v", ev)
	}
}

func TestEvidenceFromJournald_InvalidUnitSkipped(t *testing.T) {
	// A hostile unit name must be rejected before any exec: the bin path
	// points at a missing binary, so reaching exec would produce a
	// different note than the validation one.
	bin := filepath.Join(t.TempDir(), "no-such-journalctl")

	for _, unit := range []string{"", "unit name", "unit;rm -rf /", "unit\x00evil", "$(reboot)"} {
		ev := evidenceFromJournald(context.Background(), bin, unit, netip.MustParseAddr("203.0.113.7"))
		if ev.Note != "invalid unit name; skipped" {
			t.Errorf("unit %q: want validation note, got %+v", unit, ev)
		}
	}
}

// dockerEvidenceFrame encodes one Docker multiplexed-stream frame.
func dockerEvidenceFrame(streamType byte, payload string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = streamType
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload))) //nolint:gosec // test payload, never overflows
	return append(hdr, payload...)
}

// startEvidenceDockerAPI serves GET /containers/<name>/logs on a unix socket
// with the given status and body, recording the request URL. Unlike the
// collector's mock it completes the response (no follow semantics).
func startEvidenceDockerAPI(t *testing.T, status int, body []byte) (sockPath string, gotURL *string) {
	t.Helper()
	sockPath = filepath.Join(t.TempDir(), "docker.sock")
	gotURL = new(string)

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", sockPath)
	if err != nil {
		t.Fatalf("listen mock docker socket: %v", err)
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*gotURL = r.URL.String()
			w.WriteHeader(status)
			_, _ = w.Write(body)
		}),
		ReadHeaderTimeout: 2 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})
	return sockPath, gotURL
}

func TestEvidenceFromDocker_Match(t *testing.T) {
	payload := append(
		dockerEvidenceFrame(1, "2026-07-13T10:00:01Z 203.0.113.7 - - \"GET /wp-login.php\" 404\r\n"),
		dockerEvidenceFrame(2, "2026-07-13T10:00:02Z 198.51.100.9 - - \"GET /\" 200\n2026-07-13T10:00:03Z error from 203.0.113.7 upstream\n")...,
	)
	sock, gotURL := startEvidenceDockerAPI(t, http.StatusOK, payload)

	ev := evidenceFromDocker(context.Background(), sock, "web", netip.MustParseAddr("203.0.113.7"))
	if ev.Source != "docker:web" {
		t.Errorf("source: got %q, want docker:web", ev.Source)
	}
	if len(ev.Lines) != 2 {
		t.Fatalf("want 2 matching lines, got %d: %q (note %q)", len(ev.Lines), ev.Lines, ev.Note)
	}
	if strings.HasSuffix(ev.Lines[0], "\r") {
		t.Errorf("CR must be stripped: %q", ev.Lines[0])
	}
	if ev.Note != "" {
		t.Errorf("clean extraction: want no note, got %q", ev.Note)
	}
	if !strings.HasPrefix(*gotURL, "/containers/web/logs?") ||
		!strings.Contains(*gotURL, "tail=") || !strings.Contains(*gotURL, "timestamps=true") ||
		strings.Contains(*gotURL, "follow") {
		t.Errorf("unexpected request URL: %q", *gotURL)
	}
}

func TestEvidenceFromDocker_ContainerNotFound(t *testing.T) {
	sock, _ := startEvidenceDockerAPI(t, http.StatusNotFound, []byte(`{"message":"No such container"}`))

	ev := evidenceFromDocker(context.Background(), sock, "gone", netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(ev.Note, "container not found") {
		t.Errorf("want not-found note, got %+v", ev)
	}
	if strings.Contains(ev.Note, "No such container") {
		t.Errorf("response body must not leak into the note: %q", ev.Note)
	}
}

func TestEvidenceFromDocker_SocketUnreachable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "no-such.sock")

	ev := evidenceFromDocker(context.Background(), sock, "web", netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(ev.Note, "socket unreachable") {
		t.Errorf("want unreachable note, got %+v", ev)
	}
}

func TestEvidenceFromDocker_FrameCapRejected(t *testing.T) {
	// Header advertising an 8 MiB frame with no payload: the demuxer must
	// reject it instead of allocating attacker-chosen memory.
	hdr := make([]byte, 8)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[4:8], 8*1024*1024)
	sock, _ := startEvidenceDockerAPI(t, http.StatusOK, hdr)

	ev := evidenceFromDocker(context.Background(), sock, "web", netip.MustParseAddr("203.0.113.7"))
	if !strings.Contains(ev.Note, "log stream error") {
		t.Errorf("want stream-error note, got %+v", ev)
	}
	if len(ev.Lines) != 0 {
		t.Errorf("no lines expected, got %q", ev.Lines)
	}
}

func TestEvidenceFromDocker_InvalidNameSkipped(t *testing.T) {
	// Validation must run before any request: point at a live server and
	// assert it was never hit.
	sock, gotURL := startEvidenceDockerAPI(t, http.StatusOK, nil)

	for _, name := range []string{"", "web app", "web/../etc", "web;rm", "-web"} {
		ev := evidenceFromDocker(context.Background(), sock, name, netip.MustParseAddr("203.0.113.7"))
		if ev.Note != "invalid container name; skipped" {
			t.Errorf("container %q: want validation note, got %+v", name, ev)
		}
	}
	if *gotURL != "" {
		t.Errorf("no request expected for invalid names, server saw %q", *gotURL)
	}
}

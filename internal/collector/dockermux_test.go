package collector_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/evertramos/ezy-shield/internal/collector"
)

// muxFrame encodes one Docker multiplexed-stream frame.
func muxFrame(streamType byte, payload string) []byte {
	hdr := make([]byte, 8)
	hdr[0] = streamType
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload))) //nolint:gosec // test payload, never overflows
	return append(hdr, payload...)
}

func TestDemuxDockerLogStream_ReassemblyAndCRStrip(t *testing.T) {
	// One line split across two frames, one CRLF line, one zero-size frame,
	// one trailing partial line (dropped at EOF).
	var stream []byte
	stream = append(stream, muxFrame(1, "first ha")...)
	stream = append(stream, muxFrame(2, "lf\nsecond\r\n")...)
	stream = append(stream, muxFrame(1, "")...)
	stream = append(stream, muxFrame(1, "partial-no-newline")...)

	var got []string
	err := collector.DemuxDockerLogStream(context.Background(), bytes.NewReader(stream), func(line []byte) bool {
		got = append(got, string(line))
		return false
	})
	if err != nil {
		t.Fatalf("demux error: %v", err)
	}
	want := []string{"first half", "second"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("lines: got %q, want %q", got, want)
	}
}

func TestDemuxDockerLogStream_StopEarly(t *testing.T) {
	stream := muxFrame(1, "one\ntwo\nthree\n")

	var got []string
	err := collector.DemuxDockerLogStream(context.Background(), bytes.NewReader(stream), func(line []byte) bool {
		got = append(got, string(line))
		return len(got) == 2 // stop after the second line
	})
	if err != nil {
		t.Fatalf("demux error: %v", err)
	}
	if len(got) != 2 || got[1] != "two" {
		t.Errorf("stop contract violated: got %q", got)
	}
}

func TestDemuxDockerLogStream_FrameCap(t *testing.T) {
	hdr := make([]byte, 8)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[4:8], 8*1024*1024) // 8 MiB > 1 MiB cap

	err := collector.DemuxDockerLogStream(context.Background(), bytes.NewReader(hdr), func([]byte) bool {
		t.Error("no line must be emitted for an oversized frame")
		return true
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Errorf("want frame-cap error, got %v", err)
	}
}

func TestDemuxDockerLogStream_TruncatedPayload(t *testing.T) {
	// Header promises 100 bytes; only 3 arrive.
	hdr := make([]byte, 8)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[4:8], 100)
	stream := append(hdr, []byte("abc")...)

	err := collector.DemuxDockerLogStream(context.Background(), bytes.NewReader(stream), func([]byte) bool { return false })
	if err == nil || !strings.Contains(err.Error(), "read payload") {
		t.Errorf("want payload read error, got %v", err)
	}
}

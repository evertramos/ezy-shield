package collector

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Regression tests for issue #306: a single oversized log line must never
// stop collection (bufio.Scanner died permanently at its 64 KiB token cap).

type collectedLine struct {
	text      string
	truncated bool
}

func collectAll(t *testing.T, input string, maxLine int) ([]collectedLine, error) {
	t.Helper()
	var got []collectedLine
	err := forEachLine(strings.NewReader(input), maxLine, func(line []byte, truncated bool) {
		got = append(got, collectedLine{text: string(line), truncated: truncated})
	})
	return got, err
}

func TestForEachLine(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("A", 300*1024) // 300 KiB, far past any cap

	tests := []struct {
		name    string
		input   string
		maxLine int
		want    []collectedLine
	}{
		{
			name:    "plain lines",
			input:   "one\ntwo\nthree\n",
			maxLine: 64,
			want:    []collectedLine{{"one", false}, {"two", false}, {"three", false}},
		},
		{
			name:    "CRLF endings are trimmed",
			input:   "one\r\ntwo\r\n",
			maxLine: 64,
			want:    []collectedLine{{"one", false}, {"two", false}},
		},
		{
			name:    "trailing line without newline is delivered",
			input:   "one\npartial",
			maxLine: 64,
			want:    []collectedLine{{"one", false}, {"partial", false}},
		},
		{
			name:    "oversized line is truncated and the stream continues",
			input:   "before\n" + huge + "\nafter\n",
			maxLine: 16,
			want: []collectedLine{
				{"before", false},
				{"AAAAAAAAAAAAAAAA", true},
				{"after", false},
			},
		},
		{
			name:    "line exactly at the cap is not marked truncated",
			input:   strings.Repeat("B", 16) + "\nnext\n",
			maxLine: 16,
			// The cap check runs before the newline is trimmed, so a line of
			// exactly maxLine bytes plus its newline overflows by the \n only;
			// the delivered content is complete.
			want: []collectedLine{{strings.Repeat("B", 16), true}, {"next", false}},
		},
		{
			name:    "empty input",
			input:   "",
			maxLine: 16,
			want:    nil,
		},
		{
			name:    "binary bytes pass through",
			input:   "a\x00b\x1b[31m\n",
			maxLine: 64,
			want:    []collectedLine{{"a\x00b\x1b[31m", false}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := collectAll(t, tt.input, tt.maxLine)
			if err != nil {
				t.Fatalf("forEachLine error: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("lines = %d, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("line %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// errAfterReader yields its payload, then a non-EOF error.
type errAfterReader struct {
	r   io.Reader
	err error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) {
		return n, e.err
	}
	return n, err
}

func TestForEachLine_ReadErrorFlushesPartialAndSurfaces(t *testing.T) {
	t.Parallel()
	boom := errors.New("pipe broke")
	var got []collectedLine
	err := forEachLine(&errAfterReader{r: strings.NewReader("done\npartial"), err: boom},
		64, func(line []byte, truncated bool) {
			got = append(got, collectedLine{string(line), truncated})
		})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the underlying read error", err)
	}
	if len(got) != 2 || got[0].text != "done" || got[1].text != "partial" {
		t.Errorf("lines = %+v, want done + flushed partial", got)
	}
}

// TestLineAssembler covers the capped cross-chunk reassembly used by the
// docker demux and filetail (issue #307).
func TestLineAssembler(t *testing.T) {
	t.Parallel()

	t.Run("late newline after a capped flood does not glue lines", func(t *testing.T) {
		t.Parallel()
		a := newLineAssembler(8)
		var got []string
		emit := func(line []byte) bool {
			got = append(got, string(line))
			return false
		}
		a.feed([]byte("AAAAAAAAAA"), emit) // 10 bytes, no newline: buffered capped at 8
		a.feed([]byte("BBBB"), emit)       // still past cap: dropped
		a.feed([]byte("\nok\n"), emit)     // newline ends the flood; next line intact
		if len(got) != 2 || got[0] != "AAAAAAAA" || got[1] != "ok" {
			t.Fatalf("lines = %v, want capped flood then ok", got)
		}
	})

	t.Run("buffer never exceeds the cap while fed newline-free chunks", func(t *testing.T) {
		t.Parallel()
		a := newLineAssembler(16)
		for i := 0; i < 1000; i++ {
			a.feed([]byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"), func([]byte) bool { return false })
		}
		if len(a.line) > 16 {
			t.Fatalf("assembler buffer grew to %d bytes despite cap 16", len(a.line))
		}
	})

	t.Run("stop from emit propagates", func(t *testing.T) {
		t.Parallel()
		a := newLineAssembler(64)
		calls := 0
		stopped := a.feed([]byte("one\ntwo\n"), func([]byte) bool { calls++; return true })
		if !stopped || calls != 1 {
			t.Fatalf("stopped=%v calls=%d, want stop after first line", stopped, calls)
		}
	})

	t.Run("discard drops a buffered partial line", func(t *testing.T) {
		t.Parallel()
		a := newLineAssembler(64)
		a.feed([]byte("old-file-fragment"), func([]byte) bool { return false })
		a.discard()
		var got []string
		a.feed([]byte("fresh\n"), func(line []byte) bool { got = append(got, string(line)); return false })
		if len(got) != 1 || got[0] != "fresh" {
			t.Fatalf("lines = %v, want only the fresh line", got)
		}
	})

	t.Run("CRLF stripped", func(t *testing.T) {
		t.Parallel()
		a := newLineAssembler(64)
		var got []string
		a.feed([]byte("win\r\n"), func(line []byte) bool { got = append(got, string(line)); return false })
		if len(got) != 1 || got[0] != "win" {
			t.Fatalf("lines = %v, want CR-stripped line", got)
		}
	})
}

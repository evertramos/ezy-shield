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

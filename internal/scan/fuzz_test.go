package scan

import (
	"context"
	"strings"
	"testing"
)

// FuzzParseProcNetTCP guards panic-safety of the /proc/net/tcp[6] parser on
// hostile bytes — the equivalent parser in internal/decision has had
// FuzzProcTCPPeers since #331, this one had none (issue #361). Same input
// format, same seed classes: malformed, oversized, binary, ANSI, CRLF.
func FuzzParseProcNetTCP(f *testing.F) {
	f.Add("   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0", "tcp")
	f.Add("   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  0        0 999 1", "tcp6")
	f.Add("sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", "tcp")
	f.Add("garbage line with too few fields", "tcp")
	f.Add("   0: ZZZZZZZZ:GGGG 00000000:0000 0A 0:0 00:0 0  notanuid        0 1 1", "tcp")
	f.Add(strings.Repeat("A", 8192)+":0016 "+strings.Repeat("F", 8192)+":0000 0A x x x x notanuid x inode", "tcp6")
	f.Add("\x1b[31m   0: 0100007F:0016 00000000:0000 0A\x1b[0m 0:0 0:0 0 1000 0 1 1", "tcp")
	f.Add("line one\r\n   0: 0100007F:0016 00000000:0000 0A 0:0 0:0 0 1000 0 1 1\r\n\x00\xff", "tcp")
	f.Add("\x00\xfe\xff binary noise", "tcp6")
	f.Fuzz(func(t *testing.T, input, proto string) {
		if proto != "tcp6" {
			proto = "tcp"
		}
		_, _ = parseProcNetTCP(context.Background(), strings.NewReader(input), proto)
	})
}

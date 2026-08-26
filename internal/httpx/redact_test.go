// SPDX-License-Identifier: AGPL-3.0-only

package httpx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
)

func urlErr(op, rawURL string, cause error) *url.Error {
	return &url.Error{Op: op, URL: rawURL, Err: cause}
}

func TestRedactTransportErr_KeepHost(t *testing.T) {
	t.Parallel()
	cause := errors.New("dial tcp: connection refused")
	err := RedactTransportErr(
		urlErr("Get", "https://api.example.com/bot123456:SECRET-TOKEN/sendMessage?chat_id=1", cause), true)

	msg := err.Error()
	if strings.Contains(msg, "SECRET-TOKEN") || strings.Contains(msg, "chat_id") {
		t.Fatalf("secret path/query leaked: %q", msg)
	}
	if !strings.Contains(msg, "https://api.example.com/[redacted]") {
		t.Errorf("keepHost must preserve scheme+host: %q", msg)
	}
	if !errors.Is(err, cause) {
		t.Error("keepHost must preserve the errors.Is chain to the transport cause")
	}
}

func TestRedactTransportErr_DropHost(t *testing.T) {
	t.Parallel()
	cause := &net.DNSError{Name: "secret-internal-host.corp", IsNotFound: true}
	err := RedactTransportErr(
		urlErr("Post", "https://secret-internal-host.corp/hook/capability", cause), false)

	msg := err.Error()
	if strings.Contains(msg, "secret-internal-host") || strings.Contains(msg, "capability") {
		t.Fatalf("secret host leaked with keepHost=false: %q", msg)
	}
	if !strings.Contains(msg, "no such host") {
		t.Errorf("cause must collapse to its fixed classification: %q", msg)
	}
	if errors.Is(err, error(cause)) {
		t.Error("keepHost=false must drop the errors.Is chain (cause text can embed the host)")
	}
}

func TestRedactTransportErr_NonURLErrorPassthrough(t *testing.T) {
	t.Parallel()
	plain := errors.New("not a url error")
	if got := RedactTransportErr(plain, true); got != plain {
		t.Errorf("non-*url.Error must pass through unchanged, got %v", got)
	}
}

func TestClassifyCause_FixedLabels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{&net.DNSError{IsNotFound: true}, "no such host"},
		{&net.DNSError{}, "dns error"},
		{fmt.Errorf("wrap: %w", syscall.ECONNREFUSED), "connection refused"},
		{fmt.Errorf("wrap: %w", syscall.ECONNRESET), "connection reset"},
		{context.Canceled, "canceled"},
		{context.DeadlineExceeded, "timeout"},
		{errors.New("anything else"), "transport error"},
	}
	for _, c := range cases {
		if got := classifyCause(c.err); got != c.want {
			t.Errorf("classifyCause(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

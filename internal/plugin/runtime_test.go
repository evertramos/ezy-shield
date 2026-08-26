// SPDX-License-Identifier: AGPL-3.0-only

package plugin

// Runtime tests (issue #206), driven by fixture plugin processes: the
// test binary re-execs ITSELF (the classic os/exec helper-process
// pattern) with EZY_PLUGIN_FIXTURE selecting a behavior — well-behaved,
// hanging, crashing, garbage-spewing, oversized-response, wrong-version.
// No external binaries, no on-the-fly compilation, -race clean.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain intercepts the helper re-exec before any tests run.
func TestMain(m *testing.M) {
	if behavior := os.Getenv("EZY_PLUGIN_FIXTURE"); behavior != "" {
		runFixture(behavior)
		return
	}
	os.Exit(m.Run())
}

// runFixture implements the plugin side of the stdio protocol.
func runFixture(behavior string) {
	in := bufio.NewReader(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush() //nolint:errcheck

	// Read the daemon's handshake line.
	if _, err := in.ReadString('\n'); err != nil {
		os.Exit(1)
	}

	writeJSON := func(v any) {
		b, _ := json.Marshal(v)
		b = append(b, '\n')
		_, _ = out.Write(b)
		_ = out.Flush()
	}

	version := ProtocolVersion
	if behavior == "wrong-version" {
		version = ProtocolVersion + 41
	}
	writeJSON(HandshakeResponse{
		ProtocolVersion: version,
		Name:            "fixture-" + behavior,
		Version:         "1.0.0",
		Capabilities:    []string{"echo"},
	})

	switch behavior {
	case "crash-after-handshake":
		fmt.Fprintln(os.Stderr, "fixture: crashing deliberately")
		os.Exit(3)
	case "hang":
		select {} // never answers anything
	}

	for {
		line, err := in.ReadString('\n')
		if err != nil {
			os.Exit(0)
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			os.Exit(1)
		}
		switch behavior {
		case "well":
			writeJSON(response{ID: req.ID, OK: true, Result: req.Payload})
		case "declines":
			writeJSON(response{ID: req.ID, OK: false, Error: "cannot handle " + req.Method})
		case "garbage":
			_, _ = out.WriteString("this is not JSON at all {{{{\n")
			_ = out.Flush()
		case "oversize":
			_, _ = out.WriteString(strings.Repeat("x", MaxResponseBytes+1024) + "\n")
			_ = out.Flush()
		case "hang-after-first":
			writeJSON(response{ID: req.ID, OK: true, Result: req.Payload})
			behavior = "hang-now"
		case "hang-now":
			select {}
		case "wrong-id":
			writeJSON(response{ID: req.ID + 999, OK: true})
		}
	}
}

// fixtureConfig builds a runtime config that re-execs this test binary.
func fixtureConfig(t *testing.T, behavior string, opts ...func(*Config)) Config {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cfg := Config{
		Path: exe,
		Type: "parser",
	}
	for _, o := range opts {
		o(&cfg)
	}
	// The helper selects behavior via env; exec.Command inherits our env.
	t.Setenv("EZY_PLUGIN_FIXTURE", behavior)
	return cfg
}

func startFixture(t *testing.T, behavior string, opts ...func(*Config)) (*Runtime, context.CancelFunc) {
	t.Helper()
	cfg := fixtureConfig(t, behavior, opts...)
	rt := NewRuntime(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	rt.Start(ctx)
	t.Cleanup(cancel)
	return rt, cancel
}

func waitHandshake(t *testing.T, rt *Runtime) HandshakeResponse {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if hs, ok := rt.Handshake(); ok {
			return hs
		}
		if disabled, why := rt.Disabled(); disabled {
			t.Fatalf("plugin disabled while waiting for handshake: %s", why)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("handshake never completed")
	return HandshakeResponse{}
}

func TestRuntime_WellBehavedEcho(t *testing.T) {
	rt, _ := startFixture(t, "well")
	hs := waitHandshake(t, rt)
	if hs.Name != "fixture-well" || hs.Version != "1.0.0" {
		t.Errorf("handshake = %+v", hs)
	}

	res, err := rt.Call(context.Background(), "echo", json.RawMessage(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if string(res) != `{"hello":"world"}` {
		t.Errorf("result = %s", res)
	}
}

func TestRuntime_StructuredErrorIsNotFatal(t *testing.T) {
	rt, _ := startFixture(t, "declines")
	waitHandshake(t, rt)

	_, err := rt.Call(context.Background(), "parse", nil)
	if err == nil || !strings.Contains(err.Error(), "cannot handle parse") {
		t.Fatalf("expected the plugin's structured error, got %v", err)
	}
	// The process must still be alive and NOT counted as a failure.
	if disabled, why := rt.Disabled(); disabled {
		t.Errorf("structured errors must not trip the breaker: %s", why)
	}
	if _, err := rt.Call(context.Background(), "parse", nil); err == nil ||
		!strings.Contains(err.Error(), "cannot handle") {
		t.Errorf("process should still answer after a declined request: %v", err)
	}
}

func TestRuntime_WrongVersionDisablesPermanently(t *testing.T) {
	rt, _ := startFixture(t, "wrong-version")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if disabled, why := rt.Disabled(); disabled {
			if !strings.Contains(why, "protocol") {
				t.Errorf("disable reason should name the protocol mismatch: %s", why)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("version mismatch never disabled the plugin")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := rt.Call(context.Background(), "echo", nil); err == nil {
		t.Errorf("calls to a disabled plugin must fail")
	}
}

func TestRuntime_HangIsKilledAndTimedOut(t *testing.T) {
	rt, _ := startFixture(t, "hang-after-first", func(c *Config) {
		c.RequestTimeout = 300 * time.Millisecond
	})
	waitHandshake(t, rt)

	// First call succeeds; second hangs → timeout error, process killed.
	if _, err := rt.Call(context.Background(), "echo", json.RawMessage(`1`)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	start := time.Now()
	_, err := rt.Call(context.Background(), "echo", json.RawMessage(`2`))
	if err == nil {
		t.Fatalf("hung request must fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %s — the watchdog did not kill promptly", elapsed)
	}
}

func TestRuntime_CrashRestartsThenBreakerTrips(t *testing.T) {
	var mu sync.Mutex
	var audits []string
	cfg := fixtureConfig(t, "crash-after-handshake", func(c *Config) {
		c.Audit = func(op, reason string) {
			mu.Lock()
			audits = append(audits, op)
			mu.Unlock()
		}
	})
	rt := NewRuntime(cfg)
	rt.backoff = []time.Duration{10 * time.Millisecond} // fast restarts under test
	ctx, cancel := context.WithCancel(context.Background())
	rt.Start(ctx)
	t.Cleanup(cancel)

	// The fixture crashes right after every handshake: restarts with
	// backoff until the breaker trips at maxFailuresPerHour.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if disabled, why := rt.Disabled(); disabled {
			if !strings.Contains(why, "failures within one hour") {
				t.Errorf("breaker reason = %s", why)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("breaker never tripped")
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	restarts, disables := 0, 0
	for _, op := range audits {
		switch op {
		case "plugin_restart":
			restarts++
		case "plugin_disabled":
			disables++
		}
	}
	if restarts < maxFailuresPerHour || disables != 1 {
		t.Errorf("audit trail: %d restarts, %d disables (want >=%d, 1)", restarts, disables, maxFailuresPerHour)
	}
}

func TestRuntime_GarbageOutputIsFatalForProcess(t *testing.T) {
	rt, _ := startFixture(t, "garbage", func(c *Config) {
		c.RequestTimeout = 2 * time.Second
	})
	waitHandshake(t, rt)

	_, err := rt.Call(context.Background(), "echo", nil)
	if err == nil {
		t.Fatalf("garbage response must fail the call")
	}
}

func TestRuntime_OversizedResponseCapped(t *testing.T) {
	rt, _ := startFixture(t, "oversize", func(c *Config) {
		c.RequestTimeout = 5 * time.Second
	})
	waitHandshake(t, rt)

	start := time.Now()
	_, err := rt.Call(context.Background(), "echo", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response must be cut off with a size error, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("size cap should trigger while reading, not at timeout")
	}
}

func TestRuntime_WrongResponseIDIsFatal(t *testing.T) {
	rt, _ := startFixture(t, "wrong-id", func(c *Config) {
		c.RequestTimeout = 2 * time.Second
	})
	waitHandshake(t, rt)
	if _, err := rt.Call(context.Background(), "echo", nil); err == nil {
		t.Fatalf("mismatched response id must fail the call")
	}
}

func TestRuntime_QueueFullDropsWithoutBlocking(t *testing.T) {
	rt, _ := startFixture(t, "hang", func(c *Config) {
		c.QueueCap = 2
		c.RequestTimeout = 30 * time.Second // the queue, not the timeout, is under test
	})
	// The fixture hangs after handshake, so nothing drains the queue.
	waitHandshake(t, rt)

	// Saturate: one request goes in-flight (the fixture never answers),
	// QueueCap more sit queued, anything beyond that must drop. Fired
	// async because a successfully queued Call blocks awaiting its result.
	for i := 0; i < 4; i++ {
		go func() {
			_, _ = rt.Call(context.Background(), "echo", nil)
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for rt.Dropped() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rt.Dropped() == 0 {
		t.Fatalf("saturating the queue never dropped a request")
	}

	// A direct call against the saturated queue fails IMMEDIATELY with
	// ErrBusy — the pipeline never blocks on a slow plugin.
	start := time.Now()
	_, err := rt.Call(context.Background(), "echo", nil)
	if err == nil || !strings.Contains(err.Error(), "queue full") {
		t.Fatalf("full queue must drop with ErrBusy, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("drop must be immediate, took %s", time.Since(start))
	}
}

func TestRuntime_ShutdownKillsPlugin(t *testing.T) {
	rt, cancel := startFixture(t, "well")
	waitHandshake(t, rt)
	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case <-rt.done:
			return // supervisor exited; process group was killed
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("runtime did not stop after ctx cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FuzzPluginResponse: hostile stdout must never panic the decoder path.
func FuzzPluginResponse(f *testing.F) {
	f.Add([]byte(`{"id":1,"ok":true,"result":{"a":1}}`))
	f.Add([]byte(`{"id":1,"ok":false,"error":"` + strings.Repeat("x", 10000) + `"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"id":"string-not-number"}`))
	f.Add([]byte{0xff, 0xfe, 0x00})
	f.Add([]byte(`{"id":1,"unknown_field":{"deep":[1,2,3]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var resp response
		if err := json.Unmarshal(data, &resp); err != nil {
			return
		}
		_ = capString(resp.Error, maxErrorChars)
	})
}

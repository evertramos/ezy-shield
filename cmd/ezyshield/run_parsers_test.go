package main

import (
	"io"
	"log/slog"
	"testing"

	"github.com/evertramos/ezy-shield/internal/config"
)

// TestDefaultParsersCoverAllValidParserNames guards issue #308: a collector
// parser name that config validation accepts but no registered parser handles
// causes daemon.parse to find no match and silently drop every line — a whole
// log source produces zero detections (SECURITY-REVIEW §1/§2). This asserts
// that for every parser name config accepts, at least one parser in
// defaultParsers() Matches the source it routes to.
func TestDefaultParsersCoverAllValidParserNames(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	parsers := defaultParsers(logger)

	for _, name := range config.ValidParserNames() {
		// A file collector with `parser: <name>` routes lines under the
		// source "<name>:<path>" (see sourceID). Some sources use a plain
		// path (e.g. "/var/log/apache2/error.log"); the explicit override
		// prefix is the canonical worst case and what every parser must claim.
		source := sourceID(name, "/var/log/example.log")

		matched := false
		for _, p := range parsers {
			if p.Matches(source) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("config accepts parser %q but no registered parser Matches source %q: "+
				"lines from this log source are silently dropped (issue #308)", name, source)
		}
	}
}

// TestDefaultParsersHandleApacheError is the direct regression for issue #308:
// the ApacheErrorParser was implemented, tested, config-accepted and
// documented, yet absent from the daemon's parser list, so `parser: apache-error`
// collectors dropped every line.
func TestDefaultParsersHandleApacheError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	parsers := defaultParsers(logger)

	sources := []string{
		"apache-error:/var/log/apache2/error.log",
		"file:/var/log/apache2/error.log",
		"file:/var/log/httpd/error_log",
	}
	for _, source := range sources {
		matched := false
		for _, p := range parsers {
			if p.Matches(source) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("no registered parser Matches Apache error source %q (issue #308)", source)
		}
	}
}

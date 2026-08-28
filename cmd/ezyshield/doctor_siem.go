// SPDX-License-Identifier: AGPL-3.0-only

package main

// SIEM sink doctor checks (issue #203): endpoint reachability (non-fatal —
// a SIEM being down never blocks EzyShield) and a LOUD warning for any sink
// running a plaintext transport.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/evertramos/ezy-shield/internal/config"
	"github.com/evertramos/ezy-shield/internal/siem"
)

// checkSIEMSinks validates every configured SIEM sink. Returns a single N/A
// result when none is configured.
func checkSIEMSinks(configDir string) []CheckResult {
	cfg, err := config.LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil || len(cfg.SIEM) == 0 {
		return []CheckResult{{
			Name:   "siem: forwarding",
			Status: statusNA,
			Hint:   "no siem sinks configured",
		}}
	}
	var out []CheckResult
	for i := range cfg.SIEM {
		out = append(out, checkOneSIEMSink(&cfg.SIEM[i])...)
	}
	return out
}

func checkOneSIEMSink(s *config.SIEMSinkCfg) []CheckResult {
	label := "siem(" + s.Name + ")"
	scheme, target, err := siem.ParseAddress(s.Address)
	if err != nil {
		return []CheckResult{{
			Name:   label + ": address",
			Status: statusFail,
			Hint:   err.Error(),
		}}
	}
	var results []CheckResult

	// Loud plaintext warning — validation already required the explicit
	// opt-in; doctor keeps reminding, per the AC.
	if scheme == "tcp" || scheme == "udp" {
		results = append(results, CheckResult{
			Name:   label + ": transport security",
			Status: statusWarn,
			Hint: "plaintext " + scheme + ":// — audit events (IPs, rule reasons quoting log lines) cross the network UNENCRYPTED; " +
				"switch to tls:// unless this network segment is fully trusted",
		})
	}

	// Reachability (non-fatal by design: a warn, never a fail — the daemon
	// keeps working and buffering regardless).
	name := label + ": reachable"
	switch scheme {
	case "tcp", "tls":
		// A plain TCP dial suffices for both; a TLS handshake would need
		// the server certificate chain, which doctor should not require.
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, derr := (&net.Dialer{}).DialContext(dctx, "tcp", target)
		dcancel()
		if derr != nil {
			results = append(results, CheckResult{Name: name, Status: statusWarn,
				Hint: "endpoint not reachable: " + sanitizeErrorMessage(derr.Error()) + " -- events will buffer (bounded) and drop oldest"})
		} else {
			_ = conn.Close()
			results = append(results, CheckResult{Name: name, Status: statusPass})
		}
	case "udp":
		results = append(results, CheckResult{Name: name, Status: statusNA,
			Hint: "udp is fire-and-forget; reachability cannot be probed"})
	case "uds":
		if fi, serr := os.Stat(target); serr != nil {
			results = append(results, CheckResult{Name: name, Status: statusWarn,
				Hint: "socket path not present: " + sanitizeErrorMessage(serr.Error())})
		} else if fi.Mode()&os.ModeSocket == 0 {
			results = append(results, CheckResult{Name: name, Status: statusWarn,
				Hint: "path exists but is not a unix socket"})
		} else {
			results = append(results, CheckResult{Name: name, Status: statusPass})
		}
	case "file":
		dir := filepath.Dir(target)
		if fi, serr := os.Stat(dir); serr != nil || !fi.IsDir() {
			results = append(results, CheckResult{Name: name, Status: statusWarn,
				Hint: "target directory " + dir + " does not exist"})
		} else {
			results = append(results, CheckResult{Name: name, Status: statusPass})
		}
	}

	// CA pin sanity.
	if s.CAFile != "" {
		if _, serr := os.Stat(s.CAFile); serr != nil {
			results = append(results, CheckResult{
				Name:   label + ": ca_file",
				Status: statusFail,
				Hint:   "ca_file not readable: " + sanitizeErrorMessage(serr.Error()),
			})
		} else if !strings.HasSuffix(s.CAFile, ".pem") && !strings.HasSuffix(s.CAFile, ".crt") {
			results = append(results, CheckResult{
				Name:   label + ": ca_file",
				Status: statusPass,
				Hint:   "present (extension is unusual; expecting a PEM bundle)",
			})
		} else {
			results = append(results, CheckResult{Name: label + ": ca_file", Status: statusPass})
		}
	}
	return results
}

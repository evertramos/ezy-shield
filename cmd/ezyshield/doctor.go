package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	statusPass = "PASS"
	statusFail = "FAIL"
	statusNA   = "N/A"
)

// CheckResult is the result of a single doctor check.
type CheckResult struct {
	Name   string `json:"name"`
	Status string `json:"status"`         // PASS | FAIL | N/A
	Hint   string `json:"hint,omitempty"` // human-readable hint shown on FAIL/N/A
}

// DoctorSummary aggregates all check counts.
type DoctorSummary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
}

func newDoctorCmd() *cobra.Command {
	var configDir string

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run environment health checks",
		Long: `Check that EzyShield's environment is correctly configured:
  - config.yaml / policy.yaml -- exist and are valid YAML
  - file permissions -- config files are not world-readable
  - nft binary -- nftables is installed
  - journald -- journalctl is present and accessible

Each check prints PASS, FAIL, or N/A with a remediation hint on failure.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDoctor(cmd, configDir, jsonOutput)
		},
	}

	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/ezyshield",
		"directory containing config.yaml and policy.yaml")

	return cmd
}

// runDoctor runs all health checks and writes results to cmd.
// jsonOut controls whether output is JSON (true) or human-readable (false).
func runDoctor(cmd *cobra.Command, configDir string, jsonOut bool) error {
	checks := []CheckResult{
		checkFileExists(filepath.Join(configDir, "config.yaml"), "config.yaml"),
		checkFileParses(filepath.Join(configDir, "config.yaml"), "config.yaml"),
		checkFileExists(filepath.Join(configDir, "policy.yaml"), "policy.yaml"),
		checkFileParses(filepath.Join(configDir, "policy.yaml"), "policy.yaml"),
		checkFilePerms(filepath.Join(configDir, "config.yaml"), "config.yaml"),
		checkFilePerms(filepath.Join(configDir, "policy.yaml"), "policy.yaml"),
		checkNFTPresent(),
		checkJournaldReadable(),
	}

	summary := DoctorSummary{Total: len(checks)}
	for _, c := range checks {
		switch c.Status {
		case statusPass:
			summary.Pass++
		case statusFail:
			summary.Fail++
		}
	}

	if jsonOut {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"checks":  checks,
			"summary": summary,
		})
	}

	w := cmd.OutOrStdout()
	for _, c := range checks {
		line := fmt.Sprintf("[%s] %s", c.Status, c.Name)
		if c.Hint != "" {
			line += "\n       hint: " + c.Hint
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}
	if _, err := fmt.Fprintf(w, "\n%d/%d checks passed\n", summary.Pass, summary.Total); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

// checkFileExists returns PASS when path exists and is a regular file.
func checkFileExists(path, label string) CheckResult {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return CheckResult{
			Name:   label + ": exists",
			Status: statusFail,
			Hint:   fmt.Sprintf("file not found -- run 'ezyshield init' to create %s", path),
		}
	}
	if err != nil {
		return CheckResult{Name: label + ": exists", Status: statusFail, Hint: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return CheckResult{
			Name:   label + ": exists",
			Status: statusFail,
			Hint:   path + " exists but is not a regular file",
		}
	}
	return CheckResult{Name: label + ": exists", Status: statusPass}
}

// checkFileParses returns PASS when path is a syntactically valid YAML file.
// Returns N/A when the file does not exist (checkFileExists covers that).
func checkFileParses(path, label string) CheckResult {
	// G304: path comes from --config-dir flag (admin-controlled), not from log input.
	data, err := os.ReadFile(path) //nolint:gosec
	if os.IsNotExist(err) {
		return CheckResult{Name: label + ": parses", Status: statusNA,
			Hint: "file absent -- run 'ezyshield init' first"}
	}
	if err != nil {
		return CheckResult{Name: label + ": parses", Status: statusFail, Hint: err.Error()}
	}

	var out any
	if err := yaml.Unmarshal(data, &out); err != nil {
		return CheckResult{
			Name:   label + ": parses",
			Status: statusFail,
			Hint:   "YAML parse error: " + err.Error(),
		}
	}
	return CheckResult{Name: label + ": parses", Status: statusPass}
}

// checkFilePerms returns PASS when path is not world-readable (perm <= 0640).
// Returns N/A when the file does not exist.
func checkFilePerms(path, label string) CheckResult {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return CheckResult{Name: label + ": permissions", Status: statusNA,
			Hint: "file absent -- run 'ezyshield init' first"}
	}
	if err != nil {
		return CheckResult{Name: label + ": permissions", Status: statusFail, Hint: err.Error()}
	}

	perm := info.Mode().Perm()
	const maxPerm = 0o640
	if perm&^os.FileMode(maxPerm) != 0 {
		return CheckResult{
			Name:   label + ": permissions",
			Status: statusFail,
			Hint: fmt.Sprintf("permissions %04o are too open (max %04o) -- run: chmod %04o %s",
				perm, maxPerm, maxPerm, path),
		}
	}
	return CheckResult{Name: label + ": permissions", Status: statusPass}
}

// checkNFTPresent returns PASS when the nft binary is found in PATH.
func checkNFTPresent() CheckResult {
	path, err := exec.LookPath("nft")
	if err != nil {
		return CheckResult{
			Name:   "nft: binary present",
			Status: statusFail,
			Hint:   "nftables not found -- install it: apt install nftables  (or dnf/zypper equivalent)",
		}
	}
	return CheckResult{
		Name:   "nft: binary present",
		Status: statusPass,
		Hint:   path,
	}
}

// checkJournaldReadable returns PASS when journalctl is present and responds.
func checkJournaldReadable() CheckResult {
	jctlPath, err := exec.LookPath("journalctl")
	if err != nil {
		return CheckResult{
			Name:   "journald: readable",
			Status: statusFail,
			Hint:   "journalctl not found -- EzyShield requires systemd journald to read SSH/service logs",
		}
	}

	// Quick probe: list 0 lines; non-zero exit means access is denied.
	// G204: jctlPath is from LookPath("journalctl"), not user input.
	ctx := context.Background()
	out, err := exec.CommandContext(ctx, jctlPath, "-n", "0", "--no-pager").CombinedOutput() //nolint:gosec
	if err != nil {
		return CheckResult{
			Name:   "journald: readable",
			Status: statusFail,
			Hint: fmt.Sprintf(
				"journalctl error: %v -- add user to 'systemd-journal' group: %s",
				err, strings.TrimSpace(string(out))),
		}
	}
	return CheckResult{Name: "journald: readable", Status: statusPass}
}

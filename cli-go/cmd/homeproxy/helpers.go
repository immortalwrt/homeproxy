package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"homeproxy-cli/internal/system"
)

// writeJSON encodes v as JSON to stdout (no HTML escape). For agent-friendly output.
func writeJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// requireRoot returns an error if the process is not running as root.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command requires root privileges")
	}
	return nil
}

// uciCommitAndReload commits the homeproxy UCI config and reloads the service.
func uciCommitAndReload() error {
	if err := system.UCICommit("homeproxy"); err != nil {
		return err
	}
	return system.ServiceReload()
}

// validateOneOf returns an error if value is not in allowed.
func validateOneOf(value string, allowed []string, name string) error {
	if containsString(allowed, value) {
		return nil
	}
	return fmt.Errorf("invalid %s: %s (use: %s)", name, value, strings.Join(allowed, ", "))
}

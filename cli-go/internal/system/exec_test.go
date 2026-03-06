package system

import (
	"strings"
	"testing"
)

func TestRunCommand_NotFound(t *testing.T) {
	// Ensure we use the real impl for this test (no mock)
	old := RunCommandImpl
	RunCommandImpl = execRunCommand
	defer func() { RunCommandImpl = old }()

	_, err := runCommand("nonexistent_cmd_xyz_12345", "arg")
	if err == nil {
		t.Fatal("expected error for nonexistent command")
	}
	if !strings.Contains(err.Error(), "failed") {
		t.Errorf("expected 'failed' in error, got: %v", err)
	}
}

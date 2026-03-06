package system

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	ConfigFile = "/etc/config/homeproxy"
	InitScript = "/etc/init.d/homeproxy"
	LogDir     = "/var/run/homeproxy"

	RPCObject = "luci.homeproxy"
)

// CheckInstalledFunc, when non-nil, overrides CheckInstalled. Tests use this to bypass the config file check.
var CheckInstalledFunc func() error

// CheckInstalled verifies that the HomeProxy UCI config exists.
func CheckInstalled() error {
	if CheckInstalledFunc != nil {
		return CheckInstalledFunc()
	}
	if _, err := os.Stat(ConfigFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("HomeProxy is not installed (missing %s)", ConfigFile)
		}
		return fmt.Errorf("failed to check HomeProxy installation: %w", err)
	}
	return nil
}

// ServiceStatus returns whether the init script reports the service as running,
// along with the raw status output.
func ServiceStatus() (bool, string, error) {
	out, err := runCommand(InitScript, "status")
	if err != nil {
		// Still return whatever output we have; caller can decide how to handle.
		return false, out, err
	}
	running := out != ""
	return running, out, nil
}

func ServiceStart() error {
	_, err := runCommand(InitScript, "start")
	return err
}

func ServiceStop() error {
	_, err := runCommand(InitScript, "stop")
	return err
}

func ServiceRestart() error {
	_, err := runCommand(InitScript, "restart")
	return err
}

func ServiceReload() error {
	_, err := runCommand(InitScript, "reload")
	return err
}

// UCIGet gets a single UCI option, e.g. "homeproxy.config.routing_mode".
func UCIGet(path string) (string, error) {
	return runCommand("uci", "get", path)
}

// UCIShow shows all config for a package, e.g. "homeproxy".
func UCIShow(pkg string) (string, error) {
	return runCommand("uci", "show", pkg)
}

// UCISet sets a UCI option, e.g. "homeproxy.config.routing_mode=proxy_all".
func UCISet(path, value string) error {
	_, err := runCommand("uci", "set", fmt.Sprintf("%s=%s", path, value))
	return err
}

// UCIAddList adds a value to a list option.
func UCIAddList(path, value string) error {
	_, err := runCommand("uci", "add_list", fmt.Sprintf("%s=%s", path, value))
	return err
}

// UCIAdd adds a new section, e.g. "uci add homeproxy node".
func UCIAdd(pkg, sectionType string) error {
	_, err := runCommand("uci", "add", pkg, sectionType)
	return err
}

// UCIDelete deletes an option or section.
func UCIDelete(path string) error {
	_, err := runCommand("uci", "delete", path)
	return err
}

// UCICommit commits a package, e.g. "homeproxy".
func UCICommit(pkg string) error {
	_, err := runCommand("uci", "commit", pkg)
	return err
}

// LogFile returns the full path to a log file under LogDir.
func LogFile(name string) string {
	return filepath.Join(LogDir, fmt.Sprintf("%s.log", name))
}

// UBUSCall calls an ubus method with a params object, returning raw JSON.
func UBUSCall(object, method string, params any) (string, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("failed to encode params: %w", err)
	}
	return runCommand("ubus", "call", object, method, string(data))
}


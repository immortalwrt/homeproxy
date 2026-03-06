package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"homeproxy-cli/internal/system"
)

const certTmpPath = "/tmp/homeproxy_certificate.tmp"

var certFilenames = []string{"client_ca", "server_publickey", "server_privatekey"}

func certCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy cert write <filename> --file <path>")
	}
	action := args[0]
	rest := args[1:]

	if action != "write" {
		return fmt.Errorf("usage: homeproxy cert write <filename> --file <path>")
	}
	return certWrite(rest)
}

func certWrite(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	filename, filePath := parseFileFlag(args)
	if filename == "" {
		return fmt.Errorf("usage: homeproxy cert write <client_ca|server_publickey|server_privatekey> --file <path>")
	}
	if err := validateOneOf(filename, certFilenames, "filename"); err != nil {
		return err
	}
	if filePath == "" {
		return fmt.Errorf("usage: homeproxy cert write <filename> --file <path>")
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	if err := os.WriteFile(certTmpPath, content, 0600); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	defer os.Remove(certTmpPath)

	raw, err := system.UBUSCall(system.RPCObject, "certificate_write", map[string]string{"filename": filename})
	if err != nil {
		return err
	}
	var out struct {
		Result bool   `json:"result"`
		Error  string `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &out) == nil {
		if !out.Result {
			return fmt.Errorf("certificate_write failed: %s", out.Error)
		}
	} else if strings.Contains(raw, `"result":false`) {
		return fmt.Errorf("certificate_write failed")
	}
	logInfo("Certificate written: " + filename)
	return nil
}

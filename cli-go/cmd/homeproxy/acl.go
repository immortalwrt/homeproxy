package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"homeproxy-cli/internal/system"
)

var aclTypes = []string{"direct_list", "proxy_list"}

func aclCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy acl <list|write> [options]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "list":
		return aclList(rest)
	case "write":
		return aclWrite(rest)
	default:
		return fmt.Errorf("unknown acl action: %s (use: list, write)", action)
	}
}

func aclList(args []string) error {
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: homeproxy acl list <direct_list|proxy_list>")
	}
	typ := args[0]
	if err := validateOneOf(typ, aclTypes, "type"); err != nil {
		return err
	}

	raw, err := system.UBUSCall(system.RPCObject, "acllist_read", map[string]string{"type": typ})
	if err != nil {
		return err
	}
	var out struct {
		Content string `json:"content"`
		Error   string `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &out) == nil {
		if out.Error != "" {
			return fmt.Errorf("%s", out.Error)
		}
		fmt.Print(out.Content)
	} else {
		fmt.Print(raw)
	}
	return nil
}

func aclWrite(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	typ, filePath := parseFileFlag(args)
	if typ == "" {
		return fmt.Errorf("usage: homeproxy acl write <direct_list|proxy_list> --file <path>")
	}
	if err := validateOneOf(typ, aclTypes, "type"); err != nil {
		return err
	}
	if filePath == "" {
		return fmt.Errorf("usage: homeproxy acl write <type> --file <path>")
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	raw, err := system.UBUSCall(system.RPCObject, "acllist_write", map[string]any{
		"type":    typ,
		"content": string(content),
	})
	if err != nil {
		return err
	}
	var out struct {
		Result bool   `json:"result"`
		Error  string `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &out) == nil {
		if !out.Result || out.Error != "" {
			return fmt.Errorf("acllist_write failed: %s", out.Error)
		}
	} else if strings.Contains(raw, `"result":false`) {
		return fmt.Errorf("acllist_write failed")
	}
	logInfo("ACL written: " + typ)
	return nil
}

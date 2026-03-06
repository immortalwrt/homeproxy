package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"homeproxy-cli/internal/system"
)

var resourceTypes = []string{"china_ip4", "china_ip6", "china_list", "gfw_list"}

func resourcesCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("usage: homeproxy resources <version|update> [type]")
	}
	action := args[0]
	rest := args[1:]

	switch action {
	case "version":
		return resourcesVersion(rest)
	case "update":
		return resourcesUpdate(rest)
	default:
		return fmt.Errorf("unknown resources action: %s (use: version, update)", action)
	}
}

func resourcesVersion(args []string) error {
	types := resourceTypes
	if len(args) > 0 && args[0] != "" {
		t := args[0]
		if err := validateOneOf(t, resourceTypes, "type"); err != nil {
			return err
		}
		types = []string{t}
	}

	for _, typ := range types {
		raw, err := system.UBUSCall(system.RPCObject, "resources_get_version", map[string]string{"type": typ})
		if err != nil {
			logWarn(typ + ": " + err.Error())
			continue
		}
		var out struct {
			Version string `json:"version"`
			Error   string `json:"error"`
		}
		if json.Unmarshal([]byte(raw), &out) == nil {
			if out.Error != "" {
				fmt.Printf("%s: error=%s\n", typ, out.Error)
			} else {
				fmt.Printf("%s: %s\n", typ, out.Version)
			}
		} else {
			fmt.Printf("%s: %s\n", typ, strings.TrimSpace(raw))
		}
	}
	return nil
}

func resourcesUpdate(args []string) error {
	if err := requireRoot(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "" {
		return fmt.Errorf("usage: homeproxy resources update <type> (china_ip4, china_ip6, china_list, gfw_list)")
	}
	typ := args[0]
	if err := validateOneOf(typ, resourceTypes, "type"); err != nil {
		return err
	}

	logInfo("Updating resource: " + typ)
	raw, err := system.UBUSCall(system.RPCObject, "resources_update", map[string]string{"type": typ})
	if err != nil {
		return err
	}
	var out struct {
		Status int    `json:"status"`
		Error  string `json:"error"`
	}
	if json.Unmarshal([]byte(raw), &out) == nil {
		switch out.Status {
		case 0:
			logInfo("Resource updated successfully")
		case 1:
			return fmt.Errorf("update failed")
		case 2:
			logInfo("Update in progress")
		case 3:
			logInfo("Already up to date")
		default:
			logInfo("Status: " + fmt.Sprint(out.Status))
		}
		if out.Error != "" {
			return fmt.Errorf("error: %s", out.Error)
		}
	}
	return nil
}

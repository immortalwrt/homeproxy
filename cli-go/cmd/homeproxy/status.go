package main

import (
	"encoding/json"
	"fmt"

	"homeproxy-cli/internal/system"
)

type singboxFeatures struct {
	Result struct {
		Version string `json:"version"`
	} `json:"result"`
}

type statusJSON struct {
	Service   string `json:"service"`
	MainNode  string `json:"main_node"`
	Routing   string `json:"routing"`
	Version   string `json:"version,omitempty"`
}

func statusCommand(args []string) error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	_, useJSON := parseJSONFlag(args)

	running, _, _ := system.ServiceStatus()
	mainNode, _ := system.UCIGet("homeproxy.config.main_node")
	mainNodeLabel := ""
	if mainNode != "" && mainNode != "nil" {
		label, err := system.UCIGet(fmt.Sprintf("homeproxy.%s.label", mainNode))
		if err != nil || label == "" {
			mainNodeLabel = mainNode
		} else {
			mainNodeLabel = label
		}
	}
	mode, _ := system.UCIGet("homeproxy.config.routing_mode")
	version := ""
	raw, err := system.UBUSCall(system.RPCObject, "singbox_get_features", map[string]any{})
	if err == nil && raw != "" {
		var f singboxFeatures
		if jsonErr := json.Unmarshal([]byte(raw), &f); jsonErr == nil && f.Result.Version != "" {
			version = f.Result.Version
		}
	}

	if useJSON {
		svc := "stopped"
		if running {
			svc = "running"
		}
		out := statusJSON{
			Service:  svc,
			MainNode: mainNodeLabel,
			Routing:  mode,
			Version:  version,
		}
		return writeJSON(out)
	}

	logInfo("HomeProxy Status")
	fmt.Println("==================")
	if running {
		logInfo("Service: RUNNING")
	} else {
		logInfo("Service: NOT RUNNING")
	}
	if mainNodeLabel != "" {
		logInfo("Main Node: " + mainNodeLabel)
	} else {
		logInfo("Main Node: Not configured")
	}
	if mode != "" {
		logInfo("Routing: " + mode)
	}
	if version != "" {
		logInfo("Version: " + version)
	}
	return nil
}


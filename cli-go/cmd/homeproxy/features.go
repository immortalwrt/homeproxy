package main

import (
	"encoding/json"
	"fmt"

	"homeproxy-cli/internal/system"
)

func featuresCommand() error {
	if err := system.CheckInstalled(); err != nil {
		return err
	}

	logInfo("Sing-box Features")
	fmt.Println("===================")

	raw, err := system.UBUSCall(system.RPCObject, "singbox_get_features", map[string]any{})
	if err != nil {
		return err
	}

	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		fmt.Println(raw)
		return nil
	}
	indent, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Println(raw)
		return nil
	}
	fmt.Println(string(indent))
	return nil
}
